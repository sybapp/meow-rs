//! Certificate parsing and authentication shared by native TLS clients.
use crate::{Result, TransportError};
use sha2::Digest as _;

/// Cover-certificate verification policy — shared by the TLS 1.3 and 1.2
/// record-level handshakes (upstream `ca` verifier semantics).
#[derive(Default)]
pub(crate) struct CertPolicy {
    /// Skip verification entirely (`skip-cert-verify`).
    pub(crate) skip_cert_verify: bool,
    /// DNS name to check — `name-cert-verify` override or SNI.
    pub(crate) verify_name: Option<String>,
    /// SHA-256 fingerprint of the cover cert (leaf or CA pin).
    pub(crate) cert_pin: Option<[u8; 32]>,
    /// Extra CA roots (DER) on top of the Mozilla bundle.
    pub(crate) additional_roots: Vec<Vec<u8>>,
}

/// TLS 1.3 `Certificate` body → DER list (context byte + u24 list + entries).
pub(crate) fn parse_certificate_list(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut pos = 0;
    let ctx_len = take_u8(body, &mut pos)? as usize;
    if ctx_len != 0 {
        return Err(TransportError::Tls(
            "tls13: nonempty server certificate context".into(),
        ));
    }
    let list_len = take_u24(body, &mut pos)?;
    let list = take(body, &mut pos, list_len)?;
    if pos != body.len() {
        return Err(TransportError::Tls(
            "tls13: trailing Certificate bytes".into(),
        ));
    }
    let mut certs = Vec::new();
    let mut lp = 0;
    while lp < list.len() {
        let clen = take_u24(list, &mut lp)?;
        if clen == 0 {
            return Err(TransportError::Tls("tls13: empty certificate".into()));
        }
        certs.push(take(list, &mut lp, clen)?.to_vec());
        let ext_len = take_u16(list, &mut lp)? as usize;
        take(list, &mut lp, ext_len)?; // per-cert extensions
    }
    if certs.is_empty() {
        return Err(TransportError::Tls("tls13: empty certificate list".into()));
    }
    Ok(certs)
}

/// Verify a TLS `SignatureScheme` signature over `content` with the leaf
/// cert's public key — shared by TLS 1.3 CertificateVerify and the TLS 1.2
/// ServerKeyExchange signature.
pub(crate) fn verify_signature(
    scheme: u16,
    signature: &[u8],
    content: &[u8],
    leaf_der: &[u8],
) -> Result<()> {
    let cert = boring::x509::X509::from_der(leaf_der)
        .map_err(|e| TransportError::Tls(format!("tls13: bad leaf cert: {e}")))?;
    let pkey = cert
        .public_key()
        .map_err(|e| TransportError::Tls(format!("tls13: leaf pubkey: {e}")))?;

    use boring::sign::Verifier;
    let (md, pss) = match scheme {
        // RSA-PSS with digest-length salt.
        0x0804 => (Some(boring::hash::MessageDigest::sha256()), true),
        0x0805 => (Some(boring::hash::MessageDigest::sha384()), true),
        0x0806 => (Some(boring::hash::MessageDigest::sha512()), true),
        // RSA PKCS#1 v1.5 and ECDSA share the plain-digest path.
        0x0401 | 0x0403 => (Some(boring::hash::MessageDigest::sha256()), false),
        0x0501 | 0x0503 => (Some(boring::hash::MessageDigest::sha384()), false),
        0x0601 | 0x0603 => (Some(boring::hash::MessageDigest::sha512()), false),
        // Ed25519 — no digest.
        0x0807 => (None, false),
        other => {
            return Err(TransportError::Tls(format!(
                "tls13: unsupported CV scheme 0x{other:04x}"
            )))
        }
    };
    let mut verifier = match md {
        Some(md) => Verifier::new(md, &pkey),
        None => Verifier::new_without_digest(&pkey),
    }
    .map_err(|e| TransportError::Tls(format!("tls13: CV verifier: {e}")))?;
    if pss {
        let md = md.expect("pss digest");
        verifier
            .set_rsa_padding(boring::rsa::Padding::PKCS1_PSS)
            .map_err(|e| TransportError::Tls(format!("tls13: CV pad: {e}")))?;
        verifier
            .set_rsa_pss_saltlen(boring::sign::RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| TransportError::Tls(format!("tls13: CV salt: {e}")))?;
        verifier
            .set_rsa_mgf1_md(md)
            .map_err(|e| TransportError::Tls(format!("tls13: CV mgf1: {e}")))?;
    }

    let ok = verifier
        .verify_oneshot(signature, content)
        .map_err(|e| TransportError::Tls(format!("tls13: CV verify: {e}")))?;
    if !ok {
        return Err(TransportError::Tls(
            "tls13: CertificateVerify mismatch".into(),
        ));
    }
    Ok(())
}

/// Verify the cover certificate chain per `policy` — `cert_pin` (leaf or CA
/// pin) → `skip_cert_verify` → Mozilla roots + `name` check.
pub(crate) fn verify_certificate_chain(
    policy: &CertPolicy,
    name: &str,
    certs: &[Vec<u8>],
) -> Result<()> {
    use boring::stack::Stack;
    use boring::x509::X509StoreContext;
    use sha2::Sha256;

    let name = policy.verify_name.as_deref().unwrap_or(name);
    let leaf_der = certs
        .first()
        .ok_or_else(|| TransportError::Tls("tls13: empty certificate chain".into()))?;
    let leaf = boring::x509::X509::from_der(leaf_der)
        .map_err(|e| TransportError::Tls(format!("tls13: leaf DER: {e}")))?;
    let mut chain = Stack::new().map_err(|e| TransportError::Tls(format!("tls13: stack: {e}")))?;
    for der in &certs[1..] {
        let c = boring::x509::X509::from_der(der)
            .map_err(|e| TransportError::Tls(format!("tls13: chain DER: {e}")))?;
        chain
            .push(c)
            .map_err(|e| TransportError::Tls(format!("tls13: chain push: {e}")))?;
    }

    // Fingerprint pin — upstream `ca.NewFingerprintVerifier` semantics:
    // a pin matching the leaf accepts directly; a pin matching a chain
    // cert verifies the chain up to the pinned CA plus the name check.
    if let Some(pin) = &policy.cert_pin {
        for (i, der) in certs.iter().enumerate() {
            if boring::memcmp::eq(Sha256::digest(der).as_slice(), pin.as_slice()) {
                if i == 0 {
                    return Ok(());
                }
                // CA pin: verify leaf against a store holding the pinned cert.
                let pinned = boring::x509::X509::from_der(der)
                    .map_err(|e| TransportError::Tls(format!("tls13: pinned cert DER: {e}")))?;
                let mut builder = boring::x509::store::X509StoreBuilder::new()
                    .map_err(|e| TransportError::Tls(format!("tls13: store: {e}")))?;
                builder
                    .add_cert(pinned)
                    .map_err(|e| TransportError::Tls(format!("tls13: pin store: {e}")))?;
                builder
                    .try_set_flags(boring::x509::verify::X509VerifyFlags::PARTIAL_CHAIN)
                    .map_err(|e| TransportError::Tls(format!("tls13: pinned CA flags: {e}")))?;
                set_server_purpose(&mut builder)?;
                set_name(&mut builder, name)?;
                let store = builder.build();
                let mut ctx = X509StoreContext::new()
                    .map_err(|e| TransportError::Tls(format!("tls13: ctx: {e}")))?;
                let (verified, err) = ctx
                    .init(&store, &leaf, &chain, |c| {
                        c.verify_cert().map(|ok| (ok, c.verify_result().err()))
                    })
                    .map_err(|e| TransportError::Tls(format!("tls13: pin verify: {e}")))?;
                return if verified {
                    Ok(())
                } else {
                    Err(TransportError::Tls(format!(
                        "tls13: pinned CA did not verify the chain: {}",
                        err.map_or("unknown", |e| e.error_string())
                    )))
                };
            }
        }
        return Err(TransportError::Tls(
            "tls13: certificate fingerprint mismatch".into(),
        ));
    }

    if policy.skip_cert_verify && policy.verify_name.is_none() {
        return Ok(());
    }

    let mut builder = crate::tls::boring_backend::build_root_store(&policy.additional_roots)?;
    set_server_purpose(&mut builder)?;
    set_name(&mut builder, name)?;
    let store = builder.build();
    let mut ctx =
        X509StoreContext::new().map_err(|e| TransportError::Tls(format!("tls13: ctx: {e}")))?;
    let (verified, err) = ctx
        .init(&store, &leaf, &chain, |c| {
            c.verify_cert().map(|ok| (ok, c.verify_result().err()))
        })
        .map_err(|e| TransportError::Tls(format!("tls13: verify: {e}")))?;
    if !verified {
        return Err(TransportError::Tls(format!(
            "tls13: certificate verification failed: {}",
            err.map_or("unknown", |e| e.error_string())
        )));
    }
    Ok(())
}
fn set_name(builder: &mut boring::x509::store::X509StoreBuilder, name: &str) -> Result<()> {
    if name.is_empty() {
        return Ok(());
    }
    let result = if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        builder.verify_param_mut().set_ip(ip)
    } else {
        builder.verify_param_mut().set_host(name)
    };
    result.map_err(|e| TransportError::Tls(format!("tls13: verify name: {e}")))
}
fn take<'a>(body: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(n)
        .ok_or_else(|| TransportError::Tls("tls13: length overflow".into()))?;
    let out = body
        .get(*pos..end)
        .ok_or_else(|| TransportError::Tls("tls13: truncated certificate".into()))?;
    *pos = end;
    Ok(out)
}
fn take_u8(body: &[u8], pos: &mut usize) -> Result<u8> {
    Ok(take(body, pos, 1)?[0])
}
fn take_u16(body: &[u8], pos: &mut usize) -> Result<u16> {
    Ok(u16::from_be_bytes(
        take(body, pos, 2)?.try_into().expect("size"),
    ))
}
fn take_u24(body: &[u8], pos: &mut usize) -> Result<usize> {
    let b = take(body, pos, 3)?;
    Ok((usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
}

fn set_server_purpose(builder: &mut boring::x509::store::X509StoreBuilder) -> Result<()> {
    use foreign_types::ForeignTypeRef as _;
    // SAFETY: the borrowed verification parameter belongs to this live store.
    // BoringSSL checks the purpose ID; SSL_SERVER restricts certificate EKU.
    let ok = unsafe {
        boring_sys::X509_VERIFY_PARAM_set_purpose(
            builder.verify_param_mut().as_ptr(),
            boring_sys::X509_PURPOSE_SSL_SERVER,
        )
    };
    if ok == 1 {
        Ok(())
    } else {
        Err(TransportError::Tls(
            "tls13: server certificate purpose rejected".into(),
        ))
    }
}
