//! Ephemeral TLS key exchange shared by the native record clients.
use crate::{Result, TransportError};
const GROUP_X25519: u16 = 0x001d;
const GROUP_P256: u16 = 0x0017;
const GROUP_P384: u16 = 0x0018;
const GROUP_P521: u16 = 0x0019;

/// One ephemeral key share — one per advertised group so the cover never
/// needs HelloRetryRequest (which the restls server cannot relay; upstream
/// has the same constraint).
pub(crate) enum Ecdhe {
    X25519([u8; 32]),
    P256(boring::ec::EcKey<boring::pkey::Private>),
    P384(boring::ec::EcKey<boring::pkey::Private>),
    P521(boring::ec::EcKey<boring::pkey::Private>),
}

pub(crate) struct KeyShare {
    pub(crate) group: u16,
    pub(crate) key: Ecdhe,
    /// Uncompressed public bytes as sent in the `key_share` extension.
    pub(crate) public: Vec<u8>,
}

impl KeyShare {
    pub(crate) fn generate(group: u16) -> Result<Self> {
        match group {
            GROUP_X25519 => {
                let mut private = rand::random::<[u8; 32]>();
                private[0] &= 248;
                private[31] &= 127;
                private[31] |= 64;
                let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
                Ok(Self {
                    group,
                    key: Ecdhe::X25519(private),
                    public: public.to_vec(),
                })
            }
            GROUP_P256 | GROUP_P384 | GROUP_P521 => {
                let nid = if group == GROUP_P256 {
                    boring::nid::Nid::X9_62_PRIME256V1
                } else if group == GROUP_P384 {
                    boring::nid::Nid::SECP384R1
                } else {
                    boring::nid::Nid::SECP521R1
                };
                let ec_group = boring::ec::EcGroup::from_curve_name(nid)
                    .map_err(|e| TransportError::Tls(format!("tls13: ec group: {e}")))?;
                let key = boring::ec::EcKey::generate(&ec_group)
                    .map_err(|e| TransportError::Tls(format!("tls13: ec generate: {e}")))?;
                let mut ctx = boring::bn::BigNumContext::new()
                    .map_err(|e| TransportError::Tls(format!("tls13: bn ctx: {e}")))?;
                let public = key
                    .public_key()
                    .to_bytes(
                        &ec_group,
                        boring::ec::PointConversionForm::UNCOMPRESSED,
                        &mut ctx,
                    )
                    .map_err(|e| TransportError::Tls(format!("tls13: ec pubkey: {e}")))?;
                Ok(Self {
                    group,
                    key: if group == GROUP_P256 {
                        Ecdhe::P256(key)
                    } else if group == GROUP_P384 {
                        Ecdhe::P384(key)
                    } else {
                        Ecdhe::P521(key)
                    },
                    public,
                })
            }
            _ => Err(TransportError::Tls(format!(
                "tls13: unsupported group {group}"
            ))),
        }
    }

    /// ECDHE shared secret with the cover's key share.
    pub(crate) fn agree(&self, peer_public: &[u8]) -> Result<Vec<u8>> {
        match &self.key {
            Ecdhe::X25519(private) => {
                let peer: [u8; 32] = peer_public
                    .try_into()
                    .map_err(|_| TransportError::Tls("tls13: bad X25519 share".into()))?;
                let out = x25519_dalek::x25519(*private, peer);
                if out == [0u8; 32] {
                    return Err(TransportError::Tls("tls13: X25519 low-order".into()));
                }
                Ok(out.to_vec())
            }
            Ecdhe::P256(key) | Ecdhe::P384(key) | Ecdhe::P521(key) => {
                let group = key.group();
                let mut ctx = boring::bn::BigNumContext::new()
                    .map_err(|e| TransportError::Tls(format!("tls13: bn ctx: {e}")))?;
                let point = boring::ec::EcPoint::from_bytes(group, peer_public, &mut ctx)
                    .map_err(|e| TransportError::Tls(format!("tls13: bad EC share: {e}")))?;
                let peer_key = boring::ec::EcKey::from_public_key(group, &point)
                    .map_err(|e| TransportError::Tls(format!("tls13: ec peer: {e}")))?;
                let pkey = boring::pkey::PKey::from_ec_key(peer_key)
                    .map_err(|e| TransportError::Tls(format!("tls13: pkey: {e}")))?;
                let ours = boring::pkey::PKey::from_ec_key(key.clone())
                    .map_err(|e| TransportError::Tls(format!("tls13: pkey: {e}")))?;
                let mut deriver = boring::derive::Deriver::new(&ours)
                    .map_err(|e| TransportError::Tls(format!("tls13: derive: {e}")))?;
                deriver
                    .set_peer(&pkey)
                    .map_err(|e| TransportError::Tls(format!("tls13: derive peer: {e}")))?;
                deriver
                    .derive_to_vec()
                    .map_err(|e| TransportError::Tls(format!("tls13: derive: {e}")))
            }
        }
    }
}
