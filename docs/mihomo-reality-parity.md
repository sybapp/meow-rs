# Native REALITY parity status

Reference: mihomo v1.19.32, commit `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`. This is protocol-specific compatibility work; it does not claim whole-kernel parity. iOS development is paused.

| Area | Implemented and covered | Remaining differences |
| --- | --- | --- |
| REALITY keys | X25519 and optional standard X25519MLKEM768, classical fallback; HelloRetryRequest with P-256/P-384/P-521 and cookies | Full browser-specific group/key-share layouts |
| REALITY framing | Fragmented plaintext ServerHello, fragmented/coalesced encrypted handshake messages | Full browser ClientHello profiles remain unimplemented; configured fingerprint produces an explicit warning |
| REALITY authentication | Authenticated client version 1.8.2, certificate HMAC, generic TLS CertificateVerify bound to the transcript, server/client Finished; AES-128/SHA-256, AES-256/SHA-384, ChaCha20/SHA-256; trusted X.509 cover fallback and bounded H2 camouflage GET | NTP-adjusted clock; full browser ClientHello profiles |
| REALITY post-handshake | Fragmented NewSessionTicket/KeyUpdate; traffic-secret updates and requested response; bounded control buffering; buffered old-epoch data stays before the update | Ticket resumption remains disabled, matching mihomo REALITY |
| Vision | Existing TCP/TLS/REALITY record bypass and tests remain in place | This increment does not expand Vision compatibility or certify every mihomo Vision behavior |

## Bounds and independent validation

The complete REALITY handshake has a 10-second timeout. Transcript/reassembly bytes, record counts and post-handshake control buffering are bounded. Trusted ordinary-cover TLS never becomes an authenticated proxy stream; only verified covers receive the bounded H2 camouflage request. Browser ClientHello profiles and NTP-adjusted time remain gaps. Vision compatibility is not expanded by this PR.

`tests/support/reality-peer` is a separate test-only Go TLS engine. It verifies authentication headers and signatures, classical/hybrid keys, P-256/P-384/P-521 retries, fragmentation, trusted/untrusted/name-mismatched cover certificates and unrelated CertificateVerify-key rejection. Go crypto primitives generate the cipher/key-schedule vectors. This is an independent cryptographic fixture, not an Xray/CDN deployment.

```sh
go build -C crates/meow-transport/tests/support/reality-peer -o /tmp/reality-peer .
MEOW_REALITY_PEER_BIN=/tmp/reality-peer cargo test -p meow-transport --features reality --test reality_mihomo_interop
```

CI requires this peer; missing binaries fail loudly. Real-node credentials must remain outside committed files.
