# VLESS / XHTTP / REALITY parity status

Reference: mihomo v1.19.32, commit
[`88dcbf7f1614a67c3b36b848ee3592dfa92ada36`](https://github.com/MetaCubeX/mihomo/tree/88dcbf7f1614a67c3b36b848ee3592dfa92ada36).
This is a protocol-specific compatibility effort. It does **not** claim that
the whole meow kernel, or even every VLESS transport setting, equals mihomo.

| Area | Implemented and covered | Remaining differences |
| --- | --- | --- |
| XHTTP modes | H2/h2c and H3 `stream-one`, `stream-up`, `packet-up`; omitted/empty `mode` uses `auto` | HTTP/1.1 transport; H3 download endpoints and mixed H2/H3 endpoints |
| Auto selection | Plain TLS/h2c/H3 chooses `packet-up`; REALITY chooses `stream-one` or `stream-up` with independent H2 download | H3 independent download selection |
| Metadata | Path/query/header/cookie sessions and sequence numbers; configurable upload method | Reserved methods still depend on peer support (mihomo server treats GET as download) |
| H2 endpoints | Independent server/port, TLS/SNI/fingerprint/ECH, trust name, certificate pin, mTLS; parent inheritance with null/empty-map semantics; app-protected dialer and probe flags | H3 or HTTP/1.1 endpoints; ShadowTLS/RESTLS/JLS security wiring; DNS-sourced download ECH |
| H2/H3 TLS identity | Leaf/non-leaf certificate pins, independent SNI/name/IP verification, complete mTLS chains and key matching; explicit verification name overrides skip-cert-verify | H3 ECH; automatic identity-file rotation; full browser ClientHello profiles |
| H2 reuse | Logical-tunnel limits, preferred transport width, concurrency overflow, requests/reuses/expiry, 300 s idle retirement; probe isolation, reset and GOAWAY preserve accepted streams; 45 s default heartbeat or signed keep-alive period | Other HTTP backends; same entry can remain eligible after expiry while active (matching pinned upstream) |
| Packet upload | Finite requests, monotonic sequence, timer/size flushing, bounded serial acknowledgement, shutdown flush | H2 XMUX manager implemented; H3 XMUX and HTTP/1.1 request pool remain absent |
| Payload | Body/auto, header and cookie; unpadded URL-safe Base64 chunking | Header/cookie packets use a conservative 8 KiB raw payload cap |
| Padding | Repeat-X/tokenish, header/queryInHeader/query/cookie; metadata applied after padding; process-sampled browser header/UA presets | Full browser ClientHello profiles (HTTP headers are implemented) |
| Sessions | Legacy hex, UUID, all nine predefined tables and custom ASCII alphabets; upstream entropy threshold | Allocation and unsafe header/cookie byte restrictions below |
| REALITY keys | X25519 and optional standard X25519MLKEM768, classical fallback; HelloRetryRequest with P-256/P-384/P-521 and cookies | Full browser-specific group/key-share layouts |
| REALITY framing | Fragmented plaintext ServerHello, fragmented/coalesced encrypted handshake messages | Full browser ClientHello profiles remain unimplemented; configured fingerprint produces an explicit warning |
| REALITY authentication | Authenticated client version 1.8.2, certificate HMAC, generic TLS CertificateVerify bound to the transcript, server/client Finished; AES-128/SHA-256, AES-256/SHA-384, ChaCha20/SHA-256; trusted X.509 cover fallback and bounded H2 camouflage GET | NTP-adjusted clock; full browser ClientHello profiles |
| REALITY post-handshake | Fragmented NewSessionTicket/KeyUpdate; traffic-secret updates and requested response; bounded control buffering; buffered old-epoch data stays before the update | Ticket resumption remains disabled, matching mihomo REALITY |
| Vision | Existing TCP/TLS/REALITY record bypass and tests remain in place | This increment does not expand Vision compatibility or certify every mihomo Vision behavior |

## Changes to earlier defaults

An omitted mode now follows mihomo's `auto`. Set `mode: stream-one` explicitly
to retain the previous meow default behavior on ordinary TLS connections.
The existing explicit `stream-up` examples keep their mode.

`path` is a literal URL path, matching mihomo's `url.URL{Path: ...}`.
Question marks, percent signs, fragments, Unicode and spaces are escaped as
path bytes. Use `session-placement: query`, `seq-placement: query`, or query
padding to put metadata in the actual query. A leading slash is added when
missing; a trailing slash is added when either session or sequence uses the path.

Padding overrides a custom header at the selected placement; session/sequence
metadata is applied afterwards. A streaming upload sets application/grpc unless
`no-grpc-header` is true, including when its HTTP method is customized.
Packet uploads do not receive the automatic gRPC Content-Type.

## Bounds and deliberate divergences

Per [ADR-0002](adr/0002-upstream-divergence-policy.md), malformed or unsafe
options are rejected instead of silently changing their meaning:

- Padding: at most 64 KiB of encoded bytes; tokenish raw text is at most
  `ceil(encoded_bytes * 8 / 5)` characters.
- Session length: 1–128; table entropy uses the upstream sum of possibilities
  across all allowed lengths, with a threshold of 2^31. Custom tables must be
  ASCII, and bytes unsafe for the selected header/cookie placement are rejected.
- Packet body: an ordered, positive range at most 1 MiB; default 1,000,000 bytes.
  Buffers grow on demand. Header/cookie payloads are flushed in at most 8 KiB
  chunks to keep HTTP field sizes practical. This changes batching, preserving
  the byte stream and sequence semantics.
- Exact singleton `h3` selects QUIC and requires TLS; exact singleton
  `http/1.1` remains rejected. Other ALPN lists use forced H2, matching mihomo.
  Independent download endpoints currently require the H2 backend.
- Reuse ranges are ordered nonnegative values capped at `i32::MAX`;
  keep-alive periods must fit a signed Go nanosecond duration.
- Client identities are limited to 1 MiB and loaded at configuration time.
  Automatic identity-file rotation is not implemented; reload the configuration.
- A single relay-supplied TCP stream cannot carry independent download endpoints;
  such relays fail explicitly. Use `dialer-proxy` for multiple protected dials.
- There is one unacknowledged upload packet per logical tunnel. Both backends
  apply backpressure; H3 may hold one additional bounded accumulation buffer.
  H2 times out a stalled packet send/acknowledgement after 15 seconds.
- Pre-authentication TLS transcript/reassembly bytes and record counts are
  capped, and the complete REALITY handshake has a 10-second timeout.

These bounds describe individual buffers, not a total RSS or iOS memory limit.
No iPhone/iPad RSS, NetworkExtension OOM, or battery benchmark has been run.

## Independent compatibility checks

`crates/meow-transport/tests/support/mihomo-xhttp-peer` imports the pinned
mihomo XHTTP server as a **test-only Go dependency**. Its runtime parser is
independent of the Rust request builder. The Rust suite exercises all modes,
H2/H3, all session/sequence/payload placement combinations, upload methods,
tables, padding, literal paths, and the bounded maximum packet size.

The same harness has a separate REALITY-authenticated test endpoint using the
Go TLS 1.3 engine. It additionally forces P-256/P-384/P-521 retries and the
ChaCha20 suite, tests trusted/untrusted/name-mismatched ordinary cover certificates,
and records the camouflage request. Go crypto primitives generate checked-in
key-schedule, Finished, record and traffic-update vectors for all three suites. It validates the auth header and real TLS signatures, tests
classical/hybrid handshakes and ServerHello fragmentation, and deliberately
signs CertificateVerify with an unrelated key to verify rejection. This is an
independent cryptographic/protocol fixture, **not** an Xray deployment or a live
CDN/REALITY cover-host test.

```sh
go build -C crates/meow-transport/tests/support/mihomo-xhttp-peer -o /tmp/mihomo-xhttp-peer .
MEOW_XHTTP_PEER_BIN=/tmp/mihomo-xhttp-peer cargo test -p meow-transport \
  --features xhttp3,reality --test xhttp_mihomo_interop
```

The peer can expose two separate H2 frontends over one upstream session handler;
request captures validate endpoint routing without duplicating the Rust builder.
The real config-to-VLESS adapter suite additionally decodes a synthetic VLESS TCP
request and verifies shared user connections, isolated probes, SNI overrides,
certificate pins and mutual TLS on H2 and H3. Client fixtures contain an intermediate-backed chain; the server trusts only the root. H3 checks also reject wrong pins/names, absent identities and truncated client chains. Name verification remains enabled with an explicit override even when skip-cert-verify is true. A wrong pin fails before any HTTP request.

```sh
MEOW_XHTTP_PEER_BIN=/tmp/mihomo-xhttp-peer cargo test -p meow-config \
  --test vless_xhttp_endpoint_interop
```

CI builds the peer and requires both suites. Missing peer binaries fail loudly.
Actual node tests remain opt-in; credentials must stay outside committed files.

## Working scope

The iOS work is paused. Existing device/simulator build files are retained, but
this work does not add device, NetworkExtension, RSS/OOM or battery validation.
HTTP/1.1, H3 reuse/download and mixed-version endpoints still need implementation.
H2 reuse/download is integrated into the VLESS TCP/UDP and mux dial paths;
configuration-to-adapter interop checks assert physical connection counts, SNI,
pinning and mutual TLS against the independent peer. H3 TLS identity support
is covered through both the transport and actual VLESS adapter; H3 reuse and
independent download remain outstanding. No previous uncommitted
prototype is counted as implemented compatibility here.
