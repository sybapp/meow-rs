# VLESS / XHTTP / REALITY parity status

Reference: mihomo v1.19.32, commit
[`88dcbf7f1614a67c3b36b848ee3592dfa92ada36`](https://github.com/MetaCubeX/mihomo/tree/88dcbf7f1614a67c3b36b848ee3592dfa92ada36).
This is a protocol-specific compatibility effort. It does **not** claim that
the whole meow kernel, or even every VLESS transport setting, equals mihomo.

| Area | Implemented and covered | Remaining differences |
| --- | --- | --- |
| XHTTP modes | H2/h2c and H3 `stream-one`, `stream-up`, `packet-up`; omitted/empty `mode` uses `auto` | HTTP/1.1 transport; independently configured download endpoints |
| Auto selection | Plain TLS/h2c/H3 chooses `packet-up`; REALITY chooses `stream-one` | REALITY + download settings should choose `stream-up` when download settings are implemented |
| Metadata | Path/query/header/cookie sessions and sequence numbers; configurable upload method | Reserved methods still depend on peer support (mihomo server treats GET as download) |
| Packet upload | Finite requests, monotonic sequence, timer/size flushing, bounded serial acknowledgement, shutdown flush | No connection reuse manager/XMUX; no HTTP/1.1 request pool |
| Payload | Body/auto, header and cookie; unpadded URL-safe Base64 chunking | Header/cookie packets use a conservative 8 KiB raw payload cap |
| Padding | Repeat-X/tokenish, header/queryInHeader/query/cookie; metadata applied after padding | Browser default request headers/UA generation |
| Sessions | Legacy hex, UUID, all nine predefined tables and custom ASCII alphabets; upstream entropy threshold | Allocation and unsafe header/cookie byte restrictions below |
| REALITY keys | X25519 and optional standard X25519MLKEM768, classical fallback | Other key-share groups and HelloRetryRequest |
| REALITY framing | Fragmented plaintext ServerHello, fragmented/coalesced encrypted handshake messages | Full browser ClientHello profiles remain unimplemented; configured fingerprint produces an explicit warning |
| REALITY authentication | Authenticated client version 1.8.2, certificate HMAC, TLS CertificateVerify signature bound to the transcript, server/client Finished | Ordinary X.509 fallback/camouflage request; NTP-adjusted clock; additional TLS cipher suites |
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
- Explicit XHTTP ALPN must be exclusively `h2` or `h3`. HTTP/1.1 and mixed
  protocol lists are rejected until the corresponding backend exists.
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
Go TLS 1.3 engine. It validates the auth header and real TLS signatures, tests
classical/hybrid handshakes and ServerHello fragmentation, and deliberately
signs CertificateVerify with an unrelated key to verify rejection. This is an
independent cryptographic/protocol fixture, **not** an Xray deployment or a live
CDN/REALITY cover-host test.

```sh
go build -C crates/meow-transport/tests/support/mihomo-xhttp-peer -o /tmp/mihomo-xhttp-peer .
MEOW_XHTTP_PEER_BIN=/tmp/mihomo-xhttp-peer cargo test -p meow-transport \
  --features xhttp3,reality --test xhttp_mihomo_interop
```

CI builds the peer and requires this suite. Missing peer binaries fail loudly.
Actual node tests remain opt-in; credentials must stay outside committed files.
