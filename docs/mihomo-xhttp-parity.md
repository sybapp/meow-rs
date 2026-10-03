# XHTTP parity status

Reference: mihomo v1.19.32, commit `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`. This is protocol-specific compatibility work; it does not claim whole-kernel parity. iOS development is paused.

| Area | Implemented and covered | Remaining differences |
| --- | --- | --- |
| XHTTP modes | H2/h2c and H3 `stream-one`, `stream-up`, `packet-up`; omitted/empty `mode` uses `auto` | HTTP/1.1 transport; H3 download endpoints and mixed H2/H3 endpoints |
| Auto selection | Plain TLS/h2c/H3 chooses `packet-up`; REALITY chooses `stream-one` or `stream-up` with independent H2 download | H3 independent download selection |
| Metadata | Path/query/header/cookie sessions and sequence numbers; configurable upload method | Reserved methods still depend on peer support (mihomo server treats GET as download) |
| H2 endpoints | Independent server/port, TLS/SNI/fingerprint/ECH, trust name, certificate pin, mTLS; parent inheritance with null/empty-map semantics; app-protected dialer and probe flags | H3 or HTTP/1.1 endpoints; ShadowTLS/RESTLS/JLS security wiring; DNS-sourced download ECH |
| H2/H3 TLS identity | Leaf/non-leaf certificate pins, independent SNI/name/IP verification, complete mTLS chains and key matching; explicit verification name overrides skip-cert-verify | H3 ECH; automatic identity-file rotation; full browser ClientHello profiles |
| H3 connection defaults | 10 s idle heartbeat capped at half the negotiated idle timeout with a 1.5 PTO floor and one pending probe, 300 s idle timeout, no server-initiated bidirectional streams; packet accumulation grows geometrically within the configured cap | Configurable H3 heartbeat and XMUX reuse remain absent |
| H2 reuse | Logical-tunnel limits, preferred transport width, concurrency overflow, requests/reuses/expiry, 300 s idle retirement; probe isolation, reset and GOAWAY preserve accepted streams; 45 s default heartbeat or signed keep-alive period | Other HTTP backends; same entry can remain eligible after expiry while active (matching pinned upstream) |
| Packet upload | Finite requests, monotonic sequence, timer/size flushing, bounded serial acknowledgement, shutdown flush | H2 XMUX manager implemented; H3 XMUX and HTTP/1.1 request pool remain absent |
| Payload | Body/auto, header and cookie; unpadded URL-safe Base64 chunking | Header/cookie packets use a conservative 8 KiB raw payload cap |
| Padding | Repeat-X/tokenish, header/queryInHeader/query/cookie; metadata applied after padding; process-sampled browser header/UA presets | Full browser ClientHello profiles (HTTP headers are implemented) |
| Sessions | Legacy hex, UUID, all nine predefined tables and custom ASCII alphabets; upstream entropy threshold | Allocation and unsafe header/cookie byte restrictions below |

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

These bounds describe individual buffers, not a total RSS or iOS memory limit.
No iPhone/iPad RSS, NetworkExtension OOM, or battery benchmark has been run.

## Independent compatibility checks

`crates/meow-transport/tests/support/mihomo-xhttp-peer` imports the pinned
mihomo XHTTP server as a **test-only Go dependency**. Its runtime parser is
independent of the Rust request builder. The Rust suite exercises all modes,
H2/H3, all session/sequence/payload placement combinations, upload methods,
tables, padding, literal paths, and the bounded maximum packet size.

```sh
go build -C crates/meow-transport/tests/support/mihomo-xhttp-peer -o /tmp/mihomo-xhttp-peer .
MEOW_XHTTP_PEER_BIN=/tmp/mihomo-xhttp-peer cargo test -p meow-transport --features xhttp3 --test xhttp_mihomo_interop
MEOW_XHTTP_PEER_BIN=/tmp/mihomo-xhttp-peer cargo test -p meow-config --test vless_xhttp_endpoint_interop
```

The separate H2 frontends share an upstream session handler. Config-to-VLESS checks validate user/probe connection counts, SNI/pins and full-chain mutual TLS on H2/H3. H3 checks reject invalid pins/names, absent identities and truncated chains. A short-idle QUIC peer checks idle heartbeat scheduling. CI requires both suites; missing peers fail loudly.

HTTP/1.1, H3 reuse/download and mixed-version endpoints remain unimplemented. REALITY handshake changes are reviewed in the separate REALITY PR.
