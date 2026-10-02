# XHTTP compatibility

VLESS `network: xhttp` supports `stream-one`, `stream-up`, and `packet-up` over HTTP/2 and HTTP/3,
including TLS with `alpn: [h2]` and plain h2c. Enable the `xhttp` transport
feature for HTTP/2 or `xhttp3` for QUIC when embedding `meow-transport`.
The VLESS feature enables both in the config/proxy crates. For the example below,
changing `alpn: [h2]` to `alpn: [h3]` selects a real QUIC/UDP connection.
Mixed ALPN lists and draft `h3-*` identifiers are rejected.

`stream-up` sends a GET download request first, then a POST upload request
on the same HTTP/2 or QUIC connection. Both carry the same fresh session ID. Connect
does not wait for response headers: some servers and CDNs send them only
after the first upload byte. The download requires HTTP 200, while the
upload acknowledgement and `stream-one` accept any successful status.

```yaml
proxies:
  - name: example-xhttp-h2
    type: vless
    server: 192.0.2.1 # replace with your server/CDN address; IPv6 also works
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811 # replace with your UUID
    tls: true
    servername: example.org
    client-fingerprint: chrome
    skip-cert-verify: false
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      host: example.org
      path: /api/v1/telemetry
      mode: stream-up
      no-grpc-header: true
      session-placement: header
      session-key: X-Session-Id
      session-table: Base62
      session-length: "16-24"
      x-padding-obfs-mode: true
      x-padding-method: tokenish
      x-padding-placement: header
      x-padding-header: X-Cache-Key
      x-padding-bytes: 128-512
```

| Option | Supported values / behavior |
| --- | --- |
| `mode` | `auto` (default), `stream-one`, `stream-up`, `packet-up`; auto uses stream-one with REALITY, packet-up otherwise |
| `session-placement` / `seq-placement` | `path` (default), `header`, `query`, `cookie` |
| `session-key` / `seq-key` | Default headers X-Session/X-Seq, query/cookie x_session/x_seq |
| `session-table` | Omitted/empty: 32 lowercase hex; uuid; all upstream predefined and custom ASCII tables |
| `session-length` | String range or fixed length, e.g. `16-24` or `24`; table default `16-32` |
| `x-padding-bytes` | Fixed/range string or two-element integer array; default `100-1000` |
| `x-padding-obfs-mode` | `false` (default): repeat-X padding in the Referer query; `true`: configurable placement |
| `x-padding-method` | Empty/default or `repeat-x`; `tokenish` uses random Base62 with HPACK byte sizing |
| `x-padding-placement` | `header`, `queryInHeader`, `query`, `cookie`; empty with obfuscation enabled emits no padding |
| `x-padding-header` | Required header name for an obfuscated header placement |
| `x-padding-key` | Query key required for obfuscated `queryInHeader` |
| `no-grpc-header` | Suppresses application/grpc on streaming uploads; packet uploads/downloads have no automatic gRPC header |

`packet-up` sends finite upload requests with monotonically increasing sequence
numbers. `uplink-http-method` defaults to POST; `uplink-data-placement` accepts
body/auto, header and cookie. Header/cookie payloads use unpadded URL-safe Base64,
with configurable `uplink-data-key` and `uplink-chunk-size`. Buffering/flush ranges
are `sc-max-each-post-bytes` (default 1,000,000) and
`sc-min-posts-interval-ms` (default 30 ms).

Padding is applied independently to upload/download requests, then metadata is
applied. `path` is a literal URL path: question marks and percent signs are
escaped; query metadata uses the query placement explicitly. Relative and empty
paths are normalized. Session entropy follows the upstream sum of possibilities
across the configured length range, with a threshold of 2^31.

Writes retain the shared HTTP/2 flow-control backpressure and at most a 64 KiB
pending payload. Upload acknowledgement bodies are drained without retaining
their data. Drop half-closes the upload and drains both response streams with
the existing one-second driver grace period, including peers that never reply.
No extra per-connection acknowledgement task is spawned during normal I/O.
HTTP/3 owns one QUIC driver and an eight-packet receive bridge for proxied UDP
associations. The bridge preserves `read_packet` futures across cancellation;
UDP socket protection, `dialer-proxy` and internal-probe metadata remain in
`meow-proxy`. It uses bounded 64 KiB duplex halves, 16 KiB body chunks, a 512 KiB
connection receive window, 256 KiB stream windows (autotuning capped at those
values), two bidirectional streams and three peer unidirectional streams.
These are buffer/window bounds, not a measured total RSS limit. Congestion
control also governs QUIC's outstanding send data. Cancelled or timed-out
handshakes abort their driver; a dropped established stream has a one-second
cleanup grace. A 15-second QUIC keepalive preserves quiet live connections
under the 30-second idle timeout. HTTP/3 checks both certificate trust and the server name, with
the same Mozilla roots and fingerprint profiles as TCP TLS. It rejects
unsupported REALITY/ECH/mTLS/pin options rather than silently ignoring them.

These bounds do not constitute an iOS memory benchmark. See
[iOS core builds](ios-core.md) for the Apple-target build workflow and the
remaining app/device validation.

## Compatibility status and limits

See [the pinned mihomo parity matrix](mihomo-vless-parity.md) for the current
implementation, independent tests, memory bounds, and remaining work. Connection
reuse/XMUX, separate download settings, HTTP/1.1 and generated browser request
headers remain unimplemented. Explicit download/reuse options fail at config
load; the loader reports and skips that node under its invalid-proxy policy.
This increment does not claim complete mihomo parity.

Hermetic and independent regression tests:

```sh
cargo test -p meow-transport --no-default-features --features xhttp,ws --lib --test xhttp_test
cargo test -p meow-transport --no-default-features --features reality,xhttp3 --lib --test xhttp3_test
cargo test -p meow-config --test vless_config_test
go build -C crates/meow-transport/tests/support/mihomo-xhttp-peer -o /tmp/mihomo-xhttp-peer .
MEOW_XHTTP_PEER_BIN=/tmp/mihomo-xhttp-peer cargo test -p meow-transport \
  --features reality,xhttp3 --test xhttp_mihomo_interop
```

Use the repository's opt-in real-node smoke procedure in `AGENTS.md` for CDN
interoperability. Keep real UUIDs and node credentials in `/tmp`, never in
committed configs or CI logs.
