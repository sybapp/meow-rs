# XHTTP compatibility

VLESS `network: xhttp` supports `stream-one` and `stream-up` over HTTP/2,
including TLS with `alpn: [h2]` and plain h2c. Enable the `xhttp` transport
feature when embedding `meow-transport`; the config crate already enables it.

`stream-up` sends a GET download request first, then a POST upload request
on the same HTTP/2 connection. Both carry the same fresh session ID. Connect
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
| `mode` | `stream-one`, `stream-up`; existing default remains `stream-one` |
| `session-placement` | `path` (default), `header` |
| `session-key` | Header name; defaults to `X-Session` for header placement |
| `session-table` | Omitted/empty: 32 hex characters; `Base62`: random token |
| `session-length` | String range or fixed length, e.g. `16-24` or `24`; Base62 default `16-32` |
| `x-padding-bytes` | Existing `min-max` string or two-element integer array; default `100-1000` |
| `x-padding-obfs-mode` | `false` (default): repeat-X padding in the Referer query; `true`: configurable placement |
| `x-padding-method` | Empty/default or `repeat-x`; `tokenish` uses random Base62 with HPACK byte sizing |
| `x-padding-placement` | `header`, `queryInHeader`; empty with obfuscation enabled emits no padding |
| `x-padding-header` | Required header name for an obfuscated header placement |
| `x-padding-key` | Query key required for obfuscated `queryInHeader` |
| `no-grpc-header` | Suppresses automatic Content-Type on POST; GET never receives an automatic gRPC header |

Padding is applied independently to GET and POST. Session metadata takes
precedence over extra headers. A padding header cannot also carry the session.
Base paths gain a trailing slash before appending a path session; existing
queries are preserved. Legacy Referer padding preserves the existing custom
Referer override behavior.

Writes retain the shared HTTP/2 flow-control backpressure and at most a 64 KiB
pending payload. Upload acknowledgement bodies are drained without retaining
their data. Drop half-closes the upload and drains both response streams with
the existing one-second driver grace period, including peers that never reply.
No extra per-connection acknowledgement task is spawned during normal I/O.
These bounds do not constitute an iOS memory benchmark or an iOS app build.

## Limitations and deliberate divergences

HTTP/3 (`alpn: [h3]`), `auto`, `packet-up`, separate download settings,
connection reuse settings, custom upload methods, cookie/query sessions,
cookie/query padding and other session alphabets are not implemented. Explicit
unsupported options are rejected instead of silently selecting another wire
format. The config loader reports the node error and skips that node, following
its existing invalid-proxy policy.

Classifications follow [ADR-0002](adr/0002-upstream-divergence-policy.md):

- **Class A:** unsupported wire/destination options are rejected; interpreting
  them as a supported transport could change the user's routing intent.
- **Class A:** session length is capped at 128 characters, Base62 minimum
  length is six, and padding is capped at 64 KiB of encoded bytes. These bound
  remotely supplied allocations and avoid short session IDs. A tokenish header
  needs at most `ceil(encoded_bytes * 8 / 5)` raw characters.
- **Class B (existing):** omitted mode remains `stream-one` rather than mihomo's
  `auto`; this change preserves the existing meow-rs default. Choose
  `stream-up` explicitly for split requests.

Protocol references: mihomo
[client.go](https://github.com/MetaCubeX/mihomo/blob/Meta/transport/xhttp/client.go),
[config.go](https://github.com/MetaCubeX/mihomo/blob/Meta/transport/xhttp/config.go),
[xpadding.go](https://github.com/MetaCubeX/mihomo/blob/Meta/transport/xhttp/xpadding.go),
and [RFC 7541 Appendix B](https://www.rfc-editor.org/rfc/rfc7541.html#appendix-B).

Hermetic regression tests:

```sh
cargo test -p meow-transport --no-default-features --features xhttp,ws --lib --test xhttp_test
cargo test -p meow-config --test vless_config_test
```

Use the repository's opt-in real-node smoke procedure in `AGENTS.md` for CDN
interoperability. Keep real UUIDs and node credentials in `/tmp`, never in
committed configs or CI logs.
