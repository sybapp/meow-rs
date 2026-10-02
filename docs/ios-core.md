# iOS core builds and custom VLESS nodes

The `iOS core` workflow builds the Rust config/proxy/transport libraries for
`aarch64-apple-ios` (device) and `aarch64-apple-ios-sim` (Apple Silicon simulator),
using Xcode's SDK on macOS and the toolchain pinned in `rust-toolchain.toml`.
It also builds the routing and listener libraries. These checks compile the
native BoringSSL/QUIC dependencies; they do not produce an installable iOS app,
a signed NetworkExtension, or an XCFramework with a Swift/C runtime API.

On a Mac with Xcode command-line tools installed:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo build --locked --target aarch64-apple-ios -p meow-config --no-default-features --features vless-vision
cargo build --locked --target aarch64-apple-ios-sim -p meow-config --no-default-features --features vless-vision
```

Supported custom-node paths:

- VLESS XHTTP `stream-up` with ALPN `h2` or `h3`, IPv4 or IPv6; header sessions,
  Base62 IDs and tokenish padding use the options in [xhttp.md](xhttp.md).
- VLESS REALITY over TCP with Vision and
  `reality-opts.support-x25519mlkem768: true`. The client advertises the standard
  `X25519MLKEM768` group (0x11ec) first, followed by the same X25519 share for an
  older server's classical fallback. ML-KEM precedes X25519 in both the wire
  share and combined TLS shared secret. REALITY session authentication still
  uses the configured X25519 public key and short ID. The false/omitted flag
  retains the legacy X25519-only behavior. The hybrid group is never accepted
  when it was not advertised. HelloRetryRequest remains unsupported.

An embedding iOS app must supply NetworkExtension lifecycle, packet ingress,
configuration storage and socket protection. HTTP/3 uses the existing protected
UDP dialer, including a UDP-capable `dialer-proxy`; a TCP-only relay cannot
carry QUIC and returns an explicit error. These protocol changes do not add
that app layer or claim to resolve an existing app's OOM behavior.

Validation still required before a device release: successful Apple-target CI,
real Cloudflare/Xray-node interoperability, sustained traffic and cancellation
on a device, and peak-memory measurements with the user's provider/ruleset
sizes. Real-node tests stay opt-in and outside CI; keep credentials under `/tmp`.

Wire reference:
[XTLS REALITY key schedule](https://github.com/XTLS/REALITY/blob/main/key_schedule.go).
