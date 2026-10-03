// Independent, test-only native REALITY TLS peer. No XHTTP dependency.
package main
import "flag"
func main() {
 protocol := flag.String("protocol", "reality", "reality or cipher-vectors")
 fragment := flag.Bool("fragment", false, "fragment plaintext ServerHello")
 bad := flag.Bool("bad-signature", false, "sign CertificateVerify with an unrelated key")
 count := flag.Int64("bytes", 0, "echo exactly this many bytes")
 curve := flag.String("curve", "", "force p256, p384 or p521 retry")
 cover := flag.Bool("cover", false, "capture ordinary cover camouflage")
 flag.Parse()
 if *protocol == "cipher-vectors" { cipherVectors(); return }
 if *protocol != "reality" { panic("unsupported protocol") }
 serveReality(*count, *fragment, *bad, *curve, *cover)
}
