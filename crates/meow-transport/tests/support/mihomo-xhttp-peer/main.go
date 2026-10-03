// Test-only independent peer. Protocol parsing is performed by pinned mihomo,
// never by a second copy of meow's request builder.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/transport/xhttp"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

func main() {
	protocol := flag.String("protocol", "h2", "h2, h3 or reality")
	fragment := flag.Bool("fragment", false, "fragment the plaintext ServerHello")
	badSignature := flag.Bool("bad-signature", false, "sign CertificateVerify with an unrelated key")
	settings := flag.String("config", "{}", "XHTTP config JSON")
	count := flag.Int64("bytes", 0, "echo exactly this many bytes")
	curve := flag.String("curve", "", "force a TLS curve/HelloRetryRequest: p256,p384,p521")
	cover := flag.Bool("cover", false, "use ordinary trusted cover certificate and capture camouflage")
	flag.Parse()
	if *protocol == "cipher-vectors" {
		cipherVectors()
		return
	}
	if *protocol == "reality" {
		serveReality(*count, *fragment, *badSignature, *curve, *cover)
		return
	}
	var cfg xhttp.Config
	if err := json.Unmarshal([]byte(*settings), &cfg); err != nil {
		panic(err)
	}
	handler, err := xhttp.NewServerHandler(xhttp.ServerOption{
		Config: cfg,
		ConnHandler: func(conn net.Conn) {
			defer conn.Close()
			if _, err := io.CopyN(conn, conn, *count); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		},
	})
	if err != nil {
		panic(err)
	}
	if *protocol == "h2" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
		protocols := new(http.Protocols)
		protocols.SetUnencryptedHTTP2(true)
		server := &http.Server{Handler: handler, Protocols: protocols}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"address": listener.Addr().String()})
		if err := server.Serve(listener); err != nil {
			panic(err)
		}
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.org"},
		DNSNames: []string{"example.org"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	server := &http3.Server{Handler: handler, TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: key}},
	}}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"address": socket.LocalAddr().String(), "certificate": certificate})
	if err := server.Serve(socket); err != nil {
		panic(err)
	}
}
