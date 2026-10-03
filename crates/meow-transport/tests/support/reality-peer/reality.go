// Independent Go TLS 1.3 engine with REALITY certificate authentication.
// This is a test harness, not a deployed REALITY server or cover endpoint.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/http2"
	"github.com/metacubex/tls"
	"golang.org/x/crypto/hkdf"
)

type replayConn struct {
	net.Conn
	reader   io.Reader
	fragment bool
}

func (c *replayConn) Read(buf []byte) (int, error) { return c.reader.Read(buf) }
func (c *replayConn) Write(buf []byte) (int, error) {
	if !c.fragment {
		return c.Conn.Write(buf)
	}
	remaining := buf
	for len(remaining) >= 5 {
		size := 5 + int(binary.BigEndian.Uint16(remaining[3:5]))
		if size > len(remaining) {
			return c.Conn.Write(buf)
		}
		record := remaining[:size]
		if record[0] == 22 && size > 7 && record[5] == 2 {
			for _, payload := range [][]byte{record[5:7], record[7:]} {
				header := append([]byte(nil), record[:5]...)
				binary.BigEndian.PutUint16(header[3:5], uint16(len(payload)))
				if _, err := c.Conn.Write(append(header, payload...)); err != nil {
					return 0, err
				}
			}
		} else if _, err := c.Conn.Write(record); err != nil {
			return 0, err
		}
		remaining = remaining[size:]
	}
	if len(remaining) != 0 {
		panic("partial server TLS record")
	}
	return len(buf), nil
}

func realityAuth(hello []byte, static *ecdh.PrivateKey) ([]byte, error) {
	if len(hello) < 75 || hello[0] != 1 || hello[38] != 32 {
		return nil, fmt.Errorf("invalid ClientHello")
	}
	p := 71
	p += 2 + int(binary.BigEndian.Uint16(hello[p:p+2]))
	p += 1 + int(hello[p])
	p += 2 // extension vector length
	var public []byte
	for p+4 <= len(hello) {
		typ := binary.BigEndian.Uint16(hello[p : p+2])
		n := int(binary.BigEndian.Uint16(hello[p+2 : p+4]))
		p += 4
		if p+n > len(hello) {
			return nil, fmt.Errorf("invalid extension size")
		}
		if typ == 51 {
			for offset := p + 2; offset+4 <= p+n; {
				group := binary.BigEndian.Uint16(hello[offset : offset+2])
				size := int(binary.BigEndian.Uint16(hello[offset+2 : offset+4]))
				offset += 4
				if offset+size > p+n {
					return nil, fmt.Errorf("invalid key share")
				}
				if group == 29 {
					public = hello[offset : offset+size]
				}
				offset += size
			}
		}
		p += n
	}
	peer, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		return nil, err
	}
	shared, err := static.ECDH(peer)
	if err != nil {
		return nil, err
	}
	auth := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, hello[6:26], []byte("REALITY")), auth); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(auth)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := append([]byte(nil), hello...)
	clear(aad[39:71])
	plain, err := aead.Open(nil, hello[26:38], hello[39:71], aad)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(plain[:4], []byte{1, 8, 2, 0}) || !bytes.Equal(plain[8:], []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		return nil, fmt.Errorf("invalid REALITY auth header")
	}
	return auth, nil
}

func serveReality(count int64, fragment, badSignature bool, curve string, cover bool) {
	static, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x23}, 32))
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	info := map[string]any{"address": listener.Addr().String(), "public_key": static.PublicKey().Bytes()}
	var coverCert tls.Certificate
	if cover {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"example.org"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		coverCert = tls.Certificate{Certificate: [][]byte{cert}, PrivateKey: key}
		info["certificate"] = cert
	}
	json.NewEncoder(os.Stdout).Encode(info)
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			header := make([]byte, 5)
			if _, err := io.ReadFull(conn, header); err != nil {
				return
			}
			body := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
			if _, err := io.ReadFull(conn, body); err != nil {
				return
			}
			auth, err := realityAuth(body, static)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				panic(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"example.org"},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
			certificate, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
			if err != nil {
				panic(err)
			}
			mac := hmac.New(sha512.New, auth)
			mac.Write(public)
			copy(certificate[len(certificate)-64:], mac.Sum(nil))
			if badSignature {
				_, private, _ = ed25519.GenerateKey(rand.Reader)
			}
			raw := &replayConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(append(header, body...)), conn), fragment: fragment}
			var curves []tls.CurveID
			switch curve {
			case "":
			case "p256":
				curves = []tls.CurveID{tls.CurveP256}
			case "p384":
				curves = []tls.CurveID{tls.CurveP384}
			case "p521":
				curves = []tls.CurveID{tls.CurveP521}
			default:
				panic("unknown curve")
			}
			certs := []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: private}}
			if cover {
				certs = []tls.Certificate{coverCert}
			}
			server := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: curves,
				NextProtos: []string{"h2"}, Certificates: certs})
			if err := server.Handshake(); err != nil {
				if !badSignature {
					fmt.Fprintln(os.Stderr, err)
				}
				return
			}
			if cover {
				h2 := new(http2.Server)
				h2.ServeConn(server, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					cookie, _ := r.Cookie("padding")
					padding := ""
					if cookie != nil {
						padding = cookie.Value
					}
					json.NewEncoder(os.Stdout).Encode(map[string]any{"method": r.Method, "path": r.URL.Path, "ua": r.UserAgent(), "padding": padding})
					w.WriteHeader(200)
				})})
				return
			}
			if _, err := io.CopyN(server, server, count); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
			server.Close()
		}()
	}
}
