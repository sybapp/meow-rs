// Test-only independent peer. Protocol parsing is performed by pinned mihomo,
// never by a second copy of meow's request builder.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/transport/xhttp"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

func main() {
	protocol := flag.String("protocol", "h2", "h2, h2-tls or h3")
	settings := flag.String("config", "{}", "XHTTP config JSON")
	clientAuth := flag.Bool("require-client-cert", false, "require the fixture CA mutual TLS identity")
	vless := flag.Bool("vless", false, "decode a synthetic plain VLESS TCP fixture before echo")
	dual := flag.Bool("dual", false, "serve upload/download on independent addresses")
	capture := flag.Bool("capture", false, "capture HTTP requests and physical connection IDs")
	downPath := flag.String("download-path", "", "download frontend path prefix")
	downHost := flag.String("download-host", "", "download frontend authority")
	count := flag.Int64("bytes", 0, "echo exactly this many bytes")
	flag.Parse()
	var cfg xhttp.Config
	if err := json.Unmarshal([]byte(*settings), &cfg); err != nil {
		panic(err)
	}
	handler, err := xhttp.NewServerHandler(xhttp.ServerOption{
		Config: cfg,
		ConnHandler: func(conn net.Conn) {
			defer conn.Close()
			if *vless {
				if err := vlessFixture(conn); err != nil {
					fmt.Fprintln(os.Stderr, err)
					return
				}
			}
			if _, err := io.CopyN(conn, conn, *count); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		},
	})
	if err != nil {
		panic(err)
	}
	if *protocol == "h2" || *protocol == "h2-tls" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
		protocols := new(http.Protocols)
		protocols.SetUnencryptedHTTP2(true)
		protocols.SetHTTP2(true)
		var tlsConfig *tls.Config
		var identityInfo map[string]any
		if *protocol == "h2-tls" {
			identity, der, certPEM, keyPEM := peerIdentity()
			tlsConfig = &tls.Config{Certificates: []tls.Certificate{identity}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS13}
			if *clientAuth {
				pool := x509.NewCertPool()
				pool.AppendCertsFromPEM([]byte(certPEM))
				tlsConfig.ClientCAs = pool
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			}
			listener = tls.NewListener(listener, tlsConfig)
			clientPEM, clientKeyPEM := peerClientIdentity(identity)
			pin := sha256.Sum256(der)
			identityInfo = map[string]any{"fingerprint": fmt.Sprintf("%x", pin), "client-certificate-pem": clientPEM, "client-private-key-pem": clientKeyPEM, "certificate": der, "certificate-pem": certPEM, "private-key-pem": keyPEM}
		}
		var outputMu sync.Mutex
		var nextID atomic.Int64
		type connIDKey struct{}
		makeServer := func(download bool) *http.Server {
			frontend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if *capture {
					outputMu.Lock()
					json.NewEncoder(os.Stdout).Encode(map[string]any{"connection": r.Context().Value(connIDKey{}), "download": download, "method": r.Method, "path": r.URL.Path, "host": r.Host, "headers": r.Header, "sni": func() string {
						if r.TLS != nil {
							return r.TLS.ServerName
						}
						return ""
					}()})
					outputMu.Unlock()
				}
				if download {
					if r.Method != "GET" || (*downHost != "" && r.Host != *downHost) || (*downPath != "" && !strings.HasPrefix(r.URL.Path, *downPath)) {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if *downPath != "" {
						r.URL.Path = strings.TrimRight(cfg.Path, "/") + strings.TrimPrefix(r.URL.Path, *downPath)
					}
					r.Host = cfg.Host
				}
				handler.ServeHTTP(w, r)
			})
			return &http.Server{Handler: frontend, Protocols: protocols, TLSConfig: tlsConfig, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, connIDKey{}, nextID.Add(1))
			}}
		}
		server := makeServer(false)
		info := map[string]any{"address": listener.Addr().String()}
		for key, value := range identityInfo {
			info[key] = value
		}
		if *dual {
			down, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				panic(err)
			}
			info["download-address"] = down.Addr().String()
			if tlsConfig != nil {
				down = tls.NewListener(down, tlsConfig)
			}
			downServer := makeServer(true)
			defer downServer.Close()
			// Publish startup info before request captures.
			json.NewEncoder(os.Stdout).Encode(info)
			go downServer.Serve(down)
		} else {
			json.NewEncoder(os.Stdout).Encode(info)
		}
		if err := server.Serve(listener); err != nil {
			panic(err)
		}
		return
	}
	identity, certificate, certPEM, keyPEM := peerIdentity()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{identity}}
	if *clientAuth {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(certPEM))
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	server := &http3.Server{Handler: handler, TLSConfig: tlsConfig}
	clientPEM, clientKeyPEM := peerClientIdentity(identity)
	pin := sha256.Sum256(certificate)
	json.NewEncoder(os.Stdout).Encode(map[string]any{"address": socket.LocalAddr().String(), "certificate": certificate, "client-certificate-pem": clientPEM, "client-private-key-pem": clientKeyPEM, "certificate-pem": certPEM, "private-key-pem": keyPEM, "fingerprint": fmt.Sprintf("%x", pin)})
	if err := server.Serve(socket); err != nil {
		panic(err)
	}
}
