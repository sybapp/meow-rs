// Independent TLS 1.3 key-schedule/record vectors from Go crypto primitives.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"io"
	"os"
)

func cipherVectors() {
	results := []map[string]any{}
	for _, suite := range []uint16{0x1301, 0x1302, 0x1303} {
		f := sha256.New
		keyLen := 16
		if suite == 0x1302 {
			f = sha512.New384
			keyLen = 32
		}
		if suite == 0x1303 {
			keyLen = 32
		}
		digest := func(b []byte) []byte { h := f(); h.Write(b); return h.Sum(nil) }
		expand := func(secret []byte, label string, context []byte, n int) []byte {
			info := []byte{byte(n >> 8), byte(n), byte(6 + len(label))}
			info = append(info, []byte("tls13 "+label)...)
			info = append(info, byte(len(context)))
			info = append(info, context...)
			out := make([]byte, n)
			if _, err := io.ReadFull(hkdf.Expand(f, secret, info), out); err != nil {
				panic(err)
			}
			return out
		}
		extract := func(salt, ikm []byte) []byte { h := hmac.New(f, salt); h.Write(ikm); return h.Sum(nil) }
		hashLen := f().Size()
		zero := make([]byte, hashLen)
		shared := make([]byte, 32)
		for i := range shared {
			shared[i] = byte(i)
		}
		transcript := []byte("independent TLS 1.3 handshake transcript")
		early := extract(zero, zero)
		derived := expand(early, "derived", digest(nil), hashLen)
		hs := extract(derived, shared)
		client := expand(hs, "c hs traffic", digest(transcript), hashLen)
		server := expand(hs, "s hs traffic", digest(transcript), hashLen)
		master := extract(expand(hs, "derived", digest(nil), hashLen), zero)
		app := expand(master, "c ap traffic", digest(transcript), hashLen)
		finishKey := expand(server, "finished", nil, hashLen)
		finish := extract(finishKey, digest(transcript))
		key := expand(app, "key", nil, keyLen)
		iv := expand(app, "iv", nil, 12)
		var aead cipher.AEAD
		var err error
		if suite == 0x1303 {
			aead, err = chacha20poly1305.New(key)
		} else {
			var block cipher.Block
			block, err = aes.NewCipher(key)
			if err == nil {
				aead, err = cipher.NewGCM(block)
			}
		}
		if err != nil {
			panic(err)
		}
		records := []string{}
		for seq := uint64(0); seq < 2; seq++ {
			payload := append([]byte("independent record plaintext"), 23)
			header := []byte{23, 3, 3, 0, byte(len(payload) + 16)}
			nonce := append([]byte(nil), iv...)
			var counter [8]byte
			binary.BigEndian.PutUint64(counter[:], seq)
			for i := range counter {
				nonce[i+4] ^= counter[i]
			}
			record := append(header, aead.Seal(nil, nonce, payload, header)...)
			records = append(records, hex.EncodeToString(record))
		}
		results = append(results, map[string]any{"suite": suite, "shared": hex.EncodeToString(shared), "transcript": hex.EncodeToString(transcript), "client_handshake_secret": hex.EncodeToString(client), "server_handshake_secret": hex.EncodeToString(server), "master_secret": hex.EncodeToString(master), "client_application_secret": hex.EncodeToString(app), "finished": hex.EncodeToString(finish), "updated_secret": hex.EncodeToString(expand(app, "traffic upd", nil, hashLen)), "records": records})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		panic(err)
	}
}
