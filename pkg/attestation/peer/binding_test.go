// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package peer

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func TestQualifyingData_WithoutBindingIsTheNonce(t *testing.T) {
	nonce := []byte("nonce")
	got := QualifyingData(nonce, nil)
	if !bytes.Equal(got, nonce) {
		t.Fatalf("got %x", got)
	}
	got[0] ^= 0xff
	if nonce[0] != 'n' {
		t.Fatal("QualifyingData returned the caller's buffer")
	}
	if !bytes.Equal(QualifyingData(nonce, []byte{}), nonce) {
		t.Fatal("empty binding must behave as no binding")
	}
}

func TestQualifyingData_WithBindingIsSHA256OfNonceThenBinding(t *testing.T) {
	nonce := []byte("nonce")
	binding := []byte("binding")
	want := sha256.Sum256([]byte("noncebinding"))
	if got := QualifyingData(nonce, binding); !bytes.Equal(got, want[:]) {
		t.Fatalf("got %x want %x", got, want)
	}
	if bytes.Equal(QualifyingData(nonce, []byte("other")), want[:]) {
		t.Fatal("a different binding produced the same qualifying data")
	}
	if got := QualifyingData(nonce, binding); len(got) != ChannelBindingLength {
		t.Fatalf("bound qualifying data is %d bytes; it must fit any TPM2B_DATA", len(got))
	}
}

func TestChannelBinding_NilStateIsError(t *testing.T) {
	_, err := ChannelBinding(nil)
	var cbe *ChannelBindingError
	if !errors.As(err, &cbe) || cbe.Cause != nil {
		t.Fatalf("err = %v", err)
	}
}

// tlsPair completes a TLS handshake over an in-memory pipe and returns both
// connection states.
func tlsPair(t *testing.T, version uint16) (client, server tls.ConnectionState) {
	t.Helper()
	key := newECKey(t, elliptic.P256())
	cert := selfSign(t, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "loopback"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"loopback"},
	}, key)
	tlsCert := tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}

	// The client verifies the server for real: the loopback certificate is
	// its only root and the SAN is its expected name. An exporter test over
	// an unverified handshake would prove less than this one.
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	cConn, sConn := net.Pipe()
	serverTLS := tls.Server(sConn, &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: version, MaxVersion: version})
	clientTLS := tls.Client(cConn, &tls.Config{RootCAs: roots, ServerName: "loopback", MinVersion: version, MaxVersion: version})

	serverErr := make(chan error, 1)
	go func() { serverErr <- serverTLS.Handshake() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	t.Cleanup(func() {
		clientTLS.Close()
		serverTLS.Close()
	})
	return clientTLS.ConnectionState(), serverTLS.ConnectionState()
}

func TestChannelBinding_BothEndsDeriveTheSameValue(t *testing.T) {
	for name, version := range map[string]uint16{"tls13": tls.VersionTLS13, "tls12": tls.VersionTLS12} {
		t.Run(name, func(t *testing.T) {
			client, server := tlsPair(t, version)
			c, err := ChannelBinding(&client)
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			s, err := ChannelBinding(&server)
			if err != nil {
				t.Fatalf("server: %v", err)
			}
			if len(c) != ChannelBindingLength || !bytes.Equal(c, s) {
				t.Fatalf("client %x != server %x", c, s)
			}
		})
	}
}

func TestChannelBinding_DiffersPerConnection(t *testing.T) {
	first, _ := tlsPair(t, tls.VersionTLS13)
	second, _ := tlsPair(t, tls.VersionTLS13)
	a, err := ChannelBinding(&first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ChannelBinding(&second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two connections derived the same binding; a quote could be replayed between them")
	}
}

func TestChannelBinding_IncompleteHandshakeIsError(t *testing.T) {
	// A ConnectionState that never completed a handshake has no exporter;
	// crypto/tls would dereference nil, so the guard must come first.
	state := tls.ConnectionState{Version: tls.VersionTLS12}
	_, err := ChannelBinding(&state)
	var cbe *ChannelBindingError
	if !errors.As(err, &cbe) || !strings.Contains(err.Error(), "handshake not complete") {
		t.Fatalf("err = %v", err)
	}
}
