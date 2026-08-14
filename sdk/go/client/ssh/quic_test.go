// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// newLoopbackTLS mints a self-signed leaf valid for 127.0.0.1 and returns the
// server TLS config plus a client config that trusts it.
func newLoopbackTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	server = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		NextProtos:   []string{http3.NextProtoH3},
	}
	client = &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		NextProtos: []string{http3.NextProtoH3},
	}
	return server, client
}

// startHTTP3 serves handler over HTTP/3 on an ephemeral loopback UDP port and
// returns the base URL.
func startHTTP3(t *testing.T, tlsCfg *tls.Config, handler http.Handler) string {
	t.Helper()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &http3.Server{TLSConfig: tlsCfg, Handler: handler}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(udpConn)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = udpConn.Close()
		<-done
	})

	addr, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected addr type %T", udpConn.LocalAddr())
	}
	return fmt.Sprintf("https://127.0.0.1:%d", addr.Port)
}

func TestNewQUIC_MissingBaseURL(t *testing.T) {
	_, err := sdkssh.NewQUIC(sdkssh.QUICOptions{})
	var nilErr *sdkssh.NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected *NilInputError, got %T %v", err, err)
	}
	if nilErr.Field != "BaseURL" {
		t.Errorf("Field = %q", nilErr.Field)
	}
}

// TestQUIC_RoundTripUsesHTTP3 proves the QUIC client really speaks HTTP/3 and
// shares the REST JSON wire format. The server asserts the negotiated protocol,
// so a regression that dropped the http3.Transport (silently falling back to
// HTTP/1 over TCP) would fail this test rather than pass unnoticed.
func TestQUIC_RoundTripUsesHTTP3(t *testing.T) {
	serverTLS, clientTLS := newLoopbackTLS(t)

	// The handler runs on an http3 server goroutine while the assertions below
	// run on the test goroutine. List returning is not a happens-before edge
	// for the handler's writes, so the captured values need a mutex — without
	// one this test is itself a data race and fails under -race intermittently.
	var mu sync.Mutex
	var sawProto, sawAuth, sawPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/xkms/v1/ssh/keys", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawProto = r.Proto
		sawAuth = r.Header.Get("Authorization")
		sawPath = r.URL.Path
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"name":"laptop","algorithm":"ed25519","backend":"tpm2"}]}`))
	})

	baseURL := startHTTP3(t, serverTLS, mux)

	client, err := sdkssh.NewQUIC(sdkssh.QUICOptions{
		BaseURL:   baseURL,
		TLSConfig: clientTLS,
		AuthToken: "token-abc",
	})
	if err != nil {
		t.Fatalf("NewQUIC: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	keys, err := client.Keys().List(ctx, sdkssh.ListKeysRequest{})
	if err != nil {
		t.Fatalf("List over QUIC: %v", err)
	}
	if len(keys) != 1 || keys[0].Name != "laptop" || keys[0].Backend != "tpm2" {
		t.Fatalf("decoded keys = %+v", keys)
	}
	mu.Lock()
	proto, auth, path := sawProto, sawAuth, sawPath
	mu.Unlock()

	if proto != "HTTP/3.0" {
		t.Errorf("server saw %q; the QUIC client must negotiate HTTP/3", proto)
	}
	// The bearer token must be attached on the QUIC path too, not just REST.
	if auth != "Bearer token-abc" {
		t.Errorf("Authorization = %q, want %q", auth, "Bearer token-abc")
	}
	if path != "/xkms/v1/ssh/keys" {
		t.Errorf("path = %q", path)
	}
}

// TestQUIC_ServerErrorMapsToTypedError checks the shared status table applies
// on the QUIC leg as well.
func TestQUIC_ServerErrorMapsToTypedError(t *testing.T) {
	serverTLS, clientTLS := newLoopbackTLS(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/xkms/v1/ssh/keys/user/alice/ghost", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"key not found"}`))
	})

	baseURL := startHTTP3(t, serverTLS, mux)
	client, err := sdkssh.NewQUIC(sdkssh.QUICOptions{BaseURL: baseURL, TLSConfig: clientTLS})
	if err != nil {
		t.Fatalf("NewQUIC: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err = client.Keys().Get(ctx, sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "ghost"})
	var nf *sdkssh.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *NotFoundError, got %T %v", err, err)
	}
}

// TestQUIC_UntrustedServerCertificateRejected is the security-relevant case:
// the default TLS config must not accept an unknown self-signed server.
func TestQUIC_UntrustedServerCertificateRejected(t *testing.T) {
	serverTLS, _ := newLoopbackTLS(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/xkms/v1/ssh/keys", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	baseURL := startHTTP3(t, serverTLS, mux)

	// nil TLSConfig -> SDK default (TLS 1.3, system roots, verification on).
	client, err := sdkssh.NewQUIC(sdkssh.QUICOptions{BaseURL: baseURL})
	if err != nil {
		t.Fatalf("NewQUIC: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if _, err := client.Keys().List(ctx, sdkssh.ListKeysRequest{}); err == nil {
		t.Fatal("the default QUIC config must reject an untrusted server certificate")
	}
}
