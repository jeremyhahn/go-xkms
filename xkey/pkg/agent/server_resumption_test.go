// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// TestServer_TLSSessionResumption_RevokedAgentRefused is a real TLS test
// for go-xkms#1285: a revoked agent's certificate must be refused on a
// resumed TLS session, not just on a fresh one.
//
// It drives two actual handshakes between an in-process client and server
// over net.Pipe. The server side is configured exactly as
// Server.buildTLSConfig wires mTLS - Certificates, ClientAuth,
// ClientCAs, and VerifyConnection: s.verifyConnection - except that
// session tickets are deliberately left enabled here.
// TestServer_BuildTLSConfig_SessionTicketsDisabled already proves
// buildTLSConfig disables them in production; leaving them on in this test
// isolates the VerifyConnection fix itself (the actual subject of #1285)
// by forcing a real resumed handshake through it, so the test still fails
// if verifyConnection is ever wired back onto VerifyPeerCertificate, which
// Go does not call on a resumed session, independent of whether some other
// change also drops SessionTicketsDisabled.
func TestServer_TLSSessionResumption_RevokedAgentRefused(t *testing.T) {
	server, store := testServerWithStore(t)
	ca := server.enrollment.ca.(*mockCAService)

	caCert, caKey := newResumptionTestCA(t)
	serverCert, serverKey := newResumptionTestLeaf(t, caCert, caKey, "localhost", 2, x509.ExtKeyUsageServerAuth)
	agentCert, agentKey := newResumptionTestLeaf(t, caCert, caKey, "test-agent", 3, x509.ExtKeyUsageClientAuth)

	agentID, err := publicKeyFingerprint(agentKey.Public())
	if err != nil {
		t.Fatalf("fingerprint agent key: %v", err)
	}
	if err := store.SaveAgent(&AgentInfo{
		ID:                     agentID,
		CertificateFingerprint: agentID,
		CertificateSerial:      agentCert.SerialNumber.Text(16),
		Status:                 "active",
	}); err != nil {
		t.Fatalf("save agent: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	serverConfig := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{serverCert.Raw}, PrivateKey: serverKey}},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        caPool,
		VerifyConnection: server.verifyConnection,
		MinVersion:       tls.VersionTLS13,
	}
	clientConfig := &tls.Config{
		Certificates:       []tls.Certificate{{Certificate: [][]byte{agentCert.Raw}, PrivateKey: agentKey}},
		RootCAs:            caPool,
		ServerName:         "localhost",
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
		MinVersion:         tls.VersionTLS13,
	}

	// First connection: the enrolled, non-revoked agent completes a full
	// handshake. pipeHandshake reads one byte after the handshake so the
	// client processes the server's post-handshake NewSessionTicket and
	// stores it in clientConfig.ClientSessionCache for reuse below.
	if serverErr, clientErr := pipeHandshake(t, serverConfig, clientConfig); serverErr != nil || clientErr != nil {
		t.Fatalf("first handshake failed: server=%v client=%v", serverErr, clientErr)
	}

	// Revoke the agent's certificate through the same CA call
	// VerifyAgentCertificate makes on every connection.
	ca.isRevokedFunc = func(serial string) (bool, error) {
		return serial == agentCert.SerialNumber.Text(16), nil
	}

	// Second connection: the client offers the ticket captured above, so
	// Go resumes the session instead of running a full handshake. A
	// wrapping VerifyConnection records whether Go considered this
	// connection resumed at the moment the check ran, proving the
	// resumption actually happened rather than coincidentally also being
	// refused as a fresh handshake.
	var observedResume bool
	serverConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		observedResume = cs.DidResume
		return server.verifyConnection(cs)
	}

	serverErr, clientErr := pipeHandshake(t, serverConfig, clientConfig)
	if serverErr == nil {
		t.Fatal("expected the resumed handshake for a revoked agent to be refused")
	}
	if !errors.Is(serverErr, ErrCertificateRevoked) {
		t.Errorf("expected ErrCertificateRevoked, got %v", serverErr)
	}
	if clientErr == nil {
		t.Error("expected the client to observe the refused handshake as an error too")
	}
	if !observedResume {
		t.Fatal("second connection did not resume the session; the test does not exercise the resumption path it claims to")
	}
}

// TestServer_TLSSessionResumption_NonRevokedAgentStillResumes proves the
// companion property: a resumed session for an agent that is still
// enrolled and unrevoked keeps working, so the fix does not simply refuse
// every resumption.
func TestServer_TLSSessionResumption_NonRevokedAgentStillResumes(t *testing.T) {
	server, store := testServerWithStore(t)

	caCert, caKey := newResumptionTestCA(t)
	serverCert, serverKey := newResumptionTestLeaf(t, caCert, caKey, "localhost", 2, x509.ExtKeyUsageServerAuth)
	agentCert, agentKey := newResumptionTestLeaf(t, caCert, caKey, "test-agent", 3, x509.ExtKeyUsageClientAuth)

	agentID, err := publicKeyFingerprint(agentKey.Public())
	if err != nil {
		t.Fatalf("fingerprint agent key: %v", err)
	}
	if err := store.SaveAgent(&AgentInfo{
		ID:                     agentID,
		CertificateFingerprint: agentID,
		CertificateSerial:      agentCert.SerialNumber.Text(16),
		Status:                 "active",
	}); err != nil {
		t.Fatalf("save agent: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	var observedResume bool
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert.Raw}, PrivateKey: serverKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		VerifyConnection: func(cs tls.ConnectionState) error {
			observedResume = cs.DidResume
			return server.verifyConnection(cs)
		},
		MinVersion: tls.VersionTLS13,
	}
	clientConfig := &tls.Config{
		Certificates:       []tls.Certificate{{Certificate: [][]byte{agentCert.Raw}, PrivateKey: agentKey}},
		RootCAs:            caPool,
		ServerName:         "localhost",
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
		MinVersion:         tls.VersionTLS13,
	}

	if serverErr, clientErr := pipeHandshake(t, serverConfig, clientConfig); serverErr != nil || clientErr != nil {
		t.Fatalf("first handshake failed: server=%v client=%v", serverErr, clientErr)
	}

	serverErr, clientErr := pipeHandshake(t, serverConfig, clientConfig)
	if serverErr != nil || clientErr != nil {
		t.Fatalf("resumed handshake for a still-enrolled, unrevoked agent should succeed: server=%v client=%v", serverErr, clientErr)
	}
	if !observedResume {
		t.Fatal("second connection did not resume the session; the test does not exercise the resumption path it claims to")
	}
}

// newResumptionTestCA creates a self-signed CA certificate/key pair. Unlike
// writeTestServerTLSFiles, the resumption tests need the CA's private key
// so they can mint a matching agent certificate as well as a server one.
func newResumptionTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "resumption test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return cert, key
}

// newResumptionTestLeaf mints a leaf certificate signed by ca/caKey, for
// either the server (x509.ExtKeyUsageServerAuth) or an agent
// (x509.ExtKeyUsageClientAuth).
func newResumptionTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, serial int64, eku x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return cert, key
}

// pipeHandshake runs one TLS handshake between a client and server built
// from clientConfig/serverConfig, over a fresh loopback TCP connection (a
// fresh connection stands in for a fresh agent connection; each call opens
// and tears down its own listener, so nothing outlives the call and no
// state is shared with the host beyond an ephemeral 127.0.0.1 port).
//
// A real loopback socket - not net.Pipe - is used deliberately: net.Pipe's
// writes block until fully drained by a matching Read with no buffering in
// between, and TLS 1.3's server flow writes the post-handshake session
// ticket from inside the same Handshake call that is still draining the
// client's own buffered Certificate/CertificateVerify/Finished flight,
// which deadlocks two unbuffered pipe ends but not two socket send buffers.
//
// On a successful handshake, it also has the client perform one Read so it
// processes any post-handshake NewSessionTicket the server sent - TLS 1.3
// tickets are only applied to ClientSessionCache when the client reads
// past them, not as part of Handshake itself - so a ticket captured on one
// call is available for a later call to resume.
//
// When the server rejects the handshake, clientConn.Handshake itself can
// still return nil: a TLS 1.3 client considers its side done as soon as it
// has sent its own Finished message and does not wait for the server's
// post-Finished decision (here, VerifyConnection) before returning. The
// server's rejection alert is still on the wire, so this then has the
// client attempt one Read to surface it as clientErr. It returns the
// server's and the client's resulting errors.
func pipeHandshake(t *testing.T, serverConfig, clientConfig *tls.Config) (serverErr, clientErr error) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.Accept()
		acceptCh <- acceptResult{conn: conn, err: err}
	}()

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	accepted := <-acceptCh
	if accepted.err != nil {
		t.Fatalf("accept: %v", accepted.err)
	}
	rawServer := accepted.conn

	serverConn := tls.Server(rawServer, serverConfig)
	clientConn := tls.Client(rawClient, clientConfig)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		serverErr = serverConn.Handshake()
	}()
	go func() {
		defer wg.Done()
		clientErr = clientConn.Handshake()
	}()
	wg.Wait()

	switch {
	case serverErr == nil && clientErr == nil:
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = serverConn.Write([]byte("x"))
		}()
		buf := make([]byte, 1)
		_, _ = io.ReadFull(clientConn, buf)
		<-done
	case serverErr != nil && clientErr == nil:
		buf := make([]byte, 1)
		_, clientErr = clientConn.Read(buf)
	}

	_ = clientConn.Close()
	_ = serverConn.Close()
	return serverErr, clientErr
}
