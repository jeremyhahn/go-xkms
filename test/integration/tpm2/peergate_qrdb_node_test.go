//go:build integration

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

package integration

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmsserver "github.com/jeremyhahn/go-xkms/pkg/server"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	tpm2lib "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// The registers the peer quotes and the verifier holds to a baseline.
var gatedPCRs = []uint{0, 1, 2, 3, 7}

// gatePKI issues the node's server certificate, the peer's client
// certificate and the TPM IAK's certificate.
type gatePKI struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newGatePKI(t *testing.T) *gatePKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "attested caller test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &gatePKI{cert: cert, key: key, pool: pool}
}

func (p *gatePKI) issue(t *testing.T, tmpl *x509.Certificate, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	require.NoError(t, err)
	tmpl.SerialNumber = serial
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(12 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, pub, p.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// tlsCert issues a certificate for a fresh key, as a tls.Certificate.
func (p *gatePKI) tlsCert(t *testing.T, tmpl *x509.Certificate) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := p.issue(t, tmpl, &key.PublicKey)
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
}

func (p *gatePKI) serverTLS(t *testing.T, clientAuth tls.ClientAuthType) *tls.Config {
	t.Helper()
	cert := p.tlsCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    p.pool,
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS13,
	}
}

// gateHost is what a host composing go-qrdb with go-xkms runs: a qrdb node
// whose admin:status permission is gated on peer attestation, and the
// collector endpoints its peers submit evidence to.
type gateHost struct {
	pki       *gatePKI
	node      *qrdbnode.Node
	store     *peergate.DAOStore
	verifier  *peergate.Verifier
	collector *peergate.Collector
	collect   string // the collector's base URL
}

func newGateHost(t *testing.T, policy peer.Policy, p *gatePKI, peerCert *x509.Certificate) *gateHost {
	t.Helper()
	ctx := context.Background()

	store, err := peergate.NewDAOStore(peergate.DAOStoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	verifier, err := peergate.NewVerifier(peergate.VerifierConfig{Store: store, Policy: policy})
	require.NoError(t, err)
	collector, err := peergate.NewCollector(peergate.CollectorConfig{Store: store})
	require.NoError(t, err)
	gate, err := qrdbsdk.NewPeerAttestationGate(verifier, qrdbsdk.PeerAttestationPolicy{
		Permissions:    []qrdbsdk.Permission{qrdbsdk.PermissionAdminStatus},
		MaxEvidenceAge: time.Minute,
	})
	require.NoError(t, err)

	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	// The node seal is on, under the "none" strategy xkmsd composes for an
	// insecure barrier (embeddednode.EmbeddedNodeStorageConfig): qrdb builds
	// its certificate provider, and with it the certificate target guard
	// users:add_cert_binding is held to, only on a node with a barrier.
	cfg.Seal.Enabled = true
	cfg.Seal.Strategy = string(qrdbsdk.StrategyNone)
	cfg.Server.Host = "127.0.0.1"
	cfg.Protocols.REST = true
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	restListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	node, err := qrdbnode.NewStandaloneNode(ctx, cfg,
		[]qrdbsdk.ServerOption{
			qrdbsdk.WithServerTLS(p.serverTLS(t, tls.VerifyClientCertIfGiven)),
			qrdbsdk.WithRESTListener(restListener),
		},
		qrdbnode.WithPeerAttestationGate(gate),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })

	// First boot seeds the system tenant, its built-in roles and the
	// bootstrap admin, as xkmsd init does. The node enforces the "required"
	// mTLS binding policy, so the admin presents a certificate from the
	// fixture's PKI (qrdb's Path C) and first boot binds it.
	adminKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	adminCert := p.issue(t, &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "admin",
			OrganizationalUnit: []string{qrdbsdk.SystemTenantID},
		},
		URIs:        []*url.URL{{Scheme: "spiffe", Host: qrdbsdk.SystemTenantID, Path: "/user/admin"}},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, &adminKey.PublicKey)
	deps, err := xkmsserver.BuildFirstBootDependencies(node, xkmsserver.FirstBootParams{Logger: slog.Default()})
	require.NoError(t, err)
	deps.AdminCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: adminCert.Raw})
	deps.AdminCertPool = p.pool
	booted, err := node.FirstBoot(ctx, deps)
	require.NoError(t, err)
	require.True(t, booted.AdminCreated)

	// The peer is an ordinary system-tenant account whose role grants
	// admin:status. RBAC admits it; only the gate stands between it and the
	// route.
	// The node's client authorizes every call as the identity on its
	// context, so the fixtures' role creation runs as the system tenant's
	// Admin and Security Officer (the SO holds roles:create).
	client := node.Client()
	ctx = qrdbsdk.ContextWithTenant(qrdbsdk.WithIdentity(ctx, &qrdbsdk.Identity{
		Subject:  "test-security-officer",
		TenantID: qrdbsdk.SystemTenantID,
		Roles: []string{
			qrdbsdk.SystemRoleID(qrdbsdk.SystemTenantID, qrdbsdk.RoleNameAdmin),
			qrdbsdk.SystemRoleID(qrdbsdk.SystemTenantID, qrdbsdk.RoleNameSO),
		},
	}), qrdbsdk.SystemTenantID)
	role, err := client.Roles().CreateRole(ctx, &qrdbtransport.CreateRoleRequest{
		Name:        "attested-status-reader",
		TenantID:    qrdbsdk.SystemTenantID,
		Permissions: []string{qrdbsdk.PermissionAdminStatus.String()},
	})
	require.NoError(t, err)
	// Creating a user with a role needs users:create and roles:assign in the
	// tenant; the test provisions as a system identity that holds exactly those.
	provisioner, err := client.Roles().CreateRole(ctx, &qrdbtransport.CreateRoleRequest{
		Name:     "test-provisioner",
		TenantID: qrdbsdk.SystemTenantID,
		Permissions: []string{
			qrdbsdk.PermissionUsersCreate.String(),
			qrdbsdk.PermissionRolesAssign.String(),
			qrdbsdk.PermissionUsersAddCertBinding.String(),
		},
	})
	require.NoError(t, err)
	provisioning := qrdbsdk.WithIdentity(ctx, &qrdbsdk.Identity{
		Subject:  "test-provisioner",
		TenantID: qrdbsdk.SystemTenantID,
		Roles:    []string{provisioner.ID},
	})
	peerUser, err := client.Users().CreateUser(provisioning, &qrdbtransport.CreateUserRequest{
		Username:             "attested-peer",
		TenantID:             qrdbsdk.SystemTenantID,
		RoleIDs:              []string{role.ID},
		WithoutEmailLoginKey: true,
	})
	require.NoError(t, err)
	// The node enforces the "required" mTLS binding policy, which refuses a
	// certificate login whose account has no binding. The peer's certificate
	// is bound by its SPKI thumbprint, so binding never refuses it and only the
	// gate decides whether it reaches the route.
	_, err = client.Users().AddCertBinding(provisioning, peerUser.ID, qrdbsdk.ComputeSPKIThumbprint(peerCert), 0)
	require.NoError(t, err)

	host := &gateHost{pki: p, node: node, store: store, verifier: verifier, collector: collector}
	host.collect = host.serveCollector(t)
	return host
}

// serveCollector mounts the collector the way a host does: POST /challenge
// returns a nonce, POST /evidence submits evidence, each against the TLS
// connection the request arrived on.
func (h *gateHost) serveCollector(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /challenge", func(w http.ResponseWriter, r *http.Request) {
		challenge, err := h.collector.Challenge(r.Context(), r.TLS)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(challenge); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("POST /evidence", func(w http.ResponseWriter, r *http.Request) {
		var evidence peer.Evidence
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&evidence); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.collector.Submit(r.Context(), r.TLS, evidence); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{
		Handler:           mux,
		TLSConfig:         h.pki.serverTLS(t, tls.RequireAndVerifyClientCert),
		ReadHeaderTimeout: 10 * time.Second,
	}
	served := make(chan error, 1)
	go func() { served <- server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		require.NoError(t, server.Close())
		require.ErrorIs(t, <-served, http.ErrServerClosed)
	})
	return "https://" + listener.Addr().String()
}

// attestedPeer is the device on the other end: an mTLS identity and a TPM.
type attestedPeer struct {
	cert  tls.Certificate
	tpm   tpm2lib.TrustedPlatformModule
	akPEM []byte
}

// session is one keep-alive HTTPS client: MaxConnsPerHost 1 holds every
// request to one TLS connection, which is what channel binding is about.
func (a *attestedPeer) session(roots *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{a.cert},
				RootCAs:      roots,
				MinVersion:   tls.VersionTLS13,
			},
			MaxConnsPerHost: 1,
		},
	}
}

// challenge asks the collector for a nonce and returns it with the client
// side of the connection it was issued on.
func (h *gateHost) challenge(t *testing.T, client *http.Client) (peergate.Challenge, *tls.ConnectionState) {
	t.Helper()
	resp, err := client.Post(h.collect+"/challenge", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var challenge peergate.Challenge
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&challenge))
	return challenge, resp.TLS
}

// connection returns the client side of a TLS connection to the collector
// that has not been issued a challenge.
func (h *gateHost) connection(t *testing.T, client *http.Client) *tls.ConnectionState {
	t.Helper()
	resp, err := client.Get(h.collect + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.NotNil(t, resp.TLS)
	return resp.TLS
}

func (h *gateHost) submit(t *testing.T, client *http.Client, evidence peer.Evidence) int {
	t.Helper()
	body, err := json.Marshal(evidence)
	require.NoError(t, err)
	resp, err := client.Post(h.collect+"/evidence", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	return resp.StatusCode
}

// status calls the gated route and returns the HTTP status.
func (h *gateHost) status(t *testing.T, a *attestedPeer) int {
	t.Helper()
	client := a.session(h.pki.pool)
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://" + h.node.Server().RESTAddr() + "/status")
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	return resp.StatusCode
}

// verdict is the verifier's own judgment, for asserting the failure class the
// gate refused on.
func (h *gateHost) verdict(t *testing.T, a *attestedPeer) *qrdbsdk.PeerAttestation {
	t.Helper()
	verdict, err := h.verifier.VerifyPeer(context.Background(), qrdbsdk.AttestedPeer{
		Certificate: a.cert.Leaf,
		Thumbprint:  qrdbsdk.ComputeSPKIThumbprint(a.cert.Leaf),
	})
	require.NoError(t, err)
	return verdict
}

// baselineOf reads the TPM's current values of the gated registers from the
// bank its IAK quotes, as an enrollment step would record them.
func baselineOf(t *testing.T, tpm tpm2lib.TrustedPlatformModule) map[int][]byte {
	t.Helper()
	banks, err := tpm.ReadPCRs(gatedPCRs)
	require.NoError(t, err)
	for _, bank := range banks {
		if bank.Algorithm != "SHA256" {
			continue
		}
		baseline := make(map[int][]byte, len(bank.PCRs))
		for _, pcr := range bank.PCRs {
			baseline[int(pcr.ID)] = pcr.Value
		}
		return baseline
	}
	t.Fatal("the TPM reported no SHA-256 bank")
	return nil
}

// TestIntegration_PeerGate_QRDBNodeAdmitsOnlyAnAttestedPeer composes a go-qrdb
// node with go-xkms's peer attestation verifier and drives a peer whose
// evidence is quoted by a real TPM (swtpm in the integration environment).
// The gated route admits the peer only while its latest evidence is a valid
// quote of the baseline state, bound to the connection it was submitted on;
// stale, forged and wrongly bound evidence is refused.
func TestIntegration_PeerGate_QRDBNodeAdmitsOnlyAnAttestedPeer(t *testing.T) {
	tpm, cleanup := setupAttestationTPM(t)
	defer cleanup()

	p := newGatePKI(t)
	akPublic, err := tpm.IAK()
	require.NoError(t, err)
	akCert := p.issue(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "iak"},
		KeyUsage: x509.KeyUsageDigitalSignature,
		Policies: []x509.OID{ca.TCGVerifiedTPMRestrictedPolicy},
	}, akPublic)

	a := &attestedPeer{
		cert: p.tlsCert(t, &x509.Certificate{
			Subject: pkix.Name{CommonName: "attested-peer", OrganizationalUnit: []string{qrdbsdk.SystemTenantID}},
			// qrdb names a certificate's tenant only by its Subject OU and
			// its SPIFFE ID SAN together (auth.TenantFromClientCert).
			URIs:        []*url.URL{{Scheme: "spiffe", Host: qrdbsdk.SystemTenantID, Path: "/user/attested-peer"}},
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}),
		tpm:   tpm,
		akPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: akCert.Raw}),
	}
	host := newGateHost(t, peer.Policy{Anchors: p.pool, Baseline: baselineOf(t, tpm)}, p, a.cert.Leaf)

	// attest runs one honest round on a fresh connection: challenge, quote
	// bound to the connection, submit.
	attest := func(t *testing.T) {
		t.Helper()
		client := a.session(p.pool)
		defer client.CloseIdleConnections()
		challenge, state := host.challenge(t, client)
		evidence, err := peergate.QuoteEvidence(state, challenge.Nonce, a.tpm, gatedPCRs, a.akPEM)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, host.submit(t, client, evidence))
	}

	t.Run("no evidence is refused", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, host.status(t, a))
		require.Equal(t, qrdbsdk.PeerAttestationFailureAbsence, host.verdict(t, a).Failure)
	})

	t.Run("a valid quote with channel binding is admitted", func(t *testing.T) {
		attest(t)
		verdict := host.verdict(t, a)
		require.True(t, verdict.Passed, "reason: %s", verdict.Reason)
		require.Equal(t, http.StatusOK, host.status(t, a))
	})

	t.Run("a forged quote is refused", func(t *testing.T) {
		client := a.session(p.pool)
		defer client.CloseIdleConnections()
		challenge, state := host.challenge(t, client)
		evidence, err := peergate.QuoteEvidence(state, challenge.Nonce, a.tpm, gatedPCRs, a.akPEM)
		require.NoError(t, err)
		evidence.Signature[len(evidence.Signature)/2] ^= 0xff
		require.Equal(t, http.StatusNoContent, host.submit(t, client, evidence), "the collector stores; the verifier judges")

		require.Equal(t, qrdbsdk.PeerAttestationFailureCryptographic, host.verdict(t, a).Failure)
		require.Equal(t, http.StatusForbidden, host.status(t, a))
	})

	t.Run("a quote bound to another connection is refused", func(t *testing.T) {
		attest(t)
		require.Equal(t, http.StatusOK, host.status(t, a), "recovered after an honest round")

		// The quote is bound to a different TLS session than the one it is
		// submitted on: a relayed quote. Only one challenge is issued, so the
		// submission answers it and the binding is all that is wrong.
		other := a.session(p.pool)
		defer other.CloseIdleConnections()
		otherState := host.connection(t, other)
		submitting := a.session(p.pool)
		defer submitting.CloseIdleConnections()
		challenge, _ := host.challenge(t, submitting)
		evidence, err := peergate.QuoteEvidence(otherState, challenge.Nonce, a.tpm, gatedPCRs, a.akPEM)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, host.submit(t, submitting, evidence))

		verdict := host.verdict(t, a)
		require.Equal(t, qrdbsdk.PeerAttestationFailureCryptographic, verdict.Failure, "reason: %s", verdict.Reason)
		require.Equal(t, http.StatusForbidden, host.status(t, a))
	})

	t.Run("a replayed nonce is refused at collection", func(t *testing.T) {
		client := a.session(p.pool)
		defer client.CloseIdleConnections()
		challenge, state := host.challenge(t, client)
		evidence, err := peergate.QuoteEvidence(state, challenge.Nonce, a.tpm, gatedPCRs, a.akPEM)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, host.submit(t, client, evidence))
		require.Equal(t, http.StatusForbidden, host.submit(t, client, evidence), "a nonce answers once")
	})

	t.Run("stale evidence is refused", func(t *testing.T) {
		attest(t)
		require.Equal(t, http.StatusOK, host.status(t, a))

		// Re-store the same, valid evidence as collected two hours ago: the
		// gate's own one-minute bound refuses it whatever the verifier says.
		thumbprint := qrdbsdk.ComputeSPKIThumbprint(a.cert.Leaf)
		record, ok, err := host.store.Get(context.Background(), thumbprint)
		require.NoError(t, err)
		require.True(t, ok)
		record.Evidence.CollectedAt = time.Now().Add(-2 * time.Hour)
		require.NoError(t, host.store.Put(context.Background(), record))

		require.True(t, host.verdict(t, a).Passed, "the quote itself is still valid")
		require.Equal(t, http.StatusForbidden, host.status(t, a))
	})

	t.Run("a peer without a client certificate never reaches the collector", func(t *testing.T) {
		anonymous := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: p.pool, MinVersion: tls.VersionTLS13}}}
		defer anonymous.CloseIdleConnections()
		_, err := anonymous.Post(host.collect+"/challenge", "application/json", nil)
		require.ErrorContains(t, err, "certificate required")
	})
}
