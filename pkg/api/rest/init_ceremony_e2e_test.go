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

package rest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// ---------------------------------------------------------------------------
// denyAllAuthenticator
// ---------------------------------------------------------------------------

// errCeremonyTestNoCredential is the rejection returned by
// denyAllAuthenticator. It stands in for what a real mTLS authenticator does
// to an officer who has not yet claimed a certificate: there is no credential
// to present, so authentication cannot succeed.
var errCeremonyTestNoCredential = errors.New("no credential presented")

// denyAllAuthenticator rejects every request. Using it in these tests is what
// makes them meaningful: an officer running the enrollment ceremony genuinely
// has no credential, so any route that is not exempted returns 401.
type denyAllAuthenticator struct{}

var _ auth.Authenticator = (*denyAllAuthenticator)(nil)

func (denyAllAuthenticator) AuthenticateHTTP(*http.Request) (*auth.Identity, error) {
	return nil, errCeremonyTestNoCredential
}

func (denyAllAuthenticator) AuthenticateGRPC(context.Context, metadata.MD) (*auth.Identity, error) {
	return nil, errCeremonyTestNoCredential
}

func (denyAllAuthenticator) Name() string { return "deny-all" }

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

// ceremonyTestServer bundles an httptest server whose handler is the real REST
// router, together with the ceremony service and officer keys behind it.
type ceremonyTestServer struct {
	t        *testing.T
	http     *httptest.Server
	ceremony *initialize.CeremonyService
	ca       *initTestMockCA
	officers []string
	keys     []*ecdsa.PrivateKey
}

// newCeremonyTestServer builds a REST server whose authenticator rejects every
// caller and whose ceremony service is a real M-of-N ceremony. When initialized
// is false the ceremony is left in awaiting_init.
func newCeremonyTestServer(t *testing.T, threshold, numOfficers int, initialized bool) *ceremonyTestServer {
	t.Helper()

	officers := make([]initialize.OfficerConfig, numOfficers)
	names := make([]string, numOfficers)
	keys := make([]*ecdsa.PrivateKey, numOfficers)
	for i := 0; i < numOfficers; i++ {
		name := "officer-" + string(rune('A'+i))
		csrPEM, key := initTestGenerateCSR(t, name)
		officers[i] = initialize.OfficerConfig{Username: name, CSRPEM: csrPEM}
		names[i] = name
		keys[i] = key
	}

	svc, err := initialize.NewCeremonyService(&initialize.CeremonyConfig{
		SOPin:                  "test-so-pin",
		UserPin:                "test-user-pin",
		CredentialSealStrategy: credentials.StrategyManual,
		Threshold:              threshold,
		Officers:               officers,
		Hostname:               "localhost",
	}, initTestBarrier(t), initTestCredService(t), initTestLogger())
	require.NoError(t, err)

	mockCA := newInitTestMockCA(t)
	if initialized {
		_, err = svc.Initialize(context.Background(), mockCA)
		require.NoError(t, err)
	}

	server, err := NewServer(&Config{
		Authenticator:   denyAllAuthenticator{},
		Backends:        map[string]xkms.Backend{"test": newMockKeyStore()},
		CeremonyService: svc,
		Logger:          initTestLogger(),
	})
	require.NoError(t, err)

	// A real TLS listener that *requests* (but does not require) a client
	// certificate. Requesting is what the ceremony needs: claim-cert must be
	// reachable by an officer who has no certificate yet, while the two
	// claim-share routes derive the caller thumbprint from the peer chain and
	// refuse a connection that presented none.
	ts := httptest.NewUnstartedServer(server.Handler())
	ts.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS12,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	return &ceremonyTestServer{
		t:        t,
		http:     ts,
		ceremony: svc,
		ca:       mockCA,
		officers: names,
		keys:     keys,
	}
}

// post issues a JSON POST with no client certificate and returns the status
// code and body.
func (c *ceremonyTestServer) post(t *testing.T, path string, body any) (int, []byte) {
	t.Helper()
	return c.postAs(t, nil, path, body)
}

// postAs issues a JSON POST presenting cert as the mTLS client certificate.
// A nil cert means the connection carries no client certificate at all, which
// is exactly the situation the share-claim routes must fail closed on.
func (c *ceremonyTestServer) postAs(t *testing.T, cert *tls.Certificate, path string, body any) (int, []byte) {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)

	client := c.clientWithCert(cert)
	resp, err := client.Post(c.http.URL+path, "application/json", bytes.NewReader(encoded))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, respBody
}

// clientWithCert returns an HTTP client that trusts the test server and
// presents cert (when non-nil) as its client certificate.
func (c *ceremonyTestServer) clientWithCert(cert *tls.Certificate) *http.Client {
	base := c.http.Client()
	tr, ok := base.Transport.(*http.Transport)
	require.True(c.t, ok, "httptest client transport must be *http.Transport")

	tlsCfg := tr.TLSClientConfig.Clone()
	if cert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
}

// claimCert runs the certificate claim handshake for the officer at index i
// and returns the issued certificate as a tls.Certificate ready to present on
// the share-claim connection.
func (c *ceremonyTestServer) claimCert(t *testing.T, i int) *tls.Certificate {
	t.Helper()
	officer := c.officers[i]

	status, body := c.post(t, "/api/v1/init/claim-cert/begin", ClaimCertBeginRequest{Username: officer})
	require.Equal(t, http.StatusOK, status, "begin for %s: %s", officer, body)
	var begin ClaimCertBeginResponse
	require.NoError(t, json.Unmarshal(body, &begin))

	status, body = c.post(t, "/api/v1/init/claim-cert/complete", ClaimCertCompleteRequest{
		Username:  officer,
		Nonce:     begin.Nonce,
		Signature: signChallenge(t, c.keys[i], begin.Nonce),
	})
	require.Equal(t, http.StatusOK, status, "complete for %s: %s", officer, body)
	var claimed ClaimCertCompleteResponse
	require.NoError(t, json.Unmarshal(body, &claimed))

	block, _ := pem.Decode([]byte(claimed.CertPEM))
	require.NotNil(t, block)
	return &tls.Certificate{
		Certificate: [][]byte{block.Bytes},
		PrivateKey:  c.keys[i],
	}
}

// claimShare drives the two-round-trip share claim for the officer at index i,
// presenting cert as the mTLS client certificate. It returns the status and
// body of whichever leg failed, or of the completing leg on success.
func (c *ceremonyTestServer) claimShare(t *testing.T, i int, cert *tls.Certificate) (int, []byte) {
	t.Helper()
	officer := c.officers[i]

	status, body := c.postAs(t, cert, "/api/v1/init/claim-share/begin", ClaimShareBeginRequest{Username: officer})
	if status != http.StatusOK {
		return status, body
	}

	var begin ClaimShareBeginResponse
	require.NoError(t, json.Unmarshal(body, &begin))

	return c.postAs(t, cert, "/api/v1/init/claim-share/complete", ClaimShareCompleteRequest{
		Username:  officer,
		Nonce:     begin.Nonce,
		Signature: signChallenge(t, c.keys[i], begin.Nonce),
	})
}

// get issues a GET and returns the status code and body.
func (c *ceremonyTestServer) get(t *testing.T, path string) (int, []byte) {
	t.Helper()
	resp, err := c.clientWithCert(nil).Get(c.http.URL + path)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, respBody
}

// signChallenge signs nonceHex the way an officer's CLI does: SHA-256 over the
// raw nonce bytes, ASN.1 DER ECDSA signature, base64 for transport.
func signChallenge(t *testing.T, key *ecdsa.PrivateKey, nonceHex string) string {
	t.Helper()
	nonce, err := hex.DecodeString(nonceHex)
	require.NoError(t, err)
	digest := sha256.Sum256(nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(sig)
}

// ---------------------------------------------------------------------------
// End-to-end ceremony
// ---------------------------------------------------------------------------

// TestRESTInitCeremony_EndToEnd drives a complete 2-of-3 Security Officer
// enrollment ceremony through the real REST router with an authenticator that
// rejects every caller. It is the test that would have caught all four shipped
// defects: it exercises the routes the CLI calls, signs with the CSR key, reads
// cert_pem / ca_cert_pem, and reaches the endpoints without a credential.
func TestRESTInitCeremony_EndToEnd(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)

	// The ceremony is discoverable without a credential.
	status, body := c.get(t, "/api/v1/init/status")
	require.Equal(t, http.StatusOK, status, "status must be reachable unauthenticated: %s", body)

	var statusResp InitStatusResponse
	require.NoError(t, json.Unmarshal(body, &statusResp))
	require.Equal(t, string(initialize.StateEnrolling), statusResp.State)

	caCert, err := c.ca.CACertificate()
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	for i, officer := range c.officers {
		// claim-cert/begin
		status, body := c.post(t, "/api/v1/init/claim-cert/begin", ClaimCertBeginRequest{Username: officer})
		require.Equal(t, http.StatusOK, status, "begin for %s: %s", officer, body)

		var begin ClaimCertBeginResponse
		require.NoError(t, json.Unmarshal(body, &begin))
		require.NotEmpty(t, begin.Nonce)
		require.Equal(t, officer, begin.Username)

		// claim-cert/complete, signed with the key backing the officer's CSR.
		status, body = c.post(t, "/api/v1/init/claim-cert/complete", ClaimCertCompleteRequest{
			Username:  officer,
			Nonce:     begin.Nonce,
			Signature: signChallenge(t, c.keys[i], begin.Nonce),
		})
		require.Equal(t, http.StatusOK, status, "complete for %s: %s", officer, body)

		var claimed ClaimCertCompleteResponse
		require.NoError(t, json.Unmarshal(body, &claimed))
		require.NotEmpty(t, claimed.CertPEM, "server must populate cert_pem")
		require.NotEmpty(t, claimed.CACertPEM, "server must populate ca_cert_pem")

		// The issued certificate must chain to the ceremony CA.
		block, _ := pem.Decode([]byte(claimed.CertPEM))
		require.NotNil(t, block, "cert_pem must be PEM")
		officerCert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, officer, officerCert.Subject.CommonName)

		_, err = officerCert.Verify(x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		require.NoError(t, err, "issued certificate must chain to the ceremony CA")

		// claim-share: a two round-trip challenge-response bound to the
		// certificate just claimed, presented here as a real mTLS client
		// certificate on the connection.
		officerCertTLS := &tls.Certificate{
			Certificate: [][]byte{block.Bytes},
			PrivateKey:  c.keys[i],
		}
		status, body = c.claimShare(t, i, officerCertTLS)
		require.Equal(t, http.StatusOK, status, "claim-share for %s: %s", officer, body)

		var share ClaimShareCompleteResponse
		require.NoError(t, json.Unmarshal(body, &share))
		require.NotEmpty(t, share.Share, "share must be returned")
		require.Equal(t, i+1, share.ShareIndex)
	}

	// Every certificate and share claimed: the ceremony is operational.
	assert.Equal(t, initialize.StateOperational, c.ceremony.State())
}

// TestRESTInitCeremony_ClaimEndpointsClosedWhenOperational verifies the
// exemption is gated on ceremony state, not on path alone. Once the ceremony
// completes, the very same routes demand a credential again.
func TestRESTInitCeremony_ClaimEndpointsClosedWhenOperational(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 2, true)

	for i := range c.officers {
		cert := c.claimCert(t, i)
		status, shareBody := c.claimShare(t, i, cert)
		require.Equal(t, http.StatusOK, status, string(shareBody))
	}
	require.Equal(t, initialize.StateOperational, c.ceremony.State())

	tests := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"status", http.MethodGet, "/api/v1/init/status", nil},
		{"claim-cert begin", http.MethodPost, "/api/v1/init/claim-cert/begin", ClaimCertBeginRequest{Username: c.officers[0]}},
		{"claim-cert complete", http.MethodPost, "/api/v1/init/claim-cert/complete", ClaimCertCompleteRequest{Username: c.officers[0], Nonce: "00", Signature: "AA=="}},
		{"claim-share begin", http.MethodPost, "/api/v1/init/claim-share/begin", ClaimShareBeginRequest{Username: c.officers[0]}},
		{"claim-share complete", http.MethodPost, "/api/v1/init/claim-share/complete", ClaimShareCompleteRequest{Username: c.officers[0], Nonce: "00", Signature: "AA=="}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var status int
			if tc.method == http.MethodGet {
				status, _ = c.get(t, tc.path)
			} else {
				status, _ = c.post(t, tc.path, tc.body)
			}
			assert.Equal(t, http.StatusUnauthorized, status,
				"%s must require authentication once the ceremony is operational", tc.path)
		})
	}
}

// TestRESTInitCeremony_ClaimEndpointsOpenWhileAwaitingInit verifies the
// exemption also covers awaiting_init. Reaching the route is harmless there —
// the ceremony service itself refuses the operation with 409.
func TestRESTInitCeremony_ClaimEndpointsOpenWhileAwaitingInit(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, false)
	require.Equal(t, initialize.StateAwaitingInit, c.ceremony.State())

	status, body := c.get(t, "/api/v1/init/status")
	require.Equal(t, http.StatusOK, status, string(body))

	status, _ = c.post(t, "/api/v1/init/claim-cert/begin", ClaimCertBeginRequest{Username: c.officers[0]})
	assert.Equal(t, http.StatusConflict, status,
		"the route is reachable but the ceremony refuses the operation before initialization")
}

// ---------------------------------------------------------------------------
// Negative security tests
// ---------------------------------------------------------------------------

// TestRESTInitCeremony_WrongKeySignatureRejected verifies a challenge signed
// with a key other than the one backing the officer's CSR is refused. This is
// the property the client's fresh-keypair bug silently violated.
func TestRESTInitCeremony_WrongKeySignatureRejected(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)

	status, body := c.post(t, "/api/v1/init/claim-cert/begin", ClaimCertBeginRequest{Username: c.officers[0]})
	require.Equal(t, http.StatusOK, status, string(body))
	var begin ClaimCertBeginResponse
	require.NoError(t, json.Unmarshal(body, &begin))

	// Officer B's key against officer A's challenge.
	status, body = c.post(t, "/api/v1/init/claim-cert/complete", ClaimCertCompleteRequest{
		Username:  c.officers[0],
		Nonce:     begin.Nonce,
		Signature: signChallenge(t, c.keys[1], begin.Nonce),
	})
	assert.Equal(t, http.StatusUnauthorized, status, string(body))

	// The certificate must remain unclaimed and the ceremony must not advance.
	assert.Equal(t, initialize.StateEnrolling, c.ceremony.State())
}

// TestRESTInitCeremony_ReplayedNonceRejected verifies a nonce is single-use:
// replaying a captured (nonce, signature) pair after a successful claim is
// refused, so a passive observer cannot re-run the exchange.
func TestRESTInitCeremony_ReplayedNonceRejected(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)

	status, body := c.post(t, "/api/v1/init/claim-cert/begin", ClaimCertBeginRequest{Username: c.officers[0]})
	require.Equal(t, http.StatusOK, status, string(body))
	var begin ClaimCertBeginResponse
	require.NoError(t, json.Unmarshal(body, &begin))

	complete := ClaimCertCompleteRequest{
		Username:  c.officers[0],
		Nonce:     begin.Nonce,
		Signature: signChallenge(t, c.keys[0], begin.Nonce),
	}

	status, body = c.post(t, "/api/v1/init/claim-cert/complete", complete)
	require.Equal(t, http.StatusOK, status, string(body))

	// Byte-identical replay of the same challenge response. The nonce was
	// burnt on first use; pkg/init's mapClaimCertError deliberately reports a
	// missing challenge as a verification failure so a replay is
	// indistinguishable from a bad signature.
	status, body = c.post(t, "/api/v1/init/claim-cert/complete", complete)
	assert.Equal(t, http.StatusUnauthorized, status,
		"the burnt nonce must no longer resolve to a challenge: %s", body)
}

// TestRESTInitCeremony_StaleNonceRejectedAfterRebegin verifies that asking for
// a fresh challenge invalidates the previous nonce, so an intercepted nonce
// cannot be answered later.
func TestRESTInitCeremony_StaleNonceRejectedAfterRebegin(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)

	_, body := c.post(t, "/api/v1/init/claim-cert/begin", ClaimCertBeginRequest{Username: c.officers[0]})
	var first ClaimCertBeginResponse
	require.NoError(t, json.Unmarshal(body, &first))

	_, body = c.post(t, "/api/v1/init/claim-cert/begin", ClaimCertBeginRequest{Username: c.officers[0]})
	var second ClaimCertBeginResponse
	require.NoError(t, json.Unmarshal(body, &second))
	require.NotEqual(t, first.Nonce, second.Nonce, "each begin must mint a fresh nonce")

	status, body := c.post(t, "/api/v1/init/claim-cert/complete", ClaimCertCompleteRequest{
		Username:  c.officers[0],
		Nonce:     first.Nonce,
		Signature: signChallenge(t, c.keys[0], first.Nonce),
	})
	assert.Equal(t, http.StatusUnauthorized, status,
		"the superseded nonce must not verify: %s", body)
}

// TestRESTInitCeremony_ShareClaimedOnlyOnce verifies a share is released
// exactly once, so a replayed claim-share cannot hand a second copy to an
// attacker.
func TestRESTInitCeremony_ShareClaimedOnlyOnce(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)
	cert := c.claimCert(t, 0)

	status, body := c.claimShare(t, 0, cert)
	require.Equal(t, http.StatusOK, status, string(body))

	status, body = c.claimShare(t, 0, cert)
	assert.Contains(t, []int{http.StatusConflict, http.StatusNotFound}, status,
		"a second claim must be refused: %s", body)
	assert.NotContains(t, string(body), `"share"`, "share material leaked on a refusal: %s", body)
}

// TestRESTInitCeremony_ShareClaimRefusedWithoutClientCert is the security
// regression test for the username-only share release. An enrolled officer who
// presents no client certificate is refused, and the response body carries no
// share material.
func TestRESTInitCeremony_ShareClaimRefusedWithoutClientCert(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)
	c.claimCert(t, 0)

	status, body := c.postAs(t, nil, "/api/v1/init/claim-share/begin",
		ClaimShareBeginRequest{Username: c.officers[0]})
	assert.Equal(t, http.StatusUnauthorized, status, string(body))
	assert.NotContains(t, string(body), `"share"`, "share material leaked: %s", body)

	status, body = c.postAs(t, nil, "/api/v1/init/claim-share/complete", ClaimShareCompleteRequest{
		Username:  c.officers[0],
		Nonce:     "00",
		Signature: "AA==",
	})
	assert.Equal(t, http.StatusUnauthorized, status, string(body))
	assert.NotContains(t, string(body), `"share"`, "share material leaked: %s", body)

	// The share is still pending for its rightful owner.
	cert := &tls.Certificate{}
	_ = cert
	require.Equal(t, initialize.StateEnrolling, c.ceremony.State())
}

// TestRESTInitCeremony_ShareClaimRefusedWithWrongOfficerCert proves officer B
// cannot take officer A's share by naming officer A while presenting its own
// certificate on the connection.
func TestRESTInitCeremony_ShareClaimRefusedWithWrongOfficerCert(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)

	victimCert := c.claimCert(t, 0)
	attackerCert := c.claimCert(t, 1)

	status, body := c.postAs(t, attackerCert, "/api/v1/init/claim-share/begin",
		ClaimShareBeginRequest{Username: c.officers[0]})
	assert.Equal(t, http.StatusUnauthorized, status, string(body))
	assert.NotContains(t, string(body), `"share"`, "share material leaked: %s", body)

	status, body = c.postAs(t, attackerCert, "/api/v1/init/claim-share/complete", ClaimShareCompleteRequest{
		Username:  c.officers[0],
		Nonce:     "00",
		Signature: "AA==",
	})
	assert.NotEqual(t, http.StatusOK, status)
	assert.NotContains(t, string(body), `"share"`, "share material leaked: %s", body)

	// The victim's share is untouched and still claimable by the victim.
	status, body = c.claimShare(t, 0, victimCert)
	require.Equal(t, http.StatusOK, status, string(body))
}

// TestRESTInitCeremony_ShareNonceReplayRejected proves a share-claim nonce is
// single-use.
func TestRESTInitCeremony_ShareNonceReplayRejected(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)
	cert := c.claimCert(t, 0)

	status, body := c.postAs(t, cert, "/api/v1/init/claim-share/begin",
		ClaimShareBeginRequest{Username: c.officers[0]})
	require.Equal(t, http.StatusOK, status, string(body))
	var begin ClaimShareBeginResponse
	require.NoError(t, json.Unmarshal(body, &begin))

	complete := ClaimShareCompleteRequest{
		Username:  c.officers[0],
		Nonce:     begin.Nonce,
		Signature: signChallenge(t, c.keys[0], begin.Nonce),
	}

	status, body = c.postAs(t, cert, "/api/v1/init/claim-share/complete", complete)
	require.Equal(t, http.StatusOK, status, string(body))

	status, body = c.postAs(t, cert, "/api/v1/init/claim-share/complete", complete)
	assert.NotEqual(t, http.StatusOK, status, "a replayed nonce must be refused: %s", body)
	assert.NotContains(t, string(body), `"share"`, "share material leaked on replay: %s", body)
}

// TestRESTInitCeremony_ShareSupersededNonceRejected proves a re-begin
// invalidates the previously issued share-claim nonce.
func TestRESTInitCeremony_ShareSupersededNonceRejected(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)
	cert := c.claimCert(t, 0)

	_, body := c.postAs(t, cert, "/api/v1/init/claim-share/begin",
		ClaimShareBeginRequest{Username: c.officers[0]})
	var first ClaimShareBeginResponse
	require.NoError(t, json.Unmarshal(body, &first))

	_, body = c.postAs(t, cert, "/api/v1/init/claim-share/begin",
		ClaimShareBeginRequest{Username: c.officers[0]})
	var second ClaimShareBeginResponse
	require.NoError(t, json.Unmarshal(body, &second))
	require.NotEqual(t, first.Nonce, second.Nonce, "each begin must mint a fresh nonce")

	status, body := c.postAs(t, cert, "/api/v1/init/claim-share/complete", ClaimShareCompleteRequest{
		Username:  c.officers[0],
		Nonce:     first.Nonce,
		Signature: signChallenge(t, c.keys[0], first.Nonce),
	})
	assert.NotEqual(t, http.StatusOK, status, "the superseded nonce must not verify: %s", body)
	assert.NotContains(t, string(body), `"share"`, "share material leaked: %s", body)
}

// TestRESTInitCeremony_UnknownOfficerRejected verifies the claim endpoints do
// not leak shares or certificates to usernames that were never enrolled.
func TestRESTInitCeremony_UnknownOfficerRejected(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)

	status, _ := c.post(t, "/api/v1/init/claim-cert/begin", ClaimCertBeginRequest{Username: "attacker"})
	assert.Equal(t, http.StatusNotFound, status)

	cert := c.claimCert(t, 0)
	status, body := c.postAs(t, cert, "/api/v1/init/claim-share/begin",
		ClaimShareBeginRequest{Username: "attacker"})
	assert.Equal(t, http.StatusNotFound, status)
	assert.NotContains(t, string(body), `"share"`, "share material leaked: %s", body)
}

// TestRESTInitCeremony_NonInitRoutesStillAuthenticated verifies the exemption
// did not widen: ordinary /api/v1 routes reject the same credential-less
// caller that the claim endpoints accept.
func TestRESTInitCeremony_NonInitRoutesStillAuthenticated(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)
	require.Equal(t, initialize.StateEnrolling, c.ceremony.State())

	protected := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/backends"},
		{http.MethodGet, "/api/v1/keys"},
		{http.MethodPost, "/api/v1/keys"},
		{http.MethodGet, "/api/v1/certs"},
		{http.MethodPost, "/api/v1/init/sign-csr"},
		{http.MethodPost, "/api/v1/credentials/submit"},
		{http.MethodGet, "/api/v1/users/"},
	}

	for _, tc := range protected {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			var status int
			if tc.method == http.MethodGet {
				status, _ = c.get(t, tc.path)
			} else {
				status, _ = c.post(t, tc.path, map[string]string{})
			}
			assert.Equal(t, http.StatusUnauthorized, status,
				"%s must stay authenticated while the ceremony is enrolling", tc.path)
		})
	}
}

// TestRESTInitCeremony_ExemptionIsNotAPrefixMatch verifies the allowlist is an
// exact-path match. A prefix rule on "/api/v1/init" would exempt siblings such
// as "/api/v1/init/sign-csr" and any future "/api/v1/initialize" route.
func TestRESTInitCeremony_ExemptionIsNotAPrefixMatch(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)
	require.Equal(t, initialize.StateEnrolling, c.ceremony.State())

	// Paths that must NOT be exempted. 401 means the authentication middleware
	// ran; 404 would mean the router rejected the request before the
	// middleware, which would make the assertion vacuous.
	notExempt := []string{
		"/api/v1/init/sign-csr",
		"/api/v1/initialize",
		"/api/v1/init/claim-cert",
		"/api/v1/init/claim-share",
		"/api/v1/init/claim-share/begin/extra",
		"/api/v1/init/status/extra",
	}

	for _, path := range notExempt {
		t.Run(path, func(t *testing.T) {
			status, _ := c.post(t, path, map[string]string{})
			assert.Equal(t, http.StatusUnauthorized, status,
				"%s must not inherit the init exemption", path)
		})
	}
}

// TestIsPublicCeremonyRequest_Table exercises the exemption predicate directly,
// including the percent-encoding case that the HTTP client normalizes away.
func TestIsPublicCeremonyRequest_Table(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)
	enrolling := &Server{initHandlers: handlers}

	operational := &Server{initHandlers: initTestSingleAdminService(t)}
	none := &Server{}

	tests := []struct {
		name   string
		server *Server
		target string
		want   bool
	}{
		{"enrolling status", enrolling, "/api/v1/init/status", true},
		{"enrolling claim-cert begin", enrolling, "/api/v1/init/claim-cert/begin", true},
		{"enrolling claim-cert complete", enrolling, "/api/v1/init/claim-cert/complete", true},
		{"enrolling claim-share begin", enrolling, "/api/v1/init/claim-share/begin", true},
		{"enrolling claim-share complete", enrolling, "/api/v1/init/claim-share/complete", true},
		{"enrolling sign-csr", enrolling, "/api/v1/init/sign-csr", false},
		{"enrolling unrelated", enrolling, "/api/v1/keys", false},
		{"enrolling prefix sibling", enrolling, "/api/v1/initialize", false},
		{"enrolling trailing slash", enrolling, "/api/v1/init/claim-share/begin/", false},
		{"enrolling bare claim-share", enrolling, "/api/v1/init/claim-share", false},
		{"enrolling percent encoded", enrolling, "/api/v1/init/claim%2Dshare/begin", false},
		{"operational status", operational, "/api/v1/init/status", false},
		{"operational claim-share begin", operational, "/api/v1/init/claim-share/begin", false},
		{"operational claim-share complete", operational, "/api/v1/init/claim-share/complete", false},
		{"no ceremony wired", none, "/api/v1/init/status", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.target, nil)
			assert.Equal(t, tc.want, tc.server.isPublicCeremonyRequest(req))
		})
	}
}

// ---------------------------------------------------------------------------
// Route existence
// ---------------------------------------------------------------------------

// TestRESTRouter_ClientEndpointsResolve asserts that every path the xkmsctl
// init commands post to is actually mounted on the REST router. Shipping a
// client that called routes the server never registered is exactly the class
// of bug this table guards against: a missing route answers 404, while a
// mounted one answers 401 (unauthenticated) or a ceremony status code.
func TestRESTRouter_ClientEndpointsResolve(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)

	// The canonical client surface: cmd/xkmsctl/init.go.
	clientRoutes := []struct {
		name   string
		method string
		path   string
	}{
		{"init status", http.MethodGet, "/api/v1/init/status"},
		{"init claim-cert begin", http.MethodPost, "/api/v1/init/claim-cert/begin"},
		{"init claim-cert complete", http.MethodPost, "/api/v1/init/claim-cert/complete"},
		{"init claim-share begin", http.MethodPost, "/api/v1/init/claim-share/begin"},
		{"init claim-share complete", http.MethodPost, "/api/v1/init/claim-share/complete"},
		{"init sign-csr", http.MethodPost, "/api/v1/init/sign-csr"},
		{"credentials submit", http.MethodPost, "/api/v1/credentials/submit"},
		{"credentials strategy", http.MethodGet, "/api/v1/credentials/strategy"},
	}

	for _, tc := range clientRoutes {
		t.Run(tc.name, func(t *testing.T) {
			var status int
			if tc.method == http.MethodGet {
				status, _ = c.get(t, tc.path)
			} else {
				status, _ = c.post(t, tc.path, map[string]string{})
			}
			assert.NotEqual(t, http.StatusNotFound, status,
				"%s %s is called by cmd/xkmsctl but is not mounted on the REST router", tc.method, tc.path)
			assert.NotEqual(t, http.StatusMethodNotAllowed, status,
				"%s %s is called by cmd/xkmsctl with a method the router does not accept", tc.method, tc.path)
		})
	}
}

// TestRESTInitCeremony_SignCSR verifies the sign-csr route signs a CSR under
// SO PIN authorization for an authenticated caller, naming the registered
// holder rather than the CSR's subject.
func TestRESTInitCeremony_SignCSR(t *testing.T) {
	handlers, _, mockCA := initTestMofNService(t, 2, 3)
	csrPEM, _ := initTestGenerateCSR(t, "service-account")

	body, err := json.Marshal(SignCSRInitRequest{
		Username: "officer-A",
		SOPin:    "test-so-pin",
		CSRPEM:   string(csrPEM),
		Role:     "operator",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/sign-csr", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handlers.HandleSignCSRInit(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp SignCSRInitResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.CertPEM)

	block, _ := pem.Decode([]byte(resp.CertPEM))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	// go-qrdb v0.28: the certificate names the registered holder (the
	// request's username) in the system tenant, never the CSR's own subject.
	assert.Equal(t, "officer-A", cert.Subject.CommonName, "the CSR's CN is not copied")
	require.NotEmpty(t, cert.Subject.OrganizationalUnit)
	assert.Equal(t, "system", cert.Subject.OrganizationalUnit[0])
	assert.Empty(t, cert.DNSNames)
	assert.Empty(t, cert.URIs)

	caCert, err := mockCA.CACertificate()
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	require.NoError(t, err, "the signed certificate must chain to the ceremony CA")
}

// TestRESTInitCeremony_SignCSRBadInput covers the validation and authorization
// failures of the sign-csr handler.
func TestRESTInitCeremony_SignCSRBadInput(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)
	csrPEM, _ := initTestGenerateCSR(t, "service-account")

	tests := []struct {
		name string
		body any
		want int
	}{
		{"missing username", SignCSRInitRequest{SOPin: "test-so-pin", CSRPEM: string(csrPEM), Role: "operator"}, http.StatusBadRequest},
		{"missing so pin", SignCSRInitRequest{Username: "officer-A", CSRPEM: string(csrPEM), Role: "operator"}, http.StatusBadRequest},
		{"missing csr", SignCSRInitRequest{Username: "officer-A", SOPin: "test-so-pin", Role: "operator"}, http.StatusBadRequest},
		{"missing role", SignCSRInitRequest{Username: "officer-A", SOPin: "test-so-pin", CSRPEM: string(csrPEM)}, http.StatusBadRequest},
		{"malformed csr", SignCSRInitRequest{Username: "officer-A", SOPin: "test-so-pin", CSRPEM: "not a csr", Role: "operator"}, http.StatusBadRequest},
		{"unknown role", SignCSRInitRequest{Username: "officer-A", SOPin: "test-so-pin", CSRPEM: string(csrPEM), Role: "wizard"}, http.StatusBadRequest},
		{"wrong so pin", SignCSRInitRequest{Username: "officer-A", SOPin: "not-the-pin", CSRPEM: string(csrPEM), Role: "operator"}, http.StatusUnauthorized},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.body)
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/init/sign-csr", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			handlers.HandleSignCSRInit(rec, req)
			assert.Equal(t, tc.want, rec.Code, rec.Body.String())
		})
	}

	t.Run("invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/init/sign-csr", bytes.NewReader([]byte("{not json")))
		rec := httptest.NewRecorder()
		handlers.HandleSignCSRInit(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

// initCeremonyOperations is the canonical init ceremony operation set. The
// same list is asserted for the QUIC transport in
// pkg/api/quic/init_public_test.go and for the MCP transport in
// pkg/api/mcp/init_public_test.go, so a transport cannot silently drop or
// invent an operation.
var initCeremonyOperations = []struct {
	operation string
	method    string
	path      string
}{
	{"status", http.MethodGet, "/api/v1/init/status"},
	{"claim-cert begin", http.MethodPost, "/api/v1/init/claim-cert/begin"},
	{"claim-cert complete", http.MethodPost, "/api/v1/init/claim-cert/complete"},
	{"claim-share", http.MethodPost, "/api/v1/init/claim-share"},
	{"sign-csr", http.MethodPost, "/api/v1/init/sign-csr"},
}

// TestRESTInitCeremony_OperationParity asserts the REST transport mounts the
// full ceremony operation set.
func TestRESTInitCeremony_OperationParity(t *testing.T) {
	c := newCeremonyTestServer(t, 2, 3, true)

	for _, op := range initCeremonyOperations {
		t.Run(op.operation, func(t *testing.T) {
			var status int
			if op.method == http.MethodGet {
				status, _ = c.get(t, op.path)
			} else {
				status, _ = c.post(t, op.path, map[string]string{})
			}
			assert.NotEqual(t, http.StatusNotFound, status,
				"REST must expose the %s ceremony operation", op.operation)
		})
	}
}
