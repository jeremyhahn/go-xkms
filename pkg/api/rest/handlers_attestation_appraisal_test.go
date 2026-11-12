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

package rest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/embedded"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// errAppraisalStatus carries the HTTP status of a refused appraisal call.
type errAppraisalStatus struct{ code int }

func (e *errAppraisalStatus) Error() string { return fmt.Sprintf("status %d", e.code) }

// appraisalResources are the resources the appraisal routes gate on.
var appraisalResources = map[string]bool{
	auth.ResourceAttestationEndorsements:    true,
	auth.ResourceAttestationReferenceValues: true,
	auth.ResourceAttestationVerifier:        true,
}

// appraisalRouter serves the appraisal routes over svc as the caller
// identity (tenant acme unless identity says otherwise).
func appraisalRouter(svc *xkms.XKMSService, identity *auth.Identity) http.Handler {
	server := &Server{attestationAppraisalHandlers: NewAttestationAppraisalHandlers(svc)}
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(auth.WithIdentity(req.Context(), identity)))
		})
	})
	for _, spec := range Routes() {
		if appraisalResources[spec.Resource] {
			r.Method(spec.Method, spec.Pattern, spec.Handler(server))
		}
	}
	return r
}

// appraisalClient is the REST client of the appraisal routes over router.
func appraisalClient(t *testing.T, router http.Handler) wire.AttestationAppraisalClient {
	return wire.AttestationAppraisalClient{Do: func(_ context.Context, method, path string, body any) ([]byte, error) {
		var reader io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			reader = bytes.NewReader(raw)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, path, reader))
		if w.Code >= 300 {
			return nil, &errAppraisalStatus{code: w.Code}
		}
		return w.Body.Bytes(), nil
	}}
}

// statusOf returns the HTTP status err carries, or 0.
func statusOf(err error) int {
	if err == nil {
		return 0
	}
	var s *errAppraisalStatus
	if errors.As(err, &s) {
		return s.code
	}
	return -1
}

func acmeIdentity() *auth.Identity {
	return &auth.Identity{Subject: "verifier-admin", TenantID: "acme", Roles: []string{"admin"}}
}

// testAKRootPEM returns a self-signed CA certificate for an AK-root
// endorsement.
func testAKRootPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test AK root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestAttestationAppraisalREST_RouteTable(t *testing.T) {
	want := map[string][2]string{
		"PUT " + wire.AttestationEndorsementsPath:            {auth.ResourceAttestationEndorsements, auth.ActionCreate},
		"GET " + wire.AttestationEndorsementsPath:            {auth.ResourceAttestationEndorsements, auth.ActionList},
		"DELETE " + wire.AttestationEndorsementsPath:         {auth.ResourceAttestationEndorsements, auth.ActionDelete},
		"PUT " + wire.AttestationReferenceValuesPath:         {auth.ResourceAttestationReferenceValues, auth.ActionCreate},
		"GET " + wire.AttestationReferenceValuesPath:         {auth.ResourceAttestationReferenceValues, auth.ActionList},
		"GET " + wire.AttestationReferenceValuesEntryPath:    {auth.ResourceAttestationReferenceValues, auth.ActionGet},
		"DELETE " + wire.AttestationReferenceValuesEntryPath: {auth.ResourceAttestationReferenceValues, auth.ActionDelete},
		"POST " + wire.AttestationAppraisePath:               {auth.ResourceAttestationVerifier, auth.ActionVerify},
	}
	got := map[string][2]string{}
	for _, spec := range Routes() {
		if appraisalResources[spec.Resource] {
			got[spec.Method+" "+spec.Pattern] = [2]string{spec.Resource, spec.Action}
		}
	}
	assert.Equal(t, want, got)
}

func TestAttestationAppraisalREST_Endorsements(t *testing.T) {
	svc := signingKeyXKMS(t)
	client := appraisalClient(t, appraisalRouter(svc, acmeIdentity()))
	ctx := context.Background()

	put, err := client.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{
		Name: "fleet-root", Kind: appraisal.EndorsementAKRoot, CertificatePEM: testAKRootPEM(t),
	})
	require.NoError(t, err)
	assert.Equal(t, "fleet-root", put.Name)

	list, err := client.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{Kind: appraisal.EndorsementAKRoot})
	require.NoError(t, err)
	require.Len(t, list.Endorsements, 1)
	assert.Equal(t, "fleet-root", list.Endorsements[0].Name)

	// The record is the caller's tenant's: another tenant does not see it.
	other := appraisalClient(t, appraisalRouter(svc, &auth.Identity{Subject: "x", TenantID: "globex", Roles: []string{"admin"}}))
	otherList, err := other.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
	require.NoError(t, err)
	assert.Empty(t, otherList.Endorsements)
	assert.Equal(t, http.StatusNotFound, statusOf(other.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{Name: "fleet-root"})))

	require.NoError(t, client.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{Name: "fleet-root"}))
	assert.Equal(t, http.StatusNotFound, statusOf(client.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{Name: "fleet-root"})))
}

func TestAttestationAppraisalREST_ReferenceValuesAndAppraise(t *testing.T) {
	svc := signingKeyXKMS(t)
	client := appraisalClient(t, appraisalRouter(svc, acmeIdentity()))
	ctx := context.Background()

	list, err := client.ListAttestationReferenceValues(ctx)
	require.NoError(t, err)
	assert.Empty(t, list.ReferenceValues)

	_, err = client.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{Name: "golden"})
	assert.Equal(t, http.StatusNotFound, statusOf(err))
	assert.Equal(t, http.StatusNotFound, statusOf(client.DeleteAttestationReferenceValues(ctx, &transport.DeleteAttestationReferenceValuesRequest{Name: "golden"})))

	// A CoRIM no reference signer of the tenant signed is refused.
	_, err = client.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{Name: "golden", SignedCoRIM: []byte("not a corim")})
	assert.Equal(t, http.StatusBadRequest, statusOf(err))

	// A quote naming reference values the tenant does not hold is refused.
	_, err = client.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{
		AKCertificatePEM: testAKRootPEM(t), Quote: []byte{1}, Signature: []byte{1}, Nonce: []byte{1},
		PCRs: map[uint32][]byte{0: make([]byte, 32)}, ReferenceValues: "golden",
	})
	assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, statusOf(err))
}

// TestAttestationAppraisal_RESTEmbeddedParity drives each verb through the
// REST client and the embedded transport over one service: both return the
// same records and refuse the same calls.
func TestAttestationAppraisal_RESTEmbeddedParity(t *testing.T) {
	svc := signingKeyXKMS(t)
	restClient := appraisalClient(t, appraisalRouter(svc, acmeIdentity()))
	tr, err := embedded.NewWithService(svc)
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	ctx := auth.WithIdentity(context.Background(), acmeIdentity())
	clients := map[string]transport.AttestationAppraisalService{"rest": restClient, "embedded": tr}

	for name, c := range clients {
		_, err := c.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{
			Name: "root-" + name, Kind: appraisal.EndorsementAKRoot, CertificatePEM: testAKRootPEM(t),
		})
		require.NoError(t, err, name)
	}
	lists := map[string]*transport.ListAttestationEndorsementsResponse{}
	for name, c := range clients {
		list, err := c.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
		require.NoError(t, err, name)
		require.Len(t, list.Endorsements, 2, name)
		lists[name] = list
	}
	assert.Equal(t, jsonOf(t, lists["rest"]), jsonOf(t, lists["embedded"]))

	for name, c := range clients {
		refs, err := c.ListAttestationReferenceValues(ctx)
		require.NoError(t, err, name)
		assert.Empty(t, refs.ReferenceValues, name)

		_, err = c.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{Name: "golden"})
		assert.True(t, notFound(err), "%s: %v", name, err)
		assert.True(t, notFound(c.DeleteAttestationReferenceValues(ctx, &transport.DeleteAttestationReferenceValuesRequest{Name: "golden"})), name)

		_, err = c.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{Name: "golden", SignedCoRIM: []byte("not a corim")})
		assert.Error(t, err, name)

		_, err = c.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{
			AKCertificatePEM: testAKRootPEM(t), Quote: []byte{1}, Signature: []byte{1}, Nonce: []byte{1},
			PCRs: map[uint32][]byte{0: make([]byte, 32)}, ReferenceValues: "golden",
		})
		assert.Error(t, err, name)

		require.NoError(t, c.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{Name: "root-" + name}), name)
		assert.True(t, notFound(c.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{Name: "root-" + name})), name)
	}
}

// notFound reports whether err is a not-found refusal on either transport.
func notFound(err error) bool {
	return statusOf(err) == http.StatusNotFound || errors.Is(err, appraisal.ErrRecordNotFound)
}

func jsonOf(t *testing.T, v any) string {
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return string(raw)
}

func TestAttestationAppraisalREST_WithoutAnAppraiser(t *testing.T) {
	client := appraisalClient(t, appraisalRouter(&xkms.XKMSService{}, acmeIdentity()))
	_, err := client.ListAttestationReferenceValues(context.Background())
	assert.Equal(t, http.StatusServiceUnavailable, statusOf(err))
}

func TestAttestationAppraisalREST_NotServedWithoutHandlers(t *testing.T) {
	server := &Server{}
	for _, spec := range Routes() {
		if appraisalResources[spec.Resource] {
			assert.False(t, spec.Enabled(server), "%s %s is served without the appraisal handlers", spec.Method, spec.Pattern)
		}
	}
}

func TestAttestationAppraisalWire_NilRequests(t *testing.T) {
	client := wire.AttestationAppraisalClient{}
	ctx := context.Background()
	_, err := client.PutAttestationEndorsement(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	_, err = client.ListAttestationEndorsements(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	assert.ErrorIs(t, client.DeleteAttestationEndorsement(ctx, nil), wire.ErrNilRequest)
	_, err = client.PutAttestationReferenceValues(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	_, err = client.GetAttestationReferenceValues(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	assert.ErrorIs(t, client.DeleteAttestationReferenceValues(ctx, nil), wire.ErrNilRequest)
	_, err = client.AppraiseAttestationQuote(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
}
