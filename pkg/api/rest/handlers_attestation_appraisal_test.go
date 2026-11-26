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
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	appraisalcalls "github.com/jeremyhahn/go-xkms/pkg/testutil/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// appraisalResources are the permission resources of the Verifier routes.
var appraisalResources = map[string]bool{
	auth.ResourceAttestationEndorsements:    true,
	auth.ResourceAttestationReferenceValues: true,
	auth.ResourceAttestationVerifier:        true,
}

// appraisalRouter serves the Verifier routes of the route table over svc as
// a caller of tenantID.
func appraisalRouter(svc *xkms.XKMSService, tenantID string) http.Handler {
	server := &Server{attestationAppraisalHandlers: NewAttestationAppraisalHandlers(svc)}
	r := chi.NewRouter()
	identity := &auth.Identity{Subject: "verifier@" + tenantID, TenantID: tenantID, Roles: []string{"admin"}}
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

// appraisalClient returns the wire client over router, failing a non-2xx
// answer with its status.
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
			return nil, &errSigningKeyStatus{code: w.Code}
		}
		return w.Body.Bytes(), nil
	}}
}

// appraisalREST is a Verifier service and the evidence a tenant appraises
// with it: trust anchors, a signed CoRIM and a genuine quote over the PCRs
// the CoRIM binds.
type appraisalREST struct {
	svc   *xkms.XKMSService
	akCA  *appraisaltest.Authority
	rvCA  *appraisaltest.Authority
	corim []byte
	quote *transport.AppraiseAttestationQuoteRequest
}

func newAppraisalREST(t *testing.T) *appraisalREST {
	t.Helper()
	pcrs := appraisaltest.PCRValues(0, 4, 7)
	akCA, err := appraisaltest.NewAuthority("AK CA")
	require.NoError(t, err)
	rvCA, err := appraisaltest.NewAuthority("Reference Value CA")
	require.NoError(t, err)
	ak, err := appraisaltest.IssueAttestationKey(akCA, true)
	require.NoError(t, err)
	signerCert, signerKey, err := appraisaltest.SignerUnder(rvCA)
	require.NoError(t, err)
	corim, err := appraisaltest.SignCoRIM(pcrs, signerKey, []*x509.Certificate{signerCert})
	require.NoError(t, err)
	nonce := []byte("rest-verifier-nonce-000000000000")
	quote, err := appraisaltest.SignQuote(ak, pcrs, nonce)
	require.NoError(t, err)
	return &appraisalREST{
		svc:  signingKeyXKMS(t),
		akCA: akCA, rvCA: rvCA, corim: corim,
		quote: &transport.AppraiseAttestationQuoteRequest{
			AKCertificatePEM: ak.CertificatePEM(),
			Quote:            quote.Attest,
			Signature:        quote.Signature,
			Nonce:            nonce,
			PCRs:             pcrs,
			ReferenceValues:  "golden",
		},
	}
}

// endorse stores the trust anchors and "golden" reference values through c.
func (a *appraisalREST) endorse(t *testing.T, c wire.AttestationAppraisalClient) {
	t.Helper()
	ctx := context.Background()
	_, err := c.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{
		Name: "ak-ca", Kind: appraisal.EndorsementAKRoot, CertificatePEM: a.akCA.CertificatePEM(),
	})
	require.NoError(t, err)
	_, err = c.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{
		Name: "rv-ca", Kind: appraisal.EndorsementReferenceSigner, CertificatePEM: a.rvCA.CertificatePEM(),
	})
	require.NoError(t, err)
	_, err = c.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{Name: "golden", SignedCoRIM: a.corim})
	require.NoError(t, err)
}

// TestAttestationAppraisalREST_Lifecycle proves the wire client and the
// routes drive every Verifier verb: the stored trust anchors and reference
// values appraise a genuine quote, and each delete removes what it names.
func TestAttestationAppraisalREST_Lifecycle(t *testing.T) {
	a := newAppraisalREST(t)
	c := appraisalClient(t, appraisalRouter(a.svc, "acme"))
	ctx := context.Background()
	a.endorse(t, c)

	all, err := c.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
	require.NoError(t, err)
	assert.Len(t, all.Endorsements, 2)
	roots, err := c.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{Kind: appraisal.EndorsementAKRoot})
	require.NoError(t, err)
	require.Len(t, roots.Endorsements, 1)
	assert.Equal(t, "ak-ca", roots.Endorsements[0].Name)

	golden, err := c.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{Name: "golden"})
	require.NoError(t, err)
	assert.Equal(t, "golden", golden.Name)
	listed, err := c.ListAttestationReferenceValues(ctx)
	require.NoError(t, err)
	assert.Len(t, listed.ReferenceValues, 1)

	result, err := c.AppraiseAttestationQuote(ctx, a.quote)
	require.NoError(t, err)
	assert.True(t, result.Verified, "genuine evidence must verify: %+v", result.Checks)
	assert.Equal(t, "golden", result.ReferenceValues)

	require.NoError(t, c.DeleteAttestationReferenceValues(ctx, &transport.DeleteAttestationReferenceValuesRequest{Name: "golden"}))
	_, err = c.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{Name: "golden"})
	assert.Equal(t, &errSigningKeyStatus{code: http.StatusNotFound}, err)
	require.NoError(t, c.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{Name: "ak-ca"}))
	all, err = c.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
	require.NoError(t, err)
	assert.Len(t, all.Endorsements, 1)
}

// TestAttestationAppraisalREST_TenantIsolation proves another tenant sees
// none of a tenant's records and cannot appraise against them.
func TestAttestationAppraisalREST_TenantIsolation(t *testing.T) {
	a := newAppraisalREST(t)
	a.endorse(t, appraisalClient(t, appraisalRouter(a.svc, "acme")))
	other := appraisalClient(t, appraisalRouter(a.svc, "globex"))
	ctx := context.Background()

	endorsements, err := other.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
	require.NoError(t, err)
	assert.Empty(t, endorsements.Endorsements)
	values, err := other.ListAttestationReferenceValues(ctx)
	require.NoError(t, err)
	assert.Empty(t, values.ReferenceValues)
	_, err = other.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{Name: "golden"})
	assert.Equal(t, &errSigningKeyStatus{code: http.StatusNotFound}, err)
	result, err := other.AppraiseAttestationQuote(ctx, a.quote)
	require.NoError(t, err)
	assert.False(t, result.Verified, "another tenant's baseline must not verify")
}

// TestAttestationAppraisalREST_MapsErrors proves the routes answer a
// malformed body or record with 400, a missing record with 404, and every
// route of a server with no Verifier with 503.
func TestAttestationAppraisalREST_MapsErrors(t *testing.T) {
	router := appraisalRouter(newAppraisalREST(t).svc, "acme")
	serve := func(method, path, body string) int {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		return w.Code
	}
	assert.Equal(t, http.StatusBadRequest, serve(http.MethodPut, wire.AttestationEndorsementsPath, "{"))
	assert.Equal(t, http.StatusBadRequest, serve(http.MethodPut, wire.AttestationReferenceValuesPath, "{"))
	assert.Equal(t, http.StatusBadRequest, serve(http.MethodPost, wire.AttestationAppraisePath, "{"))
	assert.Equal(t, http.StatusBadRequest, serve(http.MethodPut, wire.AttestationEndorsementsPath, `{"name":"ak-ca","kind":"ak-root"}`))
	assert.Equal(t, http.StatusBadRequest, serve(http.MethodPut, wire.AttestationReferenceValuesPath, `{"name":"golden","signed_corim":"AAEC"}`))
	assert.Equal(t, http.StatusNotFound, serve(http.MethodDelete, wire.AttestationEndorsementsPath+"/absent", ""))
	assert.Equal(t, http.StatusNotFound, serve(http.MethodGet, wire.AttestationReferenceValuesPath+"/absent", ""))
	assert.Equal(t, http.StatusNotFound, serve(http.MethodDelete, wire.AttestationReferenceValuesPath+"/absent", ""))

	unserved := appraisalClient(t, appraisalRouter(&xkms.XKMSService{}, "acme"))
	unavailable := &errSigningKeyStatus{code: http.StatusServiceUnavailable}
	for name, call := range appraisalcalls.Calls(context.Background(), unserved) {
		assert.Equal(t, unavailable, call(), name)
	}
}

// TestAttestationAppraisalWire_NilRequests proves the wire client refuses a
// nil request before it sends anything.
func TestAttestationAppraisalWire_NilRequests(t *testing.T) {
	for name, call := range appraisalcalls.NilRequestCalls(context.Background(), wire.AttestationAppraisalClient{}) {
		assert.ErrorIs(t, call(), wire.ErrNilRequest, name)
	}
}
