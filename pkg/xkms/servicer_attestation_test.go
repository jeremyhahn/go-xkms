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

package xkms

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// verifierFixture is a service wired with an Appraiser over an in-memory DAO
// store, plus the authorities and evidence a tenant needs to appraise.
type verifierFixture struct {
	svc   *XKMSService
	akCA  *appraisaltest.Authority
	rvCA  *appraisaltest.Authority
	ak    *appraisaltest.AttestationKey
	pcrs  map[uint32][]byte
	corim []byte
}

func newVerifierFixture(t *testing.T) *verifierFixture {
	t.Helper()
	store, err := appraisal.NewStore(appraisal.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	appraiser, err := appraisal.NewAppraiser(store)
	require.NoError(t, err)

	f := &verifierFixture{svc: &XKMSService{}, pcrs: appraisaltest.PCRValues(0, 4, 7)}
	f.svc.SetAttestationAppraiser(appraiser)
	f.akCA, err = appraisaltest.NewAuthority("AK CA")
	require.NoError(t, err)
	f.rvCA, err = appraisaltest.NewAuthority("Reference Value CA")
	require.NoError(t, err)
	f.ak, err = appraisaltest.IssueAttestationKey(f.akCA, true)
	require.NoError(t, err)
	signerCert, signerKey, err := appraisaltest.SignerUnder(f.rvCA)
	require.NoError(t, err)
	f.corim, err = appraisaltest.SignCoRIM(f.pcrs, signerKey, []*x509.Certificate{signerCert})
	require.NoError(t, err)
	return f
}

// endorse stores the fixture's trust anchors and its "golden" reference
// values for the tenant ctx carries.
func (f *verifierFixture) endorse(t *testing.T, ctx context.Context) {
	t.Helper()
	_, err := f.svc.PutAttestationEndorsement(ctx, &appraisal.PutEndorsementRequest{
		Name: "ak-ca", Kind: appraisal.EndorsementAKRoot, CertificatePEM: f.akCA.CertificatePEM(),
	})
	require.NoError(t, err)
	_, err = f.svc.PutAttestationEndorsement(ctx, &appraisal.PutEndorsementRequest{
		Name: "rv-ca", Kind: appraisal.EndorsementReferenceSigner, CertificatePEM: f.rvCA.CertificatePEM(),
	})
	require.NoError(t, err)
	_, err = f.svc.PutAttestationReferenceValues(ctx, &appraisal.PutReferenceValuesRequest{Name: "golden", SignedCoRIM: f.corim})
	require.NoError(t, err)
}

func (f *verifierFixture) quoteRequest(t *testing.T) *appraisal.AppraiseQuoteRequest {
	t.Helper()
	nonce := []byte("verifier-service-nonce-000000000")
	quote, err := appraisaltest.SignQuote(f.ak, f.pcrs, nonce)
	require.NoError(t, err)
	return &appraisal.AppraiseQuoteRequest{
		AKCertificatePEM: f.ak.CertificatePEM(),
		Quote:            quote.Attest,
		Signature:        quote.Signature,
		Nonce:            nonce,
		PCRs:             f.pcrs,
		ReferenceValues:  "golden",
	}
}

func TestXKMSService_AttestationVerifier_Lifecycle(t *testing.T) {
	f := newVerifierFixture(t)
	ctx := tenantCtx("acme")
	f.endorse(t, ctx)
	assert.Same(t, f.svc.appraiser.load(), f.svc.AttestationAppraiser())

	endorsements, err := f.svc.ListAttestationEndorsements(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, endorsements.Endorsements, 2)
	roots, err := f.svc.ListAttestationEndorsements(ctx, &appraisal.ListEndorsementsRequest{Kind: appraisal.EndorsementAKRoot})
	require.NoError(t, err)
	require.Len(t, roots.Endorsements, 1)
	assert.Equal(t, "ak-ca", roots.Endorsements[0].Name)

	golden, err := f.svc.GetAttestationReferenceValues(ctx, &appraisal.GetReferenceValuesRequest{Name: "golden"})
	require.NoError(t, err)
	assert.Equal(t, "golden", golden.Name)
	listed, err := f.svc.ListAttestationReferenceValues(ctx)
	require.NoError(t, err)
	assert.Len(t, listed.ReferenceValues, 1)

	result, err := f.svc.AppraiseAttestationQuote(ctx, f.quoteRequest(t))
	require.NoError(t, err)
	assert.True(t, result.Verified, "genuine evidence must verify: %+v", result.Checks)
	assert.Equal(t, "golden", result.ReferenceValues)

	require.NoError(t, f.svc.DeleteAttestationReferenceValues(ctx, &appraisal.DeleteReferenceValuesRequest{Name: "golden"}))
	_, err = f.svc.GetAttestationReferenceValues(ctx, &appraisal.GetReferenceValuesRequest{Name: "golden"})
	assert.ErrorIs(t, err, appraisal.ErrRecordNotFound)

	require.NoError(t, f.svc.DeleteAttestationEndorsement(ctx, &appraisal.DeleteEndorsementRequest{Name: "ak-ca"}))
	endorsements, err = f.svc.ListAttestationEndorsements(ctx, nil)
	require.NoError(t, err)
	require.Len(t, endorsements.Endorsements, 1)
	assert.Equal(t, "rv-ca", endorsements.Endorsements[0].Name)
}

// The service scopes every call to the caller's tenant: one tenant's
// endorsements and reference values are invisible to another, so another
// tenant's evidence cannot be appraised against them.
func TestXKMSService_AttestationVerifier_TenantIsolation(t *testing.T) {
	f := newVerifierFixture(t)
	f.endorse(t, tenantCtx("acme"))
	globex := tenantCtx("globex")

	endorsements, err := f.svc.ListAttestationEndorsements(globex, nil)
	require.NoError(t, err)
	assert.Empty(t, endorsements.Endorsements)
	listed, err := f.svc.ListAttestationReferenceValues(globex)
	require.NoError(t, err)
	assert.Empty(t, listed.ReferenceValues)
	_, err = f.svc.GetAttestationReferenceValues(globex, &appraisal.GetReferenceValuesRequest{Name: "golden"})
	assert.ErrorIs(t, err, appraisal.ErrRecordNotFound)

	result, err := f.svc.AppraiseAttestationQuote(globex, f.quoteRequest(t))
	require.NoError(t, err)
	assert.False(t, result.Verified, "another tenant's baseline must not verify")

	// A caller without an identity is the system tenant, which sees none of
	// acme's records either.
	listed, err = f.svc.ListAttestationReferenceValues(context.Background())
	require.NoError(t, err)
	assert.Empty(t, listed.ReferenceValues)
}

func TestXKMSService_AttestationVerifier_RequestErrors(t *testing.T) {
	f := newVerifierFixture(t)
	ctx := tenantCtx("acme")
	calls := map[string]func() error{
		"PutAttestationEndorsement": func() error {
			_, err := f.svc.PutAttestationEndorsement(ctx, nil)
			return err
		},
		"DeleteAttestationEndorsement": func() error { return f.svc.DeleteAttestationEndorsement(ctx, nil) },
		"PutAttestationReferenceValues": func() error {
			_, err := f.svc.PutAttestationReferenceValues(ctx, nil)
			return err
		},
		"GetAttestationReferenceValues": func() error {
			_, err := f.svc.GetAttestationReferenceValues(ctx, nil)
			return err
		},
		"DeleteAttestationReferenceValues": func() error { return f.svc.DeleteAttestationReferenceValues(ctx, nil) },
		"AppraiseAttestationQuote": func() error {
			_, err := f.svc.AppraiseAttestationQuote(ctx, nil)
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), appraisal.ErrNilRequest)
		})
	}

	t.Run("ReferenceValuesFromAnUnendorsedSigner", func(t *testing.T) {
		_, err := f.svc.PutAttestationReferenceValues(ctx, &appraisal.PutReferenceValuesRequest{Name: "golden", SignedCoRIM: f.corim})
		assert.Error(t, err)
	})
}

func TestXKMSService_AttestationVerifier_NotConfigured(t *testing.T) {
	svc := &XKMSService{}
	ctx := tenantCtx("acme")
	assert.Nil(t, svc.AttestationAppraiser())
	calls := map[string]func() error{
		"PutAttestationEndorsement": func() error {
			_, err := svc.PutAttestationEndorsement(ctx, &appraisal.PutEndorsementRequest{})
			return err
		},
		"ListAttestationEndorsements": func() error {
			_, err := svc.ListAttestationEndorsements(ctx, nil)
			return err
		},
		"DeleteAttestationEndorsement": func() error {
			return svc.DeleteAttestationEndorsement(ctx, &appraisal.DeleteEndorsementRequest{})
		},
		"PutAttestationReferenceValues": func() error {
			_, err := svc.PutAttestationReferenceValues(ctx, &appraisal.PutReferenceValuesRequest{})
			return err
		},
		"GetAttestationReferenceValues": func() error {
			_, err := svc.GetAttestationReferenceValues(ctx, &appraisal.GetReferenceValuesRequest{})
			return err
		},
		"ListAttestationReferenceValues": func() error {
			_, err := svc.ListAttestationReferenceValues(ctx)
			return err
		},
		"DeleteAttestationReferenceValues": func() error {
			return svc.DeleteAttestationReferenceValues(ctx, &appraisal.DeleteReferenceValuesRequest{})
		},
		"AppraiseAttestationQuote": func() error {
			_, err := svc.AppraiseAttestationQuote(ctx, &appraisal.AppraiseQuoteRequest{})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConfigured)
		})
	}
}
