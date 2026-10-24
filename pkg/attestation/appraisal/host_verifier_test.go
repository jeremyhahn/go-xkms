// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-quicbaas.
//
// go-quicbaas is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package orchestration_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/pkg/orchestration"
	"github.com/jeremyhahn/go-quicbaas/pkg/service"
	"github.com/jeremyhahn/go-quicbaas/pkg/service/attestationtest"
	"github.com/jeremyhahn/go-quicbaas/pkg/tenantctx"
)

// verifierTenant is the tenant the runtime tests' endorsements and reference
// values are stored under.
const verifierTenant = "acme"

// The runtime tests appraise against the real Verifier. The service package
// owns it and imports orchestration, so only this external test package can
// build it; it installs the constructor the internal tests call.
func init() {
	orchestration.NewTestHostAppraiser = newVerifierHostAppraiser
}

// newVerifierHostAppraiser stores the tenant's ak-root and reference-signer
// endorsements, then the reference values "golden" signed over reference when
// reference is non-nil, and returns the service HostAppraiser over that store.
func newVerifierHostAppraiser(t testing.TB, akRoot *attestationtest.Authority, reference []attestationtest.PCRDigest) orchestration.HostAppraiser {
	t.Helper()
	ctx := tenantctx.WithTenant(context.Background(), verifierTenant)
	store := attestationtest.NewMemoryStore()
	svc := service.NewAttestationService(nil, nil, service.WithAttestationStore(store))

	rvCA, err := attestationtest.NewAuthority("Reference Value CA")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutEndorsement(ctx, &service.PutEndorsementRequest{Name: "ak-ca", Kind: service.EndorsementAKRoot, CertificatePEM: akRoot.CertificatePEM()}); err != nil {
		t.Fatalf("PutEndorsement ak-root: %v", err)
	}
	if _, err := svc.PutEndorsement(ctx, &service.PutEndorsementRequest{Name: "rv-ca", Kind: service.EndorsementReferenceSigner, CertificatePEM: rvCA.CertificatePEM()}); err != nil {
		t.Fatalf("PutEndorsement reference-signer: %v", err)
	}
	if reference != nil {
		signerCert, signerKey, err := attestationtest.SignerUnder(rvCA)
		if err != nil {
			t.Fatal(err)
		}
		corim, err := attestationtest.SignCoRIMDigests(reference, signerKey, []*x509.Certificate{signerCert})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.PutReferenceValues(ctx, &service.PutReferenceValuesRequest{Name: "golden", SignedCoRIM: corim}); err != nil {
			t.Fatalf("PutReferenceValues: %v", err)
		}
	}

	appraiser, err := service.NewHostAppraiser(store)
	if err != nil {
		t.Fatalf("NewHostAppraiser: %v", err)
	}
	return tenantScopedAppraiser{inner: appraiser}
}

// tenantScopedAppraiser places every call in verifierTenant, standing in for
// the tenant scope a server request carries, so the runtime tests keep
// calling with t.Context().
type tenantScopedAppraiser struct {
	inner orchestration.HostAppraiser
}

func (a tenantScopedAppraiser) ReferencePCRs(ctx context.Context, name string, bank crypto.Hash) ([]uint32, error) {
	return a.inner.ReferencePCRs(tenantctx.WithTenant(ctx, verifierTenant), name, bank)
}

func (a tenantScopedAppraiser) AppraiseHost(ctx context.Context, evidence *orchestration.HostEvidence) (*orchestration.HostAppraisal, error) {
	return a.inner.AppraiseHost(tenantctx.WithTenant(ctx, verifierTenant), evidence)
}
