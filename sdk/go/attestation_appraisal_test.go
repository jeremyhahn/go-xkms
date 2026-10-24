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
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
)

// An embedder builds the Verifier from the SDK alone and manages a tenant's
// endorsements through it.
func TestAttestationAppraiser_BuiltFromTheSDK(t *testing.T) {
	store, err := NewAttestationAppraisalStore(AttestationAppraisalStoreConfig{DAOs: NewStoreDAOFactory(qrdbsdk.NewMemoryKVStore())})
	if err != nil {
		t.Fatal(err)
	}
	appraiser, err := NewAttestationAppraiser(store)
	if err != nil {
		t.Fatal(err)
	}
	akCA, err := appraisaltest.NewAuthority("AK CA")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := appraiser.PutEndorsement(ctx, "acme", &PutAttestationEndorsementRequest{
		Name: "ak-ca", Kind: AttestationEndorsementAKRoot, CertificatePEM: akCA.CertificatePEM(),
	}); err != nil {
		t.Fatalf("PutEndorsement: %v", err)
	}
	listed, err := appraiser.ListEndorsements(ctx, "acme", &ListAttestationEndorsementsRequest{Kind: AttestationEndorsementAKRoot})
	if err != nil {
		t.Fatalf("ListEndorsements: %v", err)
	}
	if len(listed.Endorsements) != 1 || listed.Endorsements[0].Name != "ak-ca" {
		t.Fatalf("listed %+v, want the one ak-ca endorsement", listed.Endorsements)
	}
	_, err = appraiser.GetReferenceValues(ctx, "acme", &GetAttestationReferenceValuesRequest{Name: "golden"})
	if !errors.Is(err, ErrAttestationRecordNotFound) {
		t.Fatalf("GetReferenceValues of a missing record = %v, want ErrAttestationRecordNotFound", err)
	}
}

func TestAttestationAppraiser_RefusesAnUnusableConfiguration(t *testing.T) {
	_, err := NewAttestationAppraisalStore(AttestationAppraisalStoreConfig{})
	if !errors.Is(err, ErrAttestationAppraisalInvalidConfig) {
		t.Fatalf("store without DAOs = %v, want ErrAttestationAppraisalInvalidConfig", err)
	}
	var configErr *AttestationAppraisalConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("store without DAOs = %T, want *AttestationAppraisalConfigError", err)
	}
	if _, err := NewAttestationAppraiser(nil); !errors.Is(err, ErrAttestationAppraisalInvalidConfig) {
		t.Fatalf("appraiser without a store = %v, want ErrAttestationAppraisalInvalidConfig", err)
	}
}
