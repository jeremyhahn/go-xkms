// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package initialize

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

const testCertPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"

// TestAdminEnrollmentParams_MTLSBindsTheAdminCertificate is the regression for
// the bug that made `xkmsd init` fail with "mtls: cert_pem is required": the
// provider returned no params for mtls, so the administrator certificate the
// ceremony had just issued was never bound as a login credential. Without this
// the admin bundle is a file on disk, not something you can sign in with.
func TestAdminEnrollmentParams_MTLSBindsTheAdminCertificate(t *testing.T) {
	params := NewAdminEnrollmentParams(AdminEnrollmentContext{
		Username:     "administrator",
		AdminCertPEM: []byte(testCertPEM),
	})

	got, err := params(context.Background(), qrdbsdk.FactorMTLS)
	if err != nil {
		t.Fatalf("params(mtls): %v", err)
	}
	if got["cert_pem"] != testCertPEM {
		t.Errorf("cert_pem = %v, want the issued admin certificate", got["cert_pem"])
	}
}

// TestAdminEnrollmentParams_MTLSRequiresACertificate proves the factor is not
// enrolled against nothing: recording an mtls credential with no certificate
// would create a login factor no operator holds.
func TestAdminEnrollmentParams_MTLSRequiresACertificate(t *testing.T) {
	params := NewAdminEnrollmentParams(AdminEnrollmentContext{Username: "administrator"})

	if _, err := params(context.Background(), qrdbsdk.FactorMTLS); !errors.Is(err, ErrAdminCertRequired) {
		t.Fatalf("params(mtls) without a cert = %v, want ErrAdminCertRequired", err)
	}
}

// TestAdminEnrollmentParams_PIVNeedsNoExtraInputs documents that the PIV
// factor reads its slot from its own configuration, so the provider
// contributes nothing rather than inventing parameters.
func TestAdminEnrollmentParams_PIVNeedsNoExtraInputs(t *testing.T) {
	params := NewAdminEnrollmentParams(AdminEnrollmentContext{Username: "administrator"})

	got, err := params(context.Background(), qrdbsdk.FactorPIV)
	if err != nil {
		t.Fatalf("params(piv): %v", err)
	}
	if got != nil {
		t.Errorf("params(piv) = %v, want nil", got)
	}
}

// TestAdminEnrollmentParams_FIDO2RequiresALocalCeremony proves a planned
// passkey on a build with no authenticator driver fails with an explanation
// rather than a nil dereference.
func TestAdminEnrollmentParams_FIDO2RequiresALocalCeremony(t *testing.T) {
	params := NewAdminEnrollmentParams(AdminEnrollmentContext{
		Username:       "administrator",
		RelyingPartyID: "xkms.example.com",
	})

	if _, err := params(context.Background(), qrdbsdk.FactorFIDO2); !errors.Is(err, ErrNoLocalFIDO2Ceremony) {
		t.Fatalf("params(fido2) = %v, want ErrNoLocalFIDO2Ceremony", err)
	}
}

// TestAdminEnrollmentParams_FIDO2RequiresARelyingParty pins the refusal to
// guess an RP ID. A credential enrolled against the wrong one verifies at
// enrollment and fails at every subsequent login.
func TestAdminEnrollmentParams_FIDO2RequiresARelyingParty(t *testing.T) {
	params := NewAdminEnrollmentParams(AdminEnrollmentContext{Username: "administrator"})

	_, err := params(context.Background(), qrdbsdk.FactorFIDO2)
	if !errors.Is(err, ErrPasskeyRPIDRequired) && !errors.Is(err, ErrNoLocalFIDO2Ceremony) {
		t.Fatalf("params(fido2) = %v, want a refusal naming the missing input", err)
	}
}

// TestAdminEnrollmentParams_PlanOrderPutsMTLSFirst pins the ordering the whole
// design rests on: the certificate is the credential that still works if a
// hardware ceremony is interrupted, so it must never be enrolled behind one.
func TestAdminEnrollmentParams_PlanOrderPutsMTLSFirst(t *testing.T) {
	plan, err := qrdbsdk.ParseAdminFactors([]string{"fido2,piv,mtls"})
	if err != nil {
		t.Fatalf("ParseAdminFactors: %v", err)
	}
	if got := plan.Factors(); got[0] != qrdbsdk.FactorMTLS {
		t.Fatalf("plan = %v, want mtls first", got)
	}
}
