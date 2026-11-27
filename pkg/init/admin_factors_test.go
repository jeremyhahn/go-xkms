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
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkmsfido2 "github.com/jeremyhahn/go-xkms/pkg/factor/fido2"
	pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"
)

const testCertPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"

// noDeviceEnumerator is a pkgfido2.HIDDeviceEnumerator that reports no
// attached authenticators, without touching any real hardware. It lets tests
// exercise LocalCeremony's "no device" path deterministically and fast.
type noDeviceEnumerator struct{}

func (noDeviceEnumerator) Enumerate(_, _ uint16) ([]pkgfido2.HIDDevice, error) {
	return nil, nil
}

func (noDeviceEnumerator) Open(_ string) (pkgfido2.HIDDevice, error) {
	return nil, errors.New("noDeviceEnumerator: Open must not be called")
}

// realLocalCeremony builds a *xkmsfido2.LocalCeremony over a real
// pkgfido2.FIDO2Handler with no attached authenticators, so tests can drive
// NewAdminEnrollmentParams' fido2 branch past the nil-ceremony guard without
// any hardware. The short timeout keeps a "no device" failure immediate
// rather than waiting out the default 60s presence window.
func realLocalCeremony(t *testing.T) *xkmsfido2.LocalCeremony {
	t.Helper()
	handler, err := pkgfido2.NewHandler(nil, noDeviceEnumerator{})
	if err != nil {
		t.Fatalf("pkgfido2.NewHandler: %v", err)
	}
	return xkmsfido2.NewLocalCeremony(handler, time.Millisecond)
}

// attachedKey is a pkgfido2.HIDDevice that is enumerated but never opened, so
// a handler can report one authenticator without touching any hardware.
type attachedKey struct{}

func (attachedKey) Write([]byte) (int, error) {
	return 0, errors.New("attachedKey: Write must not be called")
}
func (attachedKey) Read([]byte) (int, error) {
	return 0, errors.New("attachedKey: Read must not be called")
}
func (attachedKey) Close() error         { return nil }
func (attachedKey) Path() string         { return "/dev/hidraw0" }
func (attachedKey) ProductID() uint16    { return 0x0407 }
func (attachedKey) VendorID() uint16     { return 0x1050 }
func (attachedKey) Product() string      { return "Security Key" }
func (attachedKey) Manufacturer() string { return "Example" }
func (attachedKey) SerialNumber() string { return "0001" }

// oneDeviceEnumerator reports a single attached authenticator.
type oneDeviceEnumerator struct{}

func (oneDeviceEnumerator) Enumerate(_, _ uint16) ([]pkgfido2.HIDDevice, error) {
	return []pkgfido2.HIDDevice{attachedKey{}}, nil
}

func (oneDeviceEnumerator) Open(_ string) (pkgfido2.HIDDevice, error) {
	return nil, errors.New("oneDeviceEnumerator: Open must not be called")
}

// TestPreflightAdminFactors_FIDO2WithAnAttachedKeyPasses is the positive half
// of issue #1446: with a handler that can reach an authenticator, a planned
// fido2 factor preflights cleanly.
func TestPreflightAdminFactors_FIDO2WithAnAttachedKeyPasses(t *testing.T) {
	handler, err := pkgfido2.NewHandler(nil, oneDeviceEnumerator{})
	if err != nil {
		t.Fatalf("pkgfido2.NewHandler: %v", err)
	}
	err = PreflightAdminFactors(context.Background(), AdminEnrollmentConfig{
		Plan:           mustPlan(t, "fido2"),
		Username:       "administrator",
		RelyingPartyID: "example.com",
		FIDO2Handler:   handler,
	})
	if err != nil {
		t.Fatalf("fido2 must preflight cleanly with an authenticator attached, got %v", err)
	}
}

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

// TestAdminEnrollmentParams_FIDO2RequiresARelyingPartyWithRealCeremony
// isolates the RP ID check from the "no local ceremony" one above: with an
// actual (hardware-free) LocalCeremony wired in, the missing RP ID must still
// refuse before any challenge is generated or the authenticator is touched.
func TestAdminEnrollmentParams_FIDO2RequiresARelyingPartyWithRealCeremony(t *testing.T) {
	params := NewAdminEnrollmentParams(AdminEnrollmentContext{
		Username:      "administrator",
		LocalCeremony: realLocalCeremony(t),
	})

	_, err := params(context.Background(), qrdbsdk.FactorFIDO2)
	if !errors.Is(err, ErrPasskeyRPIDRequired) {
		t.Fatalf("params(fido2) with no RP ID = %v, want ErrPasskeyRPIDRequired", err)
	}
}

// TestAdminEnrollmentParams_FIDO2PropagatesCeremonyFailure verifies that once
// the RP ID and local-ceremony preconditions are satisfied, a failure from
// the authenticator ceremony itself (here: no device attached) is returned
// to the caller rather than swallowed -- the plan must not report a factor as
// enrolled when the hardware step never ran.
func TestAdminEnrollmentParams_FIDO2PropagatesCeremonyFailure(t *testing.T) {
	params := NewAdminEnrollmentParams(AdminEnrollmentContext{
		Username:       "administrator",
		RelyingPartyID: "xkms.example.com",
		LocalCeremony:  realLocalCeremony(t),
	})

	_, err := params(context.Background(), qrdbsdk.FactorFIDO2)
	if !errors.Is(err, xkmsfido2.ErrNoAuthenticator) {
		t.Fatalf("params(fido2) with no attached authenticator = %v, want ErrNoAuthenticator", err)
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
