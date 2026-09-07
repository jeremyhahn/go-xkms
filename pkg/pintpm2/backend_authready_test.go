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

package pintpm2

import (
	"crypto/sha256"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// unconfirmedSRK models the state that made the backend claim a credential it
// had never seen: a PlatformSRK that is readable, so IsProvisioned reports
// true, whose auth value this application never set or verified. An SRK left
// behind by a prior TPM owner looks exactly like this.
func unconfirmedSRK(authValue string) *mockPlatformAuth {
	m := newMockPlatformAuth(authValue, true)
	m.authReady.Store(false)
	return m
}

// TestTPM2Backend_UnconfirmedSRKReportsPINUnset is the regression test for
// the backend reporting a user PIN as configured merely because the SRK
// handle was readable. Callers use UserPINSet to decide whether a credential
// exists to check against; answering yes when the auth value is unknown sends
// them to verify against a secret nobody chose, and each such attempt spends
// one of the TPM's dictionary-attack retries.
func TestTPM2Backend_UnconfirmedSRKReportsPINUnset(t *testing.T) {
	b := NewTPM2Backend(unconfirmedSRK("srk-auth-set-by-someone-else"))

	if b.UserPINSet() {
		t.Fatal("UserPINSet must be false when the SRK auth value has never " +
			"been set or confirmed by this application")
	}
}

// TestTPM2Backend_AuthReadySRKReportsPINSet is the other half: an SRK whose
// auth this application did establish is a configured user PIN, and must
// still be reported as one.
func TestTPM2Backend_AuthReadySRKReportsPINSet(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("configured-pin", true))

	if !b.UserPINSet() {
		t.Fatal("UserPINSet must be true when the provider reports the SRK " +
			"auth value is in a known-good state")
	}
}

// TestTPM2Backend_UnprovisionedSRKReportsPINUnset covers a TPM with no
// PlatformSRK at all.
func TestTPM2Backend_UnprovisionedSRKReportsPINUnset(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("", false))

	if b.UserPINSet() {
		t.Fatal("UserPINSet must be false when the TPM has no PlatformSRK")
	}
}

// TestTPM2Backend_VerifyConfirmsUnconfirmedSRK checks that honest reporting
// does not become a dead end. Verification stays available whenever the SRK
// is provisioned, and a correct PIN confirms the auth value, after which the
// backend reports the PIN as set.
func TestTPM2Backend_VerifyConfirmsUnconfirmedSRK(t *testing.T) {
	const pin = "correct-srk-auth"
	b := NewTPM2Backend(unconfirmedSRK(pin))

	if b.UserPINSet() {
		t.Fatal("precondition: the SRK auth must start unconfirmed")
	}
	if err := b.VerifyUserPIN(pin); err != nil {
		t.Fatalf("VerifyUserPIN must remain available on a provisioned SRK: %v", err)
	}
	if !b.UserPINSet() {
		t.Fatal("a successful verification confirms the auth value, so " +
			"UserPINSet must report true afterwards")
	}
}

// TestTPM2Backend_VerifyOnUnprovisionedSRKIsNotAnAuthAttempt makes sure the
// honest path still refuses to touch the TPM when there is no SRK, rather
// than issuing an auth attempt that would count against the DA counter.
func TestTPM2Backend_VerifyOnUnprovisionedSRKIsNotAnAuthAttempt(t *testing.T) {
	mock := newMockPlatformAuth("", false)
	b := NewTPM2Backend(mock)

	err := b.VerifyUserPIN("anything")

	if !errors.Is(err, qrdbsdk.ErrPINNotSet) {
		t.Fatalf("want ErrPINNotSet on an unprovisioned SRK, got %v", err)
	}
	if got := mock.verifyCalls.Load(); got != 0 {
		t.Fatalf("an unprovisioned SRK must not be sent an auth attempt, got %d", got)
	}
}

// TestTPM2Backend_ChangeOnUnconfirmedSRKReachesTPM covers PIN change on an
// SRK whose auth is unconfirmed. The current PIN is the proof of authority,
// so the attempt must reach the TPM rather than being refused for a reason
// the backend only believes about its own bookkeeping.
func TestTPM2Backend_ChangeOnUnconfirmedSRKReachesTPM(t *testing.T) {
	const current = "current-srk-auth"
	mock := unconfirmedSRK(current)
	b := NewTPM2Backend(mock)

	if err := b.ChangeUserPIN(current, "replacement-pin"); err != nil {
		t.Fatalf("ChangeUserPIN must remain available on a provisioned SRK: %v", err)
	}
	if got := mock.changeCalls.Load(); got != 1 {
		t.Fatalf("want the change to reach the TPM once, got %d calls", got)
	}
	if !b.UserPINSet() {
		t.Fatal("a successful change proved the current auth and installed " +
			"the new one, so the credential is known and UserPINSet must " +
			"report true afterwards")
	}
}

// TestTPM2Backend_FailedChangeDropsStaleConfirmation covers a PIN change that
// fails after the SRK has already been evicted.
//
// The backend caches its answer, so a credential confirmed earlier in the
// process would otherwise keep being reported as set even though the provider
// has withdrawn its readiness and what the SRK holds is unknown.
func TestTPM2Backend_FailedChangeDropsStaleConfirmation(t *testing.T) {
	const current = "current-srk-auth"
	mock := newMockPlatformAuth(current, true)
	b := NewTPM2Backend(mock)

	if !b.UserPINSet() {
		t.Fatal("precondition: the credential starts confirmed")
	}

	// The change fails, and the provider withdraws readiness the way
	// PlatformKeyStore does when the SRK may have been left evicted.
	mock.changeErr = errors.New("tpm: recreate primary failed")
	mock.authReady.Store(false)

	if err := b.ChangeUserPIN(current, "replacement-pin"); err == nil {
		t.Fatal("ChangeUserPIN must report the failure")
	}
	if b.UserPINSet() {
		t.Fatal("the provider no longer vouches for the auth value, so the " +
			"backend must not keep reporting the credential as set")
	}
}

// TestTPM2Backend_FailedChangeDropsCachedFIDO2Hash covers the other cache the
// backend holds. VerifyFIDO2Hash is consulted directly by callers that never
// look at UserPINSet, so a failed mid-change that leaves the SRK's contents
// unknown must not leave the previous PIN's digest still verifying.
func TestTPM2Backend_FailedChangeDropsCachedFIDO2Hash(t *testing.T) {
	const current = "current-srk-auth"
	mock := newMockPlatformAuth(current, true)
	b := NewTPM2Backend(mock)

	// Confirm the credential, which caches the FIDO2 digest.
	if err := b.VerifyUserPIN(current); err != nil {
		t.Fatalf("setup: VerifyUserPIN: %v", err)
	}
	digest := sha256.Sum256([]byte(current))
	if !b.VerifyFIDO2Hash(digest[:qrdbsdk.FIDO2PINHashSize]) {
		t.Fatal("precondition: the digest for the confirmed PIN must verify")
	}

	// The change fails after the SRK may have been evicted.
	mock.changeErr = errors.New("tpm: recreate primary failed")
	mock.authReady.Store(false)
	if err := b.ChangeUserPIN(current, "replacement-pin"); err == nil {
		t.Fatal("ChangeUserPIN must report the failure")
	}

	if b.VerifyFIDO2Hash(digest[:qrdbsdk.FIDO2PINHashSize]) {
		t.Fatal("the old PIN's digest must stop verifying once the backend " +
			"can no longer vouch for what the SRK holds")
	}
}
