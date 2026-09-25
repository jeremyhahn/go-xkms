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
	"errors"
	"os"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/testing/enclavetest"
)

// assertCacheRefused checks err is the typed cache failure carrying the
// allocator's budget refusal.
func assertCacheRefused(t *testing.T, op string, err error) {
	t.Helper()
	if !errors.Is(err, ErrFIDO2HashCacheFailed) {
		t.Fatalf("%s: err = %v, want ErrFIDO2HashCacheFailed", op, err)
	}
	if !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Fatalf("%s: err = %v, want the budget refusal as its cause", op, err)
	}
}

// Under a one-page process budget, every PIN path that caches the FIDO2
// hash must return a typed error when the budget refuses it -- never proceed
// silently -- and a refused ChangeUserPIN must not leave the OLD PIN's hash
// behind for VerifyFIDO2Hash to accept.
func TestTPM2Backend_FIDO2HashCache_RefusedByProcessBudget(t *testing.T) {
	if !enclavetest.RunWithBudget(t, int64(os.Getpagesize())) {
		return
	}

	oldHash := qrdbsdk.ComputeFIDO2PINHash("old-user-pin")
	newHash := qrdbsdk.ComputeFIDO2PINHash("new-user-pin")

	// The first hash fits and takes the whole page.
	b, _ := newProvisionedTPM2Backend(t, "old-user-pin")
	defer b.Close()
	if !b.VerifyFIDO2Hash(oldHash) {
		t.Fatal("the hash cached within budget must verify")
	}

	// The new hash is admitted before the old one is released, so the page
	// is still taken: the change must stand, the refusal must surface, and
	// the stale hash must be gone.
	assertCacheRefused(t, "ChangeUserPIN", b.ChangeUserPIN("old-user-pin", "new-user-pin"))
	if !b.UserPINSet() {
		t.Fatal("the TPM accepted the change, so the PIN must still be reported set")
	}
	if b.VerifyFIDO2Hash(oldHash) {
		t.Fatal("a refused cache must not leave the previous PIN's hash verifiable")
	}
	if b.VerifyFIDO2Hash(newHash) {
		t.Fatal("nothing was cached for the new PIN")
	}

	// Dropping the stale hash returned its page, so a later verify caches.
	if err := b.VerifyUserPIN("new-user-pin"); err != nil {
		t.Fatalf("VerifyUserPIN after the page was released: %v", err)
	}
	if !b.VerifyFIDO2Hash(newHash) {
		t.Fatal("VerifyUserPIN must cache the hash once the budget allows")
	}

	// With the page held by b, a second backend is refused on both paths
	// that cache, and still records what the TPM confirmed.
	other := NewTPM2Backend(newMockPlatformAuth("other-user-pin", true))
	defer other.Close()
	assertCacheRefused(t, "SetUserPIN", other.SetUserPIN("", "other-user-pin"))
	if !other.UserPINSet() {
		t.Fatal("SetUserPIN: the TPM confirmed the PIN, so it must be reported set")
	}
	assertCacheRefused(t, "VerifyUserPIN", other.VerifyUserPIN("other-user-pin"))
	if other.VerifyFIDO2Hash(qrdbsdk.ComputeFIDO2PINHash("other-user-pin")) {
		t.Fatal("a refused cache must leave nothing to verify against")
	}
}
