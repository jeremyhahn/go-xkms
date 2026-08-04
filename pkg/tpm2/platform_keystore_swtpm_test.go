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

package tpm2

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
)

// swtpmAddr is the swtpm command-channel address used by the hardware-backed
// PIN tests. When unreachable the tests skip (mirroring the existing
// simulator-guarded patterns) so unit runs without swtpm stay green.
const swtpmAddr = "127.0.0.1:2321"

const (
	swtpmPINHandle = 0x81000002
	swtpmGoodPIN   = "123456"
	swtpmBadPIN    = "999999"
)

// newSwtpmKeyStore connects to swtpm and returns a fresh PlatformKeyStore with
// the PIN SRK handle evicted so each test starts from a clean slate. It skips
// when swtpm is unreachable. The returned cleanup evicts the PIN handle and
// resets the DA lockout so the shared swtpm is left pristine.
func newSwtpmKeyStore(t *testing.T) (*PlatformKeyStore, *TPM2, func()) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", swtpmAddr, 500*time.Millisecond)
	if err != nil {
		t.Skipf("swtpm not reachable at %s: %v", swtpmAddr, err)
	}
	_ = conn.Close()

	tr, err := OpenTCPTransport(swtpmAddr, "")
	if err != nil {
		t.Skipf("swtpm OpenTCPTransport failed: %v", err)
	}
	// Close the swtpm connection on test exit even if setup fails below; swtpm
	// serves a single client, so a leaked connection blocks every later test.
	t.Cleanup(func() { _ = tr.(transport.TPMCloser).Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	config := &Config{
		Device:          "swtpm",
		Hash:            "SHA-256",
		EK:              DefaultConfig.EK,
		PlatformPCR:     16,
		PlatformPCRBank: PCRBankSHA256,
		PlatformSRK:     &PlatformSRKConfig{SRKHandle: swtpmPINHandle},
		SSRK:            &SRKConfig{Handle: swtpmPINHandle, KeyAlgorithm: "RSA", RSAConfig: &store.RSAConfig{KeySize: 2048}},
		Tracker:         nil,
	}

	tpmIface, err := NewTPM2(&Params{
		Logger:    logger,
		Config:    config,
		Transport: tr,
	})
	// NewTPM2 returns ErrNotInitialized when no persistent EK exists; the
	// transport is still usable for owner-hierarchy primary creation.
	if err != nil && !errors.Is(err, ErrNotInitialized) {
		t.Skipf("NewTPM2 against swtpm failed: %v", err)
	}
	tpm := tpmIface.(*TPM2)

	evictPINHandle(t, tpm)
	resetSwtpmDA(t, tpm)

	keyBackend := store.NewFileBackend(logger, storage.NewMemory())

	pks, err := NewPlatformKeyStore(logger, tpm, keyBackend, config, "")
	require.NoError(t, err)

	cleanup := func() {
		evictPINHandle(t, tpm)
		resetSwtpmDA(t, tpm)
	}
	return pks, tpm, cleanup
}

// evictPINHandle removes any persistent object at the PIN handle so a test can
// enroll from a clean state. A missing handle is not an error.
func evictPINHandle(t *testing.T, tpm *TPM2) {
	t.Helper()
	name, _, err := tpm.ReadHandle(swtpmPINHandle)
	if err != nil {
		return // nothing persisted
	}
	_, _ = tpm2.EvictControl{
		Auth:             tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		ObjectHandle:     &tpm2.NamedHandle{Handle: swtpmPINHandle, Name: name},
		PersistentHandle: swtpmPINHandle,
	}.Execute(tpm.transport)
}

// resetSwtpmDA clears the dictionary-attack lockout counter using the empty
// lockout auth (swtpm default).
func resetSwtpmDA(t *testing.T, tpm *TPM2) {
	t.Helper()
	_ = tpm.DictionaryAttackLockoutReset(nil)
}

func swtpmLockoutCounter(t *testing.T, tpm *TPM2) uint32 {
	t.Helper()
	props, err := tpm.FixedProperties()
	require.NoError(t, err)
	return props.LockoutCounter
}

// TestSwtpm_VerifyAuth_CorrectAndWrongPIN proves Fix 1: with the corrected
// auth-probe template, a correct PIN verifies and a wrong PIN returns
// ErrAuthFailed (the previous null-scheme template was rejected with
// TPM_RC_ATTRIBUTES for both, masking the PIN entirely).
func TestSwtpm_VerifyAuth_CorrectAndWrongPIN(t *testing.T) {
	pks, _, cleanup := newSwtpmKeyStore(t)
	defer cleanup()

	require.NoError(t, pks.EnrollPlatformSRK(swtpmGoodPIN))

	// Correct PIN verifies.
	require.NoError(t, pks.VerifyAuth(swtpmGoodPIN))

	// Wrong PIN is classified as an authorization failure, not masked.
	err := pks.VerifyAuth(swtpmBadPIN)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrAuthFailed)
}

// TestSwtpm_VerifyAuth_WithPlatformPolicy proves the corrected template also
// works when the SRK carries the platform PCR policy.
func TestSwtpm_VerifyAuth_WithPlatformPolicy(t *testing.T) {
	pks, _, cleanup := newSwtpmKeyStore(t)
	defer cleanup()
	pks.config.PlatformSRK.PlatformPolicy = true

	require.NoError(t, pks.EnrollPlatformSRK(swtpmGoodPIN))
	require.NoError(t, pks.VerifyAuth(swtpmGoodPIN))
	require.ErrorIs(t, pks.VerifyAuth(swtpmBadPIN), ErrAuthFailed)
}

// TestSwtpm_EnrollPlatformSRK_Idempotent proves Fix 4: the first enrollment
// succeeds and a second enrollment is a no-op returning the typed
// ErrPlatformSRKAlreadyEnrolled sentinel. An empty PIN is rejected.
func TestSwtpm_EnrollPlatformSRK_Idempotent(t *testing.T) {
	pks, _, cleanup := newSwtpmKeyStore(t)
	defer cleanup()

	require.ErrorIs(t, pks.EnrollPlatformSRK(""), ErrPlatformSRKEnrollEmptyPIN)

	require.NoError(t, pks.EnrollPlatformSRK(swtpmGoodPIN))
	require.True(t, pks.IsAuthReady())

	// Second enrollment must be idempotent.
	require.ErrorIs(t, pks.EnrollPlatformSRK(swtpmGoodPIN), ErrPlatformSRKAlreadyEnrolled)

	// PIN still verifies after the idempotent call.
	require.NoError(t, pks.VerifyAuth(swtpmGoodPIN))
}

// TestSwtpm_WrongPIN_IncrementsDA proves Fix 3: with NoDA cleared on the PIN
// SRK, each wrong PIN increments the TPM dictionary-attack counter, while a
// correct PIN does not, and the counter resets cleanly afterwards.
func TestSwtpm_WrongPIN_IncrementsDA(t *testing.T) {
	pks, tpm, cleanup := newSwtpmKeyStore(t)
	defer cleanup()

	require.NoError(t, pks.EnrollPlatformSRK(swtpmGoodPIN))

	// Confirm DA protection is enabled on the enrolled SRK template.
	require.False(t, pks.SRKAttributes().TPMAttributes.Template.ObjectAttributes.NoDA,
		"PIN SRK must have NoDA cleared so wrong PINs trip DA protection")

	resetSwtpmDA(t, tpm)
	before := swtpmLockoutCounter(t, tpm)

	// A single wrong PIN must increment the DA counter.
	require.ErrorIs(t, pks.VerifyAuth(swtpmBadPIN), ErrAuthFailed)
	after := swtpmLockoutCounter(t, tpm)
	require.Greaterf(t, after, before,
		"wrong PIN must increment DA counter (before=%d after=%d)", before, after)

	// Reset and confirm a correct PIN does NOT increment the counter.
	resetSwtpmDA(t, tpm)
	baseline := swtpmLockoutCounter(t, tpm)
	require.NoError(t, pks.VerifyAuth(swtpmGoodPIN))
	require.Equal(t, baseline, swtpmLockoutCounter(t, tpm),
		"correct PIN must not increment DA counter")
}
