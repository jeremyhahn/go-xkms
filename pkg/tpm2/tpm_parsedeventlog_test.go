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

package tpm2

import (
	"errors"
	"math"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
)

// TestParsedEventLog_MissingMeasurementsFile proves ParsedEventLog builds the
// same /sys/kernel/security/<device>/binary_bios_measurements path EventLog
// uses and surfaces ParseEventLog's error rather than panicking or returning
// a nil error with a nil event slice, for a device name that is guaranteed
// never to exist on the host running the test.
func TestParsedEventLog_MissingMeasurementsFile(t *testing.T) {
	tpm := &TPM2{
		config: &Config{Device: "/dev/tpmrm-go-xkms-test-fixture-873"},
	}

	events, err := tpm.ParsedEventLog()
	assert.Error(t, err)
	assert.Nil(t, events)
}

// TestReadChunk_RequestSizeExceedsUint16 proves readChunk rejects a chunk
// size larger than TPM2_GetRandom's BytesRequested field can hold (a
// uint16) before it ever builds the command, rather than truncating the
// value silently or letting the marshaler fail deep inside Execute. The
// session-encryption branches above the check run first but perform no TPM
// I/O, so this is exercised without a transport.
func TestReadChunk_RequestSizeExceedsUint16(t *testing.T) {
	tpm := &TPM2{config: &Config{}}
	data := make([]byte, 1)

	n, err := tpm.readChunk(data, math.MaxUint16+1)
	assert.Zero(t, n)
	assert.Error(t, err)
}

// TestChangeAuth_NoTransport proves ChangeAuth refuses to recreate a
// persistent primary key against a TPM2 that was never opened, rather than
// dereferencing a nil transport on its first VerifyAuth call.
func TestChangeAuth_NoTransport(t *testing.T) {
	tpm := &TPM2{}
	err := tpm.ChangeAuth(tpm2.TPMHandle(0x81000001), []byte("old"), []byte("new"))
	assert.ErrorIs(t, err, ErrTransportNotInitialized)
}

// TestPlatformPolicyBranchDigests_UnsupportedHashAlgorithm proves the
// PolicyPCR trial-calculator construction refuses a hash algorithm ID the
// TPM 2.0 library does not implement, before ever building a trial policy
// command -- and that the refusal is the typed ErrPlatformPolicyDigestCompute
// every other producer of a platform policy digest reports.
func TestPlatformPolicyBranchDigests_UnsupportedHashAlgorithm(t *testing.T) {
	branch1, branch2, err := platformPolicyBranchDigests(tpm2.TPMAlgID(0xFFFF), DefaultPlatformPCRs(), make([]byte, 32))
	assert.Nil(t, branch1)
	assert.Nil(t, branch2)
	assert.ErrorIs(t, err, ErrPlatformPolicyDigestCompute)
}

// TestPlatformPolicyORDigest_UnsupportedHashAlgorithm proves the PolicyOR
// trial-calculator construction refuses a hash algorithm ID the TPM 2.0
// library does not implement, mirroring platformPolicyBranchDigests' own
// refusal so both branch producers and the OR that combines them fail the
// same way for the same bad input.
func TestPlatformPolicyORDigest_UnsupportedHashAlgorithm(t *testing.T) {
	digest, err := platformPolicyORDigest(tpm2.TPMAlgID(0xFFFF), make([]byte, 32), make([]byte, 32))
	assert.Nil(t, digest)
	assert.ErrorIs(t, err, ErrPlatformPolicyDigestCompute)
}

// TestPlatformPolicyDigestFromPin_NilPin proves the function refuses a nil
// pin rather than dereferencing it, since a caller may pass through a
// lookup result (e.g. a backend read that found nothing) without checking
// it first.
func TestPlatformPolicyDigestFromPin_NilPin(t *testing.T) {
	digest, err := platformPolicyDigestFromPin(nil)
	assert.Zero(t, digest)
	assert.ErrorIs(t, err, ErrPlatformPolicyDigestCompute)
}

// TestPlatformPolicyDigestFromPin_UnsupportedHashAlgorithm proves a pin
// carrying an unsupported PCR bank algorithm is refused rather than
// producing a digest under an algorithm the TPM 2.0 library cannot compute.
func TestPlatformPolicyDigestFromPin_UnsupportedHashAlgorithm(t *testing.T) {
	pin := &store.PlatformPolicyPin{
		PCRBank:   0xFFFF,
		PCRSelect: DefaultPlatformPCRs().Mask(),
		PCRDigest: make([]byte, 32),
	}
	digest, err := platformPolicyDigestFromPin(pin)
	assert.Zero(t, digest)
	assert.ErrorIs(t, err, ErrPlatformPolicyDigestCompute)
}

// TestPlatformPolicyDigestHash_InvalidPCRBank proves PlatformPolicyDigestHash
// refuses a configured PCR bank name the package does not recognize before
// ever reading a live PCR, rather than falling back to a default bank the
// operator did not choose.
func TestPlatformPolicyDigestHash_InvalidPCRBank(t *testing.T) {
	tpm := &TPM2{config: &Config{PlatformPCRBank: "not-a-real-bank"}}
	digest, err := tpm.PlatformPolicyDigestHash()
	assert.Nil(t, digest)
	assert.ErrorIs(t, err, ErrInvalidPCRBankType)
}

// TestDevIDPlatformDelegation_InvalidPCRBank proves DevIDPlatformDelegation
// refuses a configured PCR bank name the package does not recognize before
// reading any PCR or building a trial policy, and wraps the refusal as
// ErrDevIDPolicySession like every other DevID policy-session failure.
func TestDevIDPlatformDelegation_InvalidPCRBank(t *testing.T) {
	tpm := &TPM2{config: &Config{PlatformPCRBank: "not-a-real-bank"}}
	delegation, err := tpm.DevIDPlatformDelegation(tpm2.TPMAlgSHA256)
	assert.Zero(t, delegation)
	assert.ErrorIs(t, err, ErrDevIDPolicySession)
}

// TestIsTPMAuthError_LockoutResponseCode proves isTPMAuthError classifies
// TPM_RC_LOCKOUT as an auth error via its typed-response-code check, the one
// branch its other callers' test coverage (TPM_RC_BAD_AUTH from a real
// simulator probe, and nil) never exercises.
func TestIsTPMAuthError_LockoutResponseCode(t *testing.T) {
	assert.True(t, isTPMAuthError(tpm2.TPMRC(0x921)), "TPM_RC_LOCKOUT must classify as an auth error")
}

// TestIsTPMAuthError_StringFallback proves the string-matching fallback
// isTPMAuthError uses for errors that do not carry a typed tpm2.TPMRC
// (older go-tpm versions, or an error wrapped without errors.As support)
// both recognizes the auth-failure substrings it documents and rejects an
// unrelated error.
func TestIsTPMAuthError_StringFallback(t *testing.T) {
	assert.True(t, isTPMAuthError(errors.New("session 1: TPM_RC_BAD_AUTH")))
	assert.True(t, isTPMAuthError(errors.New("handle 1: TPM_RC_AUTH_FAIL")))
	assert.False(t, isTPMAuthError(errors.New("connection reset by peer")))
}

// TestPlatformPolicySession_InvalidPCRBank proves platformPolicySession
// refuses a configured PCR bank name the package does not recognize before
// computing any branch digest or starting a TPM session.
func TestPlatformPolicySession_InvalidPCRBank(t *testing.T) {
	tpm := &TPM2{config: &Config{PlatformPCRBank: "not-a-real-bank"}}
	session, closer, err := tpm.platformPolicySession(nil, nil)
	assert.Nil(t, session)
	assert.Nil(t, closer)
	assert.ErrorIs(t, err, ErrPlatformPolicySession)
}

// TestPlatformPCRDigest_InvalidPCRBank proves platformPCRDigest re-validates
// the configured PCR bank itself rather than assuming a caller who already
// parsed it once (PlatformPolicyDigestHash, DevIDPlatformDelegation) is the
// only way in -- it is an unexported helper other package code can and does
// call directly with a bank algorithm of its own choosing.
func TestPlatformPCRDigest_InvalidPCRBank(t *testing.T) {
	tpm := &TPM2{config: &Config{PlatformPCRBank: "not-a-real-bank"}}
	digest, err := tpm.platformPCRDigest(tpm2.TPMAlgSHA256)
	assert.Nil(t, digest)
	assert.ErrorIs(t, err, ErrInvalidPCRBankType)
}
