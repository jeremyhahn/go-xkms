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
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newAuthReadyKeyStore builds a PlatformKeyStore over a mock TPM whose SRK
// handle is readable. verifyErr controls whether the SRK accepts an auth
// value, which is the only thing that can confirm it.
func newAuthReadyKeyStore(t *testing.T, verifyErr error) *PlatformKeyStore {
	t.Helper()
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		verifyAuthErr: verifyErr,
	}
	pks, err := NewPlatformKeyStore(slog.Default(), mock, &mockKeyBackendForPKS{}, mock.config, "")
	require.NoError(t, err)
	require.True(t, pks.IsProvisioned(), "precondition: the SRK handle must be readable")
	return pks
}

// TestPlatformKeyStore_VerifyAuthRecordsReadiness checks that a successful
// auth confirms the SRK's auth value for the rest of the process.
//
// The TPM PIN backend derives its initial "is a user PIN configured" answer
// from IsAuthReady. PIN backends are re-selected on several paths, so if a
// successful VerifyAuth did not record readiness, a backend built later would
// report the credential as unset and decline to check it even though this
// process had just proven it.
func TestPlatformKeyStore_VerifyAuthRecordsReadiness(t *testing.T) {
	pks := newAuthReadyKeyStore(t, nil)
	require.False(t, pks.IsAuthReady(), "precondition: auth starts unconfirmed")

	require.NoError(t, pks.VerifyAuth("srk-auth-value"))

	assert.True(t, pks.IsAuthReady(),
		"a successful auth confirms the SRK auth value, so IsAuthReady must "+
			"report true afterwards")
}

// TestPlatformKeyStore_FailedVerifyLeavesAuthUnconfirmed is the other half: a
// rejected credential proves nothing about the SRK's auth value.
func TestPlatformKeyStore_FailedVerifyLeavesAuthUnconfirmed(t *testing.T) {
	pks := newAuthReadyKeyStore(t, ErrAuthFailed)

	require.Error(t, pks.VerifyAuth("wrong-auth-value"))

	assert.False(t, pks.IsAuthReady(),
		"a rejected credential must not mark the auth value known-good")
}

// TestPlatformKeyStore_ChangeAuthRecordsReadiness covers a PIN change: the
// store proved the old auth and installed the new one, so the auth value the
// SRK now holds is the one this application chose.
func TestPlatformKeyStore_ChangeAuthRecordsReadiness(t *testing.T) {
	pks := newAuthReadyKeyStore(t, nil)
	require.False(t, pks.IsAuthReady(), "precondition: auth starts unconfirmed")

	require.NoError(t, pks.ChangeAuth("current-auth-value", "replacement-auth-value"))

	assert.True(t, pks.IsAuthReady())
}

// TestPlatformKeyStore_ChangeAuthFailureLeavesAuthUnconfirmed covers a change
// rejected for the current auth value.
func TestPlatformKeyStore_ChangeAuthFailureLeavesAuthUnconfirmed(t *testing.T) {
	pks := newAuthReadyKeyStore(t, ErrAuthFailed)

	require.Error(t, pks.ChangeAuth("wrong-current-value", "replacement-auth-value"))

	assert.False(t, pks.IsAuthReady())
}

// TestPlatformKeyStore_FailedChangeClearsReadinessAfterVerify is the case the
// verification step creates. ChangeAuth verifies the current value first,
// which marks the auth known-good, and only then changes it — and changing it
// evicts the persistent SRK before recreating and re-persisting it. If that
// fails part-way there may be no key at the expected handle, so readiness
// established moments earlier is no longer true and must not be left standing:
// callers read it to skip enrollment and to decide a credential exists.
func TestPlatformKeyStore_FailedChangeClearsReadinessAfterVerify(t *testing.T) {
	mock := &mockTPMForPKS{
		config: testConfigForPKS(false),
		// The current value is accepted, so VerifyAuth succeeds...
		verifyAuthErr: nil,
		// ...and the change itself then fails, mid-eviction.
		changeAuthErr: ErrAuthChangeRecreate,
	}
	pks, err := NewPlatformKeyStore(slog.Default(), mock, &mockKeyBackendForPKS{}, mock.config, "")
	require.NoError(t, err)

	require.Error(t, pks.ChangeAuth("current-auth-value", "replacement-auth-value"))

	assert.False(t, pks.IsAuthReady(),
		"a change that failed after evicting the SRK leaves its state unknown, "+
			"so the auth value must not still be reported as known-good")
}
