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

package services

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	pkgstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/sdk/go/vaulttoken"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

var errNoSuchBackend = errors.New("no such backend")

// withKeyBackend gives the service one software key backend, named name,
// holding an EC P-256 key keyID, and returns it.
func withKeyBackend(t *testing.T, svc *StaticPasswordService, name, keyID string) pkgxkms.Backend {
	t.Helper()
	kp, err := software.NewBackend(&software.Config{KeyStorage: pkgstorage.New()})
	require.NoError(t, err)
	b, err := pkgxkms.New(&pkgxkms.BackendConfig{Backend: kp, CertStorage: pkgstorage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	_, err = b.GenerateECDSA(context.Background(), &types.KeyAttributes{
		CN: keyID, KeyType: types.KeyTypeEncryption, StoreType: b.Type(),
		KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)
	svc.keyLookup = func(n string) (pkgxkms.Backend, error) {
		if n == name {
			return b, nil
		}
		return nil, errNoSuchBackend
	}
	return b
}

func TestKeyFactor_EnrollLockUnlockRecover(t *testing.T) {
	v := newPasskeyVault(t, newVaultSimKey("123456"))
	withKeyBackend(t, v.svc, "tpm2", "vault-tpm")

	res, err := v.svc.EnrollKeyFactor(vaulttoken.FactorTPM, "tpm2", "vault-tpm", "platform", "this laptop")
	require.NoError(t, err)
	require.NotEmpty(t, res.RecoveryCode)
	assert.Equal(t, "tpm", res.Factor.Factor)
	assert.Equal(t, "platform", res.Factor.TPMPolicy)
	assert.Len(t, res.Factor.KeyFingerprint, 64)

	v.lock(t)
	require.NoError(t, v.svc.UnlockWithKeyFactor())
	assert.True(t, v.status(t).Unlocked)

	// Recovery enrolls another key factor with the one-time code.
	v.lock(t)
	withKeyBackend(t, v.svc, "pkcs11", "piv-9d")
	recovered, err := v.svc.RecoverWithKeyFactor(res.RecoveryCode, vaulttoken.FactorTPM, "pkcs11", "piv-9d", "", "backup key")
	require.NoError(t, err)
	assert.NotEqual(t, res.RecoveryCode, recovered.RecoveryCode)
}

func TestKeyFactor_Refusals(t *testing.T) {
	v := newPasskeyVault(t, newVaultSimKey("123456"))
	withKeyBackend(t, v.svc, "software", "k")

	_, err := v.svc.EnrollKeyFactor(vaulttoken.FactorCertificate, "software", "k", "", "")
	assert.ErrorIs(t, err, vaulttoken.ErrCertificateRequired)
	_, err = v.svc.EnrollKeyFactor(vaulttoken.FactorTPM, "hsm", "k", "", "")
	var backendErr *vaulttoken.BackendError
	assert.ErrorAs(t, err, &backendErr, "a backend xKey does not run")
	_, err = v.svc.RecoverWithKeyFactor("", vaulttoken.FactorTPM, "software", "k", "", "")
	assert.ErrorIs(t, err, ErrStaticPWRecoveryCodeRequired)

	_, err = v.svc.EnrollPassphrase("first passphrase", "pp")
	require.NoError(t, err)
	v.lock(t)
	assert.ErrorIs(t, v.svc.UnlockWithKeyFactor(), vaulttoken.ErrNoKeyFactor)

	noClient := NewStaticPasswordService(nil)
	_, err = noClient.EnrollKeyFactor(vaulttoken.FactorTPM, "software", "k", "", "")
	assert.ErrorIs(t, err, ErrStaticPWNoClient)
	assert.ErrorIs(t, noClient.UnlockWithKeyFactor(), ErrStaticPWNoClient)
}

// browserBridge is a vault with a TPM key factor and a recorder of the
// approval prompts the app shows.
type browserBridge struct {
	*passkeyVault
	fingerprint string
	mu          sync.Mutex
	requests    []events.VaultBrowserUnlockRequestPayload
	resolved    []events.VaultBrowserUnlockResolvedPayload
	answer      func(id string)
}

func newBrowserBridge(t *testing.T) *browserBridge {
	t.Helper()
	v := newPasskeyVault(t, newVaultSimKey("123456"))
	withKeyBackend(t, v.svc, "tpm2", "vault-tpm")
	res, err := v.svc.EnrollKeyFactor(vaulttoken.FactorTPM, "tpm2", "vault-tpm", "platform", "laptop")
	require.NoError(t, err)
	v.lock(t)
	b := &browserBridge{passkeyVault: v, fingerprint: res.Factor.KeyFingerprint}
	v.svc.SetEventEmitter(func(evt events.Event) {
		b.mu.Lock()
		defer b.mu.Unlock()
		switch p := evt.Payload.(type) {
		case events.VaultBrowserUnlockRequestPayload:
			b.requests = append(b.requests, p)
			if b.answer != nil {
				go b.answer(p.ID)
			}
		case events.VaultBrowserUnlockResolvedPayload:
			b.resolved = append(b.resolved, p)
		}
	})
	return b
}

func TestBrowserBridge_ApprovedRequestUnlocksWithoutReturningASecret(t *testing.T) {
	b := newBrowserBridge(t)
	b.answer = func(id string) { assert.NoError(t, b.svc.ApproveBrowserVaultRequest(id)) }

	err := b.svc.BrowserUnlockWithKeyFactor(b.ctx, "https://kms.example.com", []string{b.fingerprint})
	require.NoError(t, err)
	assert.True(t, b.status(t).Unlocked, "xKey unlocked the vault itself; the page receives no secret")
	require.Len(t, b.requests, 1)
	assert.Equal(t, "https://kms.example.com", b.requests[0].Origin)
	assert.Equal(t, []string{"TPM key (laptop)"}, b.requests[0].Factors)
	assert.True(t, b.resolved[0].Approved)
}

func TestBrowserBridge_WrongOriginIsRefusedBeforeAnyPrompt(t *testing.T) {
	b := newBrowserBridge(t)
	for _, origin := range []string{
		"https://evil.example.org",
		"https://kms.example.com.evil.org",
		"http://kms.example.com",
		"https://notkms.example.com",
		"https://kms.example.com/path",
		"chrome-extension://abc",
	} {
		err := b.svc.BrowserUnlockWithKeyFactor(b.ctx, origin, []string{b.fingerprint})
		assert.ErrorIs(t, err, ErrBrowserVaultOriginRefused, origin)
	}
	assert.Empty(t, b.requests, "a refused origin never reaches the user")
	assert.False(t, b.status(t).Unlocked)
}

func TestBrowserBridge_DeniedTimedOutAndMismatched(t *testing.T) {
	b := newBrowserBridge(t)
	b.answer = func(id string) { assert.NoError(t, b.svc.DenyBrowserVaultRequest(id)) }
	err := b.svc.BrowserUnlockWithKeyFactor(b.ctx, "https://kms.example.com", []string{b.fingerprint})
	assert.ErrorIs(t, err, ErrBrowserVaultDenied)
	assert.False(t, b.status(t).Unlocked)

	b.answer = nil
	b.svc.browser.timeout = 10 * time.Millisecond
	err = b.svc.BrowserUnlockWithKeyFactor(b.ctx, "https://kms.example.com", []string{b.fingerprint})
	assert.ErrorIs(t, err, ErrBrowserVaultApprovalTimeout)

	err = b.svc.BrowserUnlockWithKeyFactor(b.ctx, "https://kms.example.com", []string{"another-users-key"})
	assert.ErrorIs(t, err, ErrBrowserVaultUserMismatch)
	err = b.svc.BrowserUnlockWithKeyFactor(b.ctx, "https://kms.example.com", nil)
	assert.ErrorIs(t, err, ErrBrowserVaultNoKeyFactor)

	assert.ErrorIs(t, b.svc.ApproveBrowserVaultRequest("nope"), ErrBrowserVaultRequestNotFound)
}

func TestConsoleOriginAllowed(t *testing.T) {
	cases := []struct {
		origin, rp string
		want       bool
	}{
		{"https://kms.example.com", "kms.example.com", true},
		{"https://kms.example.com:8443", "kms.example.com", true},
		{"https://console.kms.example.com", "kms.example.com", true},
		{"http://localhost:5180", "localhost", true},
		{"https://kms.example.com", "", false},
		{"http://kms.example.com", "kms.example.com", false},
		{"https://example.com", "kms.example.com", false},
		{"https://user@kms.example.com", "kms.example.com", false},
		{"https://kms.example.com?x=1", "kms.example.com", false},
		{"not a url", "kms.example.com", false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, ConsoleOriginAllowed(tc.origin, tc.rp), tc.origin)
	}
}
