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

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildSecretRegistry_NilCredentialService verifies that buildSecretRegistry
// returns a non-nil registry even when the server has no credential service.
// The registry must not match any credential:// URI because no resolver is registered.
func TestBuildSecretRegistry_NilCredentialService(t *testing.T) {
	t.Parallel()

	s := &Server{credentialService: nil}
	reg := s.buildSecretRegistry()

	require.NotNil(t, reg, "registry must never be nil")
	assert.False(t, reg.IsSecretURI("credential://any-ref"),
		"no credential resolver registered — IsSecretURI must return false")
}

// TestBuildSecretRegistry_WithCredentialService verifies that buildSecretRegistry
// registers a credential:// resolver when the server has a credential service,
// and that the resolver correctly routes lookups through that service.
func TestBuildSecretRegistry_WithCredentialService(t *testing.T) {
	t.Parallel()

	// Use the "manual" strategy so New() needs no barrier or platform store.
	svc, err := credentialspkg.New(
		&credentialspkg.Config{Strategy: credentialspkg.StrategyManual},
		nil, // platformStore — not required for StrategyManual
		nil, // barrier      — not required for StrategyManual
		nil, // logger       — defaults to slog.Default()
	)
	require.NoError(t, err)

	// Pre-load a credential so RetrieveCredential can return it synchronously.
	const credName = "test-cred"
	const credValue = "hunter2"
	require.NoError(t, svc.StoreCredential(context.Background(), credName, []byte(credValue)))

	s := &Server{credentialService: svc}
	reg := s.buildSecretRegistry()

	require.NotNil(t, reg)
	assert.True(t, reg.IsSecretURI("credential://"+credName),
		"registry must recognise credential:// URIs after registration")

	// Full resolution round-trip. WithBytes borrows the plaintext for the
	// duration of the callback — the same shape the production path uses to
	// move a resolved credential into a types.SecretValue-typed config field
	// without ever materializing it as a Go string.
	sv, err := reg.Resolve(context.Background(), "credential://"+credName)
	require.NoError(t, err)
	var got string
	require.NoError(t, sv.WithBytes(func(b []byte) error {
		got = string(b)
		return nil
	}))
	assert.Equal(t, credValue, got)
	sv.Clear()
}

// newSecretWiringTestConfig builds a *config.Config touching several
// independent SecretValue fields scattered across the loaded configuration
// tree (barrier, RNG PKCS#11, the PKCS#11 backend, and Vault), the same shape
// resolveConfigSecrets walks once from Server.New.
func newSecretWiringTestConfig() *config.Config {
	return &config.Config{
		Barrier: config.BarrierConfig{
			Passphrase: types.SecretValue{Raw: "dev-only-passphrase"},
		},
		RNG: config.RNGConfig{
			PKCS11: &config.RNGPKCS11Config{
				// Empty Raw: not configured.
			},
		},
		Backends: config.BackendsConfig{
			PKCS11: &config.PKCS11Config{
				Pin: types.SecretValue{Raw: "1234"},
			},
			Vault: &config.VaultConfig{},
		},
	}
}

// TestResolveConfigSecrets_LiteralAndEmptyFieldsAreNoOps proves that
// resolveConfigSecrets leaves an operator-supplied literal value (no
// recognized scheme) and an unconfigured (empty Raw) SecretValue field alone:
// neither is a reference this server's registry could claim, so the walker
// reports both as qrdbsecret.UnresolvableTargetError internally, and
// resolveConfigSecrets tolerates that and returns nil. types.SecretValueBytes
// on each field afterwards proves nothing was disturbed.
func TestResolveConfigSecrets_LiteralAndEmptyFieldsAreNoOps(t *testing.T) {
	t.Parallel()

	cfg := newSecretWiringTestConfig()
	s := &Server{ctx: context.Background(), config: cfg}

	require.NoError(t, s.resolveConfigSecrets())

	got, err := types.SecretValueBytes(&cfg.Barrier.Passphrase)
	require.NoError(t, err)
	assert.Equal(t, "dev-only-passphrase", string(got))

	got, err = types.SecretValueBytes(&cfg.Backends.PKCS11.Pin)
	require.NoError(t, err)
	assert.Equal(t, "1234", string(got))

	got, err = types.SecretValueBytes(&cfg.RNG.PKCS11.PIN)
	require.NoError(t, err)
	assert.Nil(t, got, "an unconfigured field must resolve to nil, not an error")

	got, err = types.SecretValueBytes(&cfg.Backends.Vault.Token)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// TestResolveConfigSecrets_ResolvesReferenceAcrossConfig proves that a
// credential:// reference anywhere in the loaded configuration resolves
// through the one resolveConfigSecrets pass, alongside literal and
// unconfigured fields elsewhere in the same config, which are left
// untouched.
func TestResolveConfigSecrets_ResolvesReferenceAcrossConfig(t *testing.T) {
	t.Parallel()

	svc, err := credentialspkg.New(
		&credentialspkg.Config{Strategy: credentialspkg.StrategyManual},
		nil, nil, nil,
	)
	require.NoError(t, err)

	const credName = "vault-token"
	const credValue = "s.abcdef123456"
	require.NoError(t, svc.StoreCredential(context.Background(), credName, []byte(credValue)))

	cfg := newSecretWiringTestConfig()
	cfg.Backends.Vault.Token = types.SecretValue{Raw: "credential://" + credName}

	s := &Server{ctx: context.Background(), config: cfg, credentialService: svc}
	require.NoError(t, s.resolveConfigSecrets())

	got, err := types.SecretValueBytes(&cfg.Backends.Vault.Token)
	require.NoError(t, err)
	assert.Equal(t, credValue, string(got))

	// The literal and unconfigured fields elsewhere in the same config are
	// unaffected by the reference resolved next to them.
	got, err = types.SecretValueBytes(&cfg.Barrier.Passphrase)
	require.NoError(t, err)
	assert.Equal(t, "dev-only-passphrase", string(got))

	got, err = types.SecretValueBytes(&cfg.RNG.PKCS11.PIN)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// TestResolveConfigSecrets_UnresolvableReferenceFailsClosed proves that a
// credential:// reference this server's registry claims but cannot satisfy
// fails resolveConfigSecrets with the typed *ErrConfigSecretResolution,
// distinct from the tolerated empty/literal cases above.
func TestResolveConfigSecrets_UnresolvableReferenceFailsClosed(t *testing.T) {
	t.Parallel()

	svc, err := credentialspkg.New(
		&credentialspkg.Config{Strategy: credentialspkg.StrategyManual},
		nil, nil, nil,
	)
	require.NoError(t, err)

	cfg := newSecretWiringTestConfig()
	cfg.Backends.Vault.Token = types.SecretValue{Raw: "credential://does-not-exist"}

	// The "manual" strategy blocks RetrieveCredential until the operator
	// submits the named credential or the context is cancelled; bound it so
	// this test proves the failure instead of hanging on one that never
	// arrives.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	s := &Server{ctx: ctx, config: cfg, credentialService: svc}
	resolveErr := s.resolveConfigSecrets()
	require.Error(t, resolveErr)

	var typedErr *ErrConfigSecretResolution
	require.True(t, errors.As(resolveErr, &typedErr),
		"error must unwrap to *ErrConfigSecretResolution, got %v", resolveErr)
}
