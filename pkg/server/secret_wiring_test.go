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
// independent *SecretValue fields scattered across the loaded configuration
// tree (RNG PKCS#11, the PKCS#11 backend, and Vault), the same shape
// resolveConfigSecrets walks once from Server.New. Every field starts nil
// (unconfigured): go-qrdb's secret.ConfigProcessor skips a nil pointer
// before it can ever become a protected-target failure, which is the ONLY
// silent case in its contract (go-xkms#653/#654).
func newSecretWiringTestConfig() *config.Config {
	return &config.Config{
		RNG: config.RNGConfig{
			PKCS11: &config.RNGPKCS11Config{
				// PIN stays nil: not configured.
			},
		},
		Backends: config.BackendsConfig{
			PKCS11: &config.PKCS11Config{
				// Pin stays nil: not configured.
			},
			Vault: &config.VaultConfig{},
		},
	}
}

// TestResolveConfigSecrets_UnconfiguredFieldsAreNoOps proves that
// resolveConfigSecrets leaves every unconfigured (nil) *SecretValue field
// alone and reports no error: a nil pointer is how an optional secret is
// spelled under go-qrdb's protected-target contract, and the walker skips it
// before it can ever become a failure. types.SecretValueBytes on each field
// afterwards proves nothing was disturbed.
func TestResolveConfigSecrets_UnconfiguredFieldsAreNoOps(t *testing.T) {
	t.Parallel()

	cfg := newSecretWiringTestConfig()
	s := &Server{ctx: context.Background(), config: cfg}

	require.NoError(t, s.resolveConfigSecrets())

	got, err := types.SecretValueBytes(cfg.Backends.PKCS11.Pin)
	require.NoError(t, err)
	assert.Nil(t, got, "an unconfigured field must resolve to nil, not an error")

	got, err = types.SecretValueBytes(cfg.RNG.PKCS11.PIN)
	require.NoError(t, err)
	assert.Nil(t, got)

	got, err = types.SecretValueBytes(cfg.Backends.Vault.Token)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// TestResolveConfigSecrets_LiteralFailsClosed proves go-xkms#654's core fix:
// an operator-supplied literal value (no recognized scheme) in a protected
// *SecretValue field is refused, not silently tolerated — go-qrdb's
// protected-target contract requires a REFERENCE to a secret held
// elsewhere, and an inline value is refused whatever field it is in.
func TestResolveConfigSecrets_LiteralFailsClosed(t *testing.T) {
	t.Parallel()

	cfg := newSecretWiringTestConfig()
	cfg.Backends.PKCS11.Pin = &types.SecretValue{Raw: "1234"}
	s := &Server{ctx: context.Background(), config: cfg}

	resolveErr := s.resolveConfigSecrets()
	require.Error(t, resolveErr)

	var typedErr *ErrConfigSecretResolution
	require.True(t, errors.As(resolveErr, &typedErr),
		"error must unwrap to *ErrConfigSecretResolution, got %v", resolveErr)
}

// TestResolveConfigSecrets_ResolvesReferenceAcrossConfig proves that a
// credential:// reference anywhere in the loaded configuration resolves
// through the one resolveConfigSecrets pass, alongside unconfigured fields
// elsewhere in the same config, which are left untouched.
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
	cfg.Backends.Vault.Token = &types.SecretValue{Raw: "credential://" + credName}

	s := &Server{ctx: context.Background(), config: cfg, credentialService: svc}
	require.NoError(t, s.resolveConfigSecrets())

	got, err := types.SecretValueBytes(cfg.Backends.Vault.Token)
	require.NoError(t, err)
	assert.Equal(t, credValue, string(got))

	// The unconfigured fields elsewhere in the same config are unaffected by
	// the reference resolved next to them.
	got, err = types.SecretValueBytes(cfg.Backends.PKCS11.Pin)
	require.NoError(t, err)
	assert.Nil(t, got)

	got, err = types.SecretValueBytes(cfg.RNG.PKCS11.PIN)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// TestBackendCredentials_ResolveViaCredentialReference proves go-xkms#653's
// approved item 2 end to end: now that resolveConfigSecrets runs BEFORE
// initializeBackends (see Server.New), every one of the five backend
// credential fields that used to be read too early to benefit — the PKCS#11
// backend's PIN, the RNG PKCS#11 module's PIN, the AWS KMS secret key, the
// Azure Key Vault client secret, and the Vault token — resolves a
// credential:// reference through the same one-pass walk a CA password or
// the phone backend's Noise static key already used. This is the same
// resolution mechanism TestResolveConfigSecrets_ResolvesReferenceAcrossConfig
// exercises for one field; this test names all five explicitly because that
// completeness is the point of the reorder.
func TestBackendCredentials_ResolveViaCredentialReference(t *testing.T) {
	t.Parallel()

	svc, err := credentialspkg.New(
		&credentialspkg.Config{Strategy: credentialspkg.StrategyManual},
		nil, nil, nil,
	)
	require.NoError(t, err)

	creds := map[string]string{
		"pkcs11-pin":     "1234",
		"rng-pkcs11-pin": "5678",
		"aws-secret-key": "aws-secret-value",
		"azure-secret":   "azure-secret-value",
		"vault-token":    "s.abcdef123456",
	}
	for name, value := range creds {
		require.NoError(t, svc.StoreCredential(context.Background(), name, []byte(value)))
	}

	cfg := &config.Config{
		RNG: config.RNGConfig{
			PKCS11: &config.RNGPKCS11Config{
				PIN: &types.SecretValue{Raw: "credential://rng-pkcs11-pin"},
			},
		},
		Backends: config.BackendsConfig{
			PKCS11: &config.PKCS11Config{
				Pin: &types.SecretValue{Raw: "credential://pkcs11-pin"},
			},
			AWSKMS: &config.AWSKMSConfig{
				SecretKey: &types.SecretValue{Raw: "credential://aws-secret-key"},
			},
			AzureKV: &config.AzureKVConfig{
				ClientSecret: &types.SecretValue{Raw: "credential://azure-secret"},
			},
			Vault: &config.VaultConfig{
				Token: &types.SecretValue{Raw: "credential://vault-token"},
			},
		},
	}

	s := &Server{ctx: context.Background(), config: cfg, credentialService: svc}
	require.NoError(t, s.resolveConfigSecrets())

	cases := []struct {
		name string
		sv   *types.SecretValue
		want string
	}{
		{"backends.pkcs11.pin", cfg.Backends.PKCS11.Pin, "1234"},
		{"rng.pkcs11.pin", cfg.RNG.PKCS11.PIN, "5678"},
		{"backends.awskms.secret_key", cfg.Backends.AWSKMS.SecretKey, "aws-secret-value"},
		{"backends.azurekv.client_secret", cfg.Backends.AzureKV.ClientSecret, "azure-secret-value"},
		{"backends.vault.token", cfg.Backends.Vault.Token, "s.abcdef123456"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := types.SecretValueBytes(tc.sv)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(got))
		})
	}
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
	cfg.Backends.Vault.Token = &types.SecretValue{Raw: "credential://does-not-exist"}

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
