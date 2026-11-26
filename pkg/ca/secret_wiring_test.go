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

package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secret"
	pkcs8backend "github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestCredentialRegistry returns a registry with a CredentialResolver
// backed by the provided static map of credential name → plaintext value.
func buildTestCredentialRegistry(creds map[string]string) *secret.ResolverRegistry {
	reg := secret.NewResolverRegistry()
	retrieve := func(_ context.Context, name string) (*secure.Buffer, error) {
		v, ok := creds[name]
		if !ok {
			return nil, &errs.Message{Msg: fmt.Sprintf("credential not found: %s", name)}
		}
		if v == "" {
			return secure.NewEmptyBuffer(), nil
		}
		return secure.NewBufferFromBytes([]byte(v))
	}
	reg.Register(secret.NewCredentialResolver(retrieve))
	return reg
}

// TestCA_CredentialPassword_EncryptedAtRest verifies the full resolution flow:
//
//  1. A KeyConfig with Password = "credential://ca-key-pw" is resolved through
//     a registry whose credential resolver returns "correct-horse-battery-staple".
//  2. The resulting KeyAttributes carry the resolved password.
//  3. A pkcs8 backend with AllowPlaintextKeys=false generates an encrypted key
//     that is NOT parseable as plaintext PKCS#8 PrivateKeyInfo (x509.ParsePKCS8PrivateKey
//     only handles unencrypted PrivateKeyInfo, not EncryptedPrivateKeyInfo).
func TestCA_CredentialPassword_EncryptedAtRest(t *testing.T) {
	t.Parallel()

	const credName = "ca-key-pw"
	const credValue = "correct-horse-battery-staple"

	reg := buildTestCredentialRegistry(map[string]string{credName: credValue})

	cfg := &types.KeyConfig{
		CN:           "Test Root CA",
		KeyAlgorithm: types.AlgorithmECDSA,
		KeyType:      types.KeyTypeStringCA,
		Password:     &types.SecretValue{Raw: "credential://" + credName},
	}

	attrs, err := types.KeyAttributesFromConfigResolved(context.Background(), cfg, reg)
	require.NoError(t, err)
	require.NotNil(t, attrs.Password, "resolved password must be non-nil")

	// Verify the password was resolved correctly.
	pw := attrs.Password.Bytes()
	defer secure.Wipe(pw)
	assert.Equal(t, credValue, string(pw), "password must equal the retrieved credential value")

	// Generate a CA key using a fail-closed pkcs8 backend and assert it is
	// encrypted at rest (mirroring TestGenerateKey_WithPassword_ProducesEncryptedPKCS8).
	keyStorage := storage.NewMemory()
	be, err := pkcs8backend.NewBackend(&pkcs8backend.Config{
		KeyStorage:         keyStorage,
		AllowPlaintextKeys: false,
	})
	require.NoError(t, err)
	defer func() { _ = be.Close() }()

	_, err = be.GenerateKey(context.Background(), attrs)
	require.NoError(t, err, "key generation with a resolved credential password must succeed")

	// (a) Raw DER must not parse as unencrypted PKCS#8 PrivateKeyInfo.
	rawDER, err := storage.GetKey(context.Background(), keyStorage, attrs.ID())
	require.NoError(t, err)
	_, parseErr := x509.ParsePKCS8PrivateKey(rawDER)
	assert.Error(t, parseErr, "raw DER must not parse as plaintext PKCS#8 — key is NOT encrypted at rest")
}

// TestCA_EmptyPassword_AllowedByDefault verifies that CA initialization with
// an empty (nil) key password succeeds when RequireKeyPassword is false (the
// default). An empty password is a legitimate operator choice: the key is
// written as plaintext PKCS#8, which is acceptable when the storage layer
// already provides equivalent protection.
func TestCA_EmptyPassword_AllowedByDefault(t *testing.T) {
	t.Parallel()

	// rootIdentity carries no KeyConfig.Password, so attrs.Password will be nil.
	root, _, err := NewCA(context.Background(), &Params{
		Identity:        []Identity{rootIdentity("NoPassword Root CA")},
		KeyStore:        newInMemoryBackend(t),
		BackendForStore: singleBackendFactory(newInMemoryBackend(t)),
		RevocationStore: storage.NewMemory(),
		CertStore:       newInMemoryCertStore(t),
		// RequireKeyPassword defaults to false — plaintext key is allowed.
	})
	require.NoError(t, err, "CA init with empty password must succeed when RequireKeyPassword=false (default)")
	require.NotNil(t, root)
	assert.True(t, root.IsInitialized(), "CA must be marked initialized after successful Init")
}

// TestCA_RequireKeyPassword_RejectsEmptyPassword verifies that when
// RequireKeyPassword=true is set, CA initialization with an empty (nil) key
// password returns ErrKeyPasswordRequired before any key-generation I/O.
func TestCA_RequireKeyPassword_RejectsEmptyPassword(t *testing.T) {
	t.Parallel()

	// rootIdentity carries no KeyConfig.Password — attrs.Password will be nil.
	_, _, err := NewCA(context.Background(), &Params{
		Identity:           []Identity{rootIdentity("RequirePW Root CA")},
		KeyStore:           newInMemoryBackend(t),
		BackendForStore:    singleBackendFactory(newInMemoryBackend(t)),
		RevocationStore:    storage.NewMemory(),
		CertStore:          newInMemoryCertStore(t),
		RequireKeyPassword: true,
	})
	require.Error(t, err, "CA init with empty password and RequireKeyPassword=true must fail")
	assert.True(t, errors.Is(err, ErrKeyPasswordRequired),
		"expected ErrKeyPasswordRequired, got: %v", err)
}

// passwordProtectedIdentity returns a software-keyed CA identity whose key
// password is set on the KeyConfig itself (precedence 1 of
// Identity.ToKeyAttributes).
func passwordProtectedIdentity(t *testing.T, id Identity, password string) Identity {
	t.Helper()
	sv, err := types.NewLiteralSecretValue(context.Background(), []byte(password))
	require.NoError(t, err)
	key := *id.Keys[0]
	key.Password = sv
	id.Keys = []*types.KeyConfig{&key}
	return id
}

// assertKeysEncryptedAtRest asserts that the CA key of each identity is stored
// in keyStorage as encrypted PKCS#8: the raw DER is not a plaintext
// PrivateKeyInfo, and a fresh fail-closed pkcs8 backend over the same storage
// loads it with the identity's password and refuses it without one.
func assertKeysEncryptedAtRest(t *testing.T, keyStorage storage.Backend, ids ...Identity) {
	t.Helper()

	reload, err := pkcs8backend.NewBackend(&pkcs8backend.Config{
		KeyStorage:         keyStorage,
		AllowPlaintextKeys: false,
	})
	require.NoError(t, err)
	// Closing the backend closes keyStorage too, so it closes once, last.
	defer func() { require.NoError(t, reload.Close()) }()

	for _, id := range ids {
		assertKeyEncryptedAtRest(t, keyStorage, reload, id)
	}
}

func assertKeyEncryptedAtRest(t *testing.T, keyStorage storage.Backend, reload types.KeyProvider, id Identity) {
	t.Helper()
	ctx := context.Background()

	attrs, err := id.ToKeyAttributes(ctx)
	require.NoError(t, err)
	require.NotNil(t, attrs.Password, "identity must carry a key password")
	attrs.KeyType = types.KeyTypeCA

	rawDER, err := storage.GetKey(ctx, keyStorage, attrs.ID())
	require.NoError(t, err, "CA key %q must be stored", attrs.CN)
	_, parseErr := x509.ParsePKCS8PrivateKey(rawDER)
	assert.Error(t, parseErr, "CA key %q must not be stored as plaintext PKCS#8", attrs.CN)

	_, err = reload.GetKey(ctx, attrs)
	assert.NoError(t, err, "CA key %q must reload with its password", attrs.CN)

	withoutPassword := *attrs
	withoutPassword.Password = nil
	_, err = reload.GetKey(ctx, &withoutPassword)
	assert.Error(t, err, "CA key %q must not reload without its password", attrs.CN)
}

// newPKCS8CABackend returns a fail-closed (AllowPlaintextKeys=false) pkcs8
// backend for the CA and the key storage it writes to.
func newPKCS8CABackend(t *testing.T) (xkms.Backend, storage.Backend) {
	t.Helper()
	keyStorage := storage.NewMemory()
	be, err := pkcs8backend.NewBackend(&pkcs8backend.Config{
		KeyStorage:         keyStorage,
		AllowPlaintextKeys: false,
	})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     be,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)
	return backend, keyStorage
}

// TestCA_RequireKeyPassword_ConfiguredPasswordInitializes covers #1768: the
// constructors rebuild the CA identity from the flat CAConfig, and that
// rebuild must carry the configured key password so a RequireKeyPassword CA
// initializes and writes its keys as encrypted PKCS#8.
func TestCA_RequireKeyPassword_ConfiguredPasswordInitializes(t *testing.T) {
	t.Parallel()

	t.Run("NewCA root and intermediate", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend, keyStorage := newPKCS8CABackend(t)

		root := passwordProtectedIdentity(t, rootIdentity("PW Root CA"), "root-key-password")

		// The intermediate carries its password on the identity-wide software
		// keystore (precedence 2), not on the KeyConfig.
		intermediate := intermediateIdentity("PW Intermediate CA", "PW Root CA")
		sv, err := types.NewLiteralSecretValue(ctx, []byte("intermediate-key-password"))
		require.NoError(t, err)
		intermediate.Keystores = &CAKeystoresConfig{Software: &CAKeystoreSoftwareConfig{Password: sv}}

		rootCA, intermediateCA, err := NewCA(ctx, &Params{
			Identity:           []Identity{root, intermediate},
			KeyStore:           backend,
			BackendForStore:    singleBackendFactory(backend),
			RevocationStore:    storage.NewMemory(),
			CertStore:          newInMemoryCertStore(t),
			RequireKeyPassword: true,
		})
		require.NoError(t, err, "CA init with a configured password and RequireKeyPassword=true must succeed")
		require.NotNil(t, rootCA)
		require.NotNil(t, intermediateCA)

		assertKeysEncryptedAtRest(t, keyStorage, root, intermediate)
	})

	t.Run("NewParentCA then Init", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend, keyStorage := newPKCS8CABackend(t)

		root := passwordProtectedIdentity(t, rootIdentity("PW Parent CA"), "parent-key-password")
		parent, err := NewParentCA(&Params{
			Identity:           []Identity{root},
			KeyStore:           backend,
			BackendForStore:    singleBackendFactory(backend),
			RevocationStore:    storage.NewMemory(),
			CertStore:          newInMemoryCertStore(t),
			RequireKeyPassword: true,
		})
		require.NoError(t, err)
		require.NoError(t, parent.Init(ctx), "Init with a configured password and RequireKeyPassword=true must succeed")

		assertKeysEncryptedAtRest(t, keyStorage, root)
	})
}

func TestCarryKeyPassword_CarriesPassword(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	pw, err := types.NewPasswordFromString("carried-password")
	require.NoError(t, err)
	id := rootIdentity("Carry CA")

	require.NoError(t, carryKeyPassword(ctx, &id, &types.KeyAttributes{Password: pw}))
	require.NotNil(t, id.Keys[0].Password, "the password must land on KeyConfig.Password")

	attrs, err := id.ToKeyAttributes(ctx)
	require.NoError(t, err)
	require.NotNil(t, attrs.Password)
	got := attrs.Password.Bytes()
	defer secure.Wipe(got)
	assert.Equal(t, "carried-password", string(got))
}

func TestCarryKeyPassword_NoPasswordLeavesIdentityUnchanged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	empty, err := types.NewPasswordFromString("")
	require.NoError(t, err)
	tests := map[string]*types.KeyAttributes{
		"nil key attributes": nil,
		"nil password":       {},
		"empty password":     {Password: empty},
	}
	for name, keyAttrs := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			id := rootIdentity("No Password CA")
			require.NoError(t, carryKeyPassword(ctx, &id, keyAttrs))
			assert.Nil(t, id.Keys[0].Password)
		})
	}

	pw, err := types.NewPasswordFromString("unused")
	require.NoError(t, err)
	assert.NoError(t, carryKeyPassword(ctx, nil, &types.KeyAttributes{Password: pw}), "a nil identity is a no-op")
	noKeys := Identity{}
	assert.NoError(t, carryKeyPassword(ctx, &noKeys, &types.KeyAttributes{Password: pw}), "an identity without keys is a no-op")
}

// unreadablePassword is a Password whose secret cannot be retrieved: Bytes
// returns nil and WithBytes reports the retrieval error without calling fn,
// as a platform password does when unsealing fails.
type unreadablePassword struct {
	err error
}

func (p unreadablePassword) Bytes() []byte { return nil }

func (p unreadablePassword) WithBytes(func([]byte) error) error { return p.err }

func (p unreadablePassword) String() string { return types.PasswordRedacted }

func (p unreadablePassword) Clear() {}

// TestCA_UnreadableKeyPassword_FailsConstruction verifies that a configured
// key password which cannot be read fails CA construction with the retrieval
// error, instead of building the identity with no password (which would let a
// later initialization persist an unencrypted CA key).
func TestCA_UnreadableKeyPassword_FailsConstruction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	errUnavailable := errors.New("password unavailable")

	t.Run("carryKeyPassword", func(t *testing.T) {
		t.Parallel()
		id := rootIdentity("Unreadable PW CA")
		err := carryKeyPassword(ctx, &id, &types.KeyAttributes{Password: unreadablePassword{err: errUnavailable}})
		require.ErrorIs(t, err, errUnavailable)
		assert.Nil(t, id.Keys[0].Password, "no password may land on the identity")
	})

	t.Run("New", func(t *testing.T) {
		t.Parallel()
		root := rootIdentity("Unreadable PW New CA")
		keyAttrs, err := root.ToKeyAttributes(ctx)
		require.NoError(t, err)
		keyAttrs.Password = unreadablePassword{err: errUnavailable}

		instance, err := New(&Params{
			Config: &CAConfig{
				Identity:  "Unreadable PW New CA",
				Subject:   &Subject{CommonName: "Unreadable PW New CA"},
				IsRootCA:  true,
				StoreType: types.StoreSoftware,
			},
			KeyAttributes:   keyAttrs,
			KeyStore:        newInMemoryBackend(t),
			BackendForStore: singleBackendFactory(newInMemoryBackend(t)),
			RevocationStore: storage.NewMemory(),
			CertStore:       newInMemoryCertStore(t),
		})
		require.ErrorIs(t, err, errUnavailable)
		assert.Nil(t, instance, "no CA may be built without its configured password")
	})
}
