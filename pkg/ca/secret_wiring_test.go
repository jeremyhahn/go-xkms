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

	"github.com/jeremyhahn/go-qrdb/pkg/secret"
	pkcs8backend "github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestCredentialRegistry returns a registry with a CredentialResolver
// backed by the provided static map of credential name → plaintext value.
func buildTestCredentialRegistry(creds map[string]string) *secret.ResolverRegistry {
	reg := secret.NewResolverRegistry()
	retrieve := func(_ context.Context, name string) ([]byte, error) {
		v, ok := creds[name]
		if !ok {
			return nil, &errs.Message{Msg: fmt.Sprintf("credential not found: %s", name)}
		}
		return []byte(v), nil
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
		Password:     "credential://" + credName,
	}

	attrs, err := types.KeyAttributesFromConfigResolved(context.Background(), cfg, reg)
	require.NoError(t, err)
	require.NotNil(t, attrs.Password, "resolved password must be non-nil")

	// Verify the password was resolved correctly.
	pw, err := attrs.Password.String()
	require.NoError(t, err)
	assert.Equal(t, credValue, pw, "password must equal the retrieved credential value")

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
		Identity:  []Identity{rootIdentity("NoPassword Root CA")},
		KeyStore:  newInMemoryBackend(t),
		CertStore: newInMemoryCertStore(t),
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
		CertStore:          newInMemoryCertStore(t),
		RequireKeyPassword: true,
	})
	require.Error(t, err, "CA init with empty password and RequireKeyPassword=true must fail")
	assert.True(t, errors.Is(err, ErrKeyPasswordRequired),
		"expected ErrKeyPasswordRequired, got: %v", err)
}
