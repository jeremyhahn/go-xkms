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

package types

import (
	"context"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCredentialRegistry builds a ResolverRegistry backed by a static
// credential map. Keys must be credential names (without the scheme prefix).
func fakeCredentialRegistry(creds map[string]string) *secret.ResolverRegistry {
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

// TestKeyAttributesFromConfigResolved_CredentialURI verifies that a
// "credential://<name>" password reference is resolved and written into
// attrs.Password.
func TestKeyAttributesFromConfigResolved_CredentialURI(t *testing.T) {
	t.Parallel()

	reg := fakeCredentialRegistry(map[string]string{"capw": "s3cret"})

	cfg := &KeyConfig{
		CN:           "test-ca",
		KeyAlgorithm: AlgorithmECDSA,
		KeyType:      KeyTypeStringCA,
		Password:     &SecretValue{Raw: "credential://capw"},
	}

	attrs, err := KeyAttributesFromConfigResolved(context.Background(), cfg, reg)
	require.NoError(t, err)
	require.NotNil(t, attrs.Password, "resolved password must be non-nil")

	pw := string(attrs.Password.Bytes())
	assert.Equal(t, "s3cret", pw, "password must equal the value returned by the credential resolver")
}

// TestKeyAttributesFromConfigResolved_LiteralPassthrough verifies that a plain
// string password (no URI scheme) is returned unchanged by the literal fallback.
func TestKeyAttributesFromConfigResolved_LiteralPassthrough(t *testing.T) {
	t.Parallel()

	reg := fakeCredentialRegistry(map[string]string{})

	cfg := &KeyConfig{
		CN:           "test-ca",
		KeyAlgorithm: AlgorithmECDSA,
		KeyType:      KeyTypeStringCA,
		Password:     &SecretValue{Raw: "my-literal-password"},
	}

	attrs, err := KeyAttributesFromConfigResolved(context.Background(), cfg, reg)
	require.NoError(t, err)
	require.NotNil(t, attrs.Password)

	pw := string(attrs.Password.Bytes())
	assert.Equal(t, "my-literal-password", pw)
}

// TestKeyAttributesFromConfigResolved_NilRegistry verifies that a nil registry
// makes the function behave identically to KeyAttributesFromConfig.
func TestKeyAttributesFromConfigResolved_NilRegistry(t *testing.T) {
	t.Parallel()

	cfg := &KeyConfig{
		CN:           "test-ca",
		KeyAlgorithm: AlgorithmECDSA,
		KeyType:      KeyTypeStringCA,
		Password:     &SecretValue{Raw: "direct-password"},
	}

	attrsDirect, err := KeyAttributesFromConfig(cfg)
	require.NoError(t, err)

	attrsResolved, err := KeyAttributesFromConfigResolved(context.Background(), cfg, nil)
	require.NoError(t, err)

	// Both paths must produce identical CN and algorithm.
	assert.Equal(t, attrsDirect.CN, attrsResolved.CN)
	assert.Equal(t, attrsDirect.KeyAlgorithm, attrsResolved.KeyAlgorithm)

	// Both must carry the same password.
	require.NotNil(t, attrsDirect.Password)
	require.NotNil(t, attrsResolved.Password)
	pwDirect := string(attrsDirect.Password.Bytes())
	pwResolved := string(attrsResolved.Password.Bytes())
	assert.Equal(t, pwDirect, pwResolved)
}

// TestKeyAttributesFromConfigResolved_ParentPasswordResolved verifies that
// the password on a nested Parent KeyConfig is resolved through the registry.
func TestKeyAttributesFromConfigResolved_ParentPasswordResolved(t *testing.T) {
	t.Parallel()

	reg := fakeCredentialRegistry(map[string]string{
		"child-pw":  "child-secret",
		"parent-pw": "parent-secret",
	})

	cfg := &KeyConfig{
		CN:           "child-ca",
		KeyAlgorithm: AlgorithmECDSA,
		KeyType:      KeyTypeStringCA,
		Password:     &SecretValue{Raw: "credential://child-pw"},
		Parent: &KeyConfig{
			CN:           "parent-ca",
			KeyAlgorithm: AlgorithmECDSA,
			KeyType:      KeyTypeStringCA,
			Password:     &SecretValue{Raw: "credential://parent-pw"},
		},
	}

	attrs, err := KeyAttributesFromConfigResolved(context.Background(), cfg, reg)
	require.NoError(t, err)

	// Child password resolved.
	require.NotNil(t, attrs.Password)
	childPW := string(attrs.Password.Bytes())
	assert.Equal(t, "child-secret", childPW)

	// Parent password resolved.
	require.NotNil(t, attrs.Parent, "parent KeyAttributes must be set")
	require.NotNil(t, attrs.Parent.Password, "parent password must be non-nil")
	parentPW := string(attrs.Parent.Password.Bytes())
	assert.Equal(t, "parent-secret", parentPW)
}

// TestKeyAttributesFromConfigResolved_EmptyPasswordNilAttrs verifies that an
// empty resolved value leaves attrs.Password nil, preserving fail-closed
// behaviour for pkcs8 backends with AllowPlaintextKeys: false.
func TestKeyAttributesFromConfigResolved_EmptyPasswordNilAttrs(t *testing.T) {
	t.Parallel()

	// Credential that returns empty bytes.
	reg := fakeCredentialRegistry(map[string]string{"empty-pw": ""})

	cfg := &KeyConfig{
		CN:           "test-ca",
		KeyAlgorithm: AlgorithmECDSA,
		KeyType:      KeyTypeStringCA,
		Password:     &SecretValue{Raw: "credential://empty-pw"},
	}

	attrs, err := KeyAttributesFromConfigResolved(context.Background(), cfg, reg)
	require.NoError(t, err)
	assert.Nil(t, attrs.Password, "empty resolved credential must leave attrs.Password nil")
}

// TestKeyAttributesFromConfigResolved_ResolutionFailure verifies that a
// resolution error is propagated without a fallback.
func TestKeyAttributesFromConfigResolved_ResolutionFailure(t *testing.T) {
	t.Parallel()

	// Registry with no matching credential.
	reg := fakeCredentialRegistry(map[string]string{})

	cfg := &KeyConfig{
		CN:           "test-ca",
		KeyAlgorithm: AlgorithmECDSA,
		KeyType:      KeyTypeStringCA,
		Password:     &SecretValue{Raw: "credential://nonexistent"},
	}

	_, err := KeyAttributesFromConfigResolved(context.Background(), cfg, reg)
	require.Error(t, err, "resolution failure must propagate as an error")
}

// TestKeyAttributesFromConfigResolved_NilConfigWithRegistry verifies that a nil
// config with a non-nil registry returns an error rather than panicking or
// silently returning nil attrs. This exercises the config==nil fast-path inside
// resolveKeyConfigPasswords (the unexported helper), which returns (nil, nil)
// and then lets KeyAttributesFromConfig reject the nil config.
func TestKeyAttributesFromConfigResolved_NilConfigWithRegistry(t *testing.T) {
	t.Parallel()

	reg := fakeCredentialRegistry(map[string]string{})

	_, err := KeyAttributesFromConfigResolved(context.Background(), nil, reg)
	require.Error(t, err, "nil config must produce an error, not nil attrs")
}

// TestKeyAttributesFromConfigResolved_ParentPasswordResolutionError verifies
// that a credential resolution failure in a Parent config propagates correctly
// and is not silently swallowed. This exercises the error-return branch inside
// the parent-recursion path of resolveKeyConfigPasswords.
func TestKeyAttributesFromConfigResolved_ParentPasswordResolutionError(t *testing.T) {
	t.Parallel()

	// Empty registry: any credential:// URI will fail resolution.
	reg := fakeCredentialRegistry(map[string]string{})

	cfg := &KeyConfig{
		CN:           "child-ca",
		KeyAlgorithm: AlgorithmECDSA,
		KeyType:      KeyTypeStringCA,
		// No child password — child resolution is skipped, focusing the failure
		// on the parent chain.
		Parent: &KeyConfig{
			CN:           "parent-ca",
			KeyAlgorithm: AlgorithmECDSA,
			KeyType:      KeyTypeStringCA,
			Password:     &SecretValue{Raw: "credential://missing-parent-pw"},
		},
	}

	_, err := KeyAttributesFromConfigResolved(context.Background(), cfg, reg)
	require.Error(t, err, "parent resolution failure must propagate as an error")
}
