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

//go:build pkcs11

package pkcs11strategy

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// TestBuild_SealsAndUnsealsOnASoftHSMToken proves the built strategy seals
// a root key on a real token, and that a second build against the same
// token reuses the wrapping key and unseals what the first sealed.
func TestBuild_SealsAndUnsealsOnASoftHSMToken(t *testing.T) {
	token := softhsmtest.Provision(t, "pkcs11strategy")
	params := Params{CN: "test", Library: token.Library, TokenLabel: token.Label, PIN: literalPIN(t, token.UserPIN)}
	ctx := context.Background()
	rootKey := []byte("0123456789abcdef0123456789abcdef")

	first, firstCloser, err := Build(ctx, params)
	require.NoError(t, err)
	require.Equal(t, seal.StrategyPKCS11, first.ID())
	require.True(t, first.Available())
	sealed, err := first.SealRootKey(ctx, rootKey, seal.Credentials{})
	require.NoError(t, err)
	require.NoError(t, firstCloser.Close())

	params.PIN = literalPIN(t, token.UserPIN)
	second, secondCloser, err := Build(ctx, params)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, secondCloser.Close()) })
	got, err := second.UnsealRootKey(ctx, sealed, seal.Credentials{})
	require.NoError(t, err)
	require.Equal(t, rootKey, got)
}

// TestBuild_RefusesAWrongPIN proves a PIN the token rejects fails the build
// with a typed error rather than yielding a strategy that cannot seal.
func TestBuild_RefusesAWrongPIN(t *testing.T) {
	token := softhsmtest.Provision(t, "pkcs11strategy-wrong-pin")
	_, _, err := Build(context.Background(), Params{
		CN: "test", Library: token.Library, TokenLabel: token.Label, PIN: literalPIN(t, "0000"),
	})
	var buildErr *BuildError
	require.ErrorAs(t, err, &buildErr)
}

// TestBuild_RefusesAMissingLibrary proves a module path that does not exist
// fails the build with a typed error.
func TestBuild_RefusesAMissingLibrary(t *testing.T) {
	_, _, err := Build(context.Background(), Params{
		CN: "test", Library: filepath.Join(t.TempDir(), "missing.so"), TokenLabel: "token", PIN: literalPIN(t, "1234"),
	})
	var buildErr *BuildError
	require.ErrorAs(t, err, &buildErr)
}

// TestBuildWithSealedPIN_LogsInWithTheSealedPIN proves the PIN released from
// the source logs in to a real token.
func TestBuildWithSealedPIN_LogsInWithTheSealedPIN(t *testing.T) {
	token := softhsmtest.Provision(t, "pkcs11strategy-sealed-pin")
	source := &pinSource{secrets: map[string][]byte{seal.SecretPKCS11PIN: []byte(token.UserPIN)}}

	strategy, closer, err := BuildWithSealedPIN(context.Background(), source, "test", token.Library, token.Label)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, closer.Close()) })
	require.Equal(t, seal.StrategyPKCS11, strategy.ID())
}
