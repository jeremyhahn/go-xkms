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

//go:build pkcs11 && tpm_simulator

package cmd

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestPKCS11Barrier_UnsealsUnattendedAfterInit proves the strategy `barrier
// init --strategy pkcs11` leaves behind logs in to the token with the sealed
// PIN, and a second build unseals what the first sealed, with no PIN typed.
func TestPKCS11Barrier_UnsealsUnattendedAfterInit(t *testing.T) {
	token := softhsmtest.Provision(t, "xkey-barrier")
	useBarrierTPMSimulator(t)
	usePKCS11Barrier(t, token.Library, token.Label)
	pipeBarrier(t, token.UserPIN)
	dataDir := t.TempDir()
	ctx := context.Background()
	require.NoError(t, initBarrierPKCS11(ctx, io.Discard, "pkcs11", dataDir))

	first, firstCloser, err := assembleBarrierStrategy(xkms.StrategyPKCS11, dataDir)
	require.NoError(t, err)
	require.Equal(t, xkms.StrategyPKCS11, first.ID())
	rootKey := []byte("0123456789abcdef0123456789abcdef")
	sealed, err := first.SealRootKey(ctx, rootKey, xkms.SealCredentials{})
	require.NoError(t, err)
	require.NoError(t, firstCloser.Close())

	second, secondCloser, err := assembleBarrierStrategy(xkms.StrategyPKCS11, dataDir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, secondCloser.Close()) })
	got, err := second.UnsealRootKey(ctx, sealed, xkms.SealCredentials{})
	require.NoError(t, err)
	require.Equal(t, rootKey, got)
}

// TestPKCS11Barrier_RefusesAWrongSealedPIN proves a sealed PIN the token
// rejects fails the build with a typed error.
func TestPKCS11Barrier_RefusesAWrongSealedPIN(t *testing.T) {
	token := softhsmtest.Provision(t, "xkey-barrier-wrong-pin")
	useBarrierTPMSimulator(t)
	usePKCS11Barrier(t, token.Library, token.Label)
	pipeBarrier(t, "0000")
	dataDir := t.TempDir()
	require.NoError(t, initBarrierPKCS11(context.Background(), io.Discard, "pkcs11", dataDir))

	_, _, err := assembleBarrierStrategy(xkms.StrategyPKCS11, dataDir)
	var buildErr *xkms.PKCS11StrategyBuildError
	require.ErrorAs(t, err, &buildErr)
}
