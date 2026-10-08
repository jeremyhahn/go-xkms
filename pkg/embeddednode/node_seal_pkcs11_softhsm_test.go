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

package embeddednode

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11strategy"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// softHSMNodeSealConfig is a pkcs11 node seal on a fresh SoftHSM token, its
// PIN store held by the TPM simulator.
func softHSMNodeSealConfig(t *testing.T, label string) (*config.Config, softhsmtest.Token) {
	token := softhsmtest.Provision(t, label)
	cfg := simulatorPKCS11NodeSealConfig(t)
	cfg.Backends.PKCS11 = &config.PKCS11Config{Library: token.Library, Token: token.Label}
	return cfg, token
}

// TestResolveNodeSeal_PKCS11SealsTheNodeWithTheSealedPIN proves a pkcs11
// barrier resolves to a PKCS#11 node seal -- never the warning path that
// leaves the data plane unencrypted -- logged in with the PIN the TPM
// released.
func TestResolveNodeSeal_PKCS11SealsTheNodeWithTheSealedPIN(t *testing.T) {
	cfg, token := softHSMNodeSealConfig(t, "node-seal")
	sealPKCS11PIN(t, cfg, []byte(token.UserPIN))
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	res, err := ResolveNodeSeal(cfg, logger)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, res.Close()) })
	require.True(t, res.Enabled)
	require.Nil(t, res.TPM)
	require.Equal(t, seal.StrategyPKCS11, res.Strategy.ID())
	require.Empty(t, logs.String())

	ctx := context.Background()
	rootKey := []byte("0123456789abcdef0123456789abcdef")
	sealed, err := res.Strategy.SealRootKey(ctx, rootKey, seal.Credentials{})
	require.NoError(t, err)
	got, err := res.Strategy.UnsealRootKey(ctx, sealed, seal.Credentials{})
	require.NoError(t, err)
	require.Equal(t, rootKey, got)
}

// TestOpenEmbeddedNode_PKCS11AutoUnsealsAcrossBoots proves the qrdb node
// adopts the PKCS#11 node seal and unseals unattended, on first boot and
// again on a reboot that unseals the root key the first boot sealed.
func TestOpenEmbeddedNode_PKCS11AutoUnsealsAcrossBoots(t *testing.T) {
	cfg, token := softHSMNodeSealConfig(t, "node-seal-boot")
	sealPKCS11PIN(t, cfg, []byte(token.UserPIN))

	for boot := 1; boot <= 2; boot++ {
		node, sealRes, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
			Config: cfg,
			Logger: testLogger(),
		})
		require.NoError(t, err, "boot %d", boot)
		require.True(t, sealRes.Enabled)
		require.False(t, node.IsSealed(), "boot %d: a pkcs11 node seal must unseal unattended", boot)
		require.NoError(t, node.Close())
		require.NoError(t, sealRes.Close())
	}
}

// TestResolveNodeSeal_PKCS11RefusesAPINTheTokenRejects proves a sealed PIN
// the token no longer accepts fails the boot with a typed error.
func TestResolveNodeSeal_PKCS11RefusesAPINTheTokenRejects(t *testing.T) {
	cfg, _ := softHSMNodeSealConfig(t, "node-seal-wrong-pin")
	sealPKCS11PIN(t, cfg, []byte("0000"))

	res, err := ResolveNodeSeal(cfg, testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	var buildErr *pkcs11strategy.BuildError
	require.ErrorAs(t, err, &buildErr)
	require.False(t, res.Enabled)
}
