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

//go:build tpm_simulator

package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestInitTPM2Backend_SharedTPM_GenerateAndSign is the regression test for
// go-xkms#795: with barrier.strategy=tpm2 AND backends.tpm2.enabled=true,
// resolveNodeSeal opens the TPM once and hands it to initTPM2Backend, which
// must build the general TPM2 backend over that SAME connection
// (tpm2backend.NewBackendWithTPM). Before the fix, ExternalTPMConfig.KeyBackend
// was never set, so NewBackendWithTPM failed closed with "KeyBackend is nil"
// and Server.New never came up with both settings enabled. This exercises the
// full path end to end: boot, then generate and sign with a TPM2 key through
// the shared backend.
func TestInitTPM2Backend_SharedTPM_GenerateAndSign(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "tpm2"}
	cfg.Backends.TPM2 = &config.TPM2Config{Enabled: true, UseSimulator: true}

	server, err := New(cfg)
	require.NoError(t, err, "Server.New must succeed with the barrier and the general backend sharing one TPM open")
	defer func() { _ = server.Shutdown() }()

	require.True(t, server.nodeSealEnabled, "the node-seal flip must engage for qrdb + barrier + strategy tpm2")

	kp, ok := server.keyProviders["tpm2"]
	require.True(t, ok, "the tpm2 key provider must be registered")

	shared, ok := server.nodeSealTPM.(*tpm2backend.Backend)
	require.True(t, ok, "the node seal must hold the shared *tpm2backend.Backend")

	tpmKP, ok := kp.(*tpm2backend.Backend)
	require.True(t, ok, "the tpm2 key provider must be a *tpm2backend.Backend")
	assert.Same(t, shared.TPM(), tpmKP.TPM(), "the general backend must reuse the barrier's single TPM open")
	assert.Same(t, shared.KeyBackend(), tpmKP.KeyBackend(), "the general backend must reuse the barrier's key store, not a second one over the same directory")

	ctx := context.Background()
	attrs := &types.KeyAttributes{
		CN:            "xkms-795-shared-tpm",
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}

	_, err = kp.GenerateKey(ctx, attrs)
	require.NoError(t, err, "GenerateKey through the shared TPM2 backend")

	signer, err := kp.Signer(ctx, attrs)
	require.NoError(t, err, "Signer through the shared TPM2 backend")

	digest := sha256.Sum256([]byte("go-xkms#795"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err, "Sign through the shared TPM2 backend")

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok, "Public() must return an *ecdsa.PublicKey")
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], signature), "signature must verify against the reported public key")
}

// TestInitTPM2Backend_SharedTPM_InvalidKeyStorageConfig verifies that, even
// once the node seal has already opened the shared TPM (the shared branch of
// initTPM2Backend), an invalid/missing key-storage configuration still fails
// closed with the same typed error as the standalone path — resolveTPM2KeyDir
// is checked before the shared-TPM type assertion, so this must never reach a
// nil dereference on the shared backend's key store.
func TestInitTPM2Backend_SharedTPM_InvalidKeyStorageConfig(t *testing.T) {
	shared, err := tpm2backend.NewBackend(&tpm2backend.Config{
		UseSimulator: true,
		KeyDir:       t.TempDir(),
	})
	require.NoError(t, err, "constructing the shared simulator-backed TPM2 backend")
	t.Cleanup(func() { _ = shared.Close() })

	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Path: ""}, // invalid: never configured
		Backends: config.BackendsConfig{
			TPM2: &config.TPM2Config{Enabled: true, UseSimulator: true},
		},
	})
	s.keyProviders = map[string]types.KeyProvider{}
	s.nodeSealTPM = shared

	err = s.initTPM2Backend()
	require.Error(t, err)
	assert.Empty(t, s.keyProviders)

	var createErr *ErrBackendCreate
	require.True(t, errors.As(err, &createErr), "error must unwrap to *ErrBackendCreate, got %v", err)

	var cfgErr *ErrConfigRequired
	require.True(t, errors.As(err, &cfgErr), "error must unwrap to *ErrConfigRequired, got %v", err)
	assert.Equal(t, "storage.path", cfgErr.Field)
	assert.Equal(t, "tpm2", cfgErr.Backend)
}
