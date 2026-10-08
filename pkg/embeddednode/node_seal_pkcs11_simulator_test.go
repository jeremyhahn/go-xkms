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

package embeddednode

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/preseal"
)

// simulatorPKCS11NodeSealConfig is a pkcs11 node seal whose PIN store is
// held by the TPM simulator.
func simulatorPKCS11NodeSealConfig(t *testing.T) *config.Config {
	cfg := pkcs11NodeSealConfig(t)
	cfg.Backends.TPM2 = &config.TPM2Config{UseSimulator: true}
	return cfg
}

// sealPKCS11PIN seals pin into cfg's pre-barrier store, as
// `xkmsd seal-pkcs11-pin` does.
func sealPKCS11PIN(t *testing.T, cfg *config.Config, pin []byte) {
	store, closeStore, err := OpenPreseal(cfg, testLogger())
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), preseal.PKCS11PIN, pin))
	require.NoError(t, closeStore())
}

func TestOpenPreseal_SimulatorKeepsThePINAcrossOpens(t *testing.T) {
	cfg := simulatorPKCS11NodeSealConfig(t)
	sealPKCS11PIN(t, cfg, []byte("1234"))

	store, closeStore, err := OpenPreseal(cfg, testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, closeStore()) })
	pin, err := store.Get(context.Background(), preseal.PKCS11PIN)
	require.NoError(t, err)
	require.Equal(t, []byte("1234"), pin)
}

func TestResolveNodeSeal_PKCS11WithoutASealedPINFailsClosed(t *testing.T) {
	res, err := ResolveNodeSeal(simulatorPKCS11NodeSealConfig(t), testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	var notFound *preseal.NotFoundError
	require.ErrorAs(t, err, &notFound)
	require.False(t, res.Enabled)
}
