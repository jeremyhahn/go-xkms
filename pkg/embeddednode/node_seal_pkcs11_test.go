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

package embeddednode

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

func pkcs11NodeSealConfig(t *testing.T) *config.Config {
	return &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
		Barrier:   config.BarrierConfig{Enabled: true, Strategy: "pkcs11"},
		Backends: config.BackendsConfig{
			PKCS11: &config.PKCS11Config{Library: "/usr/lib/libpkcs11.so", Token: "node"},
		},
	}
}

func TestResolvePresealDir_DerivesFromTheDatastorePath(t *testing.T) {
	cfg := &config.Config{Datastore: config.DatastoreConfig{Path: "/var/lib/xkms"}}
	dir, err := ResolvePresealDir(cfg)
	require.NoError(t, err)
	require.Equal(t, filepath.Join("/var/lib/xkms", PresealSubdir), dir)
}

func TestResolvePresealDir_RequiresTheDatastorePath(t *testing.T) {
	_, err := ResolvePresealDir(&config.Config{})
	var pathErr *ErrDatastorePathRequired
	require.ErrorAs(t, err, &pathErr)
}

func TestOpenPreseal_RequiresTheDatastorePath(t *testing.T) {
	cfg := pkcs11NodeSealConfig(t)
	cfg.Datastore.Path = ""
	store, closeStore, err := OpenPreseal(cfg, testLogger())
	var pathErr *ErrDatastorePathRequired
	require.ErrorAs(t, err, &pathErr)
	require.Nil(t, store)
	require.Nil(t, closeStore)
}

func TestOpenPreseal_RequiresTheTPMBackend(t *testing.T) {
	store, closeStore, err := OpenPreseal(pkcs11NodeSealConfig(t), testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	require.Contains(t, nodeErr.Reason, "backends.tpm2 is not set")
	require.Nil(t, store)
	require.Nil(t, closeStore)
}

// TestOpenPreseal_UnusableTPMKeepsTheProbeError pins go-xkms#1528: the
// reason the configured TPM could not be used stays in the chain, so a TPM
// that failed to open is not reported as a timeout and vice versa.
func TestOpenPreseal_UnusableTPMKeepsTheProbeError(t *testing.T) {
	cfg := pkcs11NodeSealConfig(t)
	cfg.Backends.TPM2 = &config.TPM2Config{DevicePath: filepath.Join(t.TempDir(), "tpmrm0")}

	store, closeStore, err := OpenPreseal(cfg, testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	var probeErr *seal.TPM2ProbeError
	require.ErrorAs(t, err, &probeErr)
	require.NotErrorIs(t, err, seal.ErrTPM2ProbeTimeout)
	require.Nil(t, store)
	require.Nil(t, closeStore)
}

func TestResolveNodeSeal_PKCS11WithoutBackendConfigFailsClosed(t *testing.T) {
	cfg := pkcs11NodeSealConfig(t)
	cfg.Backends.PKCS11 = nil
	res, err := ResolveNodeSeal(cfg, testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	require.Contains(t, nodeErr.Reason, "backends.pkcs11 is not set")
	require.False(t, res.Enabled)
}

func TestResolveNodeSeal_PKCS11WithoutTPMFailsClosed(t *testing.T) {
	res, err := ResolveNodeSeal(pkcs11NodeSealConfig(t), testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	require.Contains(t, nodeErr.Reason, "backends.tpm2 is not set")
	require.False(t, res.Enabled)
}
