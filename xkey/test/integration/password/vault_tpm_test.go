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

//go:build integration && passwordvault

package password

import (
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"

	gotpm2 "github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/localtpm"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// tpmPolicyPCR is the PCR the named-policy test selects: an application PCR
// a locality-0 caller may extend.
const tpmPolicyPCR = "23"

var (
	swtpmOnce sync.Once
	swtpmErr  error
)

// swtpm returns the devcontainer's swtpm fixture as a TPM device xkmsctl and
// xkey open, "tcp://host:port", provisioned once as a fresh dev TPM is (its
// hierarchies carry empty auth): the EK, the Shared SRK and the Platform SRK
// xkms parents its objects under.
//
// The fixture outlives the suite, so the owner-range NV indexes a test's
// policy services define (each scope's counter and authority, each named
// policy's index) are undefined again when it ends: left behind, every run
// would spend more of the TPM's NV space.
func swtpm(t *testing.T) string {
	t.Helper()
	host, port := os.Getenv("TPM_SIMULATOR_HOST"), os.Getenv("TPM_SIMULATOR_PORT")
	require.NotEmpty(t, host, "TPM_SIMULATOR_HOST names the swtpm fixture (devcontainer)")
	require.NotEmpty(t, port, "TPM_SIMULATOR_PORT names the swtpm fixture (devcontainer)")
	address := host + ":" + port
	swtpmOnce.Do(func() { swtpmErr = provisionSWTPM(address) })
	require.NoError(t, swtpmErr, "provision the swtpm fixture")
	device := "tcp://" + address
	before := ownerNVIndexes(t, device)
	t.Cleanup(func() { undefineNewNVIndexes(t, device, before) })
	return device
}

// nvUndefiner is the TPM's owner-hierarchy NV undefine.
type nvUndefiner interface {
	UndefineNVIndex(index gotpm2.TPMHandle, ownerAuth []byte) error
}

// ownerNVIndexes returns the owner-range NV indexes defined on the TPM.
func ownerNVIndexes(t *testing.T, device string) map[gotpm2.TPMHandle]bool {
	t.Helper()
	d, err := localtpm.OpenDevice(localtpm.DeviceParams{DataDir: t.TempDir(), Device: device})
	require.NoError(t, err)
	props, err := d.TPM().FixedProperties()
	require.NoError(t, errors.Join(err, d.Close()))
	indexes := map[gotpm2.TPMHandle]bool{}
	for _, nv := range props.NVIndexes {
		if nv.Handle >= tpm2.NVOwnerIndexFirst && nv.Handle <= tpm2.NVOwnerIndexLast {
			indexes[nv.Handle] = true
		}
	}
	return indexes
}

// undefineNewNVIndexes undefines the owner-range NV indexes defined since
// before was taken.
func undefineNewNVIndexes(t *testing.T, device string, before map[gotpm2.TPMHandle]bool) {
	t.Helper()
	d, err := localtpm.OpenDevice(localtpm.DeviceParams{DataDir: t.TempDir(), Device: device})
	require.NoError(t, err)
	props, err := d.TPM().FixedProperties()
	undefiner, ok := d.TPM().(nvUndefiner)
	require.True(t, ok, "the TPM undefines NV indexes")
	if err == nil {
		for _, nv := range props.NVIndexes {
			if nv.Handle >= tpm2.NVOwnerIndexFirst && nv.Handle <= tpm2.NVOwnerIndexLast && !before[nv.Handle] {
				err = errors.Join(err, undefiner.UndefineNVIndex(nv.Handle, nil))
			}
		}
	}
	assert.NoError(t, errors.Join(err, d.Close()), "undefine the test's NV indexes")
}

// provisionSWTPM provisions the swtpm at address unless it already is.
func provisionSWTPM(address string) error {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir, err := os.MkdirTemp("", "swtpm-provision-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	factory, err := store.NewStorageFactory(logger, dir)
	if err != nil {
		return err
	}
	cfg := tpm2.DefaultConfig
	cfg.CommandAddress = address
	tpm, err := tpm2.NewTPM2(&tpm2.Params{Logger: logger, Config: &cfg, BlobStore: factory.BlobStore(), Backend: factory.KeyBackend()})
	switch {
	case errors.Is(err, tpm2.ErrNotInitialized) && tpm != nil:
		err = tpm2.ProvisionFresh(tpm, &cfg)
	case err == nil:
		err = tpm2test.EnrollPlatformSRK(tpm, &cfg)
	default:
		return errors.Join(err, factory.Close())
	}
	return errors.Join(err, tpm.Close(), factory.Close())
}

// fileStores opens the policy service's stores as xkey and xkmsctl do.
func fileStores(dir string) (storage.Backend, error) {
	return storage.OpenEngine(storage.EngineConfig{Kind: storage.EngineFile, Path: dir})
}

// createTPMKey creates EC P-256 encryption key keyID under the platform
// policy in the TPM data directory dataDir -- a key the vault never saw.
func createTPMKey(t *testing.T, device, dataDir, keyID string) {
	t.Helper()
	host, err := localtpm.OpenHost(localtpm.DeviceParams{DataDir: dataDir, Device: device}, fileStores)
	require.NoError(t, err)
	_, err = host.Backend().GenerateKey(t.Context(), &types.KeyAttributes{
		CN: keyID, KeyAlgorithm: x509.ECDSA, KeyType: types.KeyTypeEncryption,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()}, TPMPolicy: types.TPMPolicyPlatform,
	})
	require.NoError(t, errors.Join(err, host.Close()))
}

// tpmFactor returns the user's TPM vault factor.
func (u *vaultUser) tpmFactor(t *testing.T) (keyID, policy string) {
	t.Helper()
	for _, f := range u.status(t).Factors {
		if f.Factor == "tpm" {
			return f.KeyRef.KeyID, f.KeyRef.TPMPolicy
		}
	}
	require.Fail(t, "no TPM factor enrolled")
	return "", ""
}

// TestVault_TPMPlatformPolicy enrolls a TPM key on the swtpm under the
// built-in platform policy: the key in the TPM data directory unlocks; a
// different key of the same name, in another directory, and a directory
// without the key, are refused.
func TestVault_TPMPlatformPolicy(t *testing.T) {
	device := swtpm(t)
	u := newUser(t, "vault-tpm")
	dataDir := t.TempDir()

	out := u.mustCtl(t, "", "password", "vault", "enroll", "--key-factor", "tpm",
		"--tpm-device", device, "--tpm-data-dir", dataDir, "--key-id", "vault-tpm", "--tpm-create")
	recoveryCodeOf(t, out)
	keyID, policy := u.tpmFactor(t)
	assert.Equal(t, "vault-tpm", keyID)
	assert.Equal(t, types.TPMPolicyPlatform, policy)
	u.lock(t)

	t.Run("wrong token", func(t *testing.T) {
		other := t.TempDir()
		createTPMKey(t, device, other, "vault-tpm")
		out, err := u.ctl("", "password", "unlock", "--key", "--tpm-device", device, "--tpm-data-dir", other)
		require.Error(t, err, out)
		assert.Contains(t, out, "none of the vault's key factors has its token here")
		u.requireLocked(t)
	})
	t.Run("missing token", func(t *testing.T) {
		out, err := u.ctl("", "password", "unlock", "--key", "--tpm-device", device, "--tpm-data-dir", t.TempDir())
		require.Error(t, err, out)
		assert.Contains(t, out, "none of the vault's key factors has its token here")
		u.requireLocked(t)
	})
	t.Run("right token", func(t *testing.T) {
		u.mustCtl(t, "", "password", "unlock", "--key", "--tpm-device", device, "--tpm-data-dir", dataDir)
		u.requireUnlocked(t)
	})
}

// TestVault_TPMNamedPolicy enrolls a TPM key under a named policy that xkey
// created in the same data directory -- one policy registry, shared by the
// two CLIs -- and unlocks through it. Once the policy's PCR drifts the TPM
// refuses the key; updating the policy re-approves the new state and the
// same key unlocks again.
func TestVault_TPMNamedPolicy(t *testing.T) {
	device := swtpm(t)
	u := newUser(t, "vault-tpm-policy")
	dataDir := t.TempDir()
	xkeyTPM := func(args ...string) string {
		t.Helper()
		out, err := runXKeyIn(t, dataDir, append([]string{"tpm", "--device", device}, args...)...)
		require.NoError(t, err, "xkey %v:\n%s", args, out)
		return out
	}
	xkeyTPM("policy", "create", "vault-boot", "--pcrs", tpmPolicyPCR)

	u.mustCtl(t, "", "password", "vault", "enroll", "--key-factor", "tpm", "--tpm-device", device,
		"--tpm-data-dir", dataDir, "--key-id", "vault-boot-key", "--tpm-create", "--tpm-policy", "vault-boot")
	_, policy := u.tpmFactor(t)
	assert.Equal(t, "vault-boot", policy)
	assert.Contains(t, xkeyTPM("policy", "objects", "vault-boot"), "vault-boot-key", "the registry records the key")
	u.lock(t)

	unlock := func() (string, error) {
		return u.ctl("", "password", "unlock", "--key", "--tpm-device", device, "--tpm-data-dir", dataDir)
	}
	u.mustCtl(t, "", "password", "unlock", "--key", "--tpm-device", device, "--tpm-data-dir", dataDir)
	u.requireUnlocked(t)
	u.lock(t)

	t.Run("platform change", func(t *testing.T) {
		extendPCR(t, device, dataDir)
		out, err := unlock()
		require.Error(t, err, "the TPM refuses the key once the PCR drifts: %s", out)
		u.requireLocked(t)

		xkeyTPM("policy", "update", "vault-boot")
		out, err = unlock()
		require.NoError(t, err, out)
		u.requireUnlocked(t)
	})
}

// extendPCR extends the named-policy PCR on the TPM, a platform change.
func extendPCR(t *testing.T, device, dataDir string) {
	t.Helper()
	tpmDevice, err := localtpm.OpenDevice(localtpm.DeviceParams{DataDir: dataDir, Device: device})
	require.NoError(t, err)
	err = tpmDevice.TPM().ExtendPCR(23, "sha256", []byte("password vault integration: platform change"))
	require.NoError(t, errors.Join(err, tpmDevice.Close()))
}
