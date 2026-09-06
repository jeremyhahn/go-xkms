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

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

func runDetached(t *testing.T, run func(*cobra.Command, []string) error, args ...string) (string, error) {
	t.Helper()

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := run(cmd, args)
	return buf.String(), err
}

// ---------------------------------------------------------------
// extension
// ---------------------------------------------------------------

func TestBrowserArg(t *testing.T) {
	assert.Equal(t, "all", browserArg(nil), "no argument must mean every browser")
	assert.Equal(t, "all", browserArg([]string{}))
	assert.Equal(t, "chrome", browserArg([]string{"chrome"}))
	assert.Equal(t, "chrome", browserArg([]string{"chrome", "firefox"}),
		"only the first positional argument is used")
}

func TestRunExtensionInstall_RejectsUnknownBrowser(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("allowed-origin", "", "")
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := runExtensionInstall(cmd, []string{"netscape"})
	require.Error(t, err)
	assert.Empty(t, buf.String(), "nothing must be installed when the browser is unknown")
}

func TestRunExtensionUninstall_RejectsUnknownBrowser(t *testing.T) {
	_, err := runDetached(t, runExtensionUninstall, "netscape")
	assert.Error(t, err)
}

func TestRunExtensionInstallUninstall_RoundTrip(t *testing.T) {
	// The native-messaging manifest lives under $HOME, so a temp HOME keeps
	// the developer's real browser profiles untouched.
	t.Setenv("HOME", t.TempDir())

	cmd := &cobra.Command{}
	cmd.Flags().String("allowed-origin", "", "")
	var installBuf bytes.Buffer
	cmd.SetOut(&installBuf)

	require.NoError(t, runExtensionInstall(cmd, []string{"chrome"}))
	assert.Contains(t, installBuf.String(), "Installed native messaging manifest for chrome")

	statusOut, err := runDetached(t, runExtensionStatus)
	require.NoError(t, err)
	assert.Contains(t, statusOut, "BROWSER")
	assert.Contains(t, statusOut, "INSTALLED")

	uninstallOut, err := runDetached(t, runExtensionUninstall, "chrome")
	require.NoError(t, err)
	assert.Contains(t, uninstallOut, "Uninstalled native messaging manifest for chrome")

	// Uninstalling twice is not an error; it reports the manifest is gone.
	againOut, err := runDetached(t, runExtensionUninstall, "chrome")
	require.NoError(t, err)
	assert.Contains(t, againOut, "No manifest found for chrome (already removed)")
}

func TestRunExtensionStatus_ListsOnlyInstalledBrowsers(t *testing.T) {
	// A HOME with no browser profiles must produce the header and nothing
	// else: reporting manifests for browsers that are not installed would
	// send users chasing paths that can never exist.
	t.Setenv("HOME", t.TempDir())

	out, err := runDetached(t, runExtensionStatus)
	require.NoError(t, err)
	assert.Equal(t, "BROWSER    INSTALLED  PATH\n", out)
}

func TestRunExtensionStatus_ReportsInstalledManifestPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	install := &cobra.Command{}
	install.Flags().String("allowed-origin", "", "")
	install.SetOut(&bytes.Buffer{})
	require.NoError(t, runExtensionInstall(install, []string{"chrome"}))

	out, err := runDetached(t, runExtensionStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "yes", "an installed manifest must be reported as installed")
	assert.Contains(t, out, home, "the reported path must point inside the active HOME")
}

func TestRunExtensionPairStatus_NotPaired(t *testing.T) {
	// An existing xKey home with no pairing store is a genuinely
	// unpaired device; the read must report that without creating the
	// extension directory.
	root := isolatedExistingXKeyHome(t)

	out, err := runDetached(t, runExtensionPairStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "Status: Not paired")
	assertNoPath(t, filepath.Join(root, "data", "extension"))
}

func TestRunExtensionPairStatus_NoResolvableHomeIsAnError(t *testing.T) {
	// XKEY_HOME pointing at a directory that does not exist: a read must
	// not create it, and must not render the unknowable as "Not paired".
	isolateDataDirSources(t)
	t.Setenv("XKEY_HOME", filepath.Join(t.TempDir(), "missing"))

	_, err := runDetached(t, runExtensionPairStatus)
	require.ErrorIs(t, err, ErrExtensionPairStatusFailed)
	require.ErrorIs(t, err, xhome.ErrHomeNotResolved)
}

func TestRunExtensionUnpair_WhenNothingPaired(t *testing.T) {
	root := isolatedExistingXKeyHome(t)

	out, err := runDetached(t, runExtensionUnpair)
	require.NoError(t, err)
	assert.Contains(t, out, "No extension is currently paired")
	assertNoPath(t, filepath.Join(root, "data", "extension"))
}

func TestRunExtensionUnpair_NoResolvableHomeIsAnError(t *testing.T) {
	isolateDataDirSources(t)
	t.Setenv("XKEY_HOME", filepath.Join(t.TempDir(), "missing"))

	_, err := runDetached(t, runExtensionUnpair)
	require.ErrorIs(t, err, ErrExtensionUnpairFailed)
	require.ErrorIs(t, err, xhome.ErrHomeNotResolved)
}

// ---------------------------------------------------------------
// agent
// ---------------------------------------------------------------

func TestAgentDirs_FollowResolvedHome(t *testing.T) {
	isolateDataDirSources(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	previous := resolvedHome
	resolvedHome = nil
	t.Cleanup(func() { resolvedHome = previous })

	base := filepath.Join(home, ".xkey", "data", "agent")
	assert.Equal(t, base, mustAgentDataDir(t))
	assert.Equal(t, filepath.Join(base, "enrollments"), mustAgentStoreDir(t))
	assert.Equal(t, filepath.Join(base, "certs"), mustAgentCertDir(t))
}

func TestRunAgentStatus_NotRunningAndNoEnrollments(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XKEY_HOME", filepath.Join(home, ".xkey"))

	previous := resolvedHome
	resolvedHome = nil
	t.Cleanup(func() { resolvedHome = previous })

	out, err := runDetached(t, runAgentStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "Agent server: not running")
	assert.Contains(t, out, "No enrolled agents")
}

func TestRunAgentStatus_ListsEnrolledAgents(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	previous := resolvedHome
	resolvedHome = nil
	t.Cleanup(func() { resolvedHome = previous })

	store, err := agent.NewFileStore(mustAgentStoreDir(t), slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.SaveAgent(&agent.AgentInfo{
		ID:         "agent-1",
		Name:       "edge-node",
		Status:     "active",
		EnrolledAt: time.Now().Add(-time.Hour),
		LastSeen:   time.Now(),
		Address:    "10.0.0.5:9000",
	}))

	out, err := runDetached(t, runAgentStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "Enrolled Agents (1):")
	assert.Contains(t, out, "ID:          agent-1")
	assert.Contains(t, out, "Name:        edge-node")
	assert.Contains(t, out, "Address:     10.0.0.5:9000")
}

// ---------------------------------------------------------------
// piv (file-backed storage)
// ---------------------------------------------------------------

// withFilePIVStorage points the PIV commands at a temporary file-backed
// certificate store.
func withFilePIVStorage(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	previousBackend := viper.Get(viperKeyPIVBackend)
	previousStorage := viper.Get(viperKeyPIVStorage)
	previousPath := viper.Get(viperKeyPIVStoragePath)

	viper.Set(viperKeyPIVBackend, string(PIVBackendSoftware))
	viper.Set(viperKeyPIVStorage, string(PIVStorageTypeFile))
	viper.Set(viperKeyPIVStoragePath, dir)

	t.Cleanup(func() {
		viper.Set(viperKeyPIVBackend, previousBackend)
		viper.Set(viperKeyPIVStorage, previousStorage)
		viper.Set(viperKeyPIVStoragePath, previousPath)
	})

	return dir
}

// pivTestCert builds a self-signed certificate suitable for storing in a
// PIV slot.
func pivTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"piv.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestBuildPIVConfig_StorageDefaultsFollowBackend(t *testing.T) {
	previousBackend := viper.Get(viperKeyPIVBackend)
	previousStorage := viper.Get(viperKeyPIVStorage)
	t.Cleanup(func() {
		viper.Set(viperKeyPIVBackend, previousBackend)
		viper.Set(viperKeyPIVStorage, previousStorage)
	})

	tests := []struct {
		backend string
		want    PIVStorageType
	}{
		{string(PIVBackendSoftware), PIVStorageTypeFile},
		{string(PIVBackendTPM2), PIVStorageTypeTPM2},
		{string(PIVBackendPKCS11), PIVStorageTypePKCS11},
		{"unrecognised", PIVStorageTypeFile},
	}

	for _, tt := range tests {
		t.Run(tt.backend, func(t *testing.T) {
			viper.Set(viperKeyPIVBackend, tt.backend)
			viper.Set(viperKeyPIVStorage, "")
			assert.Equal(t, tt.want, buildPIVConfig().StorageType)
		})
	}
}

func TestBuildPIVConfig_ExplicitStorageOverridesBackendDefault(t *testing.T) {
	previousBackend := viper.Get(viperKeyPIVBackend)
	previousStorage := viper.Get(viperKeyPIVStorage)
	t.Cleanup(func() {
		viper.Set(viperKeyPIVBackend, previousBackend)
		viper.Set(viperKeyPIVStorage, previousStorage)
	})

	viper.Set(viperKeyPIVBackend, string(PIVBackendTPM2))
	viper.Set(viperKeyPIVStorage, string(PIVStorageTypeFile))
	assert.Equal(t, PIVStorageTypeFile, buildPIVConfig().StorageType)
}

func TestCreatePIVStorage_RejectsUnknownStorageType(t *testing.T) {
	cfg := &PIVConfig{
		Backend:     PIVBackendSoftware,
		StorageType: PIVStorageType("carrier-pigeon"),
		StoragePath: t.TempDir(),
	}

	_, err := createPIVStorage(cfg, slog.Default())
	assert.Error(t, err)
}

func TestCreatePIVStorage_FileBackendRoundTrip(t *testing.T) {
	dir := withFilePIVStorage(t)

	storage, err := createPIVStorage(buildPIVConfig(), slog.Default())
	require.NoError(t, err)
	defer func() { _ = storage.Close() }()

	cert := pivTestCert(t, "piv-round-trip")
	require.NoError(t, storage.Store(xkms.PIVSlotAuthentication, cert))

	got, err := storage.Retrieve(xkms.PIVSlotAuthentication)
	require.NoError(t, err)
	assert.Equal(t, "piv-round-trip", got.Subject.CommonName)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.NotEmpty(t, entries, "the file backend must persist to the configured path")
}

func TestRunPIVList_EmptyStore(t *testing.T) {
	withFilePIVStorage(t)

	out, err := runDetached(t, runPIVList)
	require.NoError(t, err)
	assert.Contains(t, out, "No certificates found in PIV slots.")
}

func TestRunPIVList_ShowsStoredCertificates(t *testing.T) {
	withFilePIVStorage(t)

	storage, err := createPIVStorage(buildPIVConfig(), slog.Default())
	require.NoError(t, err)
	require.NoError(t, storage.Store(xkms.PIVSlotAuthentication, pivTestCert(t, "auth-cert")))
	require.NoError(t, storage.Close())

	out, err := runDetached(t, runPIVList)
	require.NoError(t, err)
	assert.Contains(t, out, "PIV Certificates (1):")
	assert.Contains(t, out, "auth-cert")
	assert.Contains(t, out, string(xkms.PIVSlotAuthentication))
}

func TestRunPIVShow_RejectsInvalidSlot(t *testing.T) {
	withFilePIVStorage(t)

	_, err := runDetached(t, runPIVShow, "ffffff")
	assert.Error(t, err, "an unknown PIV slot must be rejected before touching storage")
}

func TestRunPIVShow_MissingCertificate(t *testing.T) {
	withFilePIVStorage(t)

	_, err := runDetached(t, runPIVShow, string(xkms.PIVSlotAuthentication))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVCertificateNotFound)
}

func TestRunPIVShow_PrintsCertificateDetails(t *testing.T) {
	withFilePIVStorage(t)

	storage, err := createPIVStorage(buildPIVConfig(), slog.Default())
	require.NoError(t, err)
	require.NoError(t, storage.Store(xkms.PIVSlotAuthentication, pivTestCert(t, "shown-cert")))
	require.NoError(t, storage.Close())

	out, err := runDetached(t, runPIVShow, string(xkms.PIVSlotAuthentication))
	require.NoError(t, err)
	assert.Contains(t, out, "shown-cert")
	assert.Contains(t, out, "Serial Number: 42")
	assert.Contains(t, out, "Key Algorithm: ECDSA")
	assert.Contains(t, out, "piv.example.com")
}

// pivDeleteCmd builds a detached delete command carrying the --force flag
// the handler reads.
func newPIVDeleteTestCmd(t *testing.T, force bool) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.Flags().Bool("force", force, "")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	return cmd, &buf
}

func TestRunPIVDelete_ForceRemovesCertificate(t *testing.T) {
	withFilePIVStorage(t)

	storage, err := createPIVStorage(buildPIVConfig(), slog.Default())
	require.NoError(t, err)
	require.NoError(t, storage.Store(xkms.PIVSlotAuthentication, pivTestCert(t, "doomed")))
	require.NoError(t, storage.Close())

	cmd, buf := newPIVDeleteTestCmd(t, true)
	require.NoError(t, runPIVDelete(cmd, []string{string(xkms.PIVSlotAuthentication)}))
	assert.Contains(t, buf.String(), "Certificate deleted from slot")

	listOut, err := runDetached(t, runPIVList)
	require.NoError(t, err)
	assert.Contains(t, listOut, "No certificates found in PIV slots.")
}

func TestRunPIVDelete_DeclinedConfirmationKeepsCertificate(t *testing.T) {
	withFilePIVStorage(t)

	storage, err := createPIVStorage(buildPIVConfig(), slog.Default())
	require.NoError(t, err)
	require.NoError(t, storage.Store(xkms.PIVSlotAuthentication, pivTestCert(t, "keeper")))
	require.NoError(t, storage.Close())

	pipeStdin(t, "n\n")

	cmd, buf := newPIVDeleteTestCmd(t, false)
	require.NoError(t, runPIVDelete(cmd, []string{string(xkms.PIVSlotAuthentication)}))
	out := buf.String()
	assert.Contains(t, out, "Subject: keeper")
	assert.Contains(t, out, "Deletion cancelled.")

	listOut, err := runDetached(t, runPIVList)
	require.NoError(t, err)
	assert.Contains(t, listOut, "keeper", "declining the prompt must not delete the certificate")
}

func TestRunPIVDelete_ConfirmedDeletionRemovesCertificate(t *testing.T) {
	withFilePIVStorage(t)

	storage, err := createPIVStorage(buildPIVConfig(), slog.Default())
	require.NoError(t, err)
	require.NoError(t, storage.Store(xkms.PIVSlotAuthentication, pivTestCert(t, "doomed")))
	require.NoError(t, storage.Close())

	pipeStdin(t, "y\n")

	cmd, buf := newPIVDeleteTestCmd(t, false)
	require.NoError(t, runPIVDelete(cmd, []string{string(xkms.PIVSlotAuthentication)}))
	assert.Contains(t, buf.String(), "Certificate deleted from slot")

	listOut, err := runDetached(t, runPIVList)
	require.NoError(t, err)
	assert.Contains(t, listOut, "No certificates found in PIV slots.")
}

func TestRunPIVDelete_RejectsInvalidSlot(t *testing.T) {
	withFilePIVStorage(t)

	cmd, _ := newPIVDeleteTestCmd(t, true)
	assert.Error(t, runPIVDelete(cmd, []string{"not-a-slot"}))
}

func TestRunPIVStatus_ReportsConfiguredBackend(t *testing.T) {
	withFilePIVStorage(t)

	out, err := runDetached(t, runPIVStatus)
	require.NoError(t, err)
	assert.Contains(t, out, string(PIVBackendSoftware))
}
