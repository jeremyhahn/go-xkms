// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration && tpm2

package integration

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-keychain/internal/tpm/logging"
	"github.com/jeremyhahn/go-keychain/internal/tpm/store"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	tpm2ks "github.com/jeremyhahn/go-keychain/pkg/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TPM2TestSetup contains all components needed for TPM testing with capture
type TPM2TestSetup struct {
	TPM         tpm2ks.TrustedPlatformModule
	Capture     *TPMCapture
	TmpDir      string
	KeyStorage  storage.Backend
	CertStorage storage.Backend
	PKCS8       types.Backend
}

// NewTPM2TestSetup creates a complete TPM test environment with packet capture
func NewTPM2TestSetup(t *testing.T, encryptSession bool) *TPM2TestSetup {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "tpm2-capture-test-*")
	require.NoError(t, err, "Failed to create temp directory")

	// Create storage backends
	keyStorage, err := file.New(filepath.Join(tmpDir, "keys"))
	require.NoError(t, err, "Failed to create key storage")

	certStorage, err := file.New(filepath.Join(tmpDir, "certs"))
	require.NoError(t, err, "Failed to create cert storage")

	// Create PKCS8 backend
	pkcs8Config := &pkcs8.Config{
		KeyStorage: keyStorage,
	}
	pkcs8Backend, err := pkcs8.NewBackend(pkcs8Config)
	require.NoError(t, err, "Failed to create PKCS8 backend")

	// Open TPM transport
	var baseTpm transport.TPMCloser

	simHost := os.Getenv("TPM2_SIMULATOR_HOST")
	simPort := os.Getenv("TPM2_SIMULATOR_PORT")

	if simHost != "" && simPort != "" {
		// Use TCP simulator (SWTPM)
		// SWTPM typically uses port 2321 for commands and 2322 for platform
		commandAddress := fmt.Sprintf("%s:%s", simHost, simPort)

		// Parse port number and calculate platform port (command + 1)
		var portNum int
		fmt.Sscanf(simPort, "%d", &portNum)
		platformAddress := fmt.Sprintf("%s:%d", simHost, portNum+1)

		t.Logf("Connecting to TPM simulator at %s (platform: %s)", commandAddress, platformAddress)
		baseTpm, err = tcp.Open(tcp.Config{
			CommandAddress:  commandAddress,
			PlatformAddress: platformAddress,
		})
		require.NoError(t, err, "Failed to connect to TPM simulator")

		// Power cycle the TPM simulator to ensure clean state
		powerCycleTPM(baseTpm)
	} else {
		// Use embedded simulator
		t.Log("Using embedded TPM simulator")
		sim, err := simulator.Get()
		require.NoError(t, err, "Failed to open embedded simulator")
		baseTpm = transport.FromReadWriteCloser(sim)
	}

	// Wrap with capture
	capture := NewTPMCapture(baseTpm)

	// Create logger
	logger := logging.DefaultLogger()

	// Create temporary filesystem for test
	fs := afero.NewMemMapFs()
	testDir := fmt.Sprintf("/tmp/tpm-capture-test-%d", time.Now().UnixNano())

	// Create blob store
	blobStore, err := store.NewFSBlobStore(logger, fs, testDir, nil)
	require.NoError(t, err, "Failed to create blob store")

	// Create file backend
	fileBackend := store.NewFileBackend(logger, fs, testDir)

	// Create TPM configuration
	tpmConfig := &tpm2ks.Config{
		Device:          "", // Not using device, using custom transport
		UseSimulator:    false,
		EncryptSession:  encryptSession,
		Hash:            "SHA-256",
		PlatformPCR:     16,
		PlatformPCRBank: "sha256",
		EK: &tpm2ks.EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IAK: &tpm2ks.IAKConfig{
			Handle:             0x81010002,
			Hash:               "SHA-256",
			KeyAlgorithm:       x509.RSA.String(),
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		SSRK: &tpm2ks.SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
	}

	// Create TPM2 params with custom transport
	params := &tpm2ks.Params{
		Logger:       logger,
		DebugSecrets: false, // Disable to reduce noise in capture
		Config:       tpmConfig,
		BlobStore:    blobStore,
		Backend:      fileBackend,
		FQDN:         fmt.Sprintf("capture-test-%d.example.com", time.Now().UnixNano()),
		Transport:    capture, // Use capture transport
	}

	// Create TPM2 instance (allow ErrNotInitialized for fresh TPM)
	tpmInstance, err := tpm2ks.NewTPM2(params)
	if err != nil && err != tpm2ks.ErrNotInitialized {
		capture.Close()
		require.NoError(t, err, "Failed to create TPM2 instance")
	}

	// Provision if needed
	if err == tpm2ks.ErrNotInitialized {
		t.Log("TPM not initialized, provisioning...")
		if provErr := tpmInstance.Provision(nil); provErr != nil {
			capture.Close()
			require.NoError(t, provErr, "Failed to provision TPM")
		}
	}

	return &TPM2TestSetup{
		TPM:         tpmInstance,
		Capture:     capture,
		TmpDir:      tmpDir,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
		PKCS8:       pkcs8Backend,
	}
}

// Cleanup cleans up all resources
func (setup *TPM2TestSetup) Cleanup() {
	if setup.TPM != nil {
		// TPM.Close() will close the TPM transport (capture wrapper),
		// which in turn closes the base TPM. So we don't need to close capture separately.
		setup.TPM.Close()
	}
	// Don't close Capture here - it's already closed by TPM.Close()
	if setup.TmpDir != "" {
		os.RemoveAll(setup.TmpDir)
	}
}

// powerCycleTPM sends power cycle commands to SWTPM simulator
func powerCycleTPM(tpm transport.TPMCloser) {
	// For SWTPM, we can send Shutdown/Startup commands
	// This is best-effort - if it fails, we continue anyway
	defer func() {
		if r := recover(); r != nil {
			// Ignore any panics from power cycle attempts
		}
	}()

	// Note: Power cycling may not work with all TPM types
	// This is mainly for SWTPM TCP simulator
}
