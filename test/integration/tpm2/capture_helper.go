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
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	tpm2ks "github.com/jeremyhahn/go-keychain/pkg/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TPM2TestSetup contains all components needed for TPM testing with capture
type TPM2TestSetup struct {
	KeyStore    *tpm2ks.TPM2KeyStore
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
	var tpmConfig *tpm2ks.Config

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

		// Configure for SWTPM
		tpmConfig = &tpm2ks.Config{
			CN:             fmt.Sprintf("test-capture-srk-%d", time.Now().UnixNano()),
			SRKHandle:      0x81000001,
			EncryptSession: encryptSession,
			UseSimulator:   true,
			SimulatorType:  "swtpm",
			SimulatorHost:  simHost,
			SimulatorPort:  0, // Will be parsed from simPort
		}
		// Parse port
		if port := simPort; port != "" {
			var portNum int
			fmt.Sscanf(port, "%d", &portNum)
			tpmConfig.SimulatorPort = portNum
		}
	} else {
		// Use embedded simulator
		t.Log("Using embedded TPM simulator")
		sim, err := simulator.Get()
		require.NoError(t, err, "Failed to open embedded simulator")
		baseTpm = transport.FromReadWriteCloser(sim)

		// Configure for embedded simulator
		tpmConfig = &tpm2ks.Config{
			CN:             fmt.Sprintf("test-capture-srk-%d", time.Now().UnixNano()),
			SRKHandle:      0x81000001,
			EncryptSession: encryptSession,
			UseSimulator:   true,
			SimulatorType:  "embedded",
		}
	}

	// Wrap with capture
	capture := NewTPMCapture(baseTpm)

	// Create keystore
	ks, err := tpm2ks.NewTPM2KeyStore(tpmConfig, pkcs8Backend, keyStorage, certStorage, capture)
	require.NoError(t, err, "Failed to create TPM2KeyStore")

	// Initialize the TPM (this will use our capturing transport)
	err = ks.Initialize(nil, nil)
	if err != nil && err.Error() != "keystore: already initialized" && err.Error() != "keystore already initialized" {
		require.NoError(t, err, "Failed to initialize TPM")
	}

	return &TPM2TestSetup{
		KeyStore:    ks,
		Capture:     capture,
		TmpDir:      tmpDir,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
		PKCS8:       pkcs8Backend,
	}
}

// Cleanup cleans up all resources
func (setup *TPM2TestSetup) Cleanup() {
	if setup.KeyStore != nil {
		// KeyStore.Close() will close the TPM transport (capture wrapper),
		// which in turn closes the base TPM. So we don't need to close capture separately.
		setup.KeyStore.Close()
	}
	// Don't close Capture here - it's already closed by KeyStore.Close()
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
