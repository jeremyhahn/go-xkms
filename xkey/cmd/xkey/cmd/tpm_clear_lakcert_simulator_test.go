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

// These tests drive `xkey tpm clear` (tpm_clear.go) and `xkey tpm lak cert`
// (tpm_lak_cert.go) against the in-process TPM 2.0 simulator. The --force
// clear path is deliberately not exercised: CI runs as root, and that path
// writes the host's UEFI PPI request and reboots the machine.
package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	gotpm2 "github.com/google/go-tpm/tpm2"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/xkmstest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lakSimulator is a simulator TPM that holds a Local Attestation Key, with
// the test CA that issues certificates for it.
type lakSimulator struct {
	tpm    xkms.TrustedPlatformModule
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

// withLAKSimulatorTPM provisions a simulator TPM, enrols its Platform SRK,
// creates the LAK under it and routes openTPM to it.
//
// The xkey CLI's own TPM configuration names no Platform SRK, so no CLI verb
// can enrol one or create a LAK; the TPM here is built from the SDK default
// configuration, which does, the way the keybackend LAK harness builds it.
func withLAKSimulatorTPM(t *testing.T) *lakSimulator {
	t.Helper()
	withTPMCfg(t, func(c *tpmConfig) {
		c.device = ""
		c.useSimulator = true
		c.outputFormat = "text"
		c.hierarchyAuth = ""
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sim, err := xkms.OpenSimulator()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, sim.Close()) })

	storageFactory, err := xkms.NewTPMStorageFactory(logger, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, storageFactory.Close()) })

	config := xkms.DefaultTPMConfig
	config.UseSimulator = false // the transport is supplied explicitly
	config.Device = ""
	// The LAK certificate lives in NV RAM, at the index xkey's own
	// configuration gives it.
	lak := *config.LAK
	lak.CertHandle = 0x01C00003
	config.LAK = &lak

	tpm, err := xkms.NewTPM2(&xkms.TPMParams{
		Config:    &config,
		Logger:    logger,
		Backend:   storageFactory.KeyBackend(),
		BlobStore: storageFactory.BlobStore(),
		Transport: sim.Transport(),
	})
	if tpm != nil {
		t.Cleanup(func() { assert.NoError(t, tpm.Close()) })
	}
	if errors.Is(err, xkms.ErrTPMNotInitialized) {
		require.NoError(t, tpm.Provision(nil))
	} else {
		require.NoError(t, err)
	}
	require.NoError(t, xkmstest.EnrollPlatformSRK(tpm, &config))
	_, err = tpm.CreateLAK(nil, nil, false)
	require.NoError(t, err)

	shared := sharedTPM{tpm}
	setVar(t, &openTPM, func() (xkms.TrustedPlatformModule, error) { return shared, nil })

	caCert, caKey := generateEKTestCA(t)
	return &lakSimulator{tpm: tpm, caCert: caCert, caKey: caKey}
}

// setLAKCertExportOutputs points the three export flags into dir.
func setLAKCertExportOutputs(t *testing.T, dir string) (certifyInfo, signature, publicArea string) {
	t.Helper()
	certifyInfo = filepath.Join(dir, "certify-info.bin")
	signature = filepath.Join(dir, "signature.bin")
	publicArea = filepath.Join(dir, "public-area.bin")
	setVar(t, &lakCertifyInfoOutput, certifyInfo)
	setVar(t, &lakSignatureOutput, signature)
	setVar(t, &lakPublicAreaOutput, publicArea)
	return certifyInfo, signature, publicArea
}

func readExportedFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

// TestRunLAKCertExport_LAKSimulator proves the exported evidence is what a
// CA verifies: a TPM2_Certify attestation that echoes the nonce, names the
// exported LAK public area, and carries a valid IAK signature.
func TestRunLAKCertExport_LAKSimulator(t *testing.T) {
	sim := withLAKSimulatorTPM(t)
	certifyInfoPath, signaturePath, publicAreaPath := setLAKCertExportOutputs(t, t.TempDir())
	nonce := []byte("lak-export-nonce")
	setVar(t, &lakCertifyNonce, hex.EncodeToString(nonce))

	stdout, _, err := runTPMSubcommand(runLAKCertExport)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Certify info written to:    "+certifyInfoPath)
	assert.Contains(t, stdout, "Signature written to:       "+signaturePath)
	assert.Contains(t, stdout, "LAK public area written to: "+publicAreaPath)
	assert.Contains(t, stdout, "Signature algorithm:        "+x509.SHA256WithRSAPSS.String())

	certifyInfo := readExportedFile(t, certifyInfoPath)
	attest, err := gotpm2.Unmarshal[gotpm2.TPMSAttest](certifyInfo)
	require.NoError(t, err)
	assert.Equal(t, gotpm2.TPMSTAttestCertify, attest.Type)
	assert.Equal(t, nonce, attest.ExtraData.Buffer)

	publicArea, err := gotpm2.Unmarshal[gotpm2.TPMTPublic](readExportedFile(t, publicAreaPath))
	require.NoError(t, err)
	lakName, err := gotpm2.ObjectName(publicArea)
	require.NoError(t, err)
	certified, err := attest.Attested.Certify()
	require.NoError(t, err)
	assert.Equal(t, lakName.Buffer, certified.Name.Buffer, "the attestation must name the exported LAK public area")

	iakPub, err := sim.tpm.IAK()
	require.NoError(t, err)
	iakRSA, ok := iakPub.(*rsa.PublicKey)
	require.True(t, ok, "the default IAK is RSA")
	digest := sha256.Sum256(certifyInfo)
	assert.NoError(t, rsa.VerifyPSS(iakRSA, crypto.SHA256, digest[:], readExportedFile(t, signaturePath),
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}), "the IAK must have signed the certify info")
}

func TestRunLAKCertExport_UnwritableOutput(t *testing.T) {
	withLAKSimulatorTPM(t)
	setLAKCertExportOutputs(t, t.TempDir())
	setVar(t, &lakCertifyNonce, "")
	setVar(t, &lakCertifyInfoOutput, filepath.Join(t.TempDir(), "missing-dir", "certify-info.bin"))

	_, _, err := runTPMSubcommand(runLAKCertExport)
	assert.ErrorIs(t, err, ErrExportFailed)
	assert.NoFileExists(t, lakSignatureOutput, "nothing after the failed write is exported")
}

func TestRunLAKCertImport_LAKSimulator(t *testing.T) {
	sim := withLAKSimulatorTPM(t)
	lakPub, err := sim.tpm.LAK()
	require.NoError(t, err)
	cert := issueTestCert(t, sim.caCert, sim.caKey, "xkey-lak", lakPub)
	setVar(t, &lakCertImportPath, writeCertPEM(t, cert))
	setVar(t, &lakCertImportForce, false)

	stdout, _, err := runTPMSubcommand(runLAKCertImport)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Public key verification: PASSED")
	assert.Contains(t, stdout, "LAK certificate imported successfully")

	stored, err := sim.tpm.LAKCertificate()
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, stored.Raw)
}

func TestRunLAKCertImport_RejectsAForeignKey(t *testing.T) {
	sim := withLAKSimulatorTPM(t)
	cert := issueTestCert(t, sim.caCert, sim.caKey, "xkey-lak", foreignRSAKey(t))
	setVar(t, &lakCertImportPath, writeCertPEM(t, cert))

	t.Run("verified", func(t *testing.T) {
		setVar(t, &lakCertImportForce, false)
		_, _, err := runTPMSubcommand(runLAKCertImport)
		assert.ErrorIs(t, err, ErrLAKPublicKeyMismatch)
	})

	// --force skips only the CLI's own comparison; the TPM still refuses to
	// bind a certificate for another key to the LAK.
	t.Run("forced", func(t *testing.T) {
		setVar(t, &lakCertImportForce, true)
		stdout, _, err := runTPMSubcommand(runLAKCertImport)
		assert.ErrorIs(t, err, ErrLAKCertImportFailed)
		assert.Contains(t, stdout, "Public key verification: SKIPPED (--force)")
	})

	_, err := sim.tpm.LAKCertificate()
	assert.Error(t, err, "a rejected import stores no certificate")
}

func TestLAKCertCommands_MissingDevice(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.device = filepath.Join(t.TempDir(), "no-such-tpm-device")
		c.useSimulator = false
		c.outputFormat = "text"
	})

	t.Run("export", func(t *testing.T) {
		dir := t.TempDir()
		setLAKCertExportOutputs(t, dir)
		setVar(t, &lakCertifyNonce, "")
		_, _, err := runTPMSubcommand(runLAKCertExport)
		assert.ErrorIs(t, err, xkms.ErrTPMOpeningDevice)
		entries, readErr := os.ReadDir(dir)
		require.NoError(t, readErr)
		assert.Empty(t, entries, "no evidence is written without a TPM")
	})

	t.Run("import", func(t *testing.T) {
		caCert, caKey := generateEKTestCA(t)
		cert := issueTestCert(t, caCert, caKey, "xkey-lak", foreignRSAKey(t))
		setVar(t, &lakCertImportPath, writeCertPEM(t, cert))
		_, _, err := runTPMSubcommand(runLAKCertImport)
		assert.ErrorIs(t, err, xkms.ErrTPMOpeningDevice)
	})
}

// TestRunTPMClear_RemovesPersistentObjects proves a confirmed clear empties
// the Endorsement and Storage hierarchies: the EK and IAK persistent handles
// are gone afterwards.
func TestRunTPMClear_RemovesPersistentObjects(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	setVar(t, clearCfg, tpmClearConfig{yes: true})

	ekAttrs, err := sim.tpm.EKAttributes()
	require.NoError(t, err)
	iakAttrs, err := sim.tpm.IAKAttributes()
	require.NoError(t, err)
	handles := map[string]gotpm2.TPMHandle{
		"EK":  ekAttrs.TPMAttributes.Handle,
		"IAK": iakAttrs.TPMAttributes.Handle,
	}
	for name, handle := range handles {
		_, err := sim.tpm.KeyAttributes(handle)
		require.NoError(t, err, "%s must be present before the clear", name)
	}

	stdout, _, err := runTPMSubcommand(runTPMClear)
	require.NoError(t, err)
	assert.Contains(t, stdout, "TPM successfully cleared.")

	for name, handle := range handles {
		_, err := sim.tpm.KeyAttributes(handle)
		assert.Error(t, err, "%s must be gone after the clear", name)
	}
}

// TestRunTPMClear_FallsBackToHierarchyAuth proves that without --lockout-auth
// the global hierarchy auth is presented as the lockout auth: a wrong one
// makes the clear fail and leaves the TPM's objects in place.
func TestRunTPMClear_FallsBackToHierarchyAuth(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	withTPMCfg(t, func(c *tpmConfig) { c.hierarchyAuth = "wrong" })
	setVar(t, clearCfg, tpmClearConfig{yes: true})

	_, stderr, err := runTPMSubcommand(runTPMClear)
	require.Error(t, err)
	assert.Contains(t, stderr, "TPM clear failed")
	_, err = sim.tpm.IAKAttributes()
	assert.NoError(t, err, "a failed clear leaves the IAK in place")
}

func TestRunTPMClear_Confirmation(t *testing.T) {
	tests := []struct {
		name      string
		force     bool
		input     string
		wantForce bool
	}{
		{name: "end of input", input: ""},
		{name: "anything but yes", input: "y\n"},
		// Refusing the force prompt returns before the root check, the PPI
		// write and the reboot.
		{name: "force refused", force: true, input: "no\n", wantForce: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setVar(t, clearCfg, tpmClearConfig{force: tt.force})
			pipeStdin(t, tt.input)

			stdout, _, err := runTPMSubcommand(runTPMClear)
			assert.ErrorIs(t, err, ErrTPMClearCancelled)
			assert.Contains(t, stdout, "WARNING: TPM CLEAR OPERATION")
			assert.Contains(t, stdout, "Type 'yes' to proceed: ")
			if tt.wantForce {
				assert.Contains(t, stdout, "System will REBOOT")
			} else {
				assert.NotContains(t, stdout, "Mode: FORCE")
			}
		})
	}
}

func TestRunTPMClear_MissingDevice(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.device = filepath.Join(t.TempDir(), "no-such-tpm-device")
		c.useSimulator = false
	})
	setVar(t, clearCfg, tpmClearConfig{yes: true})

	stdout, stderr, err := runTPMSubcommand(runTPMClear)
	assert.ErrorIs(t, err, xkms.ErrTPMOpeningDevice)
	assert.Contains(t, stderr, "Failed to open TPM")
	assert.NotContains(t, stdout, "Clearing TPM")
}
