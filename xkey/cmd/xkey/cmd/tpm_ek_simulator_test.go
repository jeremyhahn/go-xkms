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

package cmd

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// withECEKCertSimulator provisions the simulator with an EC EK certificate
// in the TCG EC index and no RSA EK certificate. openTPM always opens the
// TPM for the RSA certificate index, but EKCertificateEC reads the fixed EC
// index, so the show, export and backup verbs see the EC certificate
// through the shared simulator.
func withECEKCertSimulator(t *testing.T) *x509.Certificate {
	t.Helper()
	sim := withProvisionedSimulatorTPMForECCert(t)
	cert := issueTestCert(t, sim.caCert, sim.caKey, "Test EC EK Certificate", foreignECKey(t))
	require.NoError(t, sim.tpm.ProvisionEKCert(nil, cert.Raw))
	setVar(t, &openTPM, func() (xkms.TrustedPlatformModule, error) {
		return sharedTPM{sim.tpm}, nil
	})
	return cert
}

func TestRunEKShow_ECCertificate(t *testing.T) {
	want := withECEKCertSimulator(t)
	setVar(t, &ekUseEC, true)
	setVar(t, &tpmCfg.outputFormat, "json")

	stdout, _, err := runTPMSubcommand(runEKShow)
	require.NoError(t, err)

	var info struct {
		Algorithm   string `json:"algorithm"`
		ECCCurve    string `json:"ecc_curve"`
		RSAKeySize  *int   `json:"rsa_key_size"`
		Certificate struct {
			Subject      string `json:"subject"`
			SerialNumber string `json:"serial_number"`
		} `json:"certificate"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &info))
	assert.Equal(t, x509.ECDSA.String(), info.Algorithm)
	assert.Equal(t, "P-256", info.ECCCurve)
	assert.Nil(t, info.RSAKeySize, "--ec reports EC attributes, never the RSA key size")
	assert.Equal(t, "CN=Test EC EK Certificate", info.Certificate.Subject)
	assert.Equal(t, want.SerialNumber.String(), info.Certificate.SerialNumber)
}

func TestRunEKExport_ECCertificate(t *testing.T) {
	want := withECEKCertSimulator(t)
	setVar(t, &ekUseEC, true)
	setVar(t, &ekExportOutput, "-")

	stdout, _, err := runTPMSubcommand(runEKExport)
	require.NoError(t, err)
	assert.Equal(t, want.Raw, decodePEMCert(t, []byte(stdout)).Raw)
}

func TestRunEKBackup_ECCertificateOnly(t *testing.T) {
	want := withECEKCertSimulator(t)
	dir := filepath.Join(t.TempDir(), "backup")
	setVar(t, &ekBackupOutput, dir)

	stdout, _, err := runTPMSubcommand(runEKBackup)
	require.NoError(t, err)
	assert.Contains(t, stdout, "RSA EK certificate not available")
	assert.Contains(t, stdout, "EC EK certificate backed up to: "+filepath.Join(dir, "ek-cert-ec.pem"))
	assert.Contains(t, stdout, "Backed up 1 EK certificate(s)")

	data, err := os.ReadFile(filepath.Join(dir, "ek-cert-ec.pem"))
	require.NoError(t, err)
	assert.Equal(t, want.Raw, decodePEMCert(t, data).Raw)
	assert.NoFileExists(t, filepath.Join(dir, "ek-cert-rsa.pem"))
}

func TestRunEKCommands_WithoutEKCertificate(t *testing.T) {
	// ek show --ec opens the TPM for the EC certificate index, so each
	// algorithm gets a simulator opened for its own index; export opens
	// through openTPM either way.
	simulators := map[bool]func(t *testing.T){
		false: func(t *testing.T) { withProvisionedSimulatorTPMWithoutEKCert(t) },
		true: func(t *testing.T) {
			sim := withProvisionedSimulatorTPMForECCert(t)
			setVar(t, &openTPM, func() (xkms.TrustedPlatformModule, error) {
				return sharedTPM{sim.tpm}, nil
			})
		},
	}

	for _, useEC := range []bool{false, true} {
		t.Run(fmt.Sprintf("ec=%v", useEC), func(t *testing.T) {
			simulators[useEC](t)
			setVar(t, &ekExportOutput, "-")
			setVar(t, &ekUseEC, useEC)

			_, _, err := runTPMSubcommand(runEKShow)
			assert.ErrorIs(t, err, ErrKeyNotFound, "show")

			stdout, _, err := runTPMSubcommand(runEKExport)
			assert.ErrorIs(t, err, ErrCertificateNotFound, "export")
			assert.Empty(t, stdout, "export")
		})
	}
}

func TestRunEKBackup_NoCertificates(t *testing.T) {
	withProvisionedSimulatorTPMWithoutEKCert(t)
	dir := filepath.Join(t.TempDir(), "backup")
	setVar(t, &ekBackupOutput, dir)

	stdout, _, err := runTPMSubcommand(runEKBackup)
	assert.ErrorContains(t, err, "no EK certificates available to backup")
	assert.Contains(t, stdout, "RSA EK certificate not available")
	assert.Contains(t, stdout, "EC EK certificate not available")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "a failed backup writes no certificate files")
}

func TestRunEKCommands_MissingDevice(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.device = filepath.Join(t.TempDir(), "no-such-tpm-device")
		c.useSimulator = false
		c.outputFormat = "text"
	})
	backupDir := filepath.Join(t.TempDir(), "backup")
	setVar(t, &ekExportOutput, "-")
	setVar(t, &ekBackupOutput, backupDir)

	for name, run := range map[string]func(*cobra.Command, []string) error{
		"show":   runEKShow,
		"export": runEKExport,
		"backup": runEKBackup,
	} {
		t.Run(name, func(t *testing.T) {
			stdout, _, err := runTPMSubcommand(run)
			require.ErrorIs(t, err, xkms.ErrTPMOpeningDevice)
			assert.Empty(t, stdout)
		})
	}
	assert.NoDirExists(t, backupDir, "backup creates nothing when the TPM cannot be opened")
}
