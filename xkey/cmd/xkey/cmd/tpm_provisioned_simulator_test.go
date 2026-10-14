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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	gotpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/xkmstest"
)

// sharedTPM keeps the provisioned simulator open across subcommands: each
// subcommand defers Close on the TPM it opened, and closing the simulator
// re-manufactures it, which would discard every provisioned key.
type sharedTPM struct {
	xkms.TrustedPlatformModule
}

// Close leaves the shared simulator open; withProvisionedSimulatorTPM
// closes it when the test ends.
func (sharedTPM) Close() error { return nil }

// provisionedSimulator is an open, provisioned simulator plus the CA that
// issued its EK certificate, so tests can issue further certificates for
// TPM-resident keys.
type provisionedSimulator struct {
	tpm    xkms.TrustedPlatformModule
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey

	// The PCR overrides the last openTPMForProvisioningWithPCROverrides
	// call asked for.
	pcrBank     string
	goldenPCRs  []uint
	platformPCR int
}

// withProvisionedSimulatorTPM opens the in-process simulator, provisions
// it (EK, SRK, IAK) with a CA-issued EK certificate in NV RAM, and routes
// every `tpm` subcommand's opener through it until the test ends.
func withProvisionedSimulatorTPM(t *testing.T) *provisionedSimulator {
	t.Helper()
	sim := withProvisionedSimulatorTPMWithoutEKCert(t)
	ekPub, err := sim.tpm.EKRSA()
	require.NoError(t, err)
	ekCert := issueTestCert(t, sim.caCert, sim.caKey, "Test EK Certificate", ekPub)
	require.NoError(t, sim.tpm.ProvisionEKCert(nil, ekCert.Raw))
	return sim
}

// withProvisionedSimulatorTPMWithoutEKCert is withProvisionedSimulatorTPM
// for a platform whose EK certificate NV index is empty, as after a TPM
// clear.
func withProvisionedSimulatorTPMWithoutEKCert(t *testing.T) *provisionedSimulator {
	t.Helper()
	withSimulatorTPMCfg(t)

	tpm, err := openConfiguredTPMForProvisioningWithPCROverrides("sha256", []uint{0, 7}, 0)
	require.NoError(t, err)
	return shareProvisionedSimulatorTPM(t, tpm, ekCertHandleRSA)
}

// withProvisionedSimulatorTPMForECCert is withProvisionedSimulatorTPMWithoutEKCert
// with the TPM configured to write its EK certificate to the EC index, the
// TPM `tpm ek restore --ec` opens.
func withProvisionedSimulatorTPMForECCert(t *testing.T) *provisionedSimulator {
	t.Helper()
	withSimulatorTPMCfg(t)

	config, err := newTPMConfig("", true, ekCertHandleEC)
	require.NoError(t, err)
	tpm, err := xkms.NewTPM2(newTPMParams(config))
	require.ErrorIs(t, err, xkms.ErrTPMNotInitialized)
	return shareProvisionedSimulatorTPM(t, tpm, ekCertHandleEC)
}

func withSimulatorTPMCfg(t *testing.T) {
	t.Helper()
	withTPMCfg(t, func(c *tpmConfig) {
		c.device = ""
		c.useSimulator = true
		c.outputFormat = "text"
		c.hierarchyAuth = ""
	})
}

// shareProvisionedSimulatorTPM provisions tpm and routes every TPM opener to
// it until the test ends. ekCertHandle is the EK certificate index tpm is
// configured with; an opener that would open the TPM for another index fails
// the test.
func shareProvisionedSimulatorTPM(t *testing.T, tpm xkms.TrustedPlatformModule, ekCertHandle uint32) *provisionedSimulator {
	t.Helper()
	t.Cleanup(func() {
		assert.NoError(t, tpm.Close())
	})
	require.NoError(t, tpm.Provision(nil))

	caCert, caKey := generateEKTestCA(t)
	sim := &provisionedSimulator{tpm: tpm, caCert: caCert, caKey: caKey}

	savedOpen, savedOpenForEKCert, savedOpenForEKRestore, savedOpenWithPCROverrides := openTPM, openTPMForEKCert, openTPMForEKRestore, openTPMForProvisioningWithPCROverrides
	t.Cleanup(func() {
		openTPM, openTPMForEKCert, openTPMForEKRestore, openTPMForProvisioningWithPCROverrides = savedOpen, savedOpenForEKCert, savedOpenForEKRestore, savedOpenWithPCROverrides
	})
	shared := sharedTPM{tpm}
	openTPM = func() (xkms.TrustedPlatformModule, error) {
		require.Equal(t, ekCertHandle, ekCertHandleRSA, "openTPM opens the TPM for the RSA EK certificate index")
		return shared, nil
	}
	openTPMForEKCert = func(handle uint32) (xkms.TrustedPlatformModule, error) {
		require.Equal(t, ekCertHandle, handle, "EK certificate index the TPM is opened for")
		return shared, nil
	}
	openTPMForEKRestore = openTPMForEKCert
	openTPMForProvisioningWithPCROverrides = func(pcrBank string, goldenPCRs []uint, platformPCR int) (xkms.TrustedPlatformModule, error) {
		sim.pcrBank, sim.goldenPCRs, sim.platformPCR = pcrBank, goldenPCRs, platformPCR
		return shared, nil
	}
	return sim
}

// withIDevID creates the IDevID on the provisioned simulator, as
// `xkey tpm idevid create` does after `xkey tpm provision`.
func (s *provisionedSimulator) withIDevID(t *testing.T) crypto.PublicKey {
	t.Helper()
	setVar(t, &idevidCreateTemplate, "rsa-pss")
	setVar(t, &idevidCreateForce, false)
	_, _, err := runTPMSubcommand(runIDevIDCreate)
	require.NoError(t, err)
	pub, err := s.tpm.IDevID()
	require.NoError(t, err)
	return pub
}

// issueTestCert issues a certificate for pub, signed by the test CA, as a
// manufacturer or enterprise CA would for a TPM-resident key.
func issueTestCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// writeCertPEM writes cert as a PEM file in a fresh temp dir and returns its path.
func writeCertPEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cert.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

// writeTempInput writes content to a file in a fresh temp dir and returns its path.
func writeTempInput(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

// foreignRSAKey returns an RSA public key that no TPM key matches.
func foreignRSAKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &key.PublicKey
}

// setVar sets a package-level flag variable for the duration of the test.
func setVar[T any](t *testing.T, p *T, v T) {
	t.Helper()
	saved := *p
	*p = v
	t.Cleanup(func() { *p = saved })
}

// runTPMSubcommand runs a `tpm` subcommand's RunE and returns what it wrote
// to stdout and stderr.
func runTPMSubcommand(run func(*cobra.Command, []string) error) (string, string, error) {
	cmd := &cobra.Command{}
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := run(cmd, nil)
	return stdout.String(), stderr.String(), err
}

// decodePEMCert parses the first PEM certificate in data.
func decodePEMCert(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	require.NotNil(t, block, "no PEM block in %q", data)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func TestRunTPMStatus_ProvisionedSimulator(t *testing.T) {
	withProvisionedSimulatorTPM(t)
	setVar(t, &tpmCfg.outputFormat, "json")

	stdout, _, err := runTPMSubcommand(runTPMStatus)
	require.NoError(t, err)

	var status TPMStatusOutput
	require.NoError(t, json.Unmarshal([]byte(stdout), &status))
	assert.True(t, status.Provisioned)
	present := map[string]bool{}
	for _, key := range status.Keys {
		present[key.Name] = key.Present
	}
	assert.True(t, present["EK"], "EK present; keys = %+v", status.Keys)
	assert.True(t, present["IAK"], "IAK present; keys = %+v", status.Keys)
	assert.False(t, present["IDevID"], "IDevID is created separately; keys = %+v", status.Keys)
	certPresent := map[string]bool{}
	for _, cert := range status.Certificates {
		certPresent[cert.Name] = cert.Present
	}
	assert.True(t, certPresent["EK Cert"], "EK certificate present; certs = %+v", status.Certificates)
	assert.False(t, certPresent["IDevID Cert"], "IDevID certificate absent; certs = %+v", status.Certificates)
}

func TestRunEKShow_ProvisionedSimulator(t *testing.T) {
	withProvisionedSimulatorTPM(t)

	t.Run("text", func(t *testing.T) {
		stdout, _, err := runTPMSubcommand(runEKShow)
		require.NoError(t, err)
		assert.Contains(t, stdout, "0x81010001")
		assert.Contains(t, stdout, "Test EK Certificate")
	})

	t.Run("json", func(t *testing.T) {
		setVar(t, &tpmCfg.outputFormat, "json")
		stdout, _, err := runTPMSubcommand(runEKShow)
		require.NoError(t, err)

		var info struct {
			Handle      string `json:"handle"`
			Certificate struct {
				Subject string `json:"subject"`
				Issuer  string `json:"issuer"`
			} `json:"certificate"`
		}
		require.NoError(t, json.Unmarshal([]byte(stdout), &info))
		assert.Equal(t, "0x81010001", info.Handle)
		assert.Equal(t, "CN=Test EK Certificate", info.Certificate.Subject)
		assert.Contains(t, info.Certificate.Issuer, "Test TPM Manufacturer CA")
	})
}

// TestRunEKShow_ECCertificate proves `ek show --ec` describes the EC EK
// from its certificate at the TCG ECC P-256 index, never the RSA EK at
// 0x81010001 relabelled as ECDSA (go-xkms#704).
func TestRunEKShow_ECCertificateTextAndJSON(t *testing.T) {
	sim := withProvisionedSimulatorTPMForECCert(t)
	setVar(t, &ekUseEC, true)
	ecCert := issueTestCert(t, sim.caCert, sim.caKey, "Test EC EK Certificate", foreignECKey(t))
	require.NoError(t, sim.tpm.ProvisionEKCert(nil, ecCert.Raw))

	t.Run("text", func(t *testing.T) {
		stdout, _, err := runTPMSubcommand(runEKShow)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Algorithm: ECDSA")
		assert.Contains(t, stdout, "ECC Curve: P-256")
		assert.Contains(t, stdout, "Cert NV:   0x01C0000A")
		assert.Contains(t, stdout, "Test EC EK Certificate")
		assert.NotContains(t, stdout, "0x81010001", "the RSA EK's handle")
		assert.NotContains(t, stdout, "RSA Size")
	})

	t.Run("json", func(t *testing.T) {
		setVar(t, &tpmCfg.outputFormat, "json")
		stdout, _, err := runTPMSubcommand(runEKShow)
		require.NoError(t, err)

		var info map[string]any
		require.NoError(t, json.Unmarshal([]byte(stdout), &info))
		assert.Equal(t, "ECDSA", info["algorithm"])
		assert.Equal(t, "P-256", info["ecc_curve"])
		assert.Equal(t, "0x01C0000A", info["cert_handle"])
		assert.NotContains(t, info, "handle", "the EC EK has no persistent handle")
		assert.NotContains(t, info, "rsa_key_size")
	})
}

// TestRunEKShow_ECCertificateErrors proves `ek show --ec` fails when the EC
// index holds no certificate, or a certificate over a key that is not EC.
func TestRunEKShow_ECCertificateErrors(t *testing.T) {
	t.Run("no EC certificate", func(t *testing.T) {
		withProvisionedSimulatorTPMForECCert(t)
		setVar(t, &ekUseEC, true)

		_, _, err := runTPMSubcommand(runEKShow)
		require.ErrorIs(t, err, ErrKeyNotFound)
	})

	t.Run("RSA key at the EC index", func(t *testing.T) {
		sim := withProvisionedSimulatorTPMForECCert(t)
		setVar(t, &ekUseEC, true)
		rsaCert := issueTestCert(t, sim.caCert, sim.caKey, "Misplaced RSA Certificate", foreignRSAKey(t))
		require.NoError(t, sim.tpm.ProvisionEKCert(nil, rsaCert.Raw))

		_, _, err := runTPMSubcommand(runEKShow)
		require.ErrorIs(t, err, ErrInvalidKeyAlgorithm)
	})
}

// TestTPMCommands_NotProvisioned drives every command that needs a
// provisioned TPM against a simulator with no EK: each fails with
// ErrTPMNotInitialized and leaves the simulator free for the next open
// (go-xkms#704).
func TestTPMCommands_NotProvisioned(t *testing.T) {
	withSimulatorTPMCfg(t)
	caCert, caKey := generateEKTestCA(t)
	certFile := writeCertPEM(t, issueTestCert(t, caCert, caKey, "Unprovisioned Test Certificate", foreignECKey(t)))
	setVar(t, &ekRestoreInput, certFile)
	setVar(t, &ekRestoreForce, false)
	setVar(t, &idevidCertImportPath, certFile)
	setVar(t, &lakCertImportPath, certFile)
	setVar(t, &iakCreateTemplate, "rsa2048")
	setVar(t, &idevidCreateTemplate, "rsa2048")
	setVar(t, &quotePCRs, "0,7")
	setVar(t, &quoteNonce, "")
	setVar(t, &lakCertifyNonce, "")

	commands := map[string]struct {
		run func(*cobra.Command, []string) error
		ec  bool
	}{
		"ek show":               {run: runEKShow},
		"ek show --ec":          {run: runEKShow, ec: true},
		"ek export":             {run: runEKExport},
		"ek backup":             {run: runEKBackup},
		"ek restore":            {run: runEKRestore},
		"ek restore --ec":       {run: runEKRestore, ec: true},
		"iak show":              {run: runIAKShow},
		"iak create":            {run: runIAKCreate},
		"iak export":            {run: runIAKExport},
		"iak csr":               {run: runIAKCSR},
		"idevid show":           {run: runIDevIDShow},
		"idevid create":         {run: runIDevIDCreate},
		"idevid export":         {run: runIDevIDExport},
		"idevid csr":            {run: runIDevIDCSR},
		"idevid csr export-pem": {run: runIDevIDCSRExportPEM},
		"idevid cert import":    {run: runIDevIDCertImport},
		"lak show":              {run: runLAKShow},
		"lak create":            {run: runLAKCreate},
		"lak cert export":       {run: runLAKCertExport},
		"lak cert import":       {run: runLAKCertImport},
		"quote":                 {run: runTPMQuote},
	}
	for name, command := range commands {
		t.Run(name, func(t *testing.T) {
			setVar(t, &ekUseEC, command.ec)

			_, _, err := runTPMSubcommand(command.run)
			require.ErrorIs(t, err, ErrTPMNotInitialized)
			requireSimulatorReleased(t)
		})
	}
}

func TestRunEKExport_ProvisionedSimulator(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	want, err := sim.tpm.EKCertificate()
	require.NoError(t, err)

	t.Run("stdout", func(t *testing.T) {
		setVar(t, &ekExportOutput, "-")
		stdout, _, err := runTPMSubcommand(runEKExport)
		require.NoError(t, err)
		assert.Equal(t, want.Raw, decodePEMCert(t, []byte(stdout)).Raw)
	})

	t.Run("file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ek.pem")
		setVar(t, &ekExportOutput, path)
		stdout, _, err := runTPMSubcommand(runEKExport)
		require.NoError(t, err)
		assert.Contains(t, stdout, "EK certificate exported to: "+path)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, want.Raw, decodePEMCert(t, data).Raw)
	})

	t.Run("unwritable path", func(t *testing.T) {
		setVar(t, &ekExportOutput, filepath.Join(t.TempDir(), "missing", "ek.pem"))
		_, _, err := runTPMSubcommand(runEKExport)
		assert.ErrorIs(t, err, ErrExportFailed)
	})
}

func TestRunEKBackup_ProvisionedSimulator(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	dir := filepath.Join(t.TempDir(), "backup")
	setVar(t, &ekBackupOutput, dir)

	stdout, _, err := runTPMSubcommand(runEKBackup)
	require.NoError(t, err)
	assert.Contains(t, stdout, "EC EK certificate not available")
	assert.Contains(t, stdout, "Backed up 1 EK certificate(s)")

	data, err := os.ReadFile(filepath.Join(dir, "ek-cert-rsa.pem"))
	require.NoError(t, err)
	want, err := sim.tpm.EKCertificateRSA()
	require.NoError(t, err)
	assert.Equal(t, want.Raw, decodePEMCert(t, data).Raw)
}

func TestRunEKBackup_OutputDirIsAFile(t *testing.T) {
	withProvisionedSimulatorTPM(t)
	setVar(t, &ekBackupOutput, writeTempInput(t, "not a directory"))

	_, _, err := runTPMSubcommand(runEKBackup)
	assert.ErrorContains(t, err, "failed to create output directory")
}

func TestRunEKRestore_ProvisionedSimulator(t *testing.T) {
	t.Run("backup is written to the empty NV index", func(t *testing.T) {
		sim := withProvisionedSimulatorTPMWithoutEKCert(t)
		setVar(t, &ekUseEC, false)
		setVar(t, &ekRestoreForce, false)
		ekPub, err := sim.tpm.EKRSA()
		require.NoError(t, err)
		backup := issueTestCert(t, sim.caCert, sim.caKey, "Restored EK Certificate", ekPub)
		setVar(t, &ekRestoreInput, writeCertPEM(t, backup))

		stdout, _, err := runTPMSubcommand(runEKRestore)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Subject: CN=Restored EK Certificate")
		assert.Contains(t, stdout, "RSA EK certificate restored successfully")

		stored, err := sim.tpm.EKCertificateRSA()
		require.NoError(t, err)
		assert.Equal(t, backup.Raw, stored.Raw)
	})

	t.Run("foreign key is refused without force", func(t *testing.T) {
		sim := withProvisionedSimulatorTPM(t)
		setVar(t, &ekUseEC, false)
		setVar(t, &ekRestoreForce, false)
		before, err := sim.tpm.EKCertificateRSA()
		require.NoError(t, err)
		foreign := issueTestCert(t, sim.caCert, sim.caKey, "Foreign EK Certificate", foreignRSAKey(t))
		setVar(t, &ekRestoreInput, writeCertPEM(t, foreign))

		_, _, err = runTPMSubcommand(runEKRestore)
		assert.ErrorContains(t, err, "does not match TPM EK - use --force to override")
		after, err := sim.tpm.EKCertificateRSA()
		require.NoError(t, err)
		assert.Equal(t, before.Raw, after.Raw, "a refused restore leaves NV RAM untouched")
	})

	t.Run("foreign key is written with force", func(t *testing.T) {
		sim := withProvisionedSimulatorTPMWithoutEKCert(t)
		setVar(t, &ekUseEC, false)
		setVar(t, &ekRestoreForce, true)
		foreign := issueTestCert(t, sim.caCert, sim.caKey, "Forced EK Certificate", foreignRSAKey(t))
		setVar(t, &ekRestoreInput, writeCertPEM(t, foreign))

		stdout, _, err := runTPMSubcommand(runEKRestore)
		require.NoError(t, err)
		assert.Contains(t, stdout, "RSA EK certificate restored successfully")
		stored, err := sim.tpm.EKCertificateRSA()
		require.NoError(t, err)
		assert.Equal(t, foreign.Raw, stored.Raw)
	})

	t.Run("force replaces a stored certificate on every run", func(t *testing.T) {
		sim := withProvisionedSimulatorTPM(t)
		setVar(t, &ekUseEC, false)
		setVar(t, &ekRestoreForce, true)
		ekBefore, err := sim.tpm.EKRSA()
		require.NoError(t, err)

		for _, cn := range []string{"First Forced EK Certificate", "Second Forced EK Certificate"} {
			foreign := issueTestCert(t, sim.caCert, sim.caKey, cn, foreignRSAKey(t))
			setVar(t, &ekRestoreInput, writeCertPEM(t, foreign))

			stdout, _, err := runTPMSubcommand(runEKRestore)
			require.NoError(t, err, cn)
			assert.Contains(t, stdout, "RSA EK certificate restored successfully")
			stored, err := sim.tpm.EKCertificateRSA()
			require.NoError(t, err)
			assert.Equal(t, foreign.Raw, stored.Raw, cn)
		}

		ekAfter, err := sim.tpm.EKRSA()
		require.NoError(t, err)
		assert.True(t, ekBefore.Equal(ekAfter), "restore replaces the certificate, never the EK")
	})

	t.Run("stored certificate is not replaced without force", func(t *testing.T) {
		sim := withProvisionedSimulatorTPM(t)
		setVar(t, &ekUseEC, false)
		setVar(t, &ekRestoreForce, false)
		before, err := sim.tpm.EKCertificateRSA()
		require.NoError(t, err)
		ekPub, err := sim.tpm.EKRSA()
		require.NoError(t, err)
		matching := issueTestCert(t, sim.caCert, sim.caKey, "Matching EK Certificate", ekPub)
		setVar(t, &ekRestoreInput, writeCertPEM(t, matching))

		_, _, err = runTPMSubcommand(runEKRestore)
		assert.ErrorIs(t, err, xkms.ErrTPMEKCertExists)
		after, err := sim.tpm.EKCertificateRSA()
		require.NoError(t, err)
		assert.Equal(t, before.Raw, after.Raw, "a refused restore leaves NV RAM untouched")
	})

	t.Run("ec backup is written to the empty EC index", func(t *testing.T) {
		sim := withProvisionedSimulatorTPMForECCert(t)
		setVar(t, &ekUseEC, true)
		setVar(t, &ekRestoreForce, false)
		backup := issueTestCert(t, sim.caCert, sim.caKey, "Restored EC EK Certificate", foreignECKey(t))
		setVar(t, &ekRestoreInput, writeCertPEM(t, backup))

		stdout, _, err := runTPMSubcommand(runEKRestore)
		require.NoError(t, err)
		assert.Contains(t, stdout, "EC EK certificate restored successfully")
		stored, err := sim.tpm.EKCertificateEC()
		require.NoError(t, err)
		assert.Equal(t, backup.Raw, stored.Raw)
		_, err = sim.tpm.EKCertificateRSA()
		assert.Error(t, err, "an EC restore never writes the RSA index")
	})

	t.Run("ec force replaces the stored EC certificate on every run", func(t *testing.T) {
		sim := withProvisionedSimulatorTPMForECCert(t)
		setVar(t, &ekUseEC, true)
		setVar(t, &ekRestoreForce, true)
		stored := issueTestCert(t, sim.caCert, sim.caKey, "Stored EC EK Certificate", foreignECKey(t))
		require.NoError(t, sim.tpm.ProvisionEKCert(nil, stored.Raw))

		for _, cn := range []string{"First Forced EC EK Certificate", "Second Forced EC EK Certificate"} {
			forced := issueTestCert(t, sim.caCert, sim.caKey, cn, foreignECKey(t))
			setVar(t, &ekRestoreInput, writeCertPEM(t, forced))

			stdout, _, err := runTPMSubcommand(runEKRestore)
			require.NoError(t, err, cn)
			assert.Contains(t, stdout, "EC EK certificate restored successfully")
			got, err := sim.tpm.EKCertificateEC()
			require.NoError(t, err)
			assert.Equal(t, forced.Raw, got.Raw, cn)
		}
		_, err := sim.tpm.EKCertificateRSA()
		assert.Error(t, err, "an EC restore never writes the RSA index")
	})
}

// withUnprovisionedSimulatorTPMForECCert routes openTPMForEKRestore to a
// simulator that was never provisioned, so it has no persistent EK, and
// holds an RSA EK certificate but an empty EC certificate index. Like the
// real opener, the route returns the TPM together with ErrTPMNotInitialized,
// because NewTPM2 finds the configured EC index empty. It returns the TPM and
// the stored RSA certificate.
func withUnprovisionedSimulatorTPMForECCert(t *testing.T) (xkms.TrustedPlatformModule, *x509.Certificate) {
	t.Helper()
	withSimulatorTPMCfg(t)

	tpm, err := openConfiguredTPMForEKRestore(ekCertHandleEC)
	require.ErrorIs(t, err, ErrTPMNotInitialized)
	require.NotNil(t, tpm)
	t.Cleanup(func() {
		assert.NoError(t, tpm.Close())
	})

	caCert, caKey := generateEKTestCA(t)
	rsaCert := issueTestCert(t, caCert, caKey, "Manufacturer RSA EK Certificate", foreignRSAKey(t))
	writeOwnerNVIndex(t, tpm.Transport(), ekCertHandleRSA, rsaCert.Raw)

	saved := openTPMForEKRestore
	t.Cleanup(func() { openTPMForEKRestore = saved })
	openTPMForEKRestore = func(handle uint32) (xkms.TrustedPlatformModule, error) {
		require.Equal(t, uint32(ekCertHandleEC), handle, "EK certificate index the TPM is opened for")
		return sharedTPM{tpm}, ErrTPMNotInitialized
	}
	return tpm, rsaCert
}

// writeOwnerNVIndex defines an owner NV index holding data, the way a
// manufacturer-installed EK certificate sits in NV RAM before provisioning.
func writeOwnerNVIndex(t *testing.T, tr transport.TPM, index uint32, data []byte) {
	t.Helper()
	owner := gotpm2.AuthHandle{Handle: gotpm2.TPMRHOwner, Auth: gotpm2.PasswordAuth(nil)}
	define := gotpm2.NVDefineSpace{
		AuthHandle: owner,
		PublicInfo: gotpm2.New2B(gotpm2.TPMSNVPublic{
			NVIndex: gotpm2.TPMHandle(index),
			NameAlg: gotpm2.TPMAlgSHA256,
			Attributes: gotpm2.TPMANV{
				OwnerWrite: true,
				OwnerRead:  true,
				AuthRead:   true,
				NoDA:       true,
				NT:         gotpm2.TPMNTOrdinary,
			},
			DataSize: uint16(len(data)),
		}),
	}
	_, err := define.Execute(tr)
	require.NoError(t, err)

	public, err := define.PublicInfo.Contents()
	require.NoError(t, err)
	name, err := gotpm2.NVName(public)
	require.NoError(t, err)
	write := gotpm2.NVWrite{
		AuthHandle: owner,
		NVIndex:    gotpm2.NamedHandle{Handle: public.NVIndex, Name: *name},
		Data:       gotpm2.TPM2BMaxNVBuffer{Buffer: data},
	}
	_, err = write.Execute(tr)
	require.NoError(t, err)
}

func TestRunEKRestore_UnprovisionedSimulator(t *testing.T) {
	t.Run("ec force writes the empty EC index without a persistent EK", func(t *testing.T) {
		tpm, rsaCert := withUnprovisionedSimulatorTPMForECCert(t)
		setVar(t, &ekUseEC, true)
		setVar(t, &ekRestoreForce, true)
		caCert, caKey := generateEKTestCA(t)
		backup := issueTestCert(t, caCert, caKey, "Restored EC EK Certificate", foreignECKey(t))
		setVar(t, &ekRestoreInput, writeCertPEM(t, backup))

		stdout, _, err := runTPMSubcommand(runEKRestore)
		require.NoError(t, err)
		assert.Contains(t, stdout, "EC EK certificate restored successfully")
		stored, err := tpm.EKCertificateEC()
		require.NoError(t, err)
		assert.Equal(t, backup.Raw, stored.Raw)
		storedRSA, err := tpm.EKCertificateRSA()
		require.NoError(t, err)
		assert.Equal(t, rsaCert.Raw, storedRSA.Raw, "an EC restore never touches the RSA index")
	})

	t.Run("without force an uninitialized TPM is refused", func(t *testing.T) {
		tpm, _ := withUnprovisionedSimulatorTPMForECCert(t)
		setVar(t, &ekUseEC, true)
		setVar(t, &ekRestoreForce, false)
		caCert, caKey := generateEKTestCA(t)
		backup := issueTestCert(t, caCert, caKey, "Restored EC EK Certificate", foreignECKey(t))
		setVar(t, &ekRestoreInput, writeCertPEM(t, backup))

		_, _, err := runTPMSubcommand(runEKRestore)
		assert.ErrorIs(t, err, ErrTPMNotInitialized)
		_, err = tpm.EKCertificateEC()
		assert.Error(t, err, "a refused restore leaves the EC index empty")
	})
}

// foreignECKey returns a P-256 public key that no TPM key matches.
func foreignECKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &key.PublicKey
}

func TestRunEKRestore_RejectsBadInput(t *testing.T) {
	tests := []struct {
		name    string
		input   func(t *testing.T) string
		wantErr string
	}{
		{"missing file", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.pem") }, "failed to read certificate file"},
		{"not PEM", func(t *testing.T) string { return writeTempInput(t, "not a certificate") }, "failed to decode PEM data"},
		{"bad DER", func(t *testing.T) string {
			return writeTempInput(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})))
		}, "failed to parse certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setVar(t, &ekRestoreInput, tt.input(t))
			_, _, err := runTPMSubcommand(runEKRestore)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestRunIAKCommands_ProvisionedSimulator(t *testing.T) {
	withProvisionedSimulatorTPM(t)

	t.Run("show text", func(t *testing.T) {
		stdout, _, err := runTPMSubcommand(runIAKShow)
		require.NoError(t, err)
		assert.Contains(t, stdout, "0x81010002")
	})

	t.Run("show json", func(t *testing.T) {
		setVar(t, &tpmCfg.outputFormat, "json")
		stdout, _, err := runTPMSubcommand(runIAKShow)
		require.NoError(t, err)
		var info IAKInfo
		require.NoError(t, json.Unmarshal([]byte(stdout), &info))
		assert.Equal(t, "0x81010002", info.Handle)
		assert.False(t, info.HasCert)
	})

	t.Run("create refuses to replace without force", func(t *testing.T) {
		setVar(t, &iakCreateTemplate, "rsa-pss")
		setVar(t, &iakCreateForce, false)
		_, _, err := runTPMSubcommand(runIAKCreate)
		assert.ErrorIs(t, err, ErrIAKAlreadyExists)
		assert.ErrorContains(t, err, "use --force to recreate")
	})

	t.Run("create --force replaces the existing IAK on every run", func(t *testing.T) {
		setVar(t, &iakCreateTemplate, "rsa-pss")
		setVar(t, &iakCreateForce, true)
		for run := 1; run <= 2; run++ {
			stdout, _, err := runTPMSubcommand(runIAKCreate)
			require.NoError(t, err, "run %d", run)
			assert.Contains(t, stdout, "IAK created successfully", "run %d", run)
		}

		stdout, _, err := runTPMSubcommand(runIAKShow)
		require.NoError(t, err)
		assert.Contains(t, stdout, "0x81010002")
	})

	t.Run("export has no certificate store", func(t *testing.T) {
		setVar(t, &iakExportOutput, "-")
		_, _, err := runTPMSubcommand(runIAKExport)
		assert.ErrorIs(t, err, ErrCertificateNotFound)
	})

	t.Run("csr", func(t *testing.T) {
		setVar(t, &iakCSROutput, filepath.Join(t.TempDir(), "iak.csr"))
		_, _, err := runTPMSubcommand(runIAKCSR)
		assert.ErrorIs(t, err, ErrCSRGenerationFailed)
	})
}

func TestRunIAKCreate_RejectsUnknownTemplate(t *testing.T) {
	setVar(t, &iakCreateTemplate, "dsa1024")
	_, _, err := runTPMSubcommand(runIAKCreate)
	assert.ErrorIs(t, err, ErrInvalidIAKTemplate)
}

// TestRunIAKCommands_MissingDevice proves every IAK command fails on a TPM
// device that cannot be opened, before producing any output.
func TestRunIAKCommands_MissingDevice(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.device = "/nonexistent/xkey-test-tpm0"
		c.useSimulator = false
		c.outputFormat = "text"
	})
	setVar(t, &iakCreateTemplate, "rsa-pss")
	setVar(t, &iakExportOutput, "-")
	setVar(t, &iakCSROutput, filepath.Join(t.TempDir(), "iak.csr"))

	for name, run := range map[string]func(*cobra.Command, []string) error{
		"show":   runIAKShow,
		"create": runIAKCreate,
		"export": runIAKExport,
		"csr":    runIAKCSR,
	} {
		t.Run(name, func(t *testing.T) {
			stdout, _, err := runTPMSubcommand(run)
			require.ErrorContains(t, err, "error opening device")
			assert.Empty(t, stdout)
		})
	}
}

func TestRunIDevIDCreate_ProvisionedSimulator(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	setVar(t, &idevidCreateTemplate, "rsa-pss")
	setVar(t, &idevidCreateForce, false)

	stdout, _, err := runTPMSubcommand(runIDevIDCreate)
	require.NoError(t, err)
	assert.Contains(t, stdout, "IDevID created successfully")
	_, err = sim.tpm.IDevIDAttributes()
	require.NoError(t, err)

	_, _, err = runTPMSubcommand(runIDevIDCreate)
	assert.ErrorIs(t, err, ErrIDevIDExists)
}

// TestRunIDevIDCreate_ForceReplacesExisting checks that --force leaves the
// device exactly as a first run does: the IDevID is re-derived and
// re-persisted, and the certificate stored for the old one is gone.
func TestRunIDevIDCreate_ForceReplacesExisting(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	idevidPub := sim.withIDevID(t)
	cert := issueTestCert(t, sim.caCert, sim.caKey, "xkey-001", idevidPub)
	require.NoError(t, sim.tpm.ProvisionIDevIDCert(cert))
	_, err := sim.tpm.IDevIDCertificate()
	require.NoError(t, err)

	setVar(t, &idevidCreateForce, true)
	for run := 1; run <= 2; run++ {
		stdout, _, err := runTPMSubcommand(runIDevIDCreate)
		require.NoError(t, err, "forced run %d", run)
		assert.Contains(t, stdout, "IDevID created successfully")

		_, err = sim.tpm.IDevIDCertificate()
		assert.Error(t, err, "forced run %d left the old certificate in place", run)

		// The IDevID is a primary key derived from the endorsement seed,
		// so the recreated key is the same key, persisted afresh.
		pub, err := sim.tpm.IDevID()
		require.NoError(t, err)
		assert.Equal(t, idevidPub, pub)
	}

	setVar(t, &idevidCreateForce, false)
	_, _, err = runTPMSubcommand(runIDevIDCreate)
	assert.ErrorIs(t, err, ErrIDevIDExists)
}

func TestRunIDevIDCreate_RejectsUnknownTemplate(t *testing.T) {
	setVar(t, &idevidCreateTemplate, "dsa1024")
	_, _, err := runTPMSubcommand(runIDevIDCreate)
	assert.ErrorIs(t, err, ErrInvalidIDevIDTemplate)
}

func TestIDevIDCommands_BeforeIDevIDExists(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)

	t.Run("csr export", func(t *testing.T) {
		setVar(t, &idevidCSRExportOutput, "-")
		_, _, err := runTPMSubcommand(runIDevIDCSRExportPEM)
		assert.ErrorIs(t, err, ErrKeyNotFound)
	})

	t.Run("csr", func(t *testing.T) {
		setVar(t, &idevidCSROutput, filepath.Join(t.TempDir(), "idevid.csr"))
		_, _, err := runTPMSubcommand(runIDevIDCSR)
		assert.ErrorContains(t, err, "IDevID not found")
	})

	t.Run("cert import", func(t *testing.T) {
		cert := issueTestCert(t, sim.caCert, sim.caKey, "xkey-001", foreignRSAKey(t))
		setVar(t, &idevidCertImportPath, writeCertPEM(t, cert))
		_, _, err := runTPMSubcommand(runIDevIDCertImport)
		assert.ErrorIs(t, err, ErrKeyNotFound)
	})
}

func TestRunIDevIDShow_ProvisionedSimulator(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	sim.withIDevID(t)

	t.Run("text", func(t *testing.T) {
		stdout, _, err := runTPMSubcommand(runIDevIDShow)
		require.NoError(t, err)
		assert.Contains(t, stdout, "0x81020000")
	})

	t.Run("json", func(t *testing.T) {
		setVar(t, &tpmCfg.outputFormat, "json")
		stdout, _, err := runTPMSubcommand(runIDevIDShow)
		require.NoError(t, err)
		var info IDevIDInfo
		require.NoError(t, json.Unmarshal([]byte(stdout), &info))
		assert.Equal(t, "0x81020000", info.Handle)
		assert.False(t, info.HasCert)
	})

	t.Run("export before a certificate is imported", func(t *testing.T) {
		setVar(t, &idevidExportOutput, "-")
		_, _, err := runTPMSubcommand(runIDevIDExport)
		assert.ErrorIs(t, err, ErrCertificateNotFound)
	})
}

func TestRunIDevIDCSR_ProvisionedSimulator(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	sim.withIDevID(t)
	path := filepath.Join(t.TempDir(), "idevid.csr")
	setVar(t, &idevidCSROutput, path)

	stdout, _, err := runTPMSubcommand(runIDevIDCSR)
	require.NoError(t, err)
	assert.Contains(t, stdout, "IDevID CSR written to: "+path)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	setVar(t, &idevidCSROutput, filepath.Join(t.TempDir(), "missing", "idevid.csr"))
	_, _, err = runTPMSubcommand(runIDevIDCSR)
	assert.ErrorIs(t, err, ErrExportFailed)
}

func TestRunIDevIDCSRExportPEM_ProvisionedSimulator(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	idevidPub := sim.withIDevID(t)
	setVar(t, &idevidCertOrg, "Example Corp")
	setVar(t, &idevidCertOrgUnit, "Devices")
	setVar(t, &idevidCertCountry, "US")
	setVar(t, &idevidCertProvince, "Texas")
	setVar(t, &idevidCertLocality, "Austin")

	parseCSR := func(t *testing.T, data []byte) *x509.CertificateRequest {
		t.Helper()
		block, _ := pem.Decode(data)
		require.NotNil(t, block, "no PEM block in %q", data)
		require.Equal(t, "CERTIFICATE REQUEST", block.Type)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		require.NoError(t, err)
		require.NoError(t, csr.CheckSignature(), "CSR must be signed by the IDevID key")
		return csr
	}

	t.Run("stdout", func(t *testing.T) {
		setVar(t, &idevidCSRExportOutput, "-")
		stdout, _, err := runTPMSubcommand(runIDevIDCSRExportPEM)
		require.NoError(t, err)

		csr := parseCSR(t, []byte(stdout))
		assert.Equal(t, "xkey-001", csr.Subject.CommonName)
		assert.Equal(t, []string{"Example Corp"}, csr.Subject.Organization)
		assert.Equal(t, []string{"Devices"}, csr.Subject.OrganizationalUnit)
		assert.Equal(t, []string{"US"}, csr.Subject.Country)
		assert.Equal(t, []string{"Texas"}, csr.Subject.Province)
		assert.Equal(t, []string{"Austin"}, csr.Subject.Locality)
		assert.True(t, publicKeysEqual(csr.PublicKey, idevidPub), "CSR carries the IDevID public key")
	})

	t.Run("file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "idevid.csr.pem")
		setVar(t, &idevidCSRExportOutput, path)
		stdout, _, err := runTPMSubcommand(runIDevIDCSRExportPEM)
		require.NoError(t, err)
		assert.Contains(t, stdout, "IDevID CSR exported to: "+path)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		parseCSR(t, data)
	})

	t.Run("unwritable path", func(t *testing.T) {
		setVar(t, &idevidCSRExportOutput, filepath.Join(t.TempDir(), "missing", "idevid.csr.pem"))
		_, _, err := runTPMSubcommand(runIDevIDCSRExportPEM)
		assert.ErrorIs(t, err, ErrIDevIDCSRExportFailed)
	})
}

func TestRunIDevIDCertImport_ProvisionedSimulator(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	idevidPub := sim.withIDevID(t)

	t.Run("foreign key is refused without force", func(t *testing.T) {
		setVar(t, &idevidCertImportForce, false)
		foreign := issueTestCert(t, sim.caCert, sim.caKey, "xkey-001", foreignRSAKey(t))
		setVar(t, &idevidCertImportPath, writeCertPEM(t, foreign))
		_, _, err := runTPMSubcommand(runIDevIDCertImport)
		assert.ErrorIs(t, err, ErrIDevIDPublicKeyMismatch)
	})

	// --force only skips the CLI's own pre-check; the library still refuses
	// to store a certificate for a key the TPM does not hold.
	t.Run("force skips the pre-check but the TPM still refuses", func(t *testing.T) {
		setVar(t, &idevidCertImportForce, true)
		foreign := issueTestCert(t, sim.caCert, sim.caKey, "xkey-001", foreignRSAKey(t))
		setVar(t, &idevidCertImportPath, writeCertPEM(t, foreign))
		stdout, _, err := runTPMSubcommand(runIDevIDCertImport)
		assert.ErrorIs(t, err, ErrIDevIDCertImportFailed)
		assert.Contains(t, stdout, "Public key verification: SKIPPED (--force)")
	})

	t.Run("matching certificate is verified and exported", func(t *testing.T) {
		setVar(t, &idevidCertImportForce, false)
		cert := issueTestCert(t, sim.caCert, sim.caKey, "xkey-001", idevidPub)
		setVar(t, &idevidCertImportPath, writeCertPEM(t, cert))
		stdout, _, err := runTPMSubcommand(runIDevIDCertImport)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Public key verification: PASSED")
		assert.Contains(t, stdout, "IDevID certificate imported successfully")

		setVar(t, &idevidExportOutput, "-")
		stdout, _, err = runTPMSubcommand(runIDevIDExport)
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, decodePEMCert(t, []byte(stdout)).Raw)

		path := filepath.Join(t.TempDir(), "idevid.pem")
		setVar(t, &idevidExportOutput, path)
		stdout, _, err = runTPMSubcommand(runIDevIDExport)
		require.NoError(t, err)
		assert.Contains(t, stdout, "IDevID certificate exported to: "+path)

		setVar(t, &tpmCfg.outputFormat, "json")
		stdout, _, err = runTPMSubcommand(runIDevIDShow)
		require.NoError(t, err)
		var info IDevIDInfo
		require.NoError(t, json.Unmarshal([]byte(stdout), &info))
		assert.True(t, info.HasCert)
		assert.Equal(t, "CN=xkey-001", info.CertSubject)
	})
}

func TestRunIDevIDCertImport_RejectsBadInput(t *testing.T) {
	caCert, _ := generateEKTestCA(t)
	tests := []struct {
		name    string
		input   func(t *testing.T) string
		wantErr error
	}{
		{"missing file", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.pem") }, ErrIDevIDCertImportFailed},
		{"not PEM", func(t *testing.T) string { return writeTempInput(t, "not a certificate") }, ErrIDevIDInvalidCertificate},
		{"bad DER", func(t *testing.T) string {
			return writeTempInput(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})))
		}, ErrIDevIDInvalidCertificate},
		{"self-signed", func(t *testing.T) string { return writeCertPEM(t, caCert) }, ErrIDevIDInvalidCertificate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setVar(t, &idevidCertImportPath, tt.input(t))
			_, _, err := runTPMSubcommand(runIDevIDCertImport)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestLAKCertCommands_WithoutLAK(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)

	t.Run("export", func(t *testing.T) {
		dir := t.TempDir()
		setVar(t, &lakCertifyNonce, "")
		setVar(t, &lakCertifyInfoOutput, filepath.Join(dir, "certify-info.bin"))
		setVar(t, &lakSignatureOutput, filepath.Join(dir, "signature.bin"))
		setVar(t, &lakPublicAreaOutput, filepath.Join(dir, "public-area.bin"))
		_, _, err := runTPMSubcommand(runLAKCertExport)
		assert.ErrorContains(t, err, "LAK not found - run 'tpm lak create' first")
	})

	t.Run("import", func(t *testing.T) {
		cert := issueTestCert(t, sim.caCert, sim.caKey, "xkey-lak", foreignRSAKey(t))
		setVar(t, &lakCertImportPath, writeCertPEM(t, cert))
		stdout, _, err := runTPMSubcommand(runLAKCertImport)
		assert.ErrorContains(t, err, "LAK not found - run 'tpm lak create' first")
		assert.Contains(t, stdout, "Subject: CN=xkey-lak")
	})
}

// TestRunLAKShow_WithoutLAK proves a provisioned TPM that has no LAK yet is
// reported as a missing key that points at `tpm lak create`.
func TestRunLAKShow_WithoutLAK(t *testing.T) {
	withProvisionedSimulatorTPM(t)

	stdout, _, err := runTPMSubcommand(runLAKShow)
	require.ErrorIs(t, err, ErrKeyNotFound)
	assert.ErrorContains(t, err, "LAK not found - run 'tpm lak create' first")
	assert.Empty(t, stdout)
}

func TestRunLAKCreate_WithoutPlatformSRK(t *testing.T) {
	withProvisionedSimulatorTPM(t)

	setVar(t, &lakCreateForce, false)
	stdout, _, err := runTPMSubcommand(runLAKCreate)
	require.ErrorIs(t, err, ErrLAKPlatformSRKNotEnrolled)
	assert.ErrorContains(t, err, "xkey setup wizard")
	assert.NotContains(t, stdout, "Creating Local Attestation Key")
}

func TestRunLAKCreate_ProvisionedSimulator(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	cfg := xkms.DefaultTPMConfig
	require.NoError(t, xkmstest.EnrollPlatformSRK(sim.tpm, &cfg))

	t.Run("create", func(t *testing.T) {
		setVar(t, &lakCreateForce, false)
		stdout, _, err := runTPMSubcommand(runLAKCreate)
		require.NoError(t, err)
		assert.Contains(t, stdout, "LAK created successfully")
	})

	t.Run("show", func(t *testing.T) {
		stdout, _, err := runTPMSubcommand(runLAKShow)
		require.NoError(t, err)
		assert.Contains(t, stdout, "0x81010003")
	})

	t.Run("create refuses to replace without force", func(t *testing.T) {
		setVar(t, &lakCreateForce, false)
		_, _, err := runTPMSubcommand(runLAKCreate)
		assert.ErrorContains(t, err, "LAK already exists - use --force to recreate")
	})

	t.Run("create with force recreates", func(t *testing.T) {
		setVar(t, &lakCreateForce, true)
		stdout, _, err := runTPMSubcommand(runLAKCreate)
		require.NoError(t, err)
		assert.Contains(t, stdout, "LAK created successfully")
	})
}

// TestRunLAKCommands_MissingDevice proves the LAK commands fail on a TPM
// device that cannot be opened, before producing any output.
func TestRunLAKCommands_MissingDevice(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.device = "/nonexistent/xkey-test-tpm0"
		c.useSimulator = false
		c.outputFormat = "text"
	})

	for name, run := range map[string]func(*cobra.Command, []string) error{
		"show":   runLAKShow,
		"create": runLAKCreate,
	} {
		t.Run(name, func(t *testing.T) {
			stdout, _, err := runTPMSubcommand(run)
			require.ErrorContains(t, err, "error opening device")
			assert.Empty(t, stdout)
		})
	}
}

func TestRunLAKCertExport_RejectsNonHexNonce(t *testing.T) {
	setVar(t, &lakCertifyNonce, "not-hex")
	_, _, err := runTPMSubcommand(runLAKCertExport)
	assert.ErrorIs(t, err, ErrInvalidNonce)
}

func TestRunLAKCertImport_RejectsBadInput(t *testing.T) {
	caCert, _ := generateEKTestCA(t)
	tests := []struct {
		name    string
		input   func(t *testing.T) string
		wantErr error
	}{
		{"missing file", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.pem") }, ErrLAKCertImportFailed},
		{"not PEM", func(t *testing.T) string { return writeTempInput(t, "not a certificate") }, ErrLAKInvalidCertificate},
		{"bad DER", func(t *testing.T) string {
			return writeTempInput(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})))
		}, ErrLAKInvalidCertificate},
		{"self-signed", func(t *testing.T) string { return writeCertPEM(t, caCert) }, ErrLAKInvalidCertificate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setVar(t, &lakCertImportPath, tt.input(t))
			_, _, err := runTPMSubcommand(runLAKCertImport)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestRunTPMPCRs_ProvisionedSimulator(t *testing.T) {
	withProvisionedSimulatorTPM(t)

	t.Run("text lists every PCR by default", func(t *testing.T) {
		setVar(t, &pcrsIndices, "")
		setVar(t, &pcrsBank, "")
		stdout, _, err := runTPMSubcommand(runTPMPCRs)
		require.NoError(t, err)
		assert.Contains(t, stdout, "SHA256")
	})

	t.Run("json filtered by bank and indices", func(t *testing.T) {
		setVar(t, &tpmCfg.outputFormat, "json")
		setVar(t, &pcrsIndices, "0,7")
		setVar(t, &pcrsBank, "SHA256")
		stdout, _, err := runTPMSubcommand(runTPMPCRs)
		require.NoError(t, err)

		var output PCRsOutput
		require.NoError(t, json.Unmarshal([]byte(stdout), &output))
		require.Len(t, output.Banks, 1)
		assert.Equal(t, "SHA256", output.Banks[0].Algorithm)
		indices := []int{}
		for _, pcr := range output.Banks[0].PCRs {
			indices = append(indices, pcr.Index)
			assert.Len(t, pcr.ValueHex, 64, "PCR %d is a SHA-256 digest", pcr.Index)
		}
		assert.Equal(t, []int{0, 7}, indices)
	})
}

func TestRunTPMPCRs_RejectsBadInput(t *testing.T) {
	t.Run("bank", func(t *testing.T) {
		setVar(t, &pcrsIndices, "")
		setVar(t, &pcrsBank, "md5")
		_, _, err := runTPMSubcommand(runTPMPCRs)
		assert.ErrorIs(t, err, ErrInvalidPCRBank)
	})

	t.Run("indices", func(t *testing.T) {
		setVar(t, &pcrsIndices, "0,99")
		_, _, err := runTPMSubcommand(runTPMPCRs)
		assert.ErrorIs(t, err, ErrInvalidPCRIndices)
	})
}

func TestRunTPMQuote_ProvisionedSimulator(t *testing.T) {
	withProvisionedSimulatorTPM(t)
	setVar(t, &quotePCRs, "0,7")
	setVar(t, &quoteNonce, "c0ffee")
	setVar(t, &quoteOutputFile, "")

	t.Run("text", func(t *testing.T) {
		stdout, _, err := runTPMSubcommand(runTPMQuote)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Generating quote for PCRs: [0 7]")
		assert.Contains(t, stdout, "c0ffee")
	})

	t.Run("json", func(t *testing.T) {
		setVar(t, &tpmCfg.outputFormat, "json")
		stdout, _, err := runTPMSubcommand(runTPMQuote)
		require.NoError(t, err)

		jsonStart := bytes.IndexByte([]byte(stdout), '{')
		require.GreaterOrEqual(t, jsonStart, 0, "no JSON in %q", stdout)
		var result QuoteResult
		require.NoError(t, json.Unmarshal([]byte(stdout[jsonStart:]), &result))
		assert.Equal(t, "c0ffee", result.NonceHex)
		assert.NotEmpty(t, result.QuotedHex)
		assert.NotEmpty(t, result.SignatureHex)
	})

	t.Run("output file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "quote.json")
		setVar(t, &quoteOutputFile, path)
		stdout, _, err := runTPMSubcommand(runTPMQuote)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Quote written to: "+path)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		var result QuoteResult
		require.NoError(t, json.Unmarshal(data, &result))
		assert.Equal(t, "c0ffee", result.NonceHex)
	})
}

func TestRunTPMQuote_RejectsBadInput(t *testing.T) {
	t.Run("nonce", func(t *testing.T) {
		setVar(t, &quotePCRs, "0")
		setVar(t, &quoteNonce, "not-hex")
		_, _, err := runTPMSubcommand(runTPMQuote)
		assert.ErrorIs(t, err, ErrInvalidNonce)
	})

	t.Run("pcrs", func(t *testing.T) {
		setVar(t, &quotePCRs, "zero")
		_, _, err := runTPMSubcommand(runTPMQuote)
		assert.ErrorIs(t, err, ErrInvalidPCRIndices)
	})
}

func TestRunTPMClear_ProvisionedSimulator(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	setVar(t, clearCfg, tpmClearConfig{})

	t.Run("cancelled unless the operator types yes", func(t *testing.T) {
		pipeStdin(t, "no\n")
		_, _, err := runTPMSubcommand(runTPMClear)
		assert.ErrorIs(t, err, ErrTPMClearCancelled)
		_, err = sim.tpm.IAKAttributes()
		assert.NoError(t, err, "a cancelled clear leaves the IAK in place")
	})

	t.Run("confirmed", func(t *testing.T) {
		pipeStdin(t, "yes\n")
		stdout, _, err := runTPMSubcommand(runTPMClear)
		require.NoError(t, err)
		assert.Contains(t, stdout, "TPM successfully cleared.")
	})
}

// TestRunTPMClear_WrongLockoutAuth has its own simulator: a failed lockout
// authorization trips the TPM's dictionary-attack lockout for what follows.
func TestRunTPMClear_WrongLockoutAuth(t *testing.T) {
	withProvisionedSimulatorTPM(t)
	setVar(t, clearCfg, tpmClearConfig{yes: true, lockoutAuth: "wrong"})

	_, stderr, err := runTPMSubcommand(runTPMClear)
	require.Error(t, err)
	assert.Contains(t, stderr, "TPM clear failed")
	assert.Contains(t, stderr, "--lockout-auth")
}

func TestRunTPMInstall_ProvisionedSimulator(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	setVar(t, &tpmCfg.outputFormat, "json")
	setVar(t, &installHierarchyAuth, "")
	setVar(t, &installPCRBank, "sha256")
	setVar(t, &installGoldenPCRs, "0,7")
	setVar(t, &installPlatformPCR, 0)

	install := func(t *testing.T) ProvisionResult {
		t.Helper()
		stdout, _, err := runTPMSubcommand(runTPMInstall)
		require.NoError(t, err)
		jsonStart := bytes.IndexByte([]byte(stdout), '{')
		require.GreaterOrEqual(t, jsonStart, 0, "no JSON in %q", stdout)
		var result ProvisionResult
		require.NoError(t, json.Unmarshal([]byte(stdout[jsonStart:]), &result))
		return result
	}

	t.Run("installs the IDevID with the requested PCR policy", func(t *testing.T) {
		result := install(t)
		assert.True(t, result.Success)
		assert.Equal(t, "TPM installation completed successfully", result.Message)
		assert.Equal(t, "sha256", sim.pcrBank)
		assert.Equal(t, []uint{0, 7}, sim.goldenPCRs)
		_, err := sim.tpm.IDevIDAttributes()
		assert.NoError(t, err, "install creates the IDevID")
	})

	t.Run("second run reports the existing installation", func(t *testing.T) {
		result := install(t)
		assert.True(t, result.Success)
		assert.Equal(t, "TPM is already fully installed with all xKey keys", result.Message)
		assert.True(t, result.EKPreserved)
	})
}

func TestRunTPMProvision_FreshSimulator(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.device = ""
		c.useSimulator = true
		c.outputFormat = "text"
		c.hierarchyAuth = ""
	})
	setVar(t, &provisionHierarchyAuth, "")
	setVar(t, &provisionPCRBank, "sha256")
	setVar(t, &provisionGoldenPCRs, "0,7")
	setVar(t, &provisionPlatformPCR, 0)

	t.Run("warns and stops without confirm", func(t *testing.T) {
		setVar(t, &provisionConfirm, false)
		stdout, _, err := runTPMSubcommand(runTPMProvision)
		require.NoError(t, err)
		assert.Contains(t, stdout, "xkey tpm provision --confirm")
		assert.NotContains(t, stdout, "Performing FULL TPM provisioning")
	})

	t.Run("provisions with confirm", func(t *testing.T) {
		setVar(t, &provisionConfirm, true)
		pipeStdin(t, "")
		stdout, _, err := runTPMSubcommand(runTPMProvision)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Performing FULL TPM provisioning (destructive)...")
		assert.Contains(t, stdout, "TPM provisioning completed (manufacturer keys replaced)")
	})
}

// TestRunTPMInstall_UsesTheSuppliedHierarchyAuth proves the owner hierarchy
// auth an operator supplies, by flag or by the tpm config, is the one
// install authorizes with: the simulator's owner auth is empty, so a
// supplied one is refused and no IDevID is created.
func TestRunTPMInstall_UsesTheSuppliedHierarchyAuth(t *testing.T) {
	tests := []struct {
		name       string
		flagAuth   string
		configAuth string
	}{
		{name: "flag", flagAuth: "not-the-owner-auth"},
		{name: "tpm config", configAuth: "not-the-owner-auth"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sim := withProvisionedSimulatorTPM(t)
			setVar(t, &tpmCfg.hierarchyAuth, tt.configAuth)
			setVar(t, &installHierarchyAuth, tt.flagAuth)
			setVar(t, &installPCRBank, "sha256")
			setVar(t, &installGoldenPCRs, "0,7")
			setVar(t, &installPlatformPCR, 0)

			stdout, _, err := runTPMSubcommand(runTPMInstall)
			require.ErrorIs(t, err, ErrProvisioningFailed)
			assert.NotContains(t, stdout, "Provisioning Result")
			_, attrErr := sim.tpm.IDevIDAttributes()
			assert.Error(t, attrErr, "a refused install must not leave an IDevID behind")
		})
	}
}

// TestRunTPMProvision_TakesOwnershipWithTheSuppliedHierarchyAuth proves the
// destructive provision clears the TPM and installs the hierarchy auth the
// operator supplies, by flag or by the tpm config, as the new owner auth.
func TestRunTPMProvision_TakesOwnershipWithTheSuppliedHierarchyAuth(t *testing.T) {
	tests := []struct {
		name       string
		flagAuth   string
		configAuth string
	}{
		{name: "flag", flagAuth: "so-pin"},
		{name: "tpm config", configAuth: "so-pin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withTPMCfg(t, func(c *tpmConfig) {
				c.device = ""
				c.useSimulator = true
				c.outputFormat = "text"
				c.hierarchyAuth = tt.configAuth
			})
			tpm, err := openConfiguredTPMForProvisioningWithPCROverrides("sha256", []uint{0, 7}, 0)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, tpm.Close()) })
			setVar(t, &openTPMForProvisioningWithPCROverrides, func(string, []uint, int) (xkms.TrustedPlatformModule, error) {
				return sharedTPM{tpm}, nil
			})
			setVar(t, &provisionConfirm, true)
			setVar(t, &provisionHierarchyAuth, tt.flagAuth)
			setVar(t, &provisionPCRBank, "sha256")
			setVar(t, &provisionGoldenPCRs, "0,7")
			setVar(t, &provisionPlatformPCR, 0)
			pipeStdin(t, "")

			stdout, _, err := runTPMSubcommand(runTPMProvision)
			require.NoError(t, err)
			assert.Contains(t, stdout, "TPM provisioning completed")

			// Owner-hierarchy auth failures carry no dictionary-attack
			// implications, so probing the old (empty) auth is safe.
			owner := xkms.TPMRHOwner
			assert.Error(t, tpm.SetHierarchyAuth(nil, nil, &owner), "the empty owner auth must no longer authorize")
			soPIN, err := xkms.NewTPMStorePassword([]byte("so-pin"))
			require.NoError(t, err)
			assert.NoError(t, tpm.SetHierarchyAuth(soPIN, soPIN, &owner), "the supplied auth now owns the owner hierarchy")
		})
	}
}

// TestRunTPMInstallAndProvision_MissingDeviceIsDeviceNotFound proves both
// commands report a TPM device that cannot be opened as device-not-found,
// before touching any key.
func TestRunTPMInstallAndProvision_MissingDeviceIsDeviceNotFound(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.device = "/nonexistent/xkey-test-tpm0"
		c.useSimulator = false
		c.outputFormat = "text"
		c.hierarchyAuth = ""
	})
	setVar(t, &installPCRBank, "")
	setVar(t, &installGoldenPCRs, "")
	setVar(t, &provisionConfirm, true)
	setVar(t, &provisionPCRBank, "")
	setVar(t, &provisionGoldenPCRs, "")
	pipeStdin(t, "")

	for name, run := range map[string]func(*cobra.Command, []string) error{
		"install":   runTPMInstall,
		"provision": runTPMProvision,
	} {
		t.Run(name, func(t *testing.T) {
			stdout, _, err := runTPMSubcommand(run)
			require.ErrorIs(t, err, ErrTPMDeviceNotFound)
			assert.NotContains(t, stdout, "Installing xKey TPM keys")
			assert.NotContains(t, stdout, "Performing FULL TPM provisioning")
		})
	}
}

func TestRunTPMInstallAndProvision_RejectBadPCRFlags(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T)
		run     func(*cobra.Command, []string) error
		wantErr error
	}{
		{"install bank", func(t *testing.T) {
			setVar(t, &installPCRBank, "md5")
		}, runTPMInstall, ErrInvalidPCRBank},
		{"install golden pcrs", func(t *testing.T) {
			setVar(t, &installPCRBank, "")
			setVar(t, &installGoldenPCRs, "0,24")
		}, runTPMInstall, ErrInvalidPCRIndices},
		{"provision bank", func(t *testing.T) {
			setVar(t, &provisionConfirm, true)
			setVar(t, &provisionPCRBank, "md5")
		}, runTPMProvision, ErrInvalidPCRBank},
		{"provision golden pcrs", func(t *testing.T) {
			setVar(t, &provisionConfirm, true)
			setVar(t, &provisionPCRBank, "")
			setVar(t, &provisionGoldenPCRs, "seven")
		}, runTPMProvision, ErrInvalidPCRIndices},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)
			_, _, err := runTPMSubcommand(tt.run)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}
