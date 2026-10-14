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
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// withUnprovisionedSimulatorTPM routes openTPM and the provisioning opener to
// a fresh simulator that has never been provisioned: no EK certificate, no
// IAK and no IDevID.
func withUnprovisionedSimulatorTPM(t *testing.T) xkms.TrustedPlatformModule {
	t.Helper()
	withTPMCfg(t, func(c *tpmConfig) {
		c.device = ""
		c.useSimulator = true
		c.outputFormat = "text"
		c.hierarchyAuth = ""
	})
	tpm, err := openConfiguredTPMForProvisioningWithPCROverrides("sha256", []uint{0, 7}, 0)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, tpm.Close()) })

	shared := sharedTPM{tpm}
	setVar(t, &openTPM, func() (xkms.TrustedPlatformModule, error) { return shared, nil })
	setVar(t, &openTPMForProvisioningWithPCROverrides, func(string, []uint, int) (xkms.TrustedPlatformModule, error) {
		return shared, nil
	})
	return tpm
}

// takeOwnership sets the owner hierarchy auth of tpm to auth, so a later
// provisioning run with any other auth is refused by the TPM.
func takeOwnership(t *testing.T, tpm xkms.TrustedPlatformModule, auth string) {
	t.Helper()
	soPIN, err := xkms.NewTPMStorePassword([]byte(auth))
	require.NoError(t, err)
	owner := xkms.TPMRHOwner
	require.NoError(t, tpm.SetHierarchyAuth(nil, soPIN, &owner))
}

// withTerminalStdin makes isTerminal report a terminal by pointing os.Stdin
// at a character device, so runTPMProvision asks for the DESTROY
// confirmation; the answer itself is read from the command's input.
func withTerminalStdin(t *testing.T) {
	t.Helper()
	devNull, err := os.Open(os.DevNull)
	require.NoError(t, err)
	previous := os.Stdin
	os.Stdin = devNull
	t.Cleanup(func() {
		os.Stdin = previous
		assert.NoError(t, devNull.Close())
	})
	require.True(t, isTerminal(), "a character device on stdin must count as a terminal")
}

// runTPMSubcommandWithInput runs a TPM command with input as its stdin.
func runTPMSubcommandWithInput(run func(*cobra.Command, []string) error, input string) (string, error) {
	cmd := &cobra.Command{}
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetIn(strings.NewReader(input))
	err := run(cmd, nil)
	return stdout.String(), err
}

func TestIDevIDCommands_DeclareTheirRequiredFlags(t *testing.T) {
	tests := []struct {
		cmd   *cobra.Command
		flags []string
	}{
		{cmd: tpmIDevIDCreateCmd, flags: []string{"model", "serial"}},
		{cmd: tpmIDevIDExportCmd, flags: []string{"output"}},
		{cmd: tpmIDevIDCSRCmd, flags: []string{"output"}},
	}
	for _, tt := range tests {
		for _, name := range tt.flags {
			t.Run(tt.cmd.Name()+"/"+name, func(t *testing.T) {
				flag := tt.cmd.Flags().Lookup(name)
				require.NotNil(t, flag)
				assert.Equal(t, []string{"true"}, flag.Annotations[cobra.BashCompOneRequiredFlag])
			})
		}
	}
}

func TestRunIDevIDCreate_AcceptsEveryDocumentedTemplate(t *testing.T) {
	for _, template := range []string{"rsa2048", "rsa-pss", "ecc256"} {
		t.Run(template, func(t *testing.T) {
			sim := withProvisionedSimulatorTPM(t)
			setVar(t, &idevidCreateTemplate, template)
			setVar(t, &idevidCreateForce, false)
			setVar(t, &idevidModel, "xkey-test")
			setVar(t, &idevidSerial, "SN-001")

			stdout, _, err := runTPMSubcommand(runIDevIDCreate)
			require.NoError(t, err)
			assert.Contains(t, stdout, "Creating IDevID for xkey-test (serial: SN-001)")
			assert.NotContains(t, stdout, "EK certificate not available")
			_, err = sim.tpm.IDevIDAttributes()
			assert.NoError(t, err)
		})
	}
}

func TestIDevIDCommands_UnprovisionedTPM(t *testing.T) {
	tpm := withUnprovisionedSimulatorTPM(t)

	t.Run("create needs the IAK", func(t *testing.T) {
		setVar(t, &idevidCreateTemplate, "rsa2048")
		setVar(t, &idevidCreateForce, false)
		stdout, _, err := runTPMSubcommand(runIDevIDCreate)
		assert.ErrorContains(t, err, "IAK not found")
		assert.NotContains(t, stdout, "Creating IDevID")
		_, err = tpm.IDevIDAttributes()
		assert.Error(t, err, "no IDevID may be created without an IAK")
	})

	t.Run("csr needs the IAK", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "idevid.csr")
		setVar(t, &idevidCSROutput, output)
		stdout, _, err := runTPMSubcommand(runIDevIDCSR)
		assert.ErrorContains(t, err, "IAK not found")
		assert.Contains(t, stdout, "EK certificate not available")
		assert.NoFileExists(t, output)
	})

	t.Run("show", func(t *testing.T) {
		_, _, err := runTPMSubcommand(runIDevIDShow)
		assert.ErrorIs(t, err, ErrKeyNotFound)
	})

	t.Run("export", func(t *testing.T) {
		setVar(t, &idevidExportOutput, "-")
		_, _, err := runTPMSubcommand(runIDevIDExport)
		assert.ErrorIs(t, err, ErrCertificateNotFound)
	})
}

func TestRunIDevIDShow_BeforeIDevIDExists(t *testing.T) {
	withProvisionedSimulatorTPM(t)
	_, _, err := runTPMSubcommand(runIDevIDShow)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	assert.ErrorContains(t, err, "tpm idevid create")
}

func TestRunIDevIDExport_WritesCertificateFile(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	cert := issueTestCert(t, sim.caCert, sim.caKey, "xkey-001", sim.withIDevID(t))
	require.NoError(t, sim.tpm.ProvisionIDevIDCert(cert))

	t.Run("file", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "idevid.pem")
		setVar(t, &idevidExportOutput, output)
		stdout, _, err := runTPMSubcommand(runIDevIDExport)
		require.NoError(t, err)
		assert.Contains(t, stdout, "IDevID certificate exported to: "+output)

		data, err := os.ReadFile(output)
		require.NoError(t, err)
		block, _ := pem.Decode(data)
		require.NotNil(t, block)
		assert.Equal(t, cert.Raw, block.Bytes)
		info, err := os.Stat(output)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	})

	t.Run("unwritable path", func(t *testing.T) {
		setVar(t, &idevidExportOutput, filepath.Join(t.TempDir(), "missing", "idevid.pem"))
		_, _, err := runTPMSubcommand(runIDevIDExport)
		assert.ErrorIs(t, err, ErrExportFailed)
	})
}

func TestRunIDevIDCSR_UnwritablePath(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	sim.withIDevID(t)
	setVar(t, &idevidCSROutput, filepath.Join(t.TempDir(), "missing", "idevid.csr"))

	_, _, err := runTPMSubcommand(runIDevIDCSR)
	assert.ErrorIs(t, err, ErrExportFailed)
}

func TestIDevIDCommands_MissingDevice(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.device = "/nonexistent/xkey-test-tpm0"
		c.useSimulator = false
	})
	setVar(t, &idevidCreateTemplate, "rsa2048")
	setVar(t, &idevidExportOutput, "-")
	setVar(t, &idevidCSROutput, filepath.Join(t.TempDir(), "idevid.csr"))

	for name, run := range map[string]func(*cobra.Command, []string) error{
		"show":   runIDevIDShow,
		"create": runIDevIDCreate,
		"export": runIDevIDExport,
		"csr":    runIDevIDCSR,
	} {
		t.Run(name, func(t *testing.T) {
			stdout, _, err := runTPMSubcommand(run)
			require.ErrorContains(t, err, "error opening device")
			assert.Empty(t, stdout)
		})
	}
}

func TestRunTPMProvision_TerminalConfirmation(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     string
		wantOut     string
		provisioned bool
	}{
		{name: "DESTROY proceeds", input: "DESTROY\n", wantOut: "TPM provisioning completed", provisioned: true},
		{name: "surrounding space is ignored", input: "  DESTROY  \n", wantOut: "TPM provisioning completed", provisioned: true},
		{name: "any other answer cancels", input: "destroy\n", wantOut: "Operation cancelled."},
		{name: "unreadable answer fails", input: "", wantErr: "failed to read input"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpm := withUnprovisionedSimulatorTPM(t)
			withTerminalStdin(t)
			setVar(t, &provisionConfirm, true)
			setVar(t, &provisionHierarchyAuth, "")
			setVar(t, &provisionPCRBank, "sha256")
			setVar(t, &provisionGoldenPCRs, "0,7")
			setVar(t, &provisionPlatformPCR, 0)

			stdout, err := runTPMSubcommandWithInput(runTPMProvision, tt.input)
			assert.Contains(t, stdout, "Type 'DESTROY' to continue")
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Contains(t, stdout, tt.wantOut)
			}

			_, iakErr := tpm.IAKAttributes()
			assert.Equal(t, tt.provisioned, iakErr == nil, "the TPM is provisioned only after DESTROY")
		})
	}
}

func TestRunTPMProvision_WithoutConfirmFlagChangesNothing(t *testing.T) {
	tpm := withUnprovisionedSimulatorTPM(t)
	setVar(t, &provisionConfirm, false)

	stdout, _, err := runTPMSubcommand(runTPMProvision)
	require.NoError(t, err)
	assert.Contains(t, stdout, "xkey tpm provision --confirm")
	_, err = tpm.IAKAttributes()
	assert.Error(t, err)
}

// TestRunTPMInstall_WrongHierarchyAuthIsProvisioningFailed proves the safe
// install refuses a TPM whose owner hierarchy is already taken, unless it is
// given that owner auth. Full provisioning clears the hierarchies first, so
// it has no such failure.
func TestRunTPMInstall_WrongHierarchyAuthIsProvisioningFailed(t *testing.T) {
	tests := []struct {
		name string
		auth string
	}{
		{name: "no auth", auth: ""},
		{name: "wrong auth", auth: "not-the-owner"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpm := withUnprovisionedSimulatorTPM(t)
			takeOwnership(t, tpm, "so-pin")
			setVar(t, &installHierarchyAuth, tt.auth)
			setVar(t, &installPCRBank, "sha256")
			setVar(t, &installGoldenPCRs, "0,7")
			setVar(t, &installPlatformPCR, 0)

			stdout, _, err := runTPMSubcommand(runTPMInstall)
			assert.ErrorIs(t, err, ErrProvisioningFailed)
			assert.NotContains(t, stdout, "installation completed")
			_, err = tpm.IAKAttributes()
			assert.Error(t, err, "a refused install leaves no IAK behind")
		})
	}
}
