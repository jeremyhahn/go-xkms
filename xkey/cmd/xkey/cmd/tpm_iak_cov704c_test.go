//go:build tpm_simulator

package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// c704cIAKCreateWithTemplate runs `tpm iak create --force --template name`
// with the flag marked as given on the command line, which is what makes
// the template override the configured IAK suite.
func c704cIAKCreateWithTemplate(t *testing.T, name string) (string, error) {
	t.Helper()
	setVar(t, &iakCreateTemplate, name)
	setVar(t, &iakCreateForce, true)

	cmd := &cobra.Command{}
	cmd.Flags().StringVar(&iakCreateTemplate, "template", name, "")
	require.NoError(t, cmd.Flags().Set("template", name))
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	err := runIAKCreate(cmd, nil)
	return out.String(), err
}

// TestC704cIAK_ECCTemplateIsShownAsECDSA proves --template ecc256 replaces
// the IAK with a P-256 key, and `tpm iak show` reports its algorithm and
// curve in text and JSON.
func TestC704cIAK_ECCTemplateIsShownAsECDSA(t *testing.T) {
	withProvisionedSimulatorTPM(t)

	out, err := c704cIAKCreateWithTemplate(t, "ecc256")
	require.NoError(t, err)
	assert.Contains(t, out, "IAK created successfully")

	text, _, err := runTPMSubcommand(runIAKShow)
	require.NoError(t, err)
	assert.Contains(t, text, "ECDSA")
	assert.Contains(t, text, "P-256")

	setVar(t, &tpmCfg.outputFormat, "json")
	stdout, _, err := runTPMSubcommand(runIAKShow)
	require.NoError(t, err)
	var info IAKInfo
	require.NoError(t, json.Unmarshal([]byte(stdout), &info))
	assert.Equal(t, "ECDSA", info.Algorithm)
	assert.Equal(t, "P-256", info.Curve)
	assert.Zero(t, info.KeySize, "an EC key has no RSA modulus size")
}

// TestC704cIAK_UnknownTemplateNeverTouchesTheTPM proves an unknown
// --template is refused before the existing IAK is replaced.
func TestC704cIAK_UnknownTemplateNeverTouchesTheTPM(t *testing.T) {
	withProvisionedSimulatorTPM(t)

	_, err := c704cIAKCreateWithTemplate(t, "dsa1024")
	require.ErrorIs(t, err, ErrInvalidIAKTemplate)

	stdout, _, err := runTPMSubcommand(runIAKShow)
	require.NoError(t, err, "the provisioned IAK is still there")
	assert.Contains(t, stdout, "0x81010002")
	assert.NotContains(t, stdout, "ECDSA")
}
