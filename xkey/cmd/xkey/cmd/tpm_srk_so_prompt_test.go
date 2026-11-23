package cmd

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test-only PIN constants (ruling 994: no PIN value in code defaults).
const (
	testSOPromptUserPIN = "user-pin-ruling-1014"
	testSOPromptSOPIN   = "so-pin-ruling-1014"
)

func srkEnrollSubcommand(t *testing.T) *cobra.Command {
	t.Helper()
	for _, sc := range newTPMSRKCmd().Commands() {
		if sc.Name() == "enroll" {
			return sc
		}
	}
	t.Fatal("tpm srk has no enroll subcommand")
	return nil
}

// stubSRKSOPrompt records whether the SO PIN prompt ran and answers it.
func stubSRKSOPrompt(t *testing.T) *bool {
	t.Helper()
	prompted := false
	setVar(t, &readSRKOptionalPIN, func(io.Writer, string) (string, error) {
		prompted = true
		return testSOPromptSOPIN, nil
	})
	return &prompted
}

// A user PIN supplied by --pin-file or XKEY_PIN must not skip the SO PIN
// prompt: on a TPM with owner auth, enrolment needs the SO PIN (ruling 1014).
func TestTPMSRKEnrollSuppliedUserPINStillPromptsSOPIN(t *testing.T) {
	cases := map[string]func(t *testing.T) []string{
		"pin-file": func(t *testing.T) []string {
			path := filepath.Join(t.TempDir(), "pin")
			require.NoError(t, os.WriteFile(path, []byte(testSOPromptUserPIN+"\n"), 0o600))
			return []string{"--pin-file", path}
		},
		"XKEY_PIN": func(t *testing.T) []string {
			t.Setenv(pinEnvVar, testSOPromptUserPIN)
			return nil
		},
	}
	for name, supply := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(pinEnvVar, "")
			t.Setenv(soPINEnvVar, "")
			setVar(t, &pinInputIsTerminal, func() bool { return true })
			prompted := stubSRKSOPrompt(t)

			c := srkEnrollSubcommand(t)
			require.NoError(t, c.ParseFlags(supply(t)))
			userPIN, soPIN, err := resolveSRKEnrollPINs(c)
			require.NoError(t, err)
			assert.True(t, *prompted, "the SO PIN prompt runs when no SO PIN source is set")
			assert.True(t, userPIN == testSOPromptUserPIN, "the supplied user PIN reaches enrolment")
			assert.True(t, soPIN == testSOPromptSOPIN, "the prompted SO PIN reaches enrolment")
		})
	}
}

// No terminal and no SO PIN source still means an empty SO PIN.
func TestTPMSRKEnrollNoTerminalNoSOSourceEmptySOPIN(t *testing.T) {
	t.Setenv(pinEnvVar, testSOPromptUserPIN)
	t.Setenv(soPINEnvVar, "")
	setVar(t, &pinInputIsTerminal, func() bool { return false })
	prompted := stubSRKSOPrompt(t)

	c := srkEnrollSubcommand(t)
	require.NoError(t, c.ParseFlags(nil))
	userPIN, soPIN, err := resolveSRKEnrollPINs(c)
	require.NoError(t, err)
	assert.False(t, *prompted, "no prompt without a terminal")
	assert.True(t, userPIN == testSOPromptUserPIN, "the supplied user PIN reaches enrolment")
	assert.Empty(t, soPIN)
}
