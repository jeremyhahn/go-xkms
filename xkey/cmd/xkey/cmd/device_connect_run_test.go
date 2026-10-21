package cmd

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDeviceConnectCmd(out *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("tls-cert", "", "")
	cmd.Flags().String("tls-key", "", "")
	cmd.Flags().String("tls-ca", "", "")
	cmd.SetOut(out)
	return cmd
}

// A device that was never enrolled has no agent certificate under the
// default cert directory, so connecting fails closed before any network I/O
// succeeds and nothing reports a connection.
func TestRunDeviceConnect_DefaultCertsMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var out bytes.Buffer
	err := runDeviceConnect(newDeviceConnectCmd(&out), []string{"127.0.0.1:1"})

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAgentConnectFailed), "got %v", err)
	assert.NotContains(t, out.String(), "Connected to master")
}

// Explicit TLS paths override the defaults; unreadable files still fail
// with the typed connect error.
func TestRunDeviceConnect_ExplicitCertsMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	var out bytes.Buffer
	cmd := newDeviceConnectCmd(&out)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "tls-cert", filepath.Join(dir, "c.pem")))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "tls-key", filepath.Join(dir, "k.pem")))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "tls-ca", filepath.Join(dir, "ca.pem")))

	err := runDeviceConnect(cmd, []string{"127.0.0.1:1"})

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAgentConnectFailed), "got %v", err)
	assert.Empty(t, out.String())
}
