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

package cmd

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// isolateCertPIV points the cert commands' PIV plumbing at a fresh software
// (file-backed) PIV store under t.TempDir() and restores the previous
// loadedConfig afterward. Real xkmsd's own cert-request success path
// resolves its signing key through exactly this software/file PIV backend
// when no hardware token is present, so this is not a stand-in for
// production wiring -- it is production wiring, pointed at a scratch
// directory. The cert commands are not children of PIVCmd, so they carry
// none of its flags; buildPIVConfig resolves entirely from loadedConfig.PIV
// here, the same injection xkmsd_client_test.go and listen_config_test.go
// use (go-xkms#871).
func isolateCertPIV(t *testing.T) {
	t.Helper()

	previous := loadedConfig
	cfg := xkeyconfig.DefaultConfig()
	cfg.PIV.Backend = string(PIVBackendSoftware)
	cfg.PIV.Storage = string(PIVStorageTypeFile)
	cfg.PIV.StoragePath = t.TempDir()
	loadedConfig = cfg

	t.Cleanup(func() { loadedConfig = previous })
}

// newPIVGenerateCmd creates a detached cobra.Command carrying the exact
// flags pivGenerateCmd registers, the way cert_test.go's newCertRequestCmd
// and ca_test.go's newCAIssueCmd build detached commands for the ca/cert
// commands: a fresh, disposable *cobra.Command rather than the package-level
// singleton, so SetOut/flag mutations in one test can never leak into
// another test that runs `xkey piv generate --help` through RootCmd later
// in the same process.
func newPIVGenerateCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{RunE: runPivGenerate}
	cmd.Flags().StringP("algorithm", "a", "ECCP256", "")
	cmd.Flags().String("pin-policy", "once", "")
	cmd.Flags().String("touch-policy", "never", "")
	cmd.Flags().BoolP("force", "f", false, "")
	cmd.Flags().String("output-format", "self-signed", "")
	cmd.Flags().String("subject", "", "")
	cmd.Flags().String("organization", "", "")
	cmd.Flags().String("country", "", "")
	cmd.Flags().Int("validity-days", 0, "")
	cmd.Flags().StringP("output", "o", "", "")
	return cmd
}

// generateTestPIVKey runs the real `piv generate` command for slot 9a so a
// signer exists for cert request's CSR step to find, exactly as a user must
// run `xkey piv generate` before `xkey cert request` in practice.
func generateTestPIVKey(t *testing.T) {
	t.Helper()

	cmd := newPIVGenerateCmd(t)
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, runPivGenerate(cmd, []string{"9a"}))
}

func TestRunCertRequest_Success(t *testing.T) {
	isolateCertPIV(t)
	generateTestPIVKey(t)

	baseURL, pin := startTestXKMSdREST(t)

	cmd := newCertRequestCmd(t)
	cmd.SetContext(context.Background())
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", baseURL))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "cn", "requester@example.com"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "spki-pin", pin))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "profile", "client"))

	var buf bytes.Buffer
	cmd.SetOut(&buf)

	require.NoError(t, runCertRequest(cmd, nil))

	out := buf.String()
	assert.Contains(t, out, "Certificate issued and stored in slot")
	assert.Contains(t, out, "requester@example.com")

	// The certificate really landed in the configured PIV slot: cert show
	// must now render it without touching xkmsd again.
	showCmd := newCertShowCmd(t)
	var showBuf bytes.Buffer
	showCmd.SetOut(&showBuf)
	require.NoError(t, runCertShow(showCmd, nil))
	assert.Contains(t, showBuf.String(), "requester@example.com")
}

func TestRunCertRequest_WrongSPKIPinFailsClosed(t *testing.T) {
	isolateCertPIV(t)
	generateTestPIVKey(t)

	baseURL, _ := startTestXKMSdREST(t)

	cmd := newCertRequestCmd(t)
	cmd.SetContext(context.Background())
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", baseURL))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "cn", "wrongpin@example.com"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "spki-pin", "0000000000000000000000000000000000000000000000000000000000000000"))

	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := runCertRequest(cmd, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertConnectFailed), "want ErrCertConnectFailed, got %v", err)
}
