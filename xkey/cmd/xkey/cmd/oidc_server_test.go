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
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
)

// startOIDCXKMSd starts the harness xkmsd with an OIDC credential service
// and points xkey at it.
func startOIDCXKMSd(t *testing.T) {
	t.Helper()
	isolateXKMSdEndpoint(t)
	svc := newTestXKMSService(t)
	creds, err := credential.New(credential.RegistryBarriers(barriertest.NewRegistry(t)))
	require.NoError(t, err)
	svc.SetOIDCCredentialService(creds)
	address, _ := startTestXKMSdService(t, svc)
	xkmsdURL = address
}

// runOIDCCommand runs cmd's RunE with flags, restoring every flag to its
// default afterwards so one call's flags never leak into the next.
func runOIDCCommand(t *testing.T, cmd *cobra.Command, args []string, flags map[string]string) (string, error) {
	t.Helper()
	defer func() {
		for _, set := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags()} {
			set.VisitAll(func(f *pflag.Flag) {
				require.NoError(t, f.Value.Set(f.DefValue))
				f.Changed = false
			})
		}
	}()
	for name, value := range flags {
		require.NoError(t, cmd.Flags().Set(name, value))
	}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetContext(context.Background())
	err := cmd.RunE(cmd, args)
	return out.String(), err
}

func TestOIDCUseServer(t *testing.T) {
	isolateXKMSdEndpoint(t)
	use, err := oidcUseServer(oidcTokenCmd)
	require.NoError(t, err)
	assert.False(t, use, "with no xkmsd, xkey's OIDC is local exactly as before")

	xkmsdURL = "unix:///nonexistent.sock"
	use, err = oidcUseServer(oidcTokenCmd)
	require.NoError(t, err)
	assert.True(t, use, "an xkmsd switches xkey to the server's credentials")

	require.NoError(t, OIDCCmd.PersistentFlags().Set("local", "true"))
	t.Cleanup(func() { require.NoError(t, OIDCCmd.PersistentFlags().Set("local", "false")) })
	use, err = oidcUseServer(OIDCCmd)
	require.NoError(t, err)
	assert.False(t, use, "--local keeps the local backend while an xkmsd is configured")
}

// TestOIDCServerMode_Lifecycle drives the server backend through the same
// commands the local backend uses: add, list (with the local providers),
// import, token, refresh, remove.
func TestOIDCServerMode_Lifecycle(t *testing.T) {
	startOIDCXKMSd(t)
	t.Setenv("XKEY_DATA_DIR", t.TempDir())

	out, err := runOIDCCommand(t, oidcProvidersAddCmd, nil, map[string]string{"name": "claude", "template": "anthropic", "scope": "tenant"})
	require.NoError(t, err)
	assert.Contains(t, out, "Server OIDC credential created")
	assert.Contains(t, out, "Status:       pending")

	out, err = runOIDCCommand(t, oidcImportCmd, []string{"claude"}, map[string]string{"scope": "tenant", "access-token": "sk-ant-oat01-x"})
	require.NoError(t, err)
	assert.Contains(t, out, "Status:       active")

	tokenStore := filepath.Join(t.TempDir(), "tokens")
	out, err = runOIDCCommand(t, oidcProvidersListCmd, nil, map[string]string{"token-store": tokenStore})
	require.NoError(t, err)
	assert.Contains(t, out, "Server OIDC credentials (1)")
	assert.Contains(t, out, "claude")
	assert.Contains(t, out, "Local OIDC providers:", "both backends are listed")

	out, err = runOIDCCommand(t, oidcTokenCmd, nil, map[string]string{"provider": "claude", "scope": "tenant", "show-full": "true"})
	require.NoError(t, err)
	assert.Contains(t, out, "sk-ant-oat01-x")

	_, err = runOIDCCommand(t, oidcRefreshCmd, nil, map[string]string{"provider": "claude", "scope": "tenant"})
	assert.ErrorContains(t, err, "not refreshable", "the server's refusal reaches the CLI")

	_, err = runOIDCCommand(t, oidcLoginCmd, nil, map[string]string{"provider": "claude", "scope": "tenant"})
	assert.ErrorContains(t, err, "not supported", "anthropic tokens are imported, never device-logged-in")

	out, err = runOIDCCommand(t, oidcProvidersRemoveCmd, []string{"claude"}, map[string]string{"scope": "tenant"})
	require.NoError(t, err)
	assert.Contains(t, out, "removed")
}

func TestOIDCServerMode_ImportCodexAuth(t *testing.T) {
	startOIDCXKMSd(t)
	enc := base64.RawURLEncoding
	jwt := func(claims string) string {
		return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString([]byte(claims)) + ".sig"
	}
	data, err := json.Marshal(map[string]any{
		"tokens": map[string]any{
			"id_token":      jwt(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acct"}}`),
			"access_token":  jwt(`{"exp":4102444800}`),
			"refresh_token": "rt-codex",
		},
	})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "auth.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	out, err := runOIDCCommand(t, oidcImportCmd, []string{"codex"}, map[string]string{"scope": "tenant", "codex-auth": path, "create": "true"})
	require.NoError(t, err)
	assert.Contains(t, out, "Template:     openai")
	assert.Contains(t, out, "Status:       active")

	authOut := filepath.Join(t.TempDir(), "codex-home-auth.json")
	_, err = runOIDCCommand(t, oidcTokenCmd, nil, map[string]string{"provider": "codex", "scope": "tenant", "codex-auth-out": authOut})
	require.NoError(t, err)
	written, err := os.ReadFile(authOut)
	require.NoError(t, err)
	assert.Contains(t, string(written), "chatgptAuthTokens")
	assert.NotContains(t, string(written), "rt-codex", "the refresh token never leaves the server")
}

func TestOIDCServerMode_Refusals(t *testing.T) {
	isolateXKMSdEndpoint(t)
	_, err := runOIDCCommand(t, oidcImportCmd, []string{"x"}, map[string]string{"access-token": "at"})
	assert.ErrorIs(t, err, ErrOIDCImportNeedsServer)

	startOIDCXKMSd(t)
	_, err = runOIDCCommand(t, oidcLogoutCmd, nil, nil)
	assert.ErrorIs(t, err, ErrOIDCServerLogout)

	_, err = runOIDCCommand(t, oidcTokenCmd, nil, nil)
	assert.ErrorIs(t, err, ErrOIDCServerNameRequired)

	_, err = runOIDCCommand(t, oidcLoginCmd, nil, map[string]string{"provider": "x", "exec": "./hook.sh"})
	assert.ErrorIs(t, err, ErrOIDCServerLocalOnly, "the local login's hook does not apply to a server credential")

	_, err = runOIDCCommand(t, oidcProvidersAddCmd, nil, map[string]string{"name": "aws", "type": "aws"})
	assert.ErrorIs(t, err, ErrOIDCServerLocalOnly)

	_, err = runOIDCCommand(t, oidcImportCmd, []string{"x"}, nil)
	assert.ErrorIs(t, err, ErrOIDCImportSource)
}

func TestOIDCServerMode_Unreachable(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, cleanup := startTestXKMSd(t)
	xkmsdURL = address
	cleanup()
	_, err := runOIDCCommand(t, oidcTokenCmd, nil, map[string]string{"provider": "x"})
	assert.ErrorIs(t, err, ErrOIDCServerConnect)
}

func TestTruncateServerToken(t *testing.T) {
	assert.Equal(t, "short", truncateServerToken("short"))
	long := strings.Repeat("a", 12) + strings.Repeat("b", 20) + strings.Repeat("c", 12)
	assert.Equal(t, strings.Repeat("a", 12)+"..."+strings.Repeat("c", 12), truncateServerToken(long))
	assert.Equal(t, []string{"a", "b"}, splitScopes(" a, ,b "))
	assert.Nil(t, splitScopes(""))
}
