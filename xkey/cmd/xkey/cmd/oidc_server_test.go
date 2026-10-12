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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// deviceTestIdP is an identity provider serving RFC 8628 device
// authorization and answering each device token poll with the next queued
// reply, repeating the last one once the queue runs out.
type deviceTestIdP struct {
	*httptest.Server

	mu      sync.Mutex
	replies []func(w http.ResponseWriter)
	polls   []url.Values
}

// newDeviceTestIdP starts a device-flow identity provider whose device
// logins poll every interval seconds and expire after expiresIn seconds.
func newDeviceTestIdP(t *testing.T, interval, expiresIn int, replies ...func(w http.ResponseWriter)) *deviceTestIdP {
	t.Helper()

	idp := &deviceTestIdP{replies: replies}
	idp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/device":
			writeTestJSON(t, w, http.StatusOK, map[string]any{
				"device_code":               "device-code-1",
				"user_code":                 "WDJB-MJHT",
				"verification_uri":          idp.URL + "/activate",
				"verification_uri_complete": idp.URL + "/activate?user_code=WDJB-MJHT",
				"expires_in":                expiresIn,
				"interval":                  interval,
			})
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			idp.mu.Lock()
			idp.polls = append(idp.polls, r.PostForm)
			reply := idp.replies[0]
			if len(idp.replies) > 1 {
				idp.replies = idp.replies[1:]
			}
			idp.mu.Unlock()
			reply(w)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)
	return idp
}

// tokenPolls returns the device token polls received so far.
func (idp *deviceTestIdP) tokenPolls() []url.Values {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return append([]url.Values(nil), idp.polls...)
}

// replyWithDeviceError answers a device token poll with an RFC 8628
// section 3.5 error code.
func replyWithDeviceError(t *testing.T, code string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		writeTestJSON(t, w, http.StatusBadRequest, map[string]string{"error": code})
	}
}

// addServerDeviceCredential registers a tenant credential named name whose
// provider is idp.
func addServerDeviceCredential(t *testing.T, name string, idp *deviceTestIdP) {
	t.Helper()

	_, err := runOIDCCommand(t, oidcProvidersAddCmd, nil, map[string]string{
		"name":                   name,
		"scope":                  "tenant",
		"issuer":                 idp.URL,
		"client-id":              "xkey-cli",
		"authorization-endpoint": idp.URL + "/authorize",
		"token-endpoint":         idp.URL + "/token",
		"device-endpoint":        idp.URL + "/device",
	})
	require.NoError(t, err)
}

// TestOIDCServerMode_DeviceLogin drives `oidc login` against a server
// credential: the CLI prints the verification URI and code, polls the
// server at the provider's interval while the user has not approved, and
// stops on approval, denial, or expiry.
func TestOIDCServerMode_DeviceLogin(t *testing.T) {
	startOIDCXKMSd(t)
	t.Setenv("XKEY_DATA_DIR", t.TempDir())

	t.Run("approved after a pending poll", func(t *testing.T) {
		idp := newDeviceTestIdP(t, 1, 60,
			replyWithDeviceError(t, "authorization_pending"),
			func(w http.ResponseWriter) {
				writeTestJSON(t, w, http.StatusOK, map[string]any{
					"access_token": "device-access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
			})
		addServerDeviceCredential(t, "corp", idp)

		out, err := runOIDCCommand(t, oidcLoginCmd, nil, map[string]string{"provider": "corp", "scope": "tenant"})
		require.NoError(t, err)
		assert.Contains(t, out, "Open "+idp.URL+"/activate?user_code=WDJB-MJHT")
		assert.Contains(t, out, "and enter the code: WDJB-MJHT")
		assert.Contains(t, out, "Server OIDC credential logged in")
		assert.Contains(t, out, "Status:       active")

		polls := idp.tokenPolls()
		require.Len(t, polls, 2, "the CLI keeps polling while authorization is pending")
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:device_code", polls[1].Get("grant_type"))
		assert.Equal(t, "device-code-1", polls[1].Get("device_code"))

		out, err = runOIDCCommand(t, oidcTokenCmd, nil, map[string]string{"provider": "corp", "scope": "tenant", "show-full": "true"})
		require.NoError(t, err)
		assert.Contains(t, out, "device-access-token", "the server stored the approved tokens")
	})

	t.Run("denied", func(t *testing.T) {
		idp := newDeviceTestIdP(t, 1, 60, replyWithDeviceError(t, "access_denied"))
		addServerDeviceCredential(t, "denied", idp)

		_, err := runOIDCCommand(t, oidcLoginCmd, nil, map[string]string{"provider": "denied", "scope": "tenant"})
		require.ErrorContains(t, err, "denied")
		assert.Len(t, idp.tokenPolls(), 1, "a denial ends the login at once")
	})

	t.Run("not approved in time", func(t *testing.T) {
		// The login expires before the first poll is due.
		idp := newDeviceTestIdP(t, 5, 1, replyWithDeviceError(t, "authorization_pending"))
		addServerDeviceCredential(t, "expired", idp)

		_, err := runOIDCCommand(t, oidcLoginCmd, nil, map[string]string{"provider": "expired", "scope": "tenant"})
		require.ErrorIs(t, err, ErrOIDCDeviceLoginExpired)
		assert.Empty(t, idp.tokenPolls())
	})
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
