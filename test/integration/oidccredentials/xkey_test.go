// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

//go:build integration

package oidccredentials

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// transports are the xkmsd transports xkey reaches a server over.
var transports = []string{"unix", "rest", "grpc", "quic", "mcp"}

// unsignedJWT returns a compact JWT carrying claims; nothing in this path
// verifies the signature of a codex token.
func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + enc.EncodeToString(payload) + ".sig"
}

// codexAuthJSON writes a codex auth.json holding a ChatGPT login whose access
// token is valid for a day, and returns its path and refresh token.
func codexAuthJSON(t *testing.T) (path, refreshToken string) {
	t.Helper()
	refreshToken = "rt-codex-" + t.Name()
	data, err := json.Marshal(map[string]any{
		"OPENAI_API_KEY": nil,
		"tokens": map[string]any{
			"id_token":      unsignedJWT(t, map[string]any{"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "acct-it"}}),
			"access_token":  unsignedJWT(t, map[string]any{"exp": time.Now().Add(24 * time.Hour).Unix()}),
			"refresh_token": refreshToken,
			"account_id":    "acct-it",
		},
		"last_refresh": time.Now().UTC().Format(time.RFC3339),
	})
	require.NoError(t, err)
	path = filepath.Join(t.TempDir(), "auth.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path, refreshToken
}

// TestXKeyServerCredentialsEveryTransport drives xkey's server mode against
// the running xkmsd over each transport: create, import, list (both
// backends), token, the refusal of a refresh the provider cannot do, a codex
// import and its chatgptAuthTokens projection, and removal.
func TestXKeyServerCredentialsEveryTransport(t *testing.T) {
	for _, transport := range transports {
		t.Run(transport, func(t *testing.T) {
			name := "claude-" + transport
			out, err := xkey(t, transport, "", "oidc", "providers", "add", "--name", name, "--template", "anthropic", "--scope", "tenant")
			require.NoError(t, err, out)
			assert.Contains(t, out, "Server OIDC credential created")
			assert.Contains(t, out, "Status:       pending")

			token := "sk-ant-oat01-" + transport
			out, err = xkey(t, transport, token+"\n", "oidc", "import", name, "--scope", "tenant", "--access-token", "-")
			require.NoError(t, err, out)
			assert.Contains(t, out, "Status:       active")

			out, err = xkey(t, transport, "", "oidc", "providers", "list")
			require.NoError(t, err, out)
			assert.Contains(t, out, name)
			assert.Contains(t, out, "Local OIDC providers:", "xkey lists both backends")

			out, err = xkey(t, transport, "", "oidc", "token", "--provider", name, "--scope", "tenant", "--show-full")
			require.NoError(t, err, out)
			assert.Contains(t, out, token)

			out, err = xkey(t, transport, "", "oidc", "refresh", "--provider", name, "--scope", "tenant")
			require.Error(t, err, "a setup-token is never refreshed")
			assert.Contains(t, out, "not refreshable")

			codexPath, refreshToken := codexAuthJSON(t)
			codexName := "codex-" + transport
			out, err = xkey(t, transport, "", "oidc", "import", codexName, "--scope", "tenant", "--codex-auth", codexPath, "--create")
			require.NoError(t, err, out)
			assert.Contains(t, out, "Template:     openai")
			assert.Contains(t, out, "Status:       active")

			projected := filepath.Join(t.TempDir(), "auth.json")
			out, err = xkey(t, transport, "", "oidc", "token", "--provider", codexName, "--scope", "tenant", "--codex-auth-out", projected)
			require.NoError(t, err, out)
			data, err := os.ReadFile(projected)
			require.NoError(t, err)
			assert.Contains(t, string(data), `"auth_mode": "chatgptAuthTokens"`)
			assert.NotContains(t, string(data), refreshToken, "the refresh token never leaves the server")

			for _, n := range []string{name, codexName} {
				out, err = xkey(t, transport, "", "oidc", "providers", "remove", n, "--scope", "tenant")
				require.NoError(t, err, out)
			}
			out, err = xkey(t, transport, "", "oidc", "token", "--provider", name, "--scope", "tenant")
			require.Error(t, err)
			assert.Contains(t, strings.ToLower(out), "not found")
		})
	}
}

// TestXKeyLocalBackendStaysLocal proves xkey's local OIDC is untouched: with
// no xkmsd it manages local providers only and refuses a server import, and
// with an xkmsd configured --local still reaches the local backend.
func TestXKeyLocalBackendStaysLocal(t *testing.T) {
	store := filepath.Join(t.TempDir(), "tokens.json")

	out, err := xkey(t, "", "", "oidc", "providers", "list", "--token-store", store)
	require.NoError(t, err, out)
	assert.Contains(t, out, "No OIDC providers configured")
	assert.NotContains(t, out, "Server OIDC credentials")

	out, err = xkey(t, "", "", "oidc", "providers", "add", "--name", "corp",
		"--issuer", "https://idp.example.com", "--client-id", "cli", "--token-store", store)
	require.NoError(t, err, out)
	out, err = xkey(t, "", "", "oidc", "providers", "list", "--token-store", store)
	require.NoError(t, err, out)
	assert.Contains(t, out, "corp")

	out, err = xkey(t, "", "", "oidc", "import", "x", "--access-token", "at")
	require.Error(t, err)
	assert.Contains(t, out, "xkmsd")

	out, err = xkey(t, "rest", "", "oidc", "providers", "list", "--local", "--token-store", store)
	require.NoError(t, err, out)
	assert.Contains(t, out, "corp")
	assert.NotContains(t, out, "Server OIDC credentials", "--local keeps the local backend")
}

// TestXKMSCtlOIDC drives xkmsctl oidc against the server over REST.
func TestXKMSCtlOIDC(t *testing.T) {
	out, err := xkmsctl("rest", "oidc", "templates")
	require.NoError(t, err, out)
	assert.Contains(t, out, "openai")
	assert.Contains(t, out, "anthropic")

	codexPath, _ := codexAuthJSON(t)
	out, err = xkmsctl("rest", "oidc", "import", "codex-ctl", "--scope", "tenant", "--codex-auth", codexPath, "--create")
	require.NoError(t, err, out)
	assert.Contains(t, out, "OIDC Credential Imported")

	out, err = xkmsctl("rest", "-o", "json", "oidc", "get", "codex-ctl", "--scope", "tenant")
	require.NoError(t, err, out)
	var cred map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &cred), out)
	assert.Equal(t, "active", cred["status"])
	assert.Equal(t, true, cred["refreshable"])
	assert.NotContains(t, out, "rt-codex", "a credential's view never carries its tokens")

	out, err = xkmsctl("rest", "oidc", "list")
	require.NoError(t, err, out)
	assert.Contains(t, out, "codex-ctl")

	out, err = xkmsctl("rest", "oidc", "token", "codex-ctl", "--scope", "tenant")
	require.NoError(t, err, out)
	assert.Equal(t, 3, len(strings.Split(strings.TrimSpace(out), ".")), "the access token alone, a JWT")

	_, err = xkmsctl("rest", "oidc", "create", "codex-ctl", "--scope", "tenant", "--template", "openai")
	require.Error(t, err, "a taken name is refused")

	out, err = xkmsctl("rest", "oidc", "delete", "codex-ctl", "--scope", "tenant")
	require.NoError(t, err, out)
}
