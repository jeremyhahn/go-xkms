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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/oidc"
)

// oidcTestIdP is an identity provider serving discovery and a token endpoint,
// recording every token request it receives.
type oidcTestIdP struct {
	*httptest.Server

	mu    sync.Mutex
	forms []url.Values
}

// newOIDCTestIdP starts an identity provider whose token endpoint answers
// with reply.
func newOIDCTestIdP(t *testing.T, reply func(w http.ResponseWriter)) *oidcTestIdP {
	t.Helper()

	idp := &oidcTestIdP{}
	idp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(OIDCDiscoveryDocument{
				Issuer:                idp.URL,
				AuthorizationEndpoint: idp.URL + "/authorize",
				TokenEndpoint:         idp.URL + "/token",
			})
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			idp.mu.Lock()
			idp.forms = append(idp.forms, r.PostForm)
			idp.mu.Unlock()
			reply(w)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)
	return idp
}

// tokenRequests returns the token requests received so far.
func (idp *oidcTestIdP) tokenRequests() []url.Values {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return append([]url.Values(nil), idp.forms...)
}

// replyWithTokens answers the token endpoint with tokens.
func replyWithTokens(tokens OIDCTokenResponse) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokens)
	}
}

// oidcFlowCmd returns a login command that serves its callback on a free
// loopback port and prints the authorization URL instead of opening a
// browser, plus the token store it writes to.
func oidcFlowCmd(t *testing.T, flags map[string]string) (*cobra.Command, string) {
	t.Helper()
	withLoadedConfig(t, nil)

	cmd, _, store := oidcTestCmd(t)
	registerOIDCCallbackFlags(cmd.Flags())
	cmd.Flags().Bool("no-browser", false, "")
	setOIDCFlags(t, cmd, map[string]string{
		"no-browser":    "true",
		"callback-host": "127.0.0.1",
	})
	setOIDCFlags(t, cmd, flags)
	return cmd, store
}

// oidcLoginFlow runs a login in the background and stands in for the
// browser: it reads the printed authorization URL and calls the redirect URL
// the way the provider would send the browser there.
type oidcLoginFlow struct {
	out  *lockedBuffer
	done chan error
}

func startOIDCLogin(cmd *cobra.Command) *oidcLoginFlow {
	flow := &oidcLoginFlow{out: &lockedBuffer{}, done: make(chan error, 1)}
	cmd.SetOut(flow.out)
	go func() { flow.done <- runOIDCLogin(cmd, nil) }()
	return flow
}

// authorizationURL waits for the login to print the authorization URL on
// the issuer's endpoint and returns it.
func (f *oidcLoginFlow) authorizationURL(t *testing.T, issuer string) *url.URL {
	t.Helper()

	prefix := issuer + "/authorize?"
	var found string
	printed := assert.Eventually(t, func() bool {
		for _, line := range strings.Split(f.out.String(), "\n") {
			if strings.HasPrefix(line, prefix) {
				found = line
				return true
			}
		}
		return false
	}, 10*time.Second, 20*time.Millisecond)
	if !printed {
		t.Fatalf("no authorization URL was printed; output:\n%s", f.out.String())
	}

	authURL, err := url.Parse(found)
	require.NoError(t, err)
	return authURL
}

// redirect sends the browser to the authorization URL's redirect_uri with
// query, as the provider does once the user has authenticated.
func (f *oidcLoginFlow) redirect(t *testing.T, authURL *url.URL, query url.Values) {
	t.Helper()

	resp, err := http.Get(authURL.Query().Get("redirect_uri") + "?" + query.Encode())
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
}

// result waits for the login to finish and returns its error.
func (f *oidcLoginFlow) result(t *testing.T) error {
	t.Helper()

	select {
	case err := <-f.done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the login did not finish after the callback")
		return nil
	}
}

// TestRunOIDCLogin_CompletesTheCodeFlowForASavedProvider drives the whole
// authorization code flow for a saved provider: the provider's client,
// scopes and redirect URL reach the authorization URL, the callback's code
// is exchanged with the PKCE verifier matching the challenge, the identity
// is printed and the tokens are stored. The provider asks for auto-refresh,
// but with no refresh token issued the login warns and returns.
func TestRunOIDCLogin_CompletesTheCodeFlowForASavedProvider(t *testing.T) {
	idToken := signedTestIDToken(t, OIDCIDTokenClaims{
		Claims: jwt.Claims{Subject: "user-7"},
		Email:  "u7@example.com",
		Name:   "User Seven",
	})
	idp := newOIDCTestIdP(t, replyWithTokens(OIDCTokenResponse{
		AccessToken: xkms.SecretBytes("flow-access"),
		IDToken:     xkms.SecretBytes(idToken),
		ExpiresIn:   600,
	}))

	cmd, store := oidcFlowCmd(t, map[string]string{"provider": "corp"})
	redirectURL := "http://127.0.0.1:" + freeLoopbackPort(t) + "/corp/cb"
	hookOutput := filepath.Join(t.TempDir(), "hook.txt")
	require.NoError(t, saveOIDCConfig(getConfigPath(store), OIDCConfig{Providers: []OIDCProvider{{
		Name:         "corp",
		Issuer:       idp.URL,
		ClientID:     "corp-client",
		ClientSecret: "corp-secret",
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "email"},
		Exec:         fmt.Sprintf(`printf '%%s|%%s|%%s' "$OIDC_ACCESS_TOKEN" "$OIDC_SUBJECT" "$OIDC_SCOPES" > %q`, hookOutput),
		AutoRefresh:  60,
	}}}))

	flow := startOIDCLogin(cmd)
	authURL := flow.authorizationURL(t, idp.URL)
	query := authURL.Query()
	assert.Equal(t, "corp-client", query.Get("client_id"))
	assert.Equal(t, redirectURL, query.Get("redirect_uri"))
	assert.Equal(t, "openid email", query.Get("scope"))
	assert.Equal(t, "S256", query.Get("code_challenge_method"))

	flow.redirect(t, authURL, url.Values{"code": {"auth-code"}, "state": {query.Get("state")}})
	require.NoError(t, flow.result(t))

	requests := idp.tokenRequests()
	require.Len(t, requests, 1)
	form := requests[0]
	assert.Equal(t, "authorization_code", form.Get("grant_type"))
	assert.Equal(t, "auth-code", form.Get("code"))
	assert.Equal(t, "corp-secret", form.Get("client_secret"))
	assert.Equal(t, redirectURL, form.Get("redirect_uri"))
	challenge := sha256.Sum256([]byte(form.Get("code_verifier")))
	assert.Equal(t, query.Get("code_challenge"), base64.RawURLEncoding.EncodeToString(challenge[:]),
		"the exchanged verifier must be the one the challenge was derived from")

	output := flow.out.String()
	assert.Contains(t, output, "Login successful!")
	assert.Contains(t, output, "Subject:  user-7")
	assert.Contains(t, output, "Email:    u7@example.com")
	assert.Contains(t, output, "Name:     User Seven")
	assert.Contains(t, output, "Warning: No refresh token received. Auto-refresh will not work.")

	hookSaw, err := os.ReadFile(hookOutput)
	require.NoError(t, err, "the provider's exec hook must run after the login")
	assert.Equal(t, "flow-access|user-7|openid email", string(hookSaw))

	token, err := loadToken(cmd, store)
	require.NoError(t, err)
	defer token.Destroy()
	assert.Equal(t, "flow-access", string(token.AccessToken()))
	assert.Equal(t, idp.URL, token.Issuer)
	assert.Equal(t, "corp-client", token.ClientID)
	assert.Equal(t, []string{"openid", "email"}, token.Scopes)
	assert.WithinDuration(t, time.Now().Add(600*time.Second), token.ExpiresAt, time.Minute)
}

// TestRunOIDCLogin_ReportsAFailingExecHook proves that a failing --exec hook
// fails the login, after the tokens it was handed have been stored.
func TestRunOIDCLogin_ReportsAFailingExecHook(t *testing.T) {
	idp := newOIDCTestIdP(t, replyWithTokens(OIDCTokenResponse{AccessToken: xkms.SecretBytes("hook-access")}))
	cmd, store := oidcFlowCmd(t, map[string]string{
		"issuer":        idp.URL,
		"client-id":     "client",
		"callback-port": freeLoopbackPort(t),
		"exec":          "exit 3",
	})

	flow := startOIDCLogin(cmd)
	authURL := flow.authorizationURL(t, idp.URL)
	flow.redirect(t, authURL, url.Values{"code": {"c"}, "state": {authURL.Query().Get("state")}})

	require.ErrorIs(t, flow.result(t), ErrOIDCExecFailed)
	token, err := loadToken(cmd, store)
	require.NoError(t, err)
	defer token.Destroy()
	assert.Equal(t, "hook-access", string(token.AccessToken()))
}

// TestRunOIDCLogin_RefusesACallbackThatDoesNotCompleteTheFlow proves that a
// callback with a state the login did not issue, or with no code, ends the
// login without any code reaching the token endpoint.
func TestRunOIDCLogin_RefusesACallbackThatDoesNotCompleteTheFlow(t *testing.T) {
	tests := []struct {
		name  string
		query func(state string) url.Values
		want  []error
	}{
		{
			name:  "forged state",
			query: func(string) url.Values { return url.Values{"code": {"c"}, "state": {"forged"}} },
			want:  []error{ErrOIDCStateMismatch},
		},
		{
			name:  "no code",
			query: func(state string) url.Values { return url.Values{"state": {state}} },
			want:  []error{ErrOIDCCallbackFailed, ErrOIDCNoAuthCode},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newOIDCTestIdP(t, replyWithTokens(OIDCTokenResponse{AccessToken: xkms.SecretBytes("a")}))
			cmd, store := oidcFlowCmd(t, map[string]string{
				"issuer":        idp.URL,
				"client-id":     "client",
				"callback-port": freeLoopbackPort(t),
			})

			flow := startOIDCLogin(cmd)
			authURL := flow.authorizationURL(t, idp.URL)
			flow.redirect(t, authURL, tt.query(authURL.Query().Get("state")))

			err := flow.result(t)
			for _, want := range tt.want {
				require.ErrorIs(t, err, want)
			}
			assert.Empty(t, idp.tokenRequests())
			_, err = loadToken(cmd, store)
			assert.Error(t, err, "nothing may be stored")
		})
	}
}

// TestRunOIDCLogin_ReportsTokenEndpointFailures proves that a refused code
// exchange and an ID token that is not a JWT both fail the login, and that
// neither stores a token.
func TestRunOIDCLogin_ReportsTokenEndpointFailures(t *testing.T) {
	tests := []struct {
		name  string
		reply func(w http.ResponseWriter)
		want  error
	}{
		{
			name: "exchange refused",
			reply: func(w http.ResponseWriter) {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			},
			want: ErrOIDCTokenExchangeFailed,
		},
		{
			name: "malformed id token",
			reply: replyWithTokens(OIDCTokenResponse{
				AccessToken: xkms.SecretBytes("a"),
				IDToken:     xkms.SecretBytes("not-a-jwt"),
			}),
			want: ErrOIDCTokenValidationFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newOIDCTestIdP(t, tt.reply)
			cmd, store := oidcFlowCmd(t, map[string]string{
				"issuer":        idp.URL,
				"client-id":     "client",
				"callback-port": freeLoopbackPort(t),
			})

			flow := startOIDCLogin(cmd)
			authURL := flow.authorizationURL(t, idp.URL)
			flow.redirect(t, authURL, url.Values{"code": {"c"}, "state": {authURL.Query().Get("state")}})

			require.ErrorIs(t, flow.result(t), tt.want)
			assert.Len(t, idp.tokenRequests(), 1)
			_, err := loadToken(cmd, store)
			assert.Error(t, err, "nothing may be stored")
			assert.NotContains(t, flow.out.String(), "Login successful!")
		})
	}
}

// TestRunOIDCLogin_RefusesBeforeTheBrowser proves that configuration the
// login cannot use stops it with a typed error before any authorization URL
// is shown.
func TestRunOIDCLogin_RefusesBeforeTheBrowser(t *testing.T) {
	brokenIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(brokenIssuer.Close)

	tests := []struct {
		name      string
		flags     map[string]string
		providers []OIDCProvider
		want      error
	}{
		{
			name:  "no saved providers",
			flags: map[string]string{"provider": "corp"},
			want:  ErrOIDCConfigLoadFailed,
		},
		{
			name:      "unknown provider",
			flags:     map[string]string{"provider": "corp"},
			providers: []OIDCProvider{{Name: "other", Issuer: "https://other.example.com"}},
			want:      ErrOIDCProviderNotFound,
		},
		{
			name:  "invalid token encoding",
			flags: map[string]string{"issuer": "https://idp.example.com", "client-id": "c", "token-encoding": "xml"},
			want:  oidc.ErrInvalidTokenEncoding,
		},
		{
			name:  "no client id",
			flags: map[string]string{"issuer": "https://idp.example.com"},
			want:  ErrOIDCMissingClientID,
		},
		{
			name: "incomplete manual endpoints",
			flags: map[string]string{
				"issuer": "https://idp.example.com", "client-id": "c",
				"authorization-endpoint": "https://idp.example.com/authorize",
			},
			want: ErrOIDCIncompleteEndpoints,
		},
		{
			name:  "discovery fails",
			flags: map[string]string{"issuer": brokenIssuer.URL, "client-id": "c"},
			want:  ErrOIDCDiscoveryFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, store := oidcFlowCmd(t, tt.flags)
			if tt.providers != nil {
				require.NoError(t, saveOIDCConfig(getConfigPath(store), OIDCConfig{Providers: tt.providers}))
			}
			out := &lockedBuffer{}
			cmd.SetOut(out)

			err := loginError(t, func() error { return runOIDCLogin(cmd, nil) })
			require.ErrorIs(t, err, tt.want)
			assert.NotContains(t, out.String(), "redirect_uri")
		})
	}
}
