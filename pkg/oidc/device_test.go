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

package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deviceTestClient returns a client over explicit endpoints of srv.
func deviceTestClient(t *testing.T, srv *httptest.Server, style DeviceStyle, encoding TokenEncoding) *Client {
	t.Helper()
	provider, err := NewEndpointProvider(srv.URL, Endpoints{
		Token:               srv.URL + "/token",
		DeviceAuthorization: srv.URL + "/device",
	}, srv.Client())
	require.NoError(t, err)
	return NewClient(provider, &ProviderConfig{
		Issuer:        srv.URL,
		ClientID:      "client-1",
		Scopes:        []string{"openid", "offline_access"},
		HTTPClient:    srv.Client(),
		TokenEncoding: encoding,
		DeviceStyle:   style,
	})
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	require.NoError(t, json.NewEncoder(w).Encode(v))
}

func TestRFC8628DeviceFlow(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		switch r.URL.Path {
		case "/device":
			assert.Equal(t, "client-1", r.PostForm.Get("client_id"))
			assert.Equal(t, "openid offline_access", r.PostForm.Get("scope"))
			writeJSON(t, w, http.StatusOK, map[string]any{
				"device_code":               "dev-code",
				"user_code":                 "ABCD-EFGH",
				"verification_uri":          "https://idp.example.com/device",
				"verification_uri_complete": "https://idp.example.com/device?user_code=ABCD-EFGH",
				"expires_in":                600,
				"interval":                  7,
			})
		case "/token":
			assert.Equal(t, deviceGrantType, r.PostForm.Get("grant_type"))
			assert.Equal(t, "dev-code", r.PostForm.Get("device_code"))
			switch polls.Add(1) {
			case 1:
				writeJSON(t, w, http.StatusBadRequest, map[string]string{"error": "authorization_pending"})
			case 2:
				writeJSON(t, w, http.StatusBadRequest, map[string]string{"error": "slow_down"})
			default:
				writeJSON(t, w, http.StatusOK, map[string]any{
					"access_token": "at", "refresh_token": "rt", "token_type": "Bearer", "expires_in": 3600,
				})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := deviceTestClient(t, srv, "", "")
	ctx := context.Background()

	da, err := client.StartDeviceAuthorization(ctx)
	require.NoError(t, err)
	assert.Equal(t, "ABCD-EFGH", da.UserCode)
	assert.Equal(t, "https://idp.example.com/device", da.VerificationURI)
	assert.Equal(t, 7*time.Second, da.Interval)
	assert.WithinDuration(t, time.Now().Add(10*time.Minute), da.ExpiresAt, 5*time.Second)

	_, err = client.PollDeviceToken(ctx, da)
	assert.ErrorIs(t, err, ErrAuthorizationPending)
	_, err = client.PollDeviceToken(ctx, da)
	assert.ErrorIs(t, err, ErrSlowDown)
	tokens, err := client.PollDeviceToken(ctx, da)
	require.NoError(t, err)
	assert.Equal(t, "at", tokens.AccessToken)
	assert.Equal(t, "rt", tokens.RefreshToken)
}

func TestRFC8628DeviceFlowTerminalErrors(t *testing.T) {
	for code, want := range map[string]error{
		"access_denied": ErrDeviceAccessDenied,
		"expired_token": ErrDeviceCodeExpired,
	} {
		t.Run(code, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(t, w, http.StatusBadRequest, map[string]string{"error": code})
			}))
			defer srv.Close()
			client := deviceTestClient(t, srv, "", "")
			_, err := client.PollDeviceToken(context.Background(), &DeviceAuthorization{DeviceCode: "d", ExpiresAt: time.Now().Add(time.Minute)})
			assert.ErrorIs(t, err, want)
		})
	}
}

func TestDeviceFlowRejectsBadInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{"device_code": "only"})
	}))
	defer srv.Close()
	client := deviceTestClient(t, srv, "", "")
	ctx := context.Background()

	_, err := client.StartDeviceAuthorization(ctx)
	assert.ErrorIs(t, err, ErrDeviceAuthorizationFailed, "a response without user_code is refused")

	_, err = client.PollDeviceToken(ctx, nil)
	assert.ErrorIs(t, err, ErrDeviceAuthorizationFailed)

	_, err = client.PollDeviceToken(ctx, &DeviceAuthorization{DeviceCode: "d", ExpiresAt: time.Now().Add(-time.Second)})
	assert.ErrorIs(t, err, ErrDeviceCodeExpired, "an expired login is not polled")

	noDevice, err := NewEndpointProvider(srv.URL, Endpoints{Token: srv.URL + "/token"}, srv.Client())
	require.NoError(t, err)
	_, err = NewClient(noDevice, &ProviderConfig{ClientID: "c"}).StartDeviceAuthorization(ctx)
	assert.ErrorIs(t, err, ErrDeviceFlowUnsupported)

	_, err = NewClient(noDevice, &ProviderConfig{ClientID: "c", DeviceStyle: "bogus"}).StartDeviceAuthorization(ctx)
	assert.ErrorIs(t, err, ErrUnknownDeviceStyle)

	_, err = NewClient(&Provider{}, &ProviderConfig{ClientID: "c"}).StartDeviceAuthorization(ctx)
	assert.ErrorIs(t, err, ErrProviderNotInitialized)
}

func TestOpenAIDeviceFlow(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/accounts/deviceauth/usercode":
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			var body map[string]string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, "client-1", body["client_id"])
			// The service has answered the interval as a string.
			writeJSON(t, w, http.StatusOK, map[string]any{"device_auth_id": "dai", "user_code": "WXYZ", "interval": "3"})
		case "/api/accounts/deviceauth/token":
			var body map[string]string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, "dai", body["device_auth_id"])
			assert.Equal(t, "WXYZ", body["user_code"])
			if polls.Add(1) == 1 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			writeJSON(t, w, http.StatusOK, map[string]string{
				"authorization_code": "code-1", "code_challenge": "ch", "code_verifier": "verifier-1",
			})
		case "/token":
			// The code is exchanged form-encoded even though refresh is JSON.
			assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
			raw, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			form, err := url.ParseQuery(string(raw))
			require.NoError(t, err)
			assert.Equal(t, "authorization_code", form.Get("grant_type"))
			assert.Equal(t, "code-1", form.Get("code"))
			assert.Equal(t, "verifier-1", form.Get("code_verifier"))
			assert.Equal(t, srvURL(r)+"/deviceauth/callback", form.Get("redirect_uri"))
			writeJSON(t, w, http.StatusOK, map[string]any{"access_token": "at", "refresh_token": "rt", "id_token": "it"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := deviceTestClient(t, srv, DeviceStyleOpenAI, TokenEncodingJSON)
	ctx := context.Background()
	da, err := client.StartDeviceAuthorization(ctx)
	require.NoError(t, err)
	assert.Equal(t, "WXYZ", da.UserCode)
	assert.Equal(t, srv.URL+"/codex/device", da.VerificationURI)
	assert.Equal(t, 3*time.Second, da.Interval)

	_, err = client.PollDeviceToken(ctx, da)
	assert.ErrorIs(t, err, ErrAuthorizationPending, "403 means not yet approved")
	tokens, err := client.PollDeviceToken(ctx, da)
	require.NoError(t, err)
	assert.Equal(t, "rt", tokens.RefreshToken)
	assert.Equal(t, "it", tokens.IDToken)
}

func TestOpenAIDeviceFlowErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/accounts/deviceauth/usercode":
			http.NotFound(w, r)
		default:
			writeJSON(t, w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		}
	}))
	defer srv.Close()
	client := deviceTestClient(t, srv, DeviceStyleOpenAI, TokenEncodingJSON)
	ctx := context.Background()

	_, err := client.StartDeviceAuthorization(ctx)
	assert.ErrorIs(t, err, ErrDeviceFlowUnsupported, "404 means device login is not enabled")

	_, err = client.PollDeviceToken(ctx, &DeviceAuthorization{DeviceCode: "d", UserCode: "u", ExpiresAt: time.Now().Add(time.Minute)})
	assert.ErrorIs(t, err, ErrDeviceAuthorizationFailed)
}

func TestFlexibleSeconds(t *testing.T) {
	assert.Equal(t, 4*time.Second, flexibleSeconds(json.RawMessage(`4`)))
	assert.Equal(t, 2500*time.Millisecond, flexibleSeconds(json.RawMessage(`"2.5"`)))
	assert.Equal(t, defaultDeviceInterval, flexibleSeconds(json.RawMessage(`"x"`)))
	assert.Equal(t, defaultDeviceInterval, flexibleSeconds(json.RawMessage(`0`)))
	assert.Equal(t, defaultDeviceInterval, flexibleSeconds(nil))
}

// srvURL reconstructs the base URL a request was sent to.
func srvURL(r *http.Request) string {
	return "http://" + r.Host
}
