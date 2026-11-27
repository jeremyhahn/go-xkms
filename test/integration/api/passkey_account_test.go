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

//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	webauthnclient "github.com/jeremyhahn/go-xkms/pkg/webauthn/client"
	"github.com/jeremyhahn/go-xkms/test/integration/api/apiharness"
)

// passkeyOrigin is the WebAuthn origin the software authenticator binds into
// clientDataJSON. It must be one of config.test.yaml's webauthn.rp_origins,
// and rp_id (localhost) is its effective domain.
const passkeyOrigin = "https://localhost:8443"

// TestMain brings the server past its sealed window before any test runs,
// through the harness every api test package shares.
func TestMain(m *testing.M) {
	apiharness.Main(m)
}

// adminHTTPClient presents the administrator credential `xkmsd init` wrote
// into the server's datastore (mounted read-only into the test container).
// The server runs client_auth "verify", so this certificate authenticates
// the admin while anonymous clients still connect.
func adminHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	certFile := getEnv("XKMS_ADMIN_CERT", "/xkms-data/xkms/admin-cert.pem")
	keyFile := getEnv("XKMS_ADMIN_KEY", "/xkms-data/xkms/admin-key.pem")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load the init-ceremony admin credential (%s, %s): %v", certFile, keyFile, err)
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      loadCACertPool(),
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
			},
		},
	}
}

// PasskeyAccount is an admin-provisioned account that redeemed its invitation
// with a passkey and signed in with it. Its client sends the session token.
type PasskeyAccount struct {
	Email         string
	UserID        uint64
	Token         string
	Authenticator *webauthnclient.SoftwareAdapter
	baseURL       string
	client        *http.Client
}

// doRequest performs a request as the signed-in account.
func (a *PasskeyAccount) doRequest(method, path string, body interface{}) (*http.Response, error) {
	return sendJSON(a.client, method, a.baseURL+path, body, map[string]string{"Authorization": "Bearer " + a.Token})
}

// provisionPasskeyAccount creates an account the supported way under ruling
// 602: the administrator creates it (POST /api/v1/users/), the account
// redeems its one-time invitation with a passkey ceremony
// (/api/v1/invites/{tenant}/{token}/fido2/begin and finish), and then signs
// in with that passkey (/api/v1/webauthn/login/begin and finish).
func provisionPasskeyAccount(t *testing.T, cfg *TestConfig, email string) *PasskeyAccount {
	t.Helper()
	admin := adminHTTPClient(t)
	anon := createTLSClient(t)

	var created transport.GetUserResponse
	expectJSON(t, admin, "POST", cfg.RESTBaseURL+"/api/v1/users/", map[string]interface{}{
		"username":     strings.SplitN(email, "@", 2)[0],
		"email":        email,
		"display_name": "Integration Test User",
	}, nil, http.StatusCreated, &created)
	if created.Invite == nil || created.Invite.Token == "" {
		t.Fatalf("POST /api/v1/users/ for %s returned no invitation", email)
	}
	tenant := inviteTenant(t, created.Invite.URL)
	invitePath := "/api/v1/invites/" + url.PathEscape(tenant) + "/" + url.PathEscape(created.Invite.Token)

	var begin transport.BeginInviteRegistrationResponse
	expectJSON(t, anon, "POST", cfg.RESTBaseURL+invitePath+"/fido2/begin", map[string]interface{}{}, nil, http.StatusOK, &begin)
	if begin.SessionID == "" || begin.OptionsJSON == "" {
		t.Fatalf("invite fido2/begin returned session %q and options %q", begin.SessionID, begin.OptionsJSON)
	}
	if begin.Ceremony != transport.InviteCeremonyCreate {
		t.Fatalf("invite fido2/begin for a fresh invitation named ceremony %q, want %q", begin.Ceremony, transport.InviteCeremonyCreate)
	}

	ctx := context.Background()
	authn := webauthnclient.NewSoftwareAdapter()
	attestation, err := authn.MakeCredential(ctx, &webauthnclient.CeremonyOptions{
		OptionsJSON: []byte(begin.OptionsJSON),
		Origin:      passkeyOrigin,
	})
	if err != nil {
		t.Fatalf("software authenticator MakeCredential: %v", err)
	}
	var finished transport.FinishInviteRegistrationResponse
	expectJSON(t, anon, "POST", cfg.RESTBaseURL+invitePath+"/fido2/finish", map[string]interface{}{
		"session_id":       begin.SessionID,
		"attestation_json": string(attestation),
	}, nil, http.StatusOK, &finished)
	if finished.UserID != created.User.ID {
		t.Fatalf("invite fido2/finish activated user %d, want %d", finished.UserID, created.User.ID)
	}

	loginResp, err := sendJSON(anon, "POST", cfg.RESTBaseURL+"/api/v1/webauthn/login/begin", map[string]interface{}{"email": email}, nil)
	if err != nil {
		t.Fatalf("webauthn login/begin: %v", err)
	}
	loginOptions := readStatus(t, loginResp, http.StatusOK, "webauthn login/begin")
	loginSession := loginResp.Header.Get("X-Session-Id")
	if loginSession == "" {
		t.Fatal("webauthn login/begin returned no X-Session-Id")
	}
	assertion, err := authn.GetAssertion(ctx, &webauthnclient.CeremonyOptions{
		OptionsJSON: loginOptions,
		Origin:      passkeyOrigin,
	})
	if err != nil {
		t.Fatalf("software authenticator GetAssertion: %v", err)
	}
	var session struct {
		Token string `json:"token"`
	}
	expectJSON(t, anon, "POST", cfg.RESTBaseURL+"/api/v1/webauthn/login/finish", json.RawMessage(assertion),
		map[string]string{"X-Session-Id": loginSession}, http.StatusOK, &session)
	if session.Token == "" {
		t.Fatal("webauthn login/finish returned no token")
	}

	return &PasskeyAccount{
		Email:         email,
		UserID:        created.User.ID,
		Token:         session.Token,
		Authenticator: authn,
		baseURL:       cfg.RESTBaseURL,
		client:        anon,
	}
}

// assertNoUserWithEmail fails the test when the administrator's user list
// holds an account for email.
func assertNoUserWithEmail(t *testing.T, cfg *TestConfig, email string) {
	t.Helper()
	var users transport.ListUsersResponse
	expectJSON(t, adminHTTPClient(t), "GET", cfg.RESTBaseURL+"/api/v1/users/", nil, nil, http.StatusOK, &users)
	for _, u := range users.Users {
		if strings.EqualFold(u.Email, email) {
			t.Fatalf("user %d exists for %s; a refused registration must create no account", u.ID, email)
		}
	}
}

// inviteTenant extracts the tenant from an invitation URL
// (<base>/#/invite/<tenant>/<token>).
func inviteTenant(t *testing.T, inviteURL string) string {
	t.Helper()
	const marker = "/#/invite/"
	i := strings.Index(inviteURL, marker)
	if i < 0 {
		t.Fatalf("invitation URL %q has no %s segment", inviteURL, marker)
	}
	parts := strings.SplitN(inviteURL[i+len(marker):], "/", 2)
	tenant, err := url.PathUnescape(parts[0])
	if err != nil || tenant == "" {
		t.Fatalf("invitation URL %q names no tenant: %v", inviteURL, err)
	}
	return tenant
}

// sendJSON sends body as JSON (raw when it is a json.RawMessage) with the
// given extra headers.
func sendJSON(client *http.Client, method, target string, body interface{}, headers map[string]string) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		raw, ok := body.(json.RawMessage)
		if !ok {
			encoded, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			raw = encoded
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return client.Do(req)
}

// readStatus reads and closes resp's body, failing unless the status is want.
func readStatus(t *testing.T, resp *http.Response, want int, what string) []byte {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s: read body: %v", what, err)
	}
	if resp.StatusCode != want {
		t.Fatalf("%s: status %d, want %d: %s", what, resp.StatusCode, want, body)
	}
	return body
}

// expectJSON sends a request, requires status want, and decodes the body
// into out.
func expectJSON(t *testing.T, client *http.Client, method, target string, body interface{}, headers map[string]string, want int, out interface{}) {
	t.Helper()
	resp, err := sendJSON(client, method, target, body, headers)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	raw := readStatus(t, resp, want, method+" "+target)
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("%s %s: decode %s: %v", method, target, raw, err)
	}
}
