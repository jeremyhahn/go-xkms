package cmd

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/oidc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/aws"
)

// awsLoginHarness runs the real aws.Login flow against a local token
// endpoint and lets a test play the browser: it learns the authorization
// URL the login prints and delivers the redirect to the callback listener.
type awsLoginHarness struct {
	callback oidc.Callback
	authURLs chan string
}

// newAWSLoginHarness points awsLogin at a token endpoint served by
// tokenHandler for the duration of the test.
func newAWSLoginHarness(t *testing.T, tokenHandler http.HandlerFunc) *awsLoginHarness {
	t.Helper()

	tokenServer := httptest.NewServer(tokenHandler)
	t.Cleanup(tokenServer.Close)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())

	h := &awsLoginHarness{
		callback: oidc.Callback{Host: "127.0.0.1", Port: port},
		authURLs: make(chan string, 1),
	}
	original := awsLogin
	awsLogin = func(ctx context.Context, opts aws.LoginOptions, onAuthURL func(string)) (*aws.LoginResult, error) {
		opts.TokenEndpointOverride = tokenServer.URL
		opts.Timeout = 10 * time.Second
		return aws.Login(ctx, opts, func(authURL string) {
			onAuthURL(authURL)
			h.authURLs <- authURL
		})
	}
	t.Cleanup(func() { awsLogin = original })
	return h
}

// redirect waits for the authorization URL and then delivers the browser
// redirect carrying query, with the login's own state unless query sets one.
func (h *awsLoginHarness) redirect(t *testing.T, query url.Values) {
	t.Helper()

	var authURL string
	select {
	case authURL = <-h.authURLs:
	case <-time.After(10 * time.Second):
		t.Fatal("login never produced an authorization URL")
	}
	parsed, err := url.Parse(authURL)
	require.NoError(t, err)
	if !query.Has("state") {
		query.Set("state", parsed.Query().Get("state"))
	}

	resp, err := http.Get(h.callback.AWSRedirectURL() + "?" + query.Encode())
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
}

// awsTokenHandler answers a token request with temporary credentials and,
// when refreshToken is non-empty, a refresh token.
func awsTokenHandler(accessKeyID, refreshToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(aws.RawTokenResponse{
			AccessToken: &aws.AccessTokenCredentials{
				AccessKeyID:     accessKeyID,
				SecretAccessKey: "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
				SessionToken:    "FwoGZXIvYXdzLoginSessionToken",
				Expiration:      time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			},
			TokenType:    "DPoP",
			ExpiresIn:    3600,
			RefreshToken: refreshToken,
		})
	}
}

// oathStoreNames lists the credential names in the OATH store at storePath.
func oathStoreNames(t *testing.T, storePath string) []string {
	t.Helper()

	store, err := oath.NewFileStore(storePath)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()

	creds, err := store.List()
	require.NoError(t, err)
	names := make([]string, 0, len(creds))
	for _, cred := range creds {
		names = append(names, cred.Name)
	}
	return names
}
