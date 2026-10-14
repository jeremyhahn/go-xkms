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

package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/oidc"
	oidcaws "github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/aws"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFakeAWSTokenClient returns an AWS sign-in client whose token endpoint is
// an httptest server. A refresh succeeds only for wantRefreshToken; the
// server answers with fresh credentials and a rotated refresh token.
func newFakeAWSTokenClient(t *testing.T, wantRefreshToken string) *oidcaws.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("refresh_token") != wantRefreshToken {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token": map[string]any{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
				"session_token":     "FwoGZXIvYXdzEXAMPLESESSIONTOKEN",
				"expiration":        time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			},
			"token_type":    "urn:aws:params:oauth:token-type:access_token_sigv4",
			"expires_in":    900,
			"refresh_token": "rotated-refresh-token",
		}); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	dpopKey, err := oidc.GenerateDPoPKey()
	require.NoError(t, err)
	client, err := oidcaws.NewClient(&oidcaws.ClientConfig{
		Region:                "us-east-1",
		TokenEndpointOverride: server.URL,
	}, dpopKey)
	require.NoError(t, err)
	return client
}

// waitForRefresh polls the provider's refresh status until at least one
// refresh has been recorded, failing the test after a few ticker periods.
func waitForRefresh(t *testing.T, svc *OIDCService, provider string) *OIDCRefreshStatus {
	t.Helper()
	var status *OIDCRefreshStatus
	require.Eventually(t, func() bool {
		var err error
		status, err = svc.GetRefreshStatus(provider)
		require.NoError(t, err)
		return status.RefreshCount > 0
	}, 5*time.Second, 20*time.Millisecond)
	return status
}

// stopAWSRefresh stops the provider's refresh loop and waits until the loop
// goroutine has observed the cancellation and marked itself stopped.
func stopAWSRefresh(t *testing.T, svc *OIDCService, provider string) {
	t.Helper()
	svc.refreshMu.Lock()
	proc := svc.refreshProcs[provider]
	svc.refreshMu.Unlock()
	require.NotNil(t, proc)

	require.NoError(t, svc.StopAutoRefresh(provider))
	require.Eventually(t, func() bool { return !proc.status.Load().Running }, 5*time.Second, 20*time.Millisecond,
		"cancelling the loop must mark the refresh as stopped")
}

func TestOIDCService_StartAWSAutoRefresh_Rejects(t *testing.T) {
	svc := NewOIDCService(nil)
	client := newFakeAWSTokenClient(t, "refresh-token")

	err := svc.startAWSAutoRefresh("aws", &OIDCProviderEntry{AutoRefresh: 0}, client, "refresh-token")
	assert.ErrorIs(t, err, ErrOIDCAutoRefreshDisabled)

	entry := &OIDCProviderEntry{AutoRefresh: 3600, AWSOutput: handlers.ModeNone}
	require.NoError(t, svc.startAWSAutoRefresh("aws", entry, client, "refresh-token"))
	t.Cleanup(func() { stopAWSRefresh(t, svc, "aws") })

	err = svc.startAWSAutoRefresh("aws", entry, client, "refresh-token")
	assert.ErrorIs(t, err, ErrOIDCRefreshAlreadyRunning)
}

func TestOIDCService_AWSRefreshLoop_WritesCredentials(t *testing.T) {
	svc := NewOIDCService(nil)
	credsFile := filepath.Join(t.TempDir(), "credentials")
	entry := &OIDCProviderEntry{
		AutoRefresh:        1,
		AWSRegion:          "us-east-1",
		AWSOutput:          handlers.ModeAWSCredentials,
		AWSProfile:         "xkey-test",
		AWSCredentialsFile: credsFile,
	}
	require.NoError(t, svc.startAWSAutoRefresh("aws", entry, newFakeAWSTokenClient(t, "refresh-token"), "refresh-token"))
	t.Cleanup(func() { stopAWSRefresh(t, svc, "aws") })

	status := waitForRefresh(t, svc, "aws")
	assert.Equal(t, "success", status.LastStatus)
	assert.Empty(t, status.LastError)
	assert.True(t, status.Running)

	data, err := os.ReadFile(credsFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "[xkey-test]")
	assert.Contains(t, string(data), "AKIAIOSFODNN7EXAMPLE")

}

func TestOIDCService_AWSRefreshLoop_RecordsErrors(t *testing.T) {
	tests := []struct {
		name         string
		refreshToken string
		output       string
	}{
		{"token endpoint rejects refresh", "stale-refresh-token", handlers.ModeNone},
		{"unknown output mode", "refresh-token", "no-such-mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewOIDCService(nil)
			entry := &OIDCProviderEntry{AutoRefresh: 1, AWSRegion: "us-east-1", AWSOutput: tt.output}
			require.NoError(t, svc.startAWSAutoRefresh("aws", entry, newFakeAWSTokenClient(t, "refresh-token"), tt.refreshToken))
			t.Cleanup(func() { stopAWSRefresh(t, svc, "aws") })

			status := waitForRefresh(t, svc, "aws")
			assert.Equal(t, "error", status.LastStatus)
			assert.NotEmpty(t, status.LastError)
			assert.True(t, status.Running, "a failed refresh must keep the loop running")
		})
	}
}
