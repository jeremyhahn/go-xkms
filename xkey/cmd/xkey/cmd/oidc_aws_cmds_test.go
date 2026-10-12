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

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/aws"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// awsTestCmd builds a detached cobra command carrying every flag the AWS
// OIDC handler reads.
func awsTestCmd(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: "aws-test"}
	fs := cmd.Flags()
	for _, name := range []string{
		"region", "profile", "output", "credentials-file", "exec",
		"session-store", "log-file",
	} {
		fs.String(name, "", "")
	}
	fs.Int("auto-refresh", 0, "")
	fs.Bool("cross-device", false, "")
	fs.Bool("no-browser", false, "")
	fs.Bool("background", false, "")
	fs.Bool("background-worker", false, "")

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

// --- path helpers ---

func TestAWSPathHelpers(t *testing.T) {
	store := "/var/lib/xkey/aws-session.json"

	assert.Equal(t, "/var/lib/xkey/logs/aws-us-east-1.log",
		getAWSDefaultLogFile(store, "us-east-1"))
	assert.Equal(t, "/var/lib/xkey/pids/aws-us-east-1.pid",
		getAWSPIDFile(store, "us-east-1", ""),
		"without a provider name the region identifies the process")
	assert.Equal(t, "/var/lib/xkey/pids/prod.pid",
		getAWSPIDFile(store, "us-east-1", "prod"),
		"a named provider must win over the region-derived name")
}

func TestAWSPathHelpers_ExpandTilde(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	assert.Equal(t, filepath.Join(home, "xkey", "logs", "aws-eu-west-1.log"),
		getAWSDefaultLogFile("~/xkey/aws-session.json", "eu-west-1"))
	assert.Equal(t, filepath.Join(home, "xkey", "pids", "aws-eu-west-1.pid"),
		getAWSPIDFile("~/xkey/aws-session.json", "eu-west-1", ""))
}

// --- session persistence ---
//
// These tests all pass an explicit session store path, which bypasses
// barrier auto-detection entirely (openAWSSessionStore, matching `xkey
// oath`'s --store and `xkey oidc`'s --token-store overrides), so the cmd
// argument's flags are never consulted and an empty *cobra.Command
// suffices. See oidc_aws_barrier_test.go for the barrier-or-fallback
// decision itself.

// TestStoreAWSSession_CreatesPrivateStore complements the existing
// round-trip test by pinning the two properties that matter for safety: the
// store directory is created on demand and owner-only, and every file
// holding the refresh token is owner-only.
func TestStoreAWSSession_CreatesPrivateStore(t *testing.T) {
	cmd := &cobra.Command{}
	store := filepath.Join(t.TempDir(), "nested", "aws-session")

	require.NoError(t, storeAWSSession(cmd, store, AWSStoredSession{
		Region: "us-east-1", RefreshToken: "refresh-token-value",
	}))

	dirInfo, err := os.Stat(store)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm())

	require.NoError(t, filepath.WalkDir(store, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
			"%s: a stored refresh token must not be readable by other users", path)
		return nil
	}))

	got, err := loadAWSSession(cmd, store)
	require.NoError(t, err)
	assert.Equal(t, "refresh-token-value", got.RefreshToken)
}

func TestStoreAWSSession_ExpandsTilde(t *testing.T) {
	cmd := &cobra.Command{}
	home := t.TempDir()
	t.Setenv("HOME", home)

	require.NoError(t, storeAWSSession(cmd, "~/aws/session", AWSStoredSession{Region: "eu-west-1"}))
	assert.DirExists(t, filepath.Join(home, "aws", "session"))

	got, err := loadAWSSession(cmd, "~/aws/session")
	require.NoError(t, err)
	assert.Equal(t, "eu-west-1", got.Region)
}

func TestLoadAWSSession_MissingAndCorrupt(t *testing.T) {
	cmd := &cobra.Command{}
	dir := t.TempDir()

	_, err := loadAWSSession(cmd, filepath.Join(dir, "absent"))
	assert.ErrorIs(t, err, xkms.ErrStorageNotFound)

	corrupt := filepath.Join(dir, "corrupt")
	backend, err := xkms.NewFileStorageBackend(corrupt)
	require.NoError(t, err)
	require.NoError(t, backend.Put(t.Context(), awsSessionStoreKey, []byte("{not json")))
	require.NoError(t, backend.Close())
	_, err = loadAWSSession(cmd, corrupt)
	assert.Error(t, err)
}

func TestStoreAWSSession_ReportsUnwritablePath(t *testing.T) {
	cmd := &cobra.Command{}
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	err := storeAWSSession(cmd, filepath.Join(blocker, "aws-session.json"), AWSStoredSession{})
	assert.Error(t, err)
}

// --- isAWSProcessRunning ---

func TestIsAWSProcessRunning(t *testing.T) {
	dir := t.TempDir()

	live := filepath.Join(dir, "live.pid")
	require.NoError(t, os.WriteFile(live, []byte(strconv.Itoa(os.Getpid())), 0600))
	pid, running := isAWSProcessRunning(live)
	assert.Equal(t, os.Getpid(), pid)
	assert.True(t, running)

	_, running = isAWSProcessRunning(filepath.Join(dir, "absent.pid"))
	assert.False(t, running)

	garbage := filepath.Join(dir, "garbage.pid")
	require.NoError(t, os.WriteFile(garbage, []byte("nope"), 0600))
	_, running = isAWSProcessRunning(garbage)
	assert.False(t, running)
}

// The OAuth2 callback handler itself moved to the shared
// xkey/pkg/oidc/aws package (aws.Login's internal handleLoginCallback); see
// xkey/pkg/oidc/aws/login_test.go for its coverage.

// --- runOIDCAWS / runAWSLogin argument validation ---

func TestRunOIDCAWS_RequiresRegion(t *testing.T) {
	cmd, _ := awsTestCmd(t)

	err := runOIDCAWS(cmd, nil)
	assert.ErrorIs(t, err, ErrAWSMissingRegion,
		"AWS SSO cannot be discovered without a region")
}

func TestRunAWSLogin_RequiresRegion(t *testing.T) {
	cmd, _ := awsTestCmd(t)
	var buf bytes.Buffer
	err := runAWSLogin(cmd, &buf, "", "", false, false, "", "", "", 0, "", false, false, "", "", oidc.Callback{})
	assert.ErrorIs(t, err, ErrAWSMissingRegion)
}

// TestRunAWSLogin_StateMismatch proves that a callback delivering a code
// under a state the login never generated is rejected with aws.Login's
// typed ErrStateMismatch sentinel, reachable via errors.Is all the way
// through runAWSLogin's propagation -- not re-wrapped or swallowed into a
// second, cmd-level sentinel for the same concept.
func TestRunAWSLogin_StateMismatch(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())

	callback := oidc.Callback{Host: "127.0.0.1", Port: port}

	cmd, _ := awsTestCmd(t)
	done := make(chan error, 1)
	var buf bytes.Buffer
	go func() {
		done <- runAWSLogin(cmd, &buf, "us-east-1", "default", false, true /* noBrowser */, "none", "", "", 0, "", false, false, "", "", callback)
	}()

	// Poll until the callback server is accepting connections, then deliver
	// a code under a state runAWSLogin never generated.
	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/oauth/callback?code=test-code&state=mismatched-state"
	require.Eventually(t, func() bool {
		resp, getErr := http.Get(url)
		if getErr != nil {
			return false
		}
		defer resp.Body.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond, "callback server never accepted a connection")

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, aws.ErrStateMismatch)
	case <-time.After(5 * time.Second):
		t.Fatal("runAWSLogin did not return after the mismatched callback")
	}
}

// --- handleAWSOutput dispatch ---

func TestHandleAWSOutput_RejectsUnknownMode(t *testing.T) {
	err := handleAWSOutput("carrier-pigeon", nil, "default", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output mode: carrier-pigeon")
}

func TestHandleAWSOutput_ExecRequiresCommand(t *testing.T) {
	err := handleAWSOutput("exec", nil, "default", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exec output mode requires a command")
}

// --- AWS auto-refresh loop ---

// awsRefreshServer is an AWS token endpoint that rotates the refresh token
// on every call and records the refresh token each call presented.
type awsRefreshServer struct {
	*httptest.Server

	mu        sync.Mutex
	presented []string
}

func newAWSRefreshServer(t *testing.T) *awsRefreshServer {
	t.Helper()

	server := &awsRefreshServer{}
	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		server.mu.Lock()
		server.presented = append(server.presented, r.PostForm.Get("refresh_token"))
		call := len(server.presented)
		server.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(aws.RawTokenResponse{
			AccessToken: &aws.AccessTokenCredentials{
				AccessKeyID:     fmt.Sprintf("AKIAROTATED%09d", call),
				SecretAccessKey: "secret",
				SessionToken:    "FwoGZXIvYXdzRotatedSessionToken",
				Expiration:      time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			},
			TokenType:    "DPoP",
			ExpiresIn:    3600,
			RefreshToken: "rotated-" + strconv.Itoa(call),
		})
	}))
	t.Cleanup(server.Close)
	return server
}

func (s *awsRefreshServer) refreshTokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.presented...)
}

// awsRefreshClient returns an AWS client whose token endpoint is tokenURL.
func awsRefreshClient(t *testing.T, tokenURL string) *aws.Client {
	t.Helper()

	dpopKey, err := oidc.GenerateDPoPKey()
	require.NoError(t, err)
	client, err := aws.NewClient(&aws.ClientConfig{Region: "us-east-1", TokenEndpointOverride: tokenURL}, dpopKey)
	require.NoError(t, err)
	return client
}

// awsAutoRefreshUntil runs the AWS refresh loop on a 10ms interval, writing
// output mode output to credentialsFile, until ready reports true for its
// log, then stops it and returns the log.
func awsAutoRefreshUntil(t *testing.T, client *aws.Client, output, credentialsFile, sessionStore string, ready func(log string) bool) string {
	t.Helper()

	log := &lockedBuffer{}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runAWSAutoRefreshWithWriter(client, "seed-refresh", "us-east-1", "default", credentialsFile,
			output, "", sessionStore, "", 10*time.Millisecond, log, stop)
	}()

	reached := assert.Eventually(t, func() bool { return ready(log.String()) }, 5*time.Second, 10*time.Millisecond)
	close(stop)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the AWS refresh loop did not stop after its stop channel closed")
	}
	if !reached {
		t.Fatalf("the refresh loop never got there; log:\n%s", log.String())
	}
	return log.String()
}

// TestRunAWSAutoRefresh_RotatesTheRefreshTokenAndWritesCredentials proves
// each tick presents the refresh token the previous tick received, writes
// the new credentials to the profile, and records a successful status under
// the region's default status name.
func TestRunAWSAutoRefresh_RotatesTheRefreshTokenAndWritesCredentials(t *testing.T) {
	server := newAWSRefreshServer(t)
	dir := t.TempDir()
	credentialsFile := filepath.Join(dir, "credentials")
	sessionStore := filepath.Join(dir, "sessions", "aws.json")

	log := awsAutoRefreshUntil(t, awsRefreshClient(t, server.URL), "aws-credentials", credentialsFile, sessionStore,
		func(log string) bool { return strings.Count(log, "Credentials refreshed.") >= 2 })
	assert.Contains(t, log, "Auto-refresh stopped.")

	presented := server.refreshTokens()
	require.GreaterOrEqual(t, len(presented), 2)
	assert.Equal(t, "seed-refresh", presented[0])
	assert.Equal(t, "rotated-1", presented[1], "the second tick must present the token the first tick received")

	credentials, err := os.ReadFile(credentialsFile)
	require.NoError(t, err)
	assert.Contains(t, string(credentials), "[default]")
	assert.Contains(t, string(credentials), "AKIAROTATED")

	status, err := loadRefreshStatus(sessionStore, "aws-us-east-1")
	require.NoError(t, err)
	assert.Equal(t, "success", status.LastStatus)
	assert.GreaterOrEqual(t, status.RefreshCount, 2)
}

// TestRunAWSAutoRefresh_KeepsGoingAfterAFailedTick proves a refused refresh
// or an unusable output mode is logged and recorded, and the loop retries
// on the next tick instead of ending.
func TestRunAWSAutoRefresh_KeepsGoingAfterAFailedTick(t *testing.T) {
	refused := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(aws.ErrorResponse{Error: "invalid_grant", ErrorDescription: "revoked"})
	}))
	t.Cleanup(refused.Close)

	tests := []struct {
		name      string
		tokenURL  string
		output    string
		logLine   string
		lastError string
	}{
		{
			name:      "refresh refused",
			tokenURL:  refused.URL,
			output:    "aws-credentials",
			logLine:   "Error refreshing:",
			lastError: "refresh failed:",
		},
		{
			name:      "unusable output mode",
			tokenURL:  newAWSRefreshServer(t).URL,
			output:    "carrier-pigeon",
			logLine:   "Error outputting:",
			lastError: "output failed:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			sessionStore := filepath.Join(dir, "aws.json")

			log := awsAutoRefreshUntil(t, awsRefreshClient(t, tt.tokenURL), tt.output, filepath.Join(dir, "credentials"), sessionStore,
				func(log string) bool { return strings.Count(log, tt.logLine) >= 2 })
			assert.NotContains(t, log, "Credentials refreshed.")

			status, err := loadRefreshStatus(sessionStore, "aws-us-east-1")
			require.NoError(t, err)
			assert.Equal(t, "error", status.LastStatus)
			assert.Contains(t, status.LastError, tt.lastError)
		})
	}
}
