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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
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

// TestStoreAWSSession_CreatesParentDirWithPrivateFile complements the
// existing round-trip test by pinning the two properties that matter for
// safety: the parent directory is created on demand, and the file holding
// the refresh token is owner-only.
func TestStoreAWSSession_CreatesParentDirWithPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "aws-session.json")

	require.NoError(t, storeAWSSession(path, AWSStoredSession{
		Region: "us-east-1", RefreshToken: "refresh-token-value",
	}))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
		"a stored refresh token must not be readable by other users")

	dirInfo, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm())

	got, err := loadAWSSession(path)
	require.NoError(t, err)
	assert.Equal(t, "refresh-token-value", got.RefreshToken)
}

func TestStoreAWSSession_ExpandsTilde(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	require.NoError(t, storeAWSSession("~/aws/session.json", AWSStoredSession{Region: "eu-west-1"}))
	assert.FileExists(t, filepath.Join(home, "aws", "session.json"))

	got, err := loadAWSSession("~/aws/session.json")
	require.NoError(t, err)
	assert.Equal(t, "eu-west-1", got.Region)
}

func TestLoadAWSSession_MissingAndCorrupt(t *testing.T) {
	dir := t.TempDir()

	_, err := loadAWSSession(filepath.Join(dir, "absent.json"))
	assert.ErrorIs(t, err, os.ErrNotExist)

	corrupt := filepath.Join(dir, "corrupt.json")
	require.NoError(t, os.WriteFile(corrupt, []byte("{not json"), 0600))
	_, err = loadAWSSession(corrupt)
	assert.Error(t, err)
}

func TestStoreAWSSession_ReportsUnwritablePath(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	err := storeAWSSession(filepath.Join(blocker, "aws-session.json"), AWSStoredSession{})
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
	var buf bytes.Buffer
	err := runAWSLogin(&buf, "", "", false, false, "", "", "", 0, "", false, "", "", oidc.Callback{})
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

	done := make(chan error, 1)
	var buf bytes.Buffer
	go func() {
		done <- runAWSLogin(&buf, "us-east-1", "default", false, true /* noBrowser */, "none", "", "", 0, "", false, "", "", callback)
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
