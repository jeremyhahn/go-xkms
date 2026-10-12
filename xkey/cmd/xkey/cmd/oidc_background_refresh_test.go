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
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// These tests cover the refusals that happen before a background refresh
// worker is spawned. Each one must leave no worker behind, so none of them
// reaches the spawn.

// writeOwnPID records the test process as the running worker for pidFile.
func writeOwnPID(t *testing.T, pidFile string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(pidFile), 0700))
	require.NoError(t, os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600))
}

// writeBlocker creates a regular file at path, so that nothing can be
// created beneath it.
func writeBlocker(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte("a file, not a directory"), 0600))
}

func startOIDCRefresh(tokenStore, logFile string) (string, error) {
	var out bytes.Buffer
	err := startBackgroundRefresh(&out, "corp", "https://idp.example.com/token", "client",
		tokenStore, "", logFile, "", 60, "")
	return out.String(), err
}

func TestStartBackgroundRefresh_RefusesWhenAlreadyRunning(t *testing.T) {
	dir := t.TempDir()
	tokenStore := filepath.Join(dir, "tokens")
	writeOwnPID(t, getPIDFile(tokenStore, "corp"))

	out, err := startOIDCRefresh(tokenStore, filepath.Join(dir, "logs", "refresh.log"))
	require.Error(t, err)
	assert.Contains(t, err.Error(),
		"background refresh for 'corp' is already running (PID "+strconv.Itoa(os.Getpid())+")")
	assert.Empty(t, out)
	assert.NoFileExists(t, filepath.Join(dir, "logs", "refresh.log"),
		"a refused start must not open the log file")
}

func TestStartBackgroundRefresh_ReportsUnusableDirectories(t *testing.T) {
	t.Run("log directory", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "blocker")
		writeBlocker(t, blocker)

		_, err := startOIDCRefresh(filepath.Join(dir, "tokens"), filepath.Join(blocker, "refresh.log"))
		assert.ErrorContains(t, err, "failed to create log directory")
	})

	t.Run("PID directory", func(t *testing.T) {
		dir := t.TempDir()
		tokenStore := filepath.Join(dir, "tokens")
		writeBlocker(t, getPIDDir(tokenStore))

		_, err := startOIDCRefresh(tokenStore, filepath.Join(dir, "refresh.log"))
		assert.ErrorContains(t, err, "failed to create PID directory")
	})

	t.Run("log file", func(t *testing.T) {
		dir := t.TempDir()
		logFile := filepath.Join(dir, "refresh.log")
		require.NoError(t, os.Mkdir(logFile, 0700))

		_, err := startOIDCRefresh(filepath.Join(dir, "tokens"), logFile)
		assert.ErrorContains(t, err, "failed to open log file")
	})
}

func startAWSRefresh(t *testing.T, sessionStore, logFile, providerName string) (string, error) {
	t.Helper()
	parent, _ := awsTestCmd(t)
	parent.Flags().String("barrier-password-file", "", "")
	var out bytes.Buffer
	err := startAWSBackgroundRefresh(parent, &out, "us-east-1", "default", "", "credentials", "",
		sessionStore, sessionStore, logFile, 60, providerName)
	return out.String(), err
}

func TestStartAWSBackgroundRefresh_RefusesWhenAlreadyRunning(t *testing.T) {
	pid := strconv.Itoa(os.Getpid())
	cases := []struct {
		providerName string
		want         string
	}{
		{"", "background refresh for AWS region 'us-east-1' is already running (PID " + pid + ")"},
		{"work", "background refresh for 'work' is already running (PID " + pid + ")"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			dir := t.TempDir()
			sessionStore := filepath.Join(dir, "aws-session")
			writeOwnPID(t, getAWSPIDFile(sessionStore, "us-east-1", tc.providerName))

			out, err := startAWSRefresh(t, sessionStore, filepath.Join(dir, "refresh.log"), tc.providerName)
			assert.ErrorContains(t, err, tc.want)
			assert.Empty(t, out)
		})
	}
}

func TestStartAWSBackgroundRefresh_RequiresAStoredSession(t *testing.T) {
	dir := t.TempDir()

	_, err := startAWSRefresh(t, filepath.Join(dir, "absent"), filepath.Join(dir, "refresh.log"), "")
	require.ErrorIs(t, err, xkms.ErrStorageNotFound)
	assert.ErrorContains(t, err, "failed to load session")
	assert.Contains(t, err.Error(), "run login without --background first")
	assert.NoFileExists(t, filepath.Join(dir, "refresh.log"))
}

func TestStartAWSBackgroundRefresh_RequiresARefreshToken(t *testing.T) {
	dir := t.TempDir()
	sessionStore := filepath.Join(dir, "aws-session")
	require.NoError(t, storeAWSSession(&cobra.Command{}, sessionStore, AWSStoredSession{Region: "us-east-1"}))

	_, err := startAWSRefresh(t, sessionStore, filepath.Join(dir, "refresh.log"), "")
	assert.ErrorContains(t, err, "no refresh token in session store")
	assert.NoFileExists(t, filepath.Join(dir, "refresh.log"))
}

func TestStartAWSBackgroundRefresh_ReportsUnusablePaths(t *testing.T) {
	t.Run("log directory", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "blocker")
		writeBlocker(t, blocker)

		_, err := startAWSRefresh(t, filepath.Join(dir, "aws-session"), filepath.Join(blocker, "refresh.log"), "")
		assert.ErrorContains(t, err, "failed to create log directory")
	})

	t.Run("PID directory", func(t *testing.T) {
		dir := t.TempDir()
		sessionStore := filepath.Join(dir, "aws-session")
		writeBlocker(t, filepath.Dir(getAWSPIDFile(sessionStore, "us-east-1", "")))

		_, err := startAWSRefresh(t, sessionStore, filepath.Join(dir, "refresh.log"), "")
		assert.ErrorContains(t, err, "failed to create PID directory")
	})

	t.Run("log file", func(t *testing.T) {
		dir := t.TempDir()
		sessionStore := filepath.Join(dir, "aws-session")
		require.NoError(t, storeAWSSession(&cobra.Command{}, sessionStore, AWSStoredSession{
			Region: "us-east-1", RefreshToken: "refresh-token-value",
		}))
		logFile := filepath.Join(dir, "refresh.log")
		require.NoError(t, os.Mkdir(logFile, 0700))

		_, err := startAWSRefresh(t, sessionStore, logFile, "")
		assert.ErrorContains(t, err, "failed to open log file")
	})
}
