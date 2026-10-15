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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/oidc"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withStandInWorker records the arguments a background login spawns its
// worker with, and starts the test binary with no tests selected in its
// place: it starts, prints PASS and exits.
func withStandInWorker(t *testing.T) *[]string {
	t.Helper()
	var got []string
	previous := backgroundWorkerCommand
	backgroundWorkerCommand = func(args ...string) (*exec.Cmd, error) {
		got = append([]string(nil), args...)
		return exec.Command(os.Args[0], "-test.run=^$"), nil
	}
	t.Cleanup(func() { backgroundWorkerCommand = previous })
	return &got
}

func withWorkerCommand(t *testing.T, fn func(args ...string) (*exec.Cmd, error)) {
	t.Helper()
	previous := backgroundWorkerCommand
	backgroundWorkerCommand = fn
	t.Cleanup(func() { backgroundWorkerCommand = previous })
}

// waitForWorkerExit waits for the stand-in to exit and for the spawner to
// clean up after it.
func waitForWorkerExit(t *testing.T, pidFile, logFile string) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, err := os.Stat(pidFile)
		return errors.Is(err, os.ErrNotExist)
	}, 30*time.Second, 10*time.Millisecond, "the PID file is removed when the worker exits")

	log, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(log), "PASS", "the worker's output goes to the log file")
}

// parseWorkerArgs resolves the worker's argv against the real command tree
// and parses its flags into a copy of that command's flag set, so the
// shared command's flag values are left alone. It returns the command the
// argv names and a command carrying the parsed flags.
func parseWorkerArgs(t *testing.T, args []string) (*cobra.Command, *cobra.Command) {
	t.Helper()
	// Resolve the subcommands by name: RootCmd.Find, like InheritedFlags
	// below, merges persistent flags into the shared commands' flag sets,
	// so a later flag reset on one of them would reset the parents' too.
	target, rest := RootCmd, args
	for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		next := subcommand(target, rest[0])
		require.NotNil(t, next, "%q has no subcommand %q", target.CommandPath(), rest[0])
		target, rest = next, rest[1:]
	}

	worker := &cobra.Command{Use: target.Name()}
	fs := worker.Flags()
	clone := func(f *pflag.Flag) {
		if fs.Lookup(f.Name) != nil {
			return
		}
		switch f.Value.Type() {
		case "bool":
			fs.Bool(f.Name, false, "")
		case "int":
			fs.Int(f.Name, 0, "")
		default:
			fs.String(f.Name, "", "")
		}
	}
	target.Flags().VisitAll(clone)
	for c := target.Parent(); c != nil; c = c.Parent() {
		c.PersistentFlags().VisitAll(clone)
	}

	require.NoError(t, worker.ParseFlags(rest), "every flag the worker is given exists on %q", target.CommandPath())
	require.Empty(t, fs.Args(), "the worker is given flags only")
	return target, worker
}

func subcommand(parent *cobra.Command, name string) *cobra.Command {
	for _, child := range parent.Commands() {
		if child.Name() == name {
			return child
		}
	}
	return nil
}

func flagString(t *testing.T, cmd *cobra.Command, name string) string {
	t.Helper()
	value, err := cmd.Flags().GetString(name)
	require.NoError(t, err)
	return value
}

// TestStartBackgroundRefresh_SpawnsTheLoginWorker pins the handoff a
// --background login makes: the worker is this executable re-run as
// `oidc login --background-worker`, with every setting the refresh loop
// needs, and the spawner cleans up its PID file when the worker exits.
func TestStartBackgroundRefresh_SpawnsTheLoginWorker(t *testing.T) {
	got := withStandInWorker(t)
	dir := t.TempDir()
	tokenStore := filepath.Join(dir, "tokens")
	logFile := filepath.Join(dir, "logs", "refresh.log")
	jsonEncoding := oidc.TokenEncoding("json")

	var out bytes.Buffer
	err := startBackgroundRefresh(&out, "corp", "https://idp.example.com/token", "client-1",
		tokenStore, "notify-send refreshed", logFile, "/etc/xkey/barrier.pw", 90, jsonEncoding)
	require.NoError(t, err)

	assert.Contains(t, out.String(), "Background refresh started for 'corp'")
	assert.Contains(t, out.String(), "Log file: "+logFile)
	assert.Contains(t, out.String(), "Use 'xkey oidc stop corp' to stop")
	waitForWorkerExit(t, getPIDFile(tokenStore, "corp"), logFile)

	target, worker := parseWorkerArgs(t, *got)
	assert.Same(t, oidcLoginCmd, target)
	isWorker, err := worker.Flags().GetBool("background-worker")
	require.NoError(t, err)
	assert.True(t, isWorker)
	interval, err := worker.Flags().GetInt("auto-refresh")
	require.NoError(t, err)
	assert.Equal(t, 90, interval)
	for flag, want := range map[string]string{
		"token-endpoint":        "https://idp.example.com/token",
		"client-id":             "client-1",
		"token-store":           tokenStore,
		"log-file":              logFile,
		"provider-name":         "corp",
		"exec":                  "notify-send refreshed",
		"token-encoding":        string(jsonEncoding),
		"barrier-password-file": "/etc/xkey/barrier.pw",
	} {
		assert.Equal(t, want, flagString(t, worker, flag), "--%s", flag)
	}
	assert.NotContains(t, *got, "--barrier-password", "a barrier password value never goes on argv")
}

// TestRunBackgroundWorker_RunsWhatTheLoginHandedIt runs the worker on the
// exact argv the spawner built: it opens the token store it was pointed
// at, logs its settings and runs the refresh loop, which stops on a token
// that cannot be refreshed.
func TestRunBackgroundWorker_RunsWhatTheLoginHandedIt(t *testing.T) {
	got := withStandInWorker(t)
	seedCmd, _, tokenStore := oidcTestCmd(t)
	store, err := openOIDCTokenStore(seedCmd, tokenStore)
	require.NoError(t, err)
	seed := mustOIDCStoredToken(t, "", "https://idp.example.com", "client-1",
		"access", "", "", time.Now().Add(time.Hour), nil)
	defer seed.Destroy()
	require.NoError(t, store.Save(seed))

	spawnLog := filepath.Join(t.TempDir(), "spawn.log")
	require.NoError(t, startBackgroundRefresh(&bytes.Buffer{}, "corp", "https://idp.example.com/token", "client-1",
		tokenStore, "", spawnLog, "", 1, oidc.TokenEncodingForm))
	waitForWorkerExit(t, getPIDFile(tokenStore, "corp"), spawnLog)

	_, worker := parseWorkerArgs(t, *got)
	workerLog := filepath.Join(t.TempDir(), "worker.log")
	require.NoError(t, worker.Flags().Set("log-file", workerLog))

	err = runBackgroundWorker(worker, nil)
	require.ErrorIs(t, err, ErrOIDCInvalidRefreshToken)

	log, readErr := os.ReadFile(workerLog)
	require.NoError(t, readErr)
	assert.Contains(t, string(log), "Background refresh started for 'corp'")
	assert.Contains(t, string(log), "Token endpoint: https://idp.example.com/token")
	assert.Contains(t, string(log), "Refresh interval: 1 seconds")
	assert.Contains(t, string(log), "No refresh token available. Stopping auto-refresh.")

	status, err := loadRefreshStatus(tokenStore, "corp")
	require.NoError(t, err)
	assert.Equal(t, "no refresh token available", status.LastError)
}

func TestRunBackgroundWorker_Refusals(t *testing.T) {
	t.Run("log file", func(t *testing.T) {
		cmd, _, _ := oidcTestCmd(t)
		cmd.Flags().String("provider-name", "", "")
		logFile := t.TempDir()
		require.NoError(t, cmd.Flags().Set("log-file", logFile))

		assert.ErrorContains(t, runBackgroundWorker(cmd, nil), "failed to open log file")
	})

	t.Run("token store", func(t *testing.T) {
		cmd, _, _ := oidcTestCmd(t)
		cmd.Flags().String("provider-name", "", "")
		blocker := filepath.Join(t.TempDir(), "blocker")
		writeBlocker(t, blocker)
		require.NoError(t, cmd.Flags().Set("token-store", filepath.Join(blocker, "tokens")))
		require.NoError(t, cmd.Flags().Set("log-file", filepath.Join(t.TempDir(), "worker.log")))

		require.ErrorIs(t, runBackgroundWorker(cmd, nil), ErrOIDCTokenStoreFailed)
	})
}

func TestStartBackgroundRefresh_WorkerDoesNotStart(t *testing.T) {
	t.Run("no executable", func(t *testing.T) {
		withWorkerCommand(t, func(...string) (*exec.Cmd, error) { return nil, os.ErrNotExist })
		dir := t.TempDir()
		tokenStore := filepath.Join(dir, "tokens")

		_, err := startOIDCRefresh(tokenStore, filepath.Join(dir, "refresh.log"))
		require.ErrorIs(t, err, os.ErrNotExist)
		assert.ErrorContains(t, err, "failed to get executable path")
		assert.NoFileExists(t, getPIDFile(tokenStore, "corp"))
	})

	t.Run("start fails", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing-xkey")
		withWorkerCommand(t, func(args ...string) (*exec.Cmd, error) { return exec.Command(missing, args...), nil })
		dir := t.TempDir()
		tokenStore := filepath.Join(dir, "tokens")

		out, err := startOIDCRefresh(tokenStore, filepath.Join(dir, "refresh.log"))
		assert.ErrorContains(t, err, "failed to start background process")
		assert.Empty(t, out)
		assert.NoFileExists(t, getPIDFile(tokenStore, "corp"))
	})
}

// TestStartAWSBackgroundRefresh_SpawnsTheAWSWorker pins the AWS handoff:
// the worker is re-run as `oidc aws --background-worker` with the region,
// profile, output and session store the parent used.
func TestStartAWSBackgroundRefresh_SpawnsTheAWSWorker(t *testing.T) {
	tests := []struct {
		providerName string
		started      string
		stop         string
	}{
		{providerName: "work", started: "Background refresh started for 'work'", stop: "xkey oidc stop work"},
		{providerName: "", started: "Background refresh started for AWS region 'us-east-1'", stop: "xkey oidc stop aws-us-east-1"},
	}
	for _, tt := range tests {
		t.Run(tt.stop, func(t *testing.T) {
			got := withStandInWorker(t)
			dir := t.TempDir()
			sessionStore := filepath.Join(dir, "aws-session")
			require.NoError(t, storeAWSSession(&cobra.Command{}, sessionStore, AWSStoredSession{
				Region: "us-east-1", RefreshToken: "refresh-token-value",
			}))
			logFile := filepath.Join(dir, "refresh.log")

			out, err := startAWSRefresh(t, sessionStore, logFile, tt.providerName)
			require.NoError(t, err)
			assert.Contains(t, out, tt.started)
			assert.Contains(t, out, tt.stop)
			waitForWorkerExit(t, getAWSPIDFile(sessionStore, "us-east-1", tt.providerName), logFile)

			target, worker := parseWorkerArgs(t, *got)
			assert.Same(t, oidcAWSCmd, target)
			interval, err := worker.Flags().GetInt("auto-refresh")
			require.NoError(t, err)
			assert.Equal(t, 60, interval)
			assert.Equal(t, "us-east-1", flagString(t, worker, "region"))
			assert.Equal(t, "default", flagString(t, worker, "profile"))
			assert.Equal(t, "credentials", flagString(t, worker, "output"))
			assert.Equal(t, sessionStore, flagString(t, worker, "session-store"))
			assert.Equal(t, logFile, flagString(t, worker, "log-file"))
			assert.Equal(t, tt.providerName, flagString(t, worker, "provider-name"))
		})
	}
}
