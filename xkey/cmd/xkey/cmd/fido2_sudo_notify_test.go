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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hostileNotifyValues are WebAuthn caller-controlled values (rp.name,
// user.name) crafted to break naive shell-string assembly.
var hostileNotifyValues = []string{
	`alice'; rm -rf / #`,
	`alice"; rm -rf / #`,
	"$(id)",
	"`id`",
	"--help",
	"-rf",
}

func textArgOf(t *testing.T, argv []string) string {
	t.Helper()
	for _, a := range argv {
		if strings.HasPrefix(a, "--text=") {
			return a
		}
	}
	t.Fatal("argv has no --text= element")
	return ""
}

func TestBuildSudoDialogArgv(t *testing.T) {
	req := &notify.TouchRequest{Operation: "register", RPID: "example.com", UserName: "alice"}
	argv := buildSudoDialogArgv("alice", req, 30*time.Second)

	want := []string{
		"runuser", "-u", "alice", "--",
		"env", "DISPLAY=:0",
		"zenity", "--question", "--no-markup",
		"--icon-name=security-high",
		"--title=xKey: Touch Required",
		"--text=register request from example.com\n\nUser: alice\n\nClick Approve to authorize this action.",
		"--ok-label=✓ Approve",
		"--cancel-label=✗ Deny",
		"--width=350",
		"--timeout=30",
	}
	assert.Equal(t, want, argv)
}

// TestBuildSudoDialogArgv_HostileValuesStayInOneElement is the regression
// test for #1273's sudo dialog path: a hostile RPID/UserName must land
// inside the single "--text=" argv element, verbatim, and every other argv
// element must remain exactly the fixed flag/label text -- never split,
// widened, or replaced by caller-controlled data.
func TestBuildSudoDialogArgv_HostileValuesStayInOneElement(t *testing.T) {
	for _, hostile := range hostileNotifyValues {
		t.Run(hostile, func(t *testing.T) {
			req := &notify.TouchRequest{Operation: "register", RPID: "example.com", UserName: hostile}
			argv := buildSudoDialogArgv("alice", req, 30*time.Second)

			require.Len(t, argv, 16)
			text := textArgOf(t, argv)
			assert.Contains(t, text, hostile)

			for _, a := range argv {
				if a == text {
					continue
				}
				assert.NotContains(t, a, hostile)
			}

			// The fixed argv skeleton around the hostile value is untouched.
			assert.Equal(t, []string{"runuser", "-u", "alice", "--", "env", "DISPLAY=:0", "zenity"}, argv[:7])
			assert.Equal(t, []string{"--question", "--no-markup", "--icon-name=security-high", "--title=xKey: Touch Required"}, argv[7:11])
		})
	}
}

func TestBuildSudoTouchArgv(t *testing.T) {
	argv := buildSudoTouchArgv("alice", "/usr/bin/xkey", "/run/user/1000/xkey.sock")
	assert.Equal(t, []string{"runuser", "-u", "alice", "--", "/usr/bin/xkey", "touch", "--socket", "/run/user/1000/xkey.sock"}, argv)
}

func TestBuildSudoPassiveArgv(t *testing.T) {
	req := &notify.TouchRequest{Operation: "authenticate", RPID: "example.com", UserName: "alice"}
	argv := buildSudoPassiveArgv("alice", "1000", req)

	want := []string{
		"runuser", "-u", "alice", "--",
		"env", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
		"notify-send", "-u", "critical", "--",
		"xKey: Touch Required",
		"authenticate request from example.com\nUser: alice\nRun: xkey touch",
	}
	assert.Equal(t, want, argv)
}

// TestBuildSudoPassiveArgv_HostileValuesStayInOneElement mirrors the dialog
// test above for the passive notify-send path, and confirms the body
// element -- the only one built from caller data -- always sits after the
// "--" end-of-options marker so notify-send cannot parse a hostile value
// that starts with '-' as a flag.
func TestBuildSudoPassiveArgv_HostileValuesStayInOneElement(t *testing.T) {
	for _, hostile := range hostileNotifyValues {
		t.Run(hostile, func(t *testing.T) {
			req := &notify.TouchRequest{Operation: "authenticate", RPID: "example.com", UserName: hostile}
			argv := buildSudoPassiveArgv("alice", "1000", req)

			require.Len(t, argv, 12)
			body := argv[len(argv)-1]
			assert.Contains(t, body, hostile)
			assert.Equal(t, "--", argv[len(argv)-3])

			for i, a := range argv {
				if i == len(argv)-1 {
					continue
				}
				assert.NotContains(t, a, hostile)
			}
		})
	}
}

// writeFakeRunuserScript writes a stand-in for runuser(1) into dir and
// returns dir so it can be prepended to PATH. The script never actually
// switches users (the test does not run as root); it records every argv it
// receives -- one line per element, calls separated by a marker line -- to
// $DUMP_FILE, then exits 0, unless its own argv contains "zenity", in which
// case it exits with $DIALOG_EXIT (default 0) to simulate the dialog's
// approve/deny/timeout result.
func writeFakeRunuserScript(t *testing.T, dir string) string {
	t.Helper()

	script := "#!/bin/sh\n" +
		"{\n" +
		"  for a in \"$@\"; do printf '%s\\n' \"$a\"; done\n" +
		"  printf -- '---CALL---\\n'\n" +
		"} >> \"$DUMP_FILE\"\n" +
		"case \"$*\" in\n" +
		"  *zenity*) exit \"${DIALOG_EXIT:-0}\" ;;\n" +
		"esac\n" +
		"exit 0\n"

	path := filepath.Join(dir, "runuser")
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return dir
}

// waitForCalls polls dumpFile until it contains at least want recorded
// calls (see writeFakeRunuserScript) and returns each call's argv.
func waitForCalls(t *testing.T, dumpFile string, want int) [][]string {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	var calls [][]string
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(dumpFile)
		if err == nil {
			blocks := strings.Split(string(data), "---CALL---\n")
			calls = nil
			for _, b := range blocks {
				b = strings.TrimSuffix(b, "\n")
				if b == "" {
					continue
				}
				calls = append(calls, strings.Split(b, "\n"))
			}
			if len(calls) >= want {
				return calls
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d fake-runuser calls, got %d", want, len(calls))
	return nil
}

func TestSudoDialogNotifier_ApprovedRunsTouchCommand(t *testing.T) {
	dir := t.TempDir()
	writeFakeRunuserScript(t, dir)
	dumpFile := filepath.Join(dir, "dump.txt")

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DUMP_FILE", dumpFile)
	t.Setenv("DIALOG_EXIT", "0")

	n := newSudoDialogNotifier("alice", "/usr/bin/xkey", "/run/user/1000/xkey.sock", 30*time.Second, slog.Default())
	req := &notify.TouchRequest{Operation: "register", RPID: "example.com", UserName: `bob'; rm -rf / #`}
	require.NoError(t, n.NotifyTouchRequired(req))

	calls := waitForCalls(t, dumpFile, 2)

	// First call: the zenity dialog, run as alice.
	assert.Equal(t, []string{"-u", "alice", "--", "env", "DISPLAY=:0", "zenity"}, calls[0][:6])

	// Second call: the touch approval, run only because the dialog exited 0.
	assert.Equal(t, []string{"-u", "alice", "--", "/usr/bin/xkey", "touch", "--socket", "/run/user/1000/xkey.sock"}, calls[1])
}

func TestSudoDialogNotifier_DeniedDoesNotRunTouchCommand(t *testing.T) {
	dir := t.TempDir()
	writeFakeRunuserScript(t, dir)
	dumpFile := filepath.Join(dir, "dump.txt")

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DUMP_FILE", dumpFile)
	t.Setenv("DIALOG_EXIT", "1") // zenity's --cancel-label / timeout exit code

	n := newSudoDialogNotifier("alice", "/usr/bin/xkey", "/run/user/1000/xkey.sock", 30*time.Second, slog.Default())
	req := &notify.TouchRequest{Operation: "register", RPID: "example.com", UserName: "alice"}
	require.NoError(t, n.NotifyTouchRequired(req))

	calls := waitForCalls(t, dumpFile, 1)

	// Give a would-be second call a moment to show up, then confirm it never
	// does: denial must not run the touch command.
	time.Sleep(150 * time.Millisecond)
	data, err := os.ReadFile(dumpFile)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(data), "---CALL---"))
	assert.Len(t, calls, 1)
}

func TestSudoDialogNotifier_NotifyAfterClose(t *testing.T) {
	n := newSudoDialogNotifier("alice", "/usr/bin/xkey", "/run/user/1000/xkey.sock", 30*time.Second, slog.Default())
	require.NoError(t, n.Close())
	require.NoError(t, n.Close()) // idempotent

	err := n.NotifyTouchRequired(&notify.TouchRequest{Operation: "register", RPID: "example.com"})
	require.Error(t, err)
	assert.ErrorIs(t, err, notify.ErrNotifierClosed)
}

func TestSudoPassiveNotifier_RunsNotifySend(t *testing.T) {
	dir := t.TempDir()
	writeFakeRunuserScript(t, dir)
	dumpFile := filepath.Join(dir, "dump.txt")

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DUMP_FILE", dumpFile)

	n := newSudoPassiveNotifier("alice", "1000", slog.Default())
	req := &notify.TouchRequest{Operation: "authenticate", RPID: "example.com", UserName: `bob"; rm -rf / #`}
	require.NoError(t, n.NotifyTouchRequired(req))

	calls := waitForCalls(t, dumpFile, 1)
	assert.Equal(t, []string{"-u", "alice", "--", "env", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", "notify-send"}, calls[0][:6])
}

func TestSudoPassiveNotifier_NotifyAfterClose(t *testing.T) {
	n := newSudoPassiveNotifier("alice", "1000", slog.Default())
	require.NoError(t, n.Close())
	require.NoError(t, n.Close()) // idempotent

	err := n.NotifyTouchRequired(&notify.TouchRequest{Operation: "authenticate", RPID: "example.com"})
	require.Error(t, err)
	assert.ErrorIs(t, err, notify.ErrNotifierClosed)
}
