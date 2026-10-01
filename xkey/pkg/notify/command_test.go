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

package notify

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCommandNotifier_Valid(t *testing.T) {
	n, err := NewCommandNotifier("echo hello", slog.Default())
	require.NoError(t, err)
	require.NotNil(t, n)
	assert.Equal(t, []string{"echo", "hello"}, n.argv)
}

func TestNewCommandNotifier_EmptyCommand(t *testing.T) {
	n, err := NewCommandNotifier("", slog.Default())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCommand)
	assert.Nil(t, n)
}

func TestNewCommandNotifier_WhitespaceOnly(t *testing.T) {
	n, err := NewCommandNotifier("   \t\n  ", slog.Default())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCommand)
	assert.Nil(t, n)
}

func TestNewCommandNotifier_UnterminatedSingleQuote(t *testing.T) {
	n, err := NewCommandNotifier("echo 'unterminated", slog.Default())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnterminatedQuote)
	assert.Nil(t, n)
}

func TestNewCommandNotifier_UnterminatedDoubleQuote(t *testing.T) {
	n, err := NewCommandNotifier(`echo "unterminated`, slog.Default())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnterminatedQuote)
	assert.Nil(t, n)
}

// TestNewCommandNotifier_RejectsPlaceholders is the regression test for the
// design that replaced argv substitution: a template still using the
// retired %o/%r/%n/%u placeholders must fail loudly at construction rather
// than silently changing what argv the notifier runs.
func TestNewCommandNotifier_RejectsPlaceholders(t *testing.T) {
	tests := []struct {
		name string
		tmpl string
	}{
		{name: "operation", tmpl: "notify-send %o"},
		{name: "rp id", tmpl: "notify-send %r"},
		{name: "rp name", tmpl: "notify-send %n"},
		{name: "user name", tmpl: "notify-send %u"},
		{name: "placeholder inside a quoted argument", tmpl: `sh -c 'notify-send %u'`},
		{name: "placeholder glued to other text", tmpl: "notify-send touch-for-%u"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := NewCommandNotifier(tc.tmpl, slog.Default())
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrTemplatePlaceholder)
			assert.Nil(t, n)
		})
	}
}

func TestNewCommandNotifier_NoPlaceholdersIsAccepted(t *testing.T) {
	// A template that merely mentions the letters o/r/n/u, or the safe
	// environment-variable form, must not be rejected: only the exact
	// two-character %o/%r/%n/%u sequences are placeholders.
	n, err := NewCommandNotifier(`sh -c 'notify-send "Touch required" "$XKEY_RP_ID"'`, slog.Default())
	require.NoError(t, err)
	require.NotNil(t, n)
}

func TestSplitCommandTemplate(t *testing.T) {
	tests := []struct {
		name    string
		tmpl    string
		want    []string
		wantErr error
	}{
		{
			name: "simple words",
			tmpl: "notify-send xKey hello",
			want: []string{"notify-send", "xKey", "hello"},
		},
		{
			name: "extra whitespace collapses",
			tmpl: "  echo   hello  world  ",
			want: []string{"echo", "hello", "world"},
		},
		{
			name: "single quotes preserve literal content including metacharacters",
			tmpl: `sh -c 'echo $(id); rm -rf /'`,
			want: []string{"sh", "-c", "echo $(id); rm -rf /"},
		},
		{
			name: "double quotes preserve spaces",
			tmpl: `zenity --text="hello world"`,
			want: []string{`zenity`, `--text=hello world`},
		},
		{
			name: "double quotes allow escaped quote and backslash",
			tmpl: `echo "say \"hi\" and \\ literally"`,
			want: []string{"echo", `say "hi" and \ literally`},
		},
		{
			name: "backslash escapes a space outside quotes",
			tmpl: `echo hello\ world`,
			want: []string{"echo", "hello world"},
		},
		{
			name:    "unterminated single quote",
			tmpl:    "echo 'oops",
			wantErr: ErrUnterminatedQuote,
		},
		{
			name:    "unterminated double quote",
			tmpl:    `echo "oops`,
			wantErr: ErrUnterminatedQuote,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := splitCommandTemplate(tc.tmpl)
			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestCommandNotifier_NotifyTouchRequired is the core regression test for
// #1273: argv is run exactly as the operator configured it, unmodified,
// and hostile RPName/UserName values reach the command only through the
// environment, verbatim, never spliced into argv or re-parsed as shell
// syntax.
func TestCommandNotifier_NotifyTouchRequired(t *testing.T) {
	tmpDir := t.TempDir()
	script := writeArgvDumpScript(t, tmpDir)
	argOut := filepath.Join(tmpDir, "argv.out")
	envOut := filepath.Join(tmpDir, "env.out")

	cmd := strings.Join([]string{script, argOut, envOut, "fixed-arg"}, " ")
	n, err := NewCommandNotifier(cmd, slog.Default())
	require.NoError(t, err)
	require.Equal(t, []string{script, argOut, envOut, "fixed-arg"}, n.argv)

	hostile := `alice'; rm -rf / #$(id)` + "`id`" + `"--app-name=x`
	req := &TouchRequest{
		Operation: "register",
		RPID:      "example.com",
		RPName:    "Example Corp",
		UserName:  hostile,
	}

	err = n.NotifyTouchRequired(req)
	require.NoError(t, err)

	// The command runs in NotifyTouchRequired's own goroutine (see its doc
	// comment) and dump-argv.sh writes argOut before it starts the
	// env|grep|sort pipeline that produces envOut -- two separate writes,
	// separated by a fork/exec each test has no way to wait on directly.
	// Waiting on argOut alone and then reading envOut once, unconditionally,
	// was a race (go-xkms xkey#notify-flake): on a loaded runner argOut can
	// turn up non-empty well before the script's second pipeline has created
	// envOut at all, so the single os.ReadFile(envOut) below hit ENOENT and
	// failed the test even though the script went on to write it moments
	// later. Both files are now awaited the same way.
	argData := waitForNonEmptyFile(t, argOut, 5*time.Second)

	// argv is exactly the operator's split template: request data never
	// reaches it.
	args := splitNullTerminated(argData)
	require.Equal(t, []string{"fixed-arg"}, args)

	envData := waitForNonEmptyFile(t, envOut, 5*time.Second)
	envStr := string(envData)
	assert.Contains(t, envStr, "XKEY_OPERATION=register")
	assert.Contains(t, envStr, "XKEY_RP_ID=example.com")
	assert.Contains(t, envStr, "XKEY_RP_NAME=Example Corp")
	assert.Contains(t, envStr, "XKEY_USER_NAME="+hostile)
}

func TestCommandNotifier_NotifyTouchRequired_InvalidCommand(t *testing.T) {
	// The command is invalid but NotifyTouchRequired should not block or
	// return an error since execution is asynchronous. The error is logged.
	n, err := NewCommandNotifier("/nonexistent/binary", slog.Default())
	require.NoError(t, err)

	req := &TouchRequest{
		Operation: "register",
		RPID:      "example.com",
	}

	err = n.NotifyTouchRequired(req)
	require.NoError(t, err)
}

func TestCommandNotifier_CloseIdempotent(t *testing.T) {
	n, err := NewCommandNotifier("echo test", slog.Default())
	require.NoError(t, err)

	require.NoError(t, n.Close())
	assert.True(t, n.closed.Load())

	require.NoError(t, n.Close())
}

func TestCommandNotifier_NotifyAfterClose(t *testing.T) {
	n, err := NewCommandNotifier("echo test", slog.Default())
	require.NoError(t, err)

	require.NoError(t, n.Close())

	req := &TouchRequest{
		Operation: "register",
		RPID:      "example.com",
	}
	err = n.NotifyTouchRequired(req)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotifierClosed)
}

// writeArgvDumpScript writes a POSIX shell script to dir that, given an
// argv-dump path and an env-dump path as its first two arguments, writes
// every remaining argument NUL-terminated to the first path and every
// XKEY_-prefixed environment variable to the second. It is the test's exec
// seam: a real, separately-compiled program that reports exactly what argv
// and environment it received, so a test can prove request data reaches it
// only through the environment.
func writeArgvDumpScript(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, "dump-argv.sh")
	script := "#!/bin/sh\n" +
		"argout=\"$1\"\n" +
		"envout=\"$2\"\n" +
		"shift 2\n" +
		": > \"$argout\"\n" +
		"for a in \"$@\"; do printf '%s\\0' \"$a\" >> \"$argout\"; done\n" +
		"env | grep '^XKEY_' | sort > \"$envout\"\n"

	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path
}

// waitForNonEmptyFile polls path until it exists and is non-empty, or fails
// the test once deadline elapses. It is the synchronization seam for
// asserting on output written by a process NotifyTouchRequired launched in
// its own goroutine: the caller has no handle to wait on directly, only the
// file the process eventually produces.
func waitForNonEmptyFile(t *testing.T, path string, timeout time.Duration) []byte {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var data []byte
	var err error
	for {
		data, err = os.ReadFile(path)
		if err == nil && len(data) > 0 {
			return data
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		require.NoError(t, err, "%s should exist within %s", path, timeout)
	}
	require.NotEmpty(t, data, "%s should be non-empty within %s", path, timeout)
	return data
}

func splitNullTerminated(data []byte) []string {
	parts := bytes.Split(data, []byte{0})
	var out []string
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		out = append(out, string(p))
	}
	return out
}

func TestSanitizeTouchRequest_StripsControlCharactersAndBoundsLength(t *testing.T) {
	long := strings.Repeat("a", maxDisplayFieldLen+50)

	req := &TouchRequest{
		Operation: "register",
		RPID:      "example.com",
		RPName:    "Evil\x00Corp\nLine2",
		UserName:  long,
	}

	got := SanitizeTouchRequest(req)
	assert.Equal(t, "register", got.Operation)
	assert.Equal(t, "example.com", got.RPID)
	assert.Equal(t, "EvilCorpLine2", got.RPName)
	assert.True(t, len([]rune(got.UserName)) <= maxDisplayFieldLen+1)
	assert.True(t, strings.HasSuffix(got.UserName, "…"))
}

func TestSanitizeTouchRequest_LeavesOrdinaryValuesUnchanged(t *testing.T) {
	req := &TouchRequest{
		Operation: "authenticate",
		RPID:      "example.com",
		RPName:    "Example Corp",
		UserName:  "alice@example.com",
	}
	got := SanitizeTouchRequest(req)
	assert.Equal(t, req, got)
}

func TestTouchRequestEnv(t *testing.T) {
	req := &TouchRequest{
		Operation: "register",
		RPID:      "example.com",
		RPName:    "Example Corp",
		UserName:  "alice",
	}
	env := TouchRequestEnv(req)
	assert.Equal(t, []string{
		"XKEY_OPERATION=register",
		"XKEY_RP_ID=example.com",
		"XKEY_RP_NAME=Example Corp",
		"XKEY_USER_NAME=alice",
	}, env)
}

func TestSplitCommandTemplate_ErrorIsWrapped(t *testing.T) {
	_, err := splitCommandTemplate("echo 'unterminated")
	var sentinelCause *SentinelCauseError
	require.True(t, errors.As(err, &sentinelCause))
	assert.Equal(t, ErrUnterminatedQuote, sentinelCause.Sentinel)
}
