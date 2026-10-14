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

package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui"
)

// isolateRun saves and restores every piece of global state run() touches.
func isolateRun(t *testing.T) {
	t.Helper()

	previousArgs := os.Args
	previousGUI := guiRun
	previousCLI := cliExecute
	previousAssets := gui.Assets
	previousFirmware := gui.FirmwareVersion

	t.Cleanup(func() {
		os.Args = previousArgs
		guiRun = previousGUI
		cliExecute = previousCLI
		gui.Assets = previousAssets
		gui.FirmwareVersion = previousFirmware
	})
}

// headless removes the display environment so hasGUIEnvironment() reports
// false on Linux.
func headless(t *testing.T) {
	t.Helper()
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
}

// --- CLI dispatch ---

func TestRun_DispatchesToCLIAndReportsSuccess(t *testing.T) {
	isolateRun(t)
	headless(t)

	var executed bool
	cliExecute = func() error {
		executed = true
		return nil
	}
	guiRun = func() error {
		t.Fatal("the GUI must not start for a CLI invocation")
		return nil
	}

	var stderr bytes.Buffer
	code := run([]string{"xkey", "version"}, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !executed {
		t.Fatal("cobra was never executed")
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestRun_ReportsCLIErrorWithExitCodeOne(t *testing.T) {
	isolateRun(t)
	headless(t)

	cliExecute = func() error { return errors.New("unknown command \"bogus\"") }

	var stderr bytes.Buffer
	code := run([]string{"xkey", "bogus"}, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), `Error: unknown command "bogus"`) {
		t.Fatalf("stderr = %q, want the cobra error", stderr.String())
	}
}

func TestRun_StripsGUIFlagsBeforeCobraSeesThem(t *testing.T) {
	isolateRun(t)
	headless(t)

	var seen []string
	cliExecute = func() error {
		seen = append([]string(nil), os.Args...)
		return nil
	}

	if code := run([]string{"xkey", "--no-gui", "version", "--gui"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	for _, a := range seen {
		if a == "--no-gui" || a == "--gui" {
			t.Fatalf("cobra saw the meta-flag %q in %v", a, seen)
		}
	}
	if len(seen) != 2 || seen[1] != "version" {
		t.Fatalf("os.Args = %v, want [xkey version]", seen)
	}
}

func TestRun_NoGUIForcesCLIEvenWithDisplay(t *testing.T) {
	isolateRun(t)
	t.Setenv("DISPLAY", ":0")

	executed := false
	cliExecute = func() error { executed = true; return nil }
	guiRun = func() error {
		t.Fatal("--no-gui must never start the GUI")
		return nil
	}

	if code := run([]string{"xkey", "--no-gui"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !executed {
		t.Fatal("cobra was never executed")
	}
}

func TestRun_SubcommandForcesCLIEvenWithDisplay(t *testing.T) {
	isolateRun(t)
	t.Setenv("DISPLAY", ":0")

	executed := false
	cliExecute = func() error { executed = true; return nil }
	guiRun = func() error {
		t.Fatal("a positional subcommand must route to the CLI")
		return nil
	}

	if code := run([]string{"xkey", "version"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !executed {
		t.Fatal("cobra was never executed")
	}
}

func TestRun_HelpFlagRoutesToCLI(t *testing.T) {
	isolateRun(t)
	t.Setenv("DISPLAY", ":0")

	executed := false
	cliExecute = func() error { executed = true; return nil }
	guiRun = func() error {
		t.Fatal("--help must print CLI help, not open the GUI")
		return nil
	}

	if code := run([]string{"xkey", "--help"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !executed {
		t.Fatal("cobra was never executed")
	}
}

// --- native messaging rewrite ---

func TestRun_RewritesChromeNativeMessagingInvocation(t *testing.T) {
	isolateRun(t)
	headless(t)

	var seen []string
	cliExecute = func() error {
		seen = append([]string(nil), os.Args...)
		return nil
	}

	if code := run([]string{"xkey", "chrome-extension://abcdefghijklmnop/"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	want := []string{"xkey", "extension", "host"}
	if len(seen) != len(want) {
		t.Fatalf("os.Args = %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("os.Args = %v, want %v", seen, want)
		}
	}
}

func TestRun_RewritesFirefoxNativeMessagingInvocation(t *testing.T) {
	isolateRun(t)
	headless(t)

	var seen []string
	cliExecute = func() error {
		seen = append([]string(nil), os.Args...)
		return nil
	}

	manifest := "/home/u/.mozilla/native-messaging-hosts/" + nativeHostName + ".json"
	if code := run([]string{"xkey", manifest}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if len(seen) != 3 || seen[1] != "extension" || seen[2] != "host" {
		t.Fatalf("os.Args = %v, want [xkey extension host]", seen)
	}
}

// --- GUI dispatch ---

func TestRun_GUIPathPublishesAssetsAndFirmwareVersion(t *testing.T) {
	isolateRun(t)
	headless(t)

	started := false
	guiRun = func() error { started = true; return nil }
	cliExecute = func() error {
		t.Fatal("--gui must not fall through to the CLI")
		return nil
	}
	gui.Assets = nil

	code := run([]string{"xkey", "--gui"}, &bytes.Buffer{})

	if !guiBuildTagPresent {
		if code != 2 {
			t.Fatalf("exit code = %d, want 2 for a non-GUI build", code)
		}
		return
	}

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !started {
		t.Fatal("the GUI was never started")
	}
	if gui.Assets == nil {
		t.Fatal("frontend assets were not published to the GUI package")
	}
	if _, err := fs.Stat(gui.Assets, "."); err != nil {
		t.Fatalf("published assets are not a usable FS: %v", err)
	}
}

func TestRun_GUIStartupFailureIsReported(t *testing.T) {
	isolateRun(t)
	headless(t)

	guiRun = func() error { return errors.New("wails exploded") }
	cliExecute = func() error {
		t.Fatal("--gui must not fall through to the CLI")
		return nil
	}

	var stderr bytes.Buffer
	code := run([]string{"xkey", "--gui"}, &stderr)

	if !guiBuildTagPresent {
		if code != 2 {
			t.Fatalf("exit code = %d, want 2 for a non-GUI build", code)
		}
		if !strings.Contains(stderr.String(), "built without GUI support") {
			t.Fatalf("stderr = %q", stderr.String())
		}
		return
	}

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "GUI error: wails exploded") {
		t.Fatalf("stderr = %q, want the GUI failure", stderr.String())
	}
}

func TestRun_GUILoggingFailureIsReported(t *testing.T) {
	if !guiBuildTagPresent {
		return
	}
	isolateRun(t)
	headless(t)

	guiRun = func() error {
		t.Fatal("the GUI must not start when logging setup fails")
		return nil
	}

	// A log file whose parent is a regular file cannot be opened.
	blocker := t.TempDir() + "/blocker"
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	code := run([]string{"xkey", "--gui", "--log-file", blocker + "/xkey.log"}, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "logging setup error") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRun_DisplayEnvironmentSelectsGUI(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}
	isolateRun(t)
	t.Setenv("DISPLAY", ":0")
	t.Setenv("WAYLAND_DISPLAY", "")

	started := false
	guiRun = func() error { started = true; return nil }
	cliExecute = func() error {
		t.Fatal("a bare invocation under a display must start the GUI")
		return nil
	}

	code := run([]string{"xkey"}, &bytes.Buffer{})

	if !guiBuildTagPresent {
		if code != 2 {
			t.Fatalf("exit code = %d, want 2", code)
		}
		return
	}
	if code != 0 || !started {
		t.Fatalf("code = %d, started = %v; want 0/true", code, started)
	}
}

// --- hasGUIEnvironment ---

func TestHasGUIEnvironment(t *testing.T) {
	if runtime.GOOS != "linux" {
		// darwin/windows always report a GUI; there is nothing to vary.
		if !hasGUIEnvironment() {
			t.Fatal("a GUI is assumed on non-Linux platforms")
		}
		return
	}

	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	if hasGUIEnvironment() {
		t.Fatal("no display variables must mean no GUI environment")
	}

	t.Setenv("DISPLAY", ":0")
	if !hasGUIEnvironment() {
		t.Fatal("DISPLAY must be recognised as an X11 session")
	}

	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	if !hasGUIEnvironment() {
		t.Fatal("WAYLAND_DISPLAY must be recognised as a Wayland session")
	}
}

func TestGUIEnvironmentFor(t *testing.T) {
	tests := []struct {
		name string
		goos string
		env  map[string]string
		want bool
	}{
		{"darwin without display variables", "darwin", nil, true},
		{"windows without display variables", "windows", nil, true},
		{"linux with DISPLAY", "linux", map[string]string{"DISPLAY": ":0"}, true},
		{"linux with WAYLAND_DISPLAY", "linux", map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, true},
		{"linux headless", "linux", nil, false},
		{"unsupported OS ignores display variables", "plan9", map[string]string{"DISPLAY": ":0"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := guiEnvironmentFor(tt.goos, func(key string) string { return tt.env[key] })
			if got != tt.want {
				t.Fatalf("guiEnvironmentFor(%q) = %v, want %v", tt.goos, got, tt.want)
			}
		})
	}
}

// forceGUIBuilt makes run treat the binary as GUI-capable so the dispatch
// path is covered in builds without the Wails tags.
func forceGUIBuilt(t *testing.T) {
	t.Helper()
	previous := guiBuilt
	guiBuilt = true
	t.Cleanup(func() { guiBuilt = previous })
}

func TestRun_GUICapableBuildStartsGUIWithAssets(t *testing.T) {
	isolateRun(t)
	headless(t)
	forceGUIBuilt(t)

	started := false
	guiRun = func() error { started = true; return nil }
	cliExecute = func() error {
		t.Fatal("--gui must not fall through to the CLI")
		return nil
	}
	gui.Assets = nil

	code := run([]string{"xkey", "--gui"}, &bytes.Buffer{})

	if code != 0 || !started {
		t.Fatalf("code = %d, started = %v; want 0/true", code, started)
	}
	if gui.Assets == nil {
		t.Fatal("frontend assets were not published to the GUI package")
	}
}

func TestRun_GUICapableBuildReportsStartupFailure(t *testing.T) {
	isolateRun(t)
	headless(t)
	forceGUIBuilt(t)

	guiRun = func() error { return errors.New("wails exploded") }

	var stderr bytes.Buffer
	code := run([]string{"xkey", "--gui"}, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "GUI error: wails exploded") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRun_GUICapableBuildReportsLoggingFailure(t *testing.T) {
	isolateRun(t)
	headless(t)
	forceGUIBuilt(t)

	guiRun = func() error {
		t.Fatal("the GUI must not start when logging setup fails")
		return nil
	}
	blocker := t.TempDir() + "/blocker"
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	code := run([]string{"xkey", "--gui", "--log-file", blocker + "/xkey.log"}, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "logging setup error") {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

// --- WrappedError ---

func TestWrappedError(t *testing.T) {
	wrapped := &WrappedError{Msg: "open log file /tmp/x.log", Err: os.ErrPermission}

	if got, want := wrapped.Error(), "open log file /tmp/x.log: permission denied"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(wrapped, os.ErrPermission) {
		t.Fatal("Unwrap must expose the cause to errors.Is")
	}
	if wrapped.Unwrap() != os.ErrPermission {
		t.Fatal("Unwrap must return the wrapped cause")
	}
}

// TestPrintGUIBuildHelp verifies the guidance a user sees when a non-GUI
// build is asked to open the GUI. The message is the only recovery path
// from Wails' opaque stub error, so its content is load-bearing.
func TestPrintGUIBuildHelp(t *testing.T) {
	var buf bytes.Buffer
	printGUIBuildHelp(&buf)
	out := buf.String()

	for _, want := range []string{
		"xkey: this binary was built without GUI support.",
		"'production', 'dev', or 'bindings'",
		"make -C xkey build-local",
		"make -C xkey build",
		"go build -tags 'ble production codec_json' -o xkey ./cmd/xkey",
		"--no-gui",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("guidance is missing %q\ngot:\n%s", want, out)
		}
	}
}
