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

//go:build integration && androidemu

package phone

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ADB errors.
var (
	// ErrADBNotFound indicates the adb binary is not in PATH.
	ErrADBNotFound = errors.New("adb: binary not found in PATH")

	// ErrADBConnectionFailed indicates ADB could not connect to the emulator.
	ErrADBConnectionFailed = errors.New("adb: connection to emulator failed")

	// ErrADBInstallFailed indicates APK installation failed.
	ErrADBInstallFailed = errors.New("adb: APK installation failed")

	// ErrADBCommandFailed indicates an ADB command returned an error.
	ErrADBCommandFailed = errors.New("adb: command failed")

	// ErrEmulatorNotReady indicates the emulator hasn't finished booting.
	ErrEmulatorNotReady = errors.New("adb: emulator not ready")
)

// ADBHelper provides methods for interacting with an Android emulator via ADB.
type ADBHelper struct {
	host string // ADB server host (e.g., "android-emulator" in Docker)
}

// NewADBHelper creates a new ADB helper. The host parameter specifies the
// ADB server address (set via ANDROID_ADB_HOST environment variable in Docker).
// If host is empty, ADB connects to the default local emulator.
func NewADBHelper(host string) (*ADBHelper, error) {
	if _, err := exec.LookPath("adb"); err != nil {
		return nil, ErrADBNotFound
	}
	return &ADBHelper{host: host}, nil
}

// Connect establishes an ADB connection to the emulator.
func (a *ADBHelper) Connect() error {
	if a.host == "" {
		return nil // Local emulator, no explicit connect needed.
	}
	target := fmt.Sprintf("%s:5555", a.host)
	out, err := a.run("connect", target)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrADBConnectionFailed, out)
	}
	if !strings.Contains(out, "connected") {
		return fmt.Errorf("%w: unexpected output: %s", ErrADBConnectionFailed, out)
	}
	return nil
}

// WaitForBoot waits up to the given timeout for the emulator to finish
// booting (sys.boot_completed == 1).
func (a *ADBHelper) WaitForBoot(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := a.run("shell", "getprop", "sys.boot_completed")
		if err == nil && strings.TrimSpace(out) == "1" {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return ErrEmulatorNotReady
}

// InstallAPK installs an APK file on the emulator. The path must be
// accessible from the test runner container.
func (a *ADBHelper) InstallAPK(apkPath string) error {
	out, err := a.run("install", "-r", apkPath)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrADBInstallFailed, out)
	}
	if !strings.Contains(out, "Success") {
		return fmt.Errorf("%w: %s", ErrADBInstallFailed, out)
	}
	return nil
}

// LaunchActivity starts an Android activity via an intent.
func (a *ADBHelper) LaunchActivity(component string, extras map[string]string) error {
	args := []string{"shell", "am", "start", "-n", component}
	for k, v := range extras {
		args = append(args, "--es", k, v)
	}
	out, err := a.run(args...)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrADBCommandFailed, out)
	}
	return nil
}

// SetPreference writes a shared preference value via ADB shell.
func (a *ADBHelper) SetPreference(pkg, key, value string) error {
	// Use am broadcast with a custom receiver to set preferences.
	// This requires the Android app to have a BroadcastReceiver for testing.
	out, err := a.run("shell", "am", "broadcast",
		"-a", pkg+".SET_PREFERENCE",
		"--es", "key", key,
		"--es", "value", value,
	)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrADBCommandFailed, out)
	}
	return nil
}

// run executes an ADB command and returns the combined output.
func (a *ADBHelper) run(args ...string) (string, error) {
	if a.host != "" {
		args = append([]string{"-H", a.host}, args...)
	}
	cmd := exec.Command("adb", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
