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

//go:build linux

package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

var errUHIDTestCommand = errors.New("command failed")

// uhidSetupFixture runs runUHIDSetup as root against a temporary filesystem
// root, recording each system command instead of running it. A command whose
// name is in fail returns errUHIDTestCommand.
type uhidSetupFixture struct {
	root     string
	commands []string
	fail     map[string]bool
}

func newUHIDSetupFixture(t *testing.T, callingUser string) *uhidSetupFixture {
	t.Helper()

	f := &uhidSetupFixture{root: t.TempDir(), fail: map[string]bool{}}
	geteuid, root, run := uhidSetupGeteuid, uhidSetupRoot, uhidSetupRun
	t.Cleanup(func() { uhidSetupGeteuid, uhidSetupRoot, uhidSetupRun = geteuid, root, run })
	uhidSetupGeteuid = func() int { return 0 }
	uhidSetupRoot = f.root
	uhidSetupRun = func(name string, args ...string) error {
		f.commands = append(f.commands, strings.Join(append([]string{name}, args...), " "))
		if f.fail[name+" "+strings.Join(args, " ")] || f.fail[name] {
			return errUHIDTestCommand
		}
		return nil
	}
	t.Setenv("SUDO_USER", callingUser)
	t.Setenv("PKEXEC_UID", "")
	return f
}

func (f *uhidSetupFixture) run() (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := runUHIDSetup(cmd, nil)
	return out.String(), err
}

func TestRunUHIDSetup_InstallsRulesAndAddsCaller(t *testing.T) {
	f := newUHIDSetupFixture(t, "xkey-cov704i-no-such-user")

	out, err := f.run()
	require.NoError(t, err)

	rule, err := os.ReadFile(filepath.Join(f.root, uhidUdevRulePath))
	require.NoError(t, err)
	require.Equal(t, uhidUdevRuleContent, string(rule))
	modules, err := os.ReadFile(filepath.Join(f.root, uhidModuleLoadPath))
	require.NoError(t, err)
	require.Equal(t, uhidModuleLoadContent, string(modules))

	require.Equal(t, []string{
		"modprobe uhid",
		"udevadm control --reload-rules",
		"udevadm trigger --subsystem-match=misc",
		"usermod -aG input xkey-cov704i-no-such-user",
	}, f.commands)
	require.Contains(t, out, "Loaded uhid kernel module")
	require.Contains(t, out, `Added user "xkey-cov704i-no-such-user" to input group`)
}

func TestRunUHIDSetup_RootCallerIsNotAddedToGroup(t *testing.T) {
	f := newUHIDSetupFixture(t, "root")

	_, err := f.run()
	require.NoError(t, err)
	require.NotContains(t, strings.Join(f.commands, "\n"), "usermod")
}

func TestRunUHIDSetup_ModprobeFailureIsAWarning(t *testing.T) {
	f := newUHIDSetupFixture(t, "")
	f.fail["modprobe"] = true

	out, err := f.run()
	require.NoError(t, err)
	require.Contains(t, out, "Warning: modprobe uhid failed")
	require.Contains(t, out, "Reloaded udev rules")
}

func TestRunUHIDSetup_CommandFailures(t *testing.T) {
	tests := []struct {
		name    string
		fail    string
		user    string
		wantErr error
	}{
		{name: "udev reload", fail: "udevadm control --reload-rules", wantErr: ErrUHIDSetupUdevReloadFailed},
		{name: "udev trigger", fail: "udevadm trigger --subsystem-match=misc", wantErr: ErrUHIDSetupUdevTriggerFailed},
		{name: "usermod", fail: "usermod", user: "xkey-cov704i-no-such-user", wantErr: ErrUHIDSetupUserAddFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newUHIDSetupFixture(t, tt.user)
			f.fail[tt.fail] = true

			_, err := f.run()
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestRunUHIDSetup_FileFailures(t *testing.T) {
	tests := []struct {
		name    string
		block   string // path created as a regular file to block the write
		wantErr error
	}{
		{name: "udev rules directory", block: filepath.Dir(uhidUdevRulePath), wantErr: ErrUHIDSetupUdevDirFailed},
		{name: "udev rule file", block: uhidUdevRulePath + "/", wantErr: ErrUHIDSetupUdevWriteFailed},
		{name: "modules-load directory", block: filepath.Dir(uhidModuleLoadPath), wantErr: ErrUHIDSetupModulesDirFailed},
		{name: "module load file", block: uhidModuleLoadPath + "/", wantErr: ErrUHIDSetupModulesWriteFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newUHIDSetupFixture(t, "")
			blocked := filepath.Join(f.root, tt.block)
			if strings.HasSuffix(tt.block, "/") {
				// A directory where the file should go makes WriteFile fail.
				require.NoError(t, os.MkdirAll(blocked, 0o755))
			} else {
				require.NoError(t, os.MkdirAll(filepath.Dir(blocked), 0o755))
				require.NoError(t, os.WriteFile(blocked, nil, 0o600))
			}

			_, err := f.run()
			require.ErrorIs(t, err, tt.wantErr)
			require.Empty(t, f.commands, "no system command may run after a file step fails")
		})
	}
}
