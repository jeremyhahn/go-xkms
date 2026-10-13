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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// UHID setup errors.
var (
	// ErrUHIDSetupRequiresRoot indicates that UHID setup requires root privileges.
	ErrUHIDSetupRequiresRoot = errors.New("uhid_setup: requires root privileges")

	// ErrUHIDSetupUdevDirFailed indicates the udev rules directory could not be created.
	ErrUHIDSetupUdevDirFailed = errors.New("uhid_setup: failed to create udev rules directory")

	// ErrUHIDSetupUdevWriteFailed indicates the udev rule file could not be written.
	ErrUHIDSetupUdevWriteFailed = errors.New("uhid_setup: failed to write udev rule")

	// ErrUHIDSetupModulesDirFailed indicates the modules-load.d directory could not be created.
	ErrUHIDSetupModulesDirFailed = errors.New("uhid_setup: failed to create modules-load.d directory")

	// ErrUHIDSetupModulesWriteFailed indicates the module load config could not be written.
	ErrUHIDSetupModulesWriteFailed = errors.New("uhid_setup: failed to write module load config")

	// ErrUHIDSetupUdevReloadFailed indicates udev rules could not be reloaded.
	ErrUHIDSetupUdevReloadFailed = errors.New("uhid_setup: failed to reload udev rules")

	// ErrUHIDSetupUdevTriggerFailed indicates the udev trigger failed.
	ErrUHIDSetupUdevTriggerFailed = errors.New("uhid_setup: failed to trigger udev")

	// ErrUHIDSetupUserAddFailed indicates the calling user could not be added to the input group.
	ErrUHIDSetupUserAddFailed = errors.New("uhid_setup: failed to add user to input group")
)

const (
	// uhidUdevRulePath is the path where the xKey UHID udev rule is installed.
	uhidUdevRulePath = "/etc/udev/rules.d/99-xkey-uhid.rules"

	// uhidUdevRuleContent is the udev rule that grants the "input" group access
	// to /dev/uhid for virtual USB HID device creation.
	uhidUdevRuleContent = `# xKey FIDO2 Authenticator - UHID device access
# Allows members of the "input" group to access /dev/uhid for virtual USB HID devices.
KERNEL=="uhid", SUBSYSTEM=="misc", MODE="0660", GROUP="input"
`

	// uhidModuleLoadPath is the path where the uhid module auto-load config is installed.
	uhidModuleLoadPath = "/etc/modules-load.d/xkey-uhid.conf"

	// uhidModuleLoadContent ensures the uhid kernel module is loaded at boot.
	uhidModuleLoadContent = "# xKey FIDO2 Authenticator - load UHID module at boot\nuhid\n"
)

// uhidSetupCmd configures /dev/uhid permissions for unprivileged FIDO2 device access.
var uhidSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure UHID device permissions for FIDO2 virtual authenticator",
	Long: `Creates udev rules and module loading configuration for /dev/uhid access.

This command performs the following privileged operations:
  1. Creates a udev rule at /etc/udev/rules.d/99-xkey-uhid.rules
     that grants the "input" group read/write access to /dev/uhid
  2. Creates /etc/modules-load.d/xkey-uhid.conf to ensure the uhid
     kernel module is loaded at boot
  3. Loads the uhid kernel module immediately via modprobe
  4. Reloads udev rules and triggers a device rescan

After running this command, users in the "input" group can create virtual
FIDO2 USB HID devices without root privileges.

Requires root privileges. Normally invoked automatically via privilege
escalation from the xKey GUI.`,
	Hidden: true, // Only invoked via privilege escalation
	RunE:   runUHIDSetup,
}

// The host surface runUHIDSetup acts on: the effective UID check, the
// filesystem root its config files are written under, and the system
// commands it runs. Tests point them at a temporary root and a recorder.
var (
	uhidSetupGeteuid = os.Geteuid
	uhidSetupRoot    = "/"
	uhidSetupRun     = runUHIDSetupCommand
)

// runUHIDSetupCommand runs a system command and waits for it to finish.
func runUHIDSetupCommand(name string, args ...string) error {
	return exec.Command(name, args...).Run() // #nosec G204
}

func init() {
	uhidCmd.AddCommand(uhidSetupCmd)
}

// runUHIDSetup performs the privileged UHID setup operations.
func runUHIDSetup(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	if uhidSetupGeteuid() != 0 {
		return ErrUHIDSetupRequiresRoot
	}

	// Step 1: Write udev rule.
	udevRulePath := filepath.Join(uhidSetupRoot, uhidUdevRulePath)
	if err := os.MkdirAll(filepath.Dir(udevRulePath), 0755); err != nil {
		return &SentinelCauseError{Sentinel: ErrUHIDSetupUdevDirFailed, Cause: err}
	}
	if err := os.WriteFile(udevRulePath, []byte(uhidUdevRuleContent), 0644); err != nil {
		return &SentinelCauseError{Sentinel: ErrUHIDSetupUdevWriteFailed, Cause: err}
	}
	_, _ = fmt.Fprintln(out, "Created udev rule:", udevRulePath)

	// Step 2: Ensure uhid module loads at boot.
	moduleLoadPath := filepath.Join(uhidSetupRoot, uhidModuleLoadPath)
	if err := os.MkdirAll(filepath.Dir(moduleLoadPath), 0755); err != nil {
		return &SentinelCauseError{Sentinel: ErrUHIDSetupModulesDirFailed, Cause: err}
	}
	if err := os.WriteFile(moduleLoadPath, []byte(uhidModuleLoadContent), 0644); err != nil {
		return &SentinelCauseError{Sentinel: ErrUHIDSetupModulesWriteFailed, Cause: err}
	}
	_, _ = fmt.Fprintln(out, "Created module load config:", moduleLoadPath)

	// Step 3: Load uhid module now (may already be loaded).
	if err := uhidSetupRun("modprobe", "uhid"); err != nil {
		_, _ = fmt.Fprintf(out, "Warning: modprobe uhid failed (may already be loaded): %v\n", err)
	} else {
		_, _ = fmt.Fprintln(out, "Loaded uhid kernel module")
	}

	// Step 4: Reload udev rules and trigger device rescan.
	if err := uhidSetupRun("udevadm", "control", "--reload-rules"); err != nil {
		return &SentinelCauseError{Sentinel: ErrUHIDSetupUdevReloadFailed, Cause: err}
	}
	if err := uhidSetupRun("udevadm", "trigger", "--subsystem-match=misc"); err != nil {
		return &SentinelCauseError{Sentinel: ErrUHIDSetupUdevTriggerFailed, Cause: err}
	}
	_, _ = fmt.Fprintln(out, "Reloaded udev rules and triggered device rescan")

	// Step 5: Add the calling user to the "input" group so the udev rule
	// takes effect. Detect the unprivileged caller from pkexec/sudo env vars.
	callingUser := resolveCallingUsername()
	if callingUser != "" && callingUser != "root" {
		if !userInGroup(callingUser, "input") {
			if err := uhidSetupRun("usermod", "-aG", "input", callingUser); err != nil {
				return &DetailError{Err: ErrUHIDSetupUserAddFailed, Detail: fmt.Sprintf(": user %s: %v", callingUser, err)}
			}
			_, _ = fmt.Fprintf(out, "Added user %q to input group (session restart required for group membership)\n", callingUser)
		} else {
			_, _ = fmt.Fprintf(out, "User %q is already in input group\n", callingUser)
		}
	}

	return nil
}

// resolveCallingUsername returns the username of the unprivileged caller
// that invoked this command via privilege escalation. Checks SUDO_USER
// (set by sudo) and PKEXEC_UID (set by pkexec).
func resolveCallingUsername() string {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		return sudoUser
	}
	if pkexecUID := os.Getenv("PKEXEC_UID"); pkexecUID != "" {
		if u, err := user.LookupId(pkexecUID); err == nil {
			return u.Username
		}
	}
	return ""
}

// userInGroup checks whether the given username is a member of the named group.
func userInGroup(username, groupName string) bool {
	u, err := user.Lookup(username)
	if err != nil {
		return false
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false
	}
	g, err := user.LookupGroup(groupName)
	if err != nil {
		return false
	}
	for _, gid := range gids {
		if gid == g.Gid {
			return true
		}
	}
	// Also check /etc/group directly since user.GroupIds() may not include
	// supplementary groups added via usermod until the next login.
	out, err := exec.Command("id", "-Gn", username).Output() // #nosec G204
	if err != nil {
		return false
	}
	for _, name := range strings.Fields(string(out)) {
		if name == groupName {
			return true
		}
	}
	return false
}
