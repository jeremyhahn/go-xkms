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

func init() {
	uhidCmd.AddCommand(uhidSetupCmd)
}

// runUHIDSetup performs the privileged UHID setup operations.
func runUHIDSetup(_ *cobra.Command, _ []string) error {
	if os.Geteuid() != 0 {
		return ErrUHIDSetupRequiresRoot
	}

	// Step 1: Write udev rule.
	if err := os.MkdirAll(filepath.Dir(uhidUdevRulePath), 0755); err != nil {
		return fmt.Errorf("%w: %v", ErrUHIDSetupUdevDirFailed, err)
	}
	if err := os.WriteFile(uhidUdevRulePath, []byte(uhidUdevRuleContent), 0644); err != nil {
		return fmt.Errorf("%w: %v", ErrUHIDSetupUdevWriteFailed, err)
	}
	fmt.Println("Created udev rule:", uhidUdevRulePath)

	// Step 2: Ensure uhid module loads at boot.
	if err := os.MkdirAll(filepath.Dir(uhidModuleLoadPath), 0755); err != nil {
		return fmt.Errorf("%w: %v", ErrUHIDSetupModulesDirFailed, err)
	}
	if err := os.WriteFile(uhidModuleLoadPath, []byte(uhidModuleLoadContent), 0644); err != nil {
		return fmt.Errorf("%w: %v", ErrUHIDSetupModulesWriteFailed, err)
	}
	fmt.Println("Created module load config:", uhidModuleLoadPath)

	// Step 3: Load uhid module now (may already be loaded).
	if err := exec.Command("modprobe", "uhid").Run(); err != nil { // #nosec G204
		fmt.Printf("Warning: modprobe uhid failed (may already be loaded): %v\n", err)
	} else {
		fmt.Println("Loaded uhid kernel module")
	}

	// Step 4: Reload udev rules and trigger device rescan.
	if err := exec.Command("udevadm", "control", "--reload-rules").Run(); err != nil { // #nosec G204
		return fmt.Errorf("%w: %v", ErrUHIDSetupUdevReloadFailed, err)
	}
	if err := exec.Command("udevadm", "trigger", "--subsystem-match=misc").Run(); err != nil { // #nosec G204
		return fmt.Errorf("%w: %v", ErrUHIDSetupUdevTriggerFailed, err)
	}
	fmt.Println("Reloaded udev rules and triggered device rescan")

	// Step 5: Add the calling user to the "input" group so the udev rule
	// takes effect. Detect the unprivileged caller from pkexec/sudo env vars.
	callingUser := resolveCallingUsername()
	if callingUser != "" && callingUser != "root" {
		if !userInGroup(callingUser, "input") {
			if err := exec.Command("usermod", "-aG", "input", callingUser).Run(); err != nil { // #nosec G204
				return fmt.Errorf("%w: user %s: %v", ErrUHIDSetupUserAddFailed, callingUser, err)
			}
			fmt.Printf("Added user %q to input group (session restart required for group membership)\n", callingUser)
		} else {
			fmt.Printf("User %q is already in input group\n", callingUser)
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
