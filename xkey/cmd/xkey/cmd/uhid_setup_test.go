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

//go:build linux

package cmd

import (
	"fmt"
	"os"
	"os/user"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// TestRunUHIDSetup_RequiresRoot exercises the real, unprivileged code path:
// the test process is never root in CI, so runUHIDSetup must refuse before
// touching any host file (/etc/udev, /etc/modules-load.d) or spawning
// modprobe/udevadm/usermod.
func TestRunUHIDSetup_RequiresRoot(t *testing.T) {
	require.NotEqual(t, 0, os.Geteuid(), "this test must not run as root")

	cmd := &cobra.Command{}
	err := runUHIDSetup(cmd, nil)
	require.ErrorIs(t, err, ErrUHIDSetupRequiresRoot)
}

func TestResolveCallingUsername_SudoUser(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	t.Setenv("PKEXEC_UID", "")
	require.Equal(t, "alice", resolveCallingUsername())
}

func TestResolveCallingUsername_PkexecUID(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	t.Setenv("PKEXEC_UID", fmt.Sprint(os.Getuid()))

	got := resolveCallingUsername()
	require.NotEmpty(t, got, "a valid PKEXEC_UID must resolve to the current user's name")
}

func TestResolveCallingUsername_PkexecUIDUnknown(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	t.Setenv("PKEXEC_UID", "999999999")
	require.Empty(t, resolveCallingUsername())
}

func TestResolveCallingUsername_NoEnv(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	t.Setenv("PKEXEC_UID", "")
	require.Empty(t, resolveCallingUsername())
}

func TestUserInGroup_UnknownUser(t *testing.T) {
	require.False(t, userInGroup("xkey-definitely-nonexistent-user", "input"))
}

func TestUserInGroup_UnknownGroup(t *testing.T) {
	me, err := user.Current()
	require.NoError(t, err)
	require.False(t, userInGroup(me.Username, "xkey-definitely-nonexistent-group"))
}

func TestUserInGroup_PrimaryGroupIsMembership(t *testing.T) {
	me, err := user.Current()
	require.NoError(t, err)
	primary, err := user.LookupGroupId(me.Gid)
	require.NoError(t, err)

	require.True(t, userInGroup(me.Username, primary.Name))
}
