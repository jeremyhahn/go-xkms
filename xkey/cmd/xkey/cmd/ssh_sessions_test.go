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
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

func TestSessionOrigin_Profile(t *testing.T) {
	s := &sshsdk.ConsoleSessionRecord{ProfileID: "prod-bastion"}
	require.Equal(t, "profile:prod-bastion", sessionOrigin(s))
}

func TestSessionOrigin_SSHConfigAlias(t *testing.T) {
	s := &sshsdk.ConsoleSessionRecord{Alias: "myhost"}
	require.Equal(t, "ssh_config:myhost", sessionOrigin(s))
}

func TestSessionOrigin_OneTimeHostOnly(t *testing.T) {
	s := &sshsdk.ConsoleSessionRecord{Host: "10.0.0.5"}
	require.Equal(t, "10.0.0.5", sessionOrigin(s))
}

func TestSessionOrigin_OneTimeUserAndHost(t *testing.T) {
	s := &sshsdk.ConsoleSessionRecord{Host: "10.0.0.5", User: "root"}
	require.Equal(t, "root@10.0.0.5", sessionOrigin(s))
}

func TestSessionOrigin_OneTimeNonStandardPort(t *testing.T) {
	s := &sshsdk.ConsoleSessionRecord{Host: "10.0.0.5", User: "root", Port: 2222}
	require.Equal(t, "root@10.0.0.5:2222", sessionOrigin(s))
}

func TestSessionOrigin_OneTimeDefaultPortOmitted(t *testing.T) {
	s := &sshsdk.ConsoleSessionRecord{Host: "10.0.0.5", Port: 22}
	require.Equal(t, "10.0.0.5", sessionOrigin(s))
}

// TestSessionOrigin_ProfileTakesPrecedenceOverAlias documents the switch's
// ordering: a record should never carry both, but if it did, ProfileID wins.
func TestSessionOrigin_ProfileTakesPrecedenceOverAlias(t *testing.T) {
	s := &sshsdk.ConsoleSessionRecord{ProfileID: "p1", Alias: "a1"}
	require.Equal(t, "profile:p1", sessionOrigin(s))
}

func TestXkeySessionStore_RoundTrip(t *testing.T) {
	withCLIHome(t)

	store, err := xkeySessionStore()
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	rec := &sshsdk.ConsoleSessionRecord{Title: "test@host", Host: "host", User: "test"}
	require.NoError(t, store.Save(rec))
	require.NotEmpty(t, rec.ID)

	all, err := store.List()
	require.NoError(t, err)
	require.Len(t, all, 1)
	require.Equal(t, "test@host", all[0].Title)
}

func TestRunSSHSessionsList_Empty(t *testing.T) {
	withCLIHome(t)

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	require.NoError(t, runSSHSessionsList(cmd, nil))
	require.Contains(t, buf.String(), "No persistent sessions found")
}

func TestRunSSHSessionsList_WithRecords(t *testing.T) {
	withCLIHome(t)

	store, err := xkeySessionStore()
	require.NoError(t, err)
	rec := &sshsdk.ConsoleSessionRecord{
		Title:           "prod@bastion",
		ProfileID:       "prod-bastion",
		LastConnectedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	require.NoError(t, store.Save(rec))
	require.NoError(t, store.Close())

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	require.NoError(t, runSSHSessionsList(cmd, nil))
	out := buf.String()
	require.Contains(t, out, rec.ID)
	require.Contains(t, out, "prod@bastion")
	require.Contains(t, out, "profile:prod-bastion")
}

func TestRunSSHSessionsRemove_Success(t *testing.T) {
	withCLIHome(t)

	store, err := xkeySessionStore()
	require.NoError(t, err)
	rec := &sshsdk.ConsoleSessionRecord{Title: "to-delete", Host: "h"}
	require.NoError(t, store.Save(rec))
	require.NoError(t, store.Close())

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	require.NoError(t, runSSHSessionsRemove(cmd, []string{rec.ID}))
	require.Contains(t, buf.String(), rec.ID)

	store2, err := xkeySessionStore()
	require.NoError(t, err)
	defer func() { _ = store2.Close() }()
	all, err := store2.List()
	require.NoError(t, err)
	require.Empty(t, all)
}

func TestRunSSHSessionsRemove_NotFound(t *testing.T) {
	withCLIHome(t)

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := runSSHSessionsRemove(cmd, []string{"does-not-exist"})
	require.Error(t, err)
	require.ErrorIs(t, err, sshsdk.ErrConsoleSessionNotFound)
}

func TestSSHSessionsCmd_Wiring(t *testing.T) {
	require.Equal(t, "sessions", sshSessionsCmd.Use)
	found := false
	for _, c := range sshSessionsCmd.Commands() {
		if c.Name() == "list" {
			found = true
		}
	}
	require.True(t, found, "sessions list subcommand must be registered")
}
