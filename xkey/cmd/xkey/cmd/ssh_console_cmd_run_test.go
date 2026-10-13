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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// closedLocalPort returns a loopback port nothing listens on, so a dial is
// refused immediately instead of waiting on a timeout.
func closedLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// writeTestIdentity writes an unencrypted OpenSSH ed25519 private key and
// returns its path.
func writeTestIdentity(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := gossh.MarshalPrivateKey(priv, "console-test")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))
	return path
}

func TestRunSSHConsole_IdentityFlagForcesLocalSigners(t *testing.T) {
	withCLIHome(t)
	missing := filepath.Join(t.TempDir(), "absent_key")

	cmd := sshConsoleTestCmd()
	// --key names a managed key, but --identity must still route the
	// session through the operator's local identity.
	require.NoError(t, cmd.Flags().Set("key", "managed"))
	require.NoError(t, cmd.Flags().Set("identity", "  "+missing+"  "))

	err := runSSHConsole(cmd, []string{"alice@host.example.com"})
	var noIdentity *sshsdk.NoUsableLocalIdentityError
	require.ErrorAs(t, err, &noIdentity)
	require.Equal(t, missing, noIdentity.Alias)
}

func TestRunSSHConsole_ProfileSuppliesLocalIdentity(t *testing.T) {
	withCLIHome(t)
	missing := filepath.Join(t.TempDir(), "profile_key")

	store, closeStore, err := xkeyProfileStore()
	require.NoError(t, err)
	require.NoError(t, store.Add(&sshsdk.Profile{
		Name: "console-profile", Host: "console.example.com", User: "ops",
		KeySource: "local", LocalIdentity: missing,
	}))
	closeStore()

	err = runSSHConsole(sshConsoleTestCmd(), []string{"console-profile"})
	var noIdentity *sshsdk.NoUsableLocalIdentityError
	require.ErrorAs(t, err, &noIdentity)
	require.Equal(t, missing, noIdentity.Alias)
}

func TestRunSSHConsole_LocalDialFailureIsReturned(t *testing.T) {
	withCLIHome(t)

	cmd := sshConsoleTestCmd()
	require.NoError(t, cmd.Flags().Set("identity", writeTestIdentity(t)))
	require.NoError(t, cmd.Flags().Set("port", strconv.Itoa(closedLocalPort(t))))

	err := runSSHConsole(cmd, []string{"ops@127.0.0.1"})
	require.Error(t, err)
	var noIdentity *sshsdk.NoUsableLocalIdentityError
	require.False(t, errors.As(err, &noIdentity), "a usable identity must reach the dial, got %v", err)
}

func TestRunSSHConsole_ManagedKeyDialFailureIsReturned(t *testing.T) {
	withEmbeddedSSHStore(t)

	gen, _ := sshTestCmd(t)
	setSSHFlags(t, gen, map[string]string{
		"scope": "user", "owner": "alice", "name": "laptop", "type": "ed25519",
	})
	require.NoError(t, runSSHKeysGenerate(gen, nil))

	cmd := sshConsoleTestCmd()
	require.NoError(t, cmd.Flags().Set("key", "laptop"))
	require.NoError(t, cmd.Flags().Set("key-owner", "alice"))
	require.NoError(t, cmd.Flags().Set("port", strconv.Itoa(closedLocalPort(t))))

	err := runSSHConsole(cmd, []string{"alice@127.0.0.1"})
	require.Error(t, err)
	var noIdentity *sshsdk.NoUsableLocalIdentityError
	require.False(t, errors.As(err, &noIdentity), "a managed key must not fall back to local identities, got %v", err)
}
