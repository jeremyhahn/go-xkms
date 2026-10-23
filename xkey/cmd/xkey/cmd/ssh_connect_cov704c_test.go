package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// c704cSSHRun is one run of the native ssh client.
type c704cSSHRun struct {
	args, env []string
}

// c704cSSH replaces the ssh client with a fake that records each run and
// calls client, which plays the server side of the session.
func c704cSSH(t *testing.T, client func(args []string) error) *[]c704cSSHRun {
	t.Helper()
	runs := &[]c704cSSHRun{}
	saved := runSSHClient
	runSSHClient = func(args, env []string) error {
		*runs = append(*runs, c704cSSHRun{args: args, env: env})
		return client(args)
	}
	t.Cleanup(func() { runSSHClient = saved })
	return runs
}

// c704cKnownHostsFile returns the UserKnownHostsFile the session gave ssh.
func c704cKnownHostsFile(t *testing.T, args []string) string {
	t.Helper()
	for _, a := range args {
		if path, ok := strings.CutPrefix(a, "UserKnownHostsFile="); ok {
			return path
		}
	}
	t.Fatalf("no UserKnownHostsFile in %v", args)
	return ""
}

// c704cSSHKeyConnect generates the managed key "laptop" and returns a
// connect command that uses it.
func c704cSSHKeyConnect(t *testing.T) func(target string) error {
	t.Helper()
	withEmbeddedSSHStore(t)
	t.Setenv("TMPDIR", t.TempDir())
	gen, _ := sshTestCmd(t)
	setSSHFlags(t, gen, map[string]string{
		"scope": "user", "owner": "alice", "name": "laptop", "type": "ed25519",
	})
	require.NoError(t, runSSHKeysGenerate(gen, nil))

	return func(target string) error {
		cmd := newSSHConnectCmd(t)
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "key", "laptop"))
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "key-owner", "alice"))
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "port", "2222"))
		return runSSHConnect(cmd, []string{target})
	}
}

// TestC704cSSHConnect_ManagedKeyPinsTheHostKey drives a managed-key connect
// whose ssh run accepts a new host key; the key is pinned in the store
// afterwards.
func TestC704cSSHConnect_ManagedKeyPinsTheHostKey(t *testing.T) {
	connect := c704cSSHKeyConnect(t)
	hostPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(hostPub)
	require.NoError(t, err)

	runs := c704cSSH(t, func(args []string) error {
		// What ssh writes on first contact: the accepted host key.
		line := "[server.example.com]:2222 " + string(ssh.MarshalAuthorizedKey(sshPub))
		return os.WriteFile(c704cKnownHostsFile(t, args), []byte(line), 0o600)
	})

	require.NoError(t, connect("bob@server.example.com"))
	require.Len(t, *runs, 1)
	run := (*runs)[0]
	assert.Equal(t, "bob@server.example.com", run.args[len(run.args)-1])
	assert.Contains(t, run.args, "2222")
	assert.True(t, c704cHasEnv(run.env, "SSH_AUTH_SOCK"), "ssh signs through the session's agent")

	list, buf := sshTestCmd(t)
	setSSHFlags(t, list, map[string]string{"scope": "user", "owner": "alice"})
	require.NoError(t, runSSHHostKeysList(list, nil))
	assert.Contains(t, buf.String(), "server.example.com")
}

func TestC704cSSHConnect_ManagedKeyReturnsTheSSHExit(t *testing.T) {
	connect := c704cSSHKeyConnect(t)
	c704cSSH(t, func([]string) error { return errC704cHost })

	require.ErrorIs(t, connect("server.example.com"), errC704cHost)
}

func TestC704cSSHConnect_LocalPassthrough(t *testing.T) {
	withCLIHome(t)
	isolateXKMSdEndpoint(t)
	runs := c704cSSH(t, func([]string) error { return nil })

	cmd := newSSHConnectCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "user", "bob"))
	require.NoError(t, runSSHConnect(cmd, []string{"server.example.com"}))
	require.Len(t, *runs, 1)
	assert.Contains(t, (*runs)[0].args, "bob@server.example.com")
	assert.Equal(t, os.Environ(), (*runs)[0].env, "the environment is passed through unchanged")

	c704cSSH(t, func([]string) error { return errC704cHost })
	require.ErrorIs(t, runSSHConnect(newSSHConnectCmd(t), []string{"server.example.com"}), errC704cHost)
}

// c704cHasEnv reports whether env sets name.
func c704cHasEnv(env []string, name string) bool {
	for _, kv := range env {
		if strings.HasPrefix(kv, name+"=") {
			return true
		}
	}
	return false
}
