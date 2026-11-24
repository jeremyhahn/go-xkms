package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// Issue #2284: a server-backed connect omits only the remote key owner (the
// server resolves it to the caller); the host-key pins it seeds from and
// syncs back to this machine's own pin store keep a concrete owner, "local".

// pinOwnerKeys stands in for an xkmsd server's keys API: it records the owner
// each Signer request sends and answers with one signer.
type pinOwnerKeys struct {
	sshsdk.KeysClient
	signer gossh.Signer
	owners *[]string
}

func (k pinOwnerKeys) Signer(_ context.Context, req sshsdk.GetKeyRequest) (gossh.Signer, error) {
	*k.owners = append(*k.owners, req.Owner)
	return k.signer, nil
}

// pinOwnerClient is a server-backed SSH client whose Keys() is pinOwnerKeys.
type pinOwnerClient struct {
	sshsdk.Client
	keys sshsdk.KeysClient
}

func (c pinOwnerClient) Keys() sshsdk.KeysClient { return c.keys }

// shortSocketTempDir returns a fresh directory directly under the system
// temp dir. The ssh agent binds a unix socket under TMPDIR, and sun_path
// holds 108 bytes (104 on macOS): a t.TempDir() nests the test name and
// overflowed it in CI ("bind: invalid argument").
func shortSocketTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "xs")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// withServerBackedConnect points connect at a stand-in xkmsd server paired
// with the real local pin store, and returns the owners its Signer saw.
func withServerBackedConnect(t *testing.T) *[]string {
	t.Helper()
	withEmbeddedSSHStore(t)
	t.Setenv(envXKMSdURL, "https://xkmsd.example.test:8443")
	t.Setenv("TMPDIR", shortSocketTempDir(t))
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(priv)
	require.NoError(t, err)

	owners := &[]string{}
	saved := sshConnectClient
	sshConnectClient = func(*cobra.Command) (sshsdk.Client, sshsdk.HostKeyStore, func(), error) {
		hostKeys, closeHostKeys, err := xkeyHostKeyStore()
		if err != nil {
			return nil, nil, nil, err
		}
		return pinOwnerClient{keys: pinOwnerKeys{signer: signer, owners: owners}}, hostKeys, closeHostKeys, nil
	}
	t.Cleanup(func() { sshConnectClient = saved })
	return owners
}

// TestServerBackedConnectSocketDirIsShort proves the server-backed helper
// leaves the agent's socket path under the unix sun_path floor (104 bytes on
// macOS, 108 on Linux).
func TestServerBackedConnectSocketDirIsShort(t *testing.T) {
	withServerBackedConnect(t)
	sock := filepath.Join(os.Getenv("TMPDIR"), "xkey-ssh-0000000000", "agent.sock")
	assert.Less(t, len(sock), 104, "agent socket path %q exceeds the unix limit", sock)
}

// hostKeyLine is the known_hosts line ssh writes on first contact.
func hostKeyLine(t *testing.T, host string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)
	return "[" + host + "]:2222 " + string(gossh.MarshalAuthorizedKey(sshPub))
}

func connectServerBacked(t *testing.T, target, keyOwner string) error {
	t.Helper()
	cmd := newSSHConnectCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "key", "laptop"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "port", "2222"))
	if keyOwner != "" {
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "key-owner", keyOwner))
	}
	return runSSHConnect(cmd, []string{target})
}

// listPins lists the hosts pinned in this machine's own pin store under
// user/owner.
func listPins(t *testing.T, owner string) string {
	t.Helper()
	hostKeys, closeHostKeys, err := xkeyHostKeyStore()
	require.NoError(t, err)
	defer closeHostKeys()
	pins, err := hostKeys.List(context.Background(), "user", owner)
	require.NoError(t, err)
	var hosts strings.Builder
	for _, pin := range pins {
		assert.Equal(t, owner, pin.Owner)
		hosts.WriteString(pin.Host + "\n")
	}
	return hosts.String()
}

func TestSSHConnect_ServerBackedOmitsKeyOwnerButPinsLocally(t *testing.T) {
	owners := withServerBackedConnect(t)

	// Another owner's pin in the same local store: an omitted key owner must
	// not seed it.
	c704cSSH(t, func(args []string) error {
		return os.WriteFile(c704cKnownHostsFile(t, args), []byte(hostKeyLine(t, "other.example.com")), 0o600)
	})
	require.NoError(t, connectServerBacked(t, "bob@other.example.com", "alice"))
	assert.Contains(t, listPins(t, "alice"), "other.example.com")

	// First contact without --key-owner: the server gets no owner, and the
	// accepted host key is synced under "local".
	runs := c704cSSH(t, func(args []string) error {
		seeded, err := os.ReadFile(c704cKnownHostsFile(t, args))
		require.NoError(t, err)
		assert.NotContains(t, string(seeded), "other.example.com", "seeded another owner's pin")
		return os.WriteFile(c704cKnownHostsFile(t, args), []byte(hostKeyLine(t, "server.example.com")), 0o600)
	})
	require.NoError(t, connectServerBacked(t, "bob@server.example.com", ""))
	require.Len(t, *runs, 1)
	assert.Equal(t, []string{"alice", ""}, *owners, "the remote key owner is omitted unless given")
	assert.Contains(t, listPins(t, "local"), "server.example.com", "the accepted host key was not pinned")

	// A later connect seeds that pin from the "local" namespace.
	runs = c704cSSH(t, func(args []string) error {
		seeded, err := os.ReadFile(c704cKnownHostsFile(t, args))
		require.NoError(t, err)
		assert.Contains(t, string(seeded), "server.example.com", "the local pin was not seeded")
		assert.NotContains(t, string(seeded), "other.example.com", "seeded another owner's pin")
		return nil
	})
	require.NoError(t, connectServerBacked(t, "bob@server.example.com", ""))
	require.Len(t, *runs, 1)
}

func TestSSHHostPinOwner(t *testing.T) {
	assert.Equal(t, "local", sshHostPinOwner(""))
	assert.Equal(t, "alice", sshHostPinOwner("alice"))
}
