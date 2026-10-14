package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

// writeOpenSSHPrivateKey writes a fresh, unencrypted ed25519 key in OpenSSH
// PEM form to dir/name and returns the path, the authorized_keys line of its
// public half and the key's fingerprint.
func writeOpenSSHPrivateKey(t *testing.T, dir, name, comment string) (string, string, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := gossh.MarshalPrivateKey(priv, comment)
	require.NoError(t, err)
	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)

	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))
	line := strings.TrimRight(string(gossh.MarshalAuthorizedKey(sshPub)), "\n")
	return path, line, gossh.FingerprintSHA256(sshPub)
}

func TestRunSSHKeysImport_ImportsPEMUnderFileName(t *testing.T) {
	withEmbeddedSSHStore(t)

	path, _, fingerprint := writeOpenSSHPrivateKey(t, t.TempDir(), "workstation.pem", "")

	imp, impBuf := sshTestCmd(t)
	setSSHFlags(t, imp, map[string]string{"owner": "alice", "comment": "alice@workstation"})
	require.NoError(t, runSSHKeysImport(imp, []string{path}))

	// Scope defaults to "user" and the name to the file's base name
	// without its extension.
	out := impBuf.String()
	assert.Contains(t, out, "Imported SSH key: user/alice/workstation")
	assert.Contains(t, out, "Fingerprint: "+fingerprint)

	get, getBuf := sshTestCmd(t)
	setSSHFlags(t, get, map[string]string{"scope": "user", "owner": "alice", "name": "workstation"})
	require.NoError(t, runSSHKeysGet(get, nil))
	assert.Contains(t, getBuf.String(), fingerprint)
}

func TestRunSSHKeysImport_RejectsNonKeyPEM(t *testing.T) {
	withEmbeddedSSHStore(t)

	path := filepath.Join(t.TempDir(), "garbage.pem")
	require.NoError(t, os.WriteFile(path, []byte("not a private key\n"), 0o600))

	imp, impBuf := sshTestCmd(t)
	setSSHFlags(t, imp, map[string]string{"owner": "alice"})
	require.Error(t, runSSHKeysImport(imp, []string{path}))
	assert.NotContains(t, impBuf.String(), "Imported SSH key")
}

func TestSSHHostPublicKeyFromFlags_Sources(t *testing.T) {
	line, fingerprint := randomHostKeyLine(t)

	t.Run("key flag wins over file", func(t *testing.T) {
		cmd, _ := sshTestCmd(t)
		setSSHFlags(t, cmd, map[string]string{"key": line, "file": filepath.Join(t.TempDir(), "absent")})
		pub, err := sshHostPublicKeyFromFlags(cmd)
		require.NoError(t, err)
		assert.Equal(t, fingerprint, gossh.FingerprintSHA256(pub))
	})

	t.Run("file is read when key is empty", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "host.pub")
		require.NoError(t, os.WriteFile(path, []byte(line+"\n"), 0o600))
		cmd, _ := sshTestCmd(t)
		setSSHFlags(t, cmd, map[string]string{"file": path})
		pub, err := sshHostPublicKeyFromFlags(cmd)
		require.NoError(t, err)
		assert.Equal(t, fingerprint, gossh.FingerprintSHA256(pub))
	})

	t.Run("missing file", func(t *testing.T) {
		cmd, _ := sshTestCmd(t)
		setSSHFlags(t, cmd, map[string]string{"file": filepath.Join(t.TempDir(), "absent")})
		_, err := sshHostPublicKeyFromFlags(cmd)
		assert.ErrorIs(t, err, ErrSSHReadHostKeyFile)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("unparsable key", func(t *testing.T) {
		cmd, _ := sshTestCmd(t)
		setSSHFlags(t, cmd, map[string]string{"key": "ssh-ed25519 not-base64"})
		_, err := sshHostPublicKeyFromFlags(cmd)
		assert.ErrorIs(t, err, ErrSSHParseHostKey)
	})

	t.Run("neither flag", func(t *testing.T) {
		cmd, _ := sshTestCmd(t)
		_, err := sshHostPublicKeyFromFlags(cmd)
		assert.ErrorIs(t, err, ErrSSHMissingHostKey)
	})
}

func TestRunSSHLocalKeys_ListsHomeIdentity(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	require.NoError(t, os.Mkdir(sshDir, 0o700))
	keyPath, pubLine, fingerprint := writeOpenSSHPrivateKey(t, sshDir, "id_ed25519", "alice@laptop")
	require.NoError(t, os.WriteFile(keyPath+".pub", []byte(pubLine+" alice@laptop\n"), 0o600))

	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")

	cmd := &cobra.Command{RunE: runSSHLocalKeys}
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.RunE(cmd, nil))

	listing := out.String()
	assert.Contains(t, listing, fingerprint)
	assert.Contains(t, listing, filepath.Join(sshDir, "id_ed25519"))
	assert.Contains(t, listing, "ssh-ed25519")
	assert.Contains(t, listing, "alice@laptop")
}
