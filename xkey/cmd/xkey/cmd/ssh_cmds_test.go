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

package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
)

// sshTestCmd builds a detached cobra command carrying the union of every
// flag the SSH handlers read, so a handler can be driven directly without
// mutating the shared command tree.
func sshTestCmd(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: "ssh-test"}
	fs := cmd.Flags()
	for _, name := range []string{
		"scope", "owner", "name", "type", "comment", "backend",
		"host", "key", "file", "algorithm", "source",
		"server", "tls-ca",
	} {
		fs.String(name, "", "")
	}
	fs.Int("bits", 0, "")
	fs.Bool("local", false, "")

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

// setSSHFlags applies a name→value map to the command's flags.
func setSSHFlags(t *testing.T, cmd *cobra.Command, values map[string]string) {
	t.Helper()
	for k, v := range values {
		require.NoError(t, setFlagForTest(t, cmd.Flags(), k, v), "set --%s", k)
	}
}

// withEmbeddedSSHStore isolates the local SSH store in a temp HOME and
// clears every environment source that would divert the CLI to a server.
func withEmbeddedSSHStore(t *testing.T) string {
	t.Helper()
	home := withCLIHome(t)
	isolateXKMSdEndpoint(t)
	return home
}

// --- helpers ---

func TestFirstNonEmpty(t *testing.T) {
	assert.Equal(t, "", firstNonEmpty())
	assert.Equal(t, "", firstNonEmpty("", "  ", "\t"))
	assert.Equal(t, "b", firstNonEmpty("", "b", "c"))
	assert.Equal(t, " padded ", firstNonEmpty(" padded "),
		"the original (untrimmed) value is returned so callers can trim once")
}

func TestIsValidSSHAlgorithm(t *testing.T) {
	for _, ok := range []string{"ed25519", "rsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"} {
		assert.True(t, isValidSSHAlgorithm(ok), "%q must be accepted", ok)
	}
	for _, bad := range []string{"", "ED25519", "dsa", "ecdsa", "ecdsa-p224", "rsa4096"} {
		assert.False(t, isValidSSHAlgorithm(bad), "%q must be rejected", bad)
	}
}

func TestDefaultOwner_Precedence(t *testing.T) {
	t.Setenv("USER", "alice")
	t.Setenv("LOGNAME", "bob")
	assert.Equal(t, "alice", defaultOwner())

	t.Setenv("USER", "  ")
	assert.Equal(t, "bob", defaultOwner(), "a blank USER must fall through to LOGNAME")

	t.Setenv("LOGNAME", "")
	assert.Equal(t, "default", defaultOwner())
}

func TestReadKeySelector_DefaultsAndValidation(t *testing.T) {
	t.Setenv("USER", "alice")

	cmd, _ := sshTestCmd(t)
	_, _, _, err := readKeySelector(cmd)
	assert.ErrorIs(t, err, ErrSSHMissingKeyName)

	setSSHFlags(t, cmd, map[string]string{"name": "laptop"})
	scope, owner, name, err := readKeySelector(cmd)
	require.NoError(t, err)
	assert.Equal(t, "user", scope, "scope defaults to user")
	assert.Equal(t, "alice", owner, "owner defaults to $USER")
	assert.Equal(t, "laptop", name)

	setSSHFlags(t, cmd, map[string]string{"scope": "host", "owner": "svc"})
	scope, owner, _, err = readKeySelector(cmd)
	require.NoError(t, err)
	assert.Equal(t, "host", scope)
	assert.Equal(t, "svc", owner)
}

func TestPrintGeneratedKey_NilAndPopulated(t *testing.T) {
	cmd, buf := sshTestCmd(t)

	printGeneratedKey(cmd, nil)
	assert.Empty(t, buf.String(), "a nil key must print nothing rather than a blank record")
}

func TestSSHConfigError_MessageAndUnwrap(t *testing.T) {
	err := &SSHConfigError{Op: "read_pem", Err: os.ErrNotExist}
	assert.Equal(t, "ssh: config: read_pem: file does not exist", err.Error())
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// --- argument validation (no client construction required) ---

func TestSSHHandlers_RejectMissingRequiredFlags(t *testing.T) {
	tests := []struct {
		name string
		run  func(*cobra.Command, []string) error
		want error
	}{
		{"keys generate without name", runSSHKeysGenerate, ErrSSHMissingKeyName},
		{"keys get without name", runSSHKeysGet, ErrSSHMissingKeyName},
		{"keys delete without name", runSSHKeysDelete, ErrSSHMissingKeyName},
		{"keys export without name", runSSHKeysExport, ErrSSHMissingKeyName},
		{"host-keys add without host", runSSHHostKeysAdd, ErrSSHMissingHost},
		{"host-keys remove without host", runSSHHostKeysRemove, ErrSSHMissingHost},
		{"authorized add without name", runSSHAuthorizedAdd, ErrSSHMissingKeyName},
		{"authorized remove without name", runSSHAuthorizedRemove, ErrSSHMissingKeyName},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, _ := sshTestCmd(t)
			err := tt.run(cmd, []string{"unused"})
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestRunSSHHostKeysAdd_RequiresHostKey(t *testing.T) {
	cmd, _ := sshTestCmd(t)
	setSSHFlags(t, cmd, map[string]string{"host": "bastion.example.com"})

	err := runSSHHostKeysAdd(cmd, nil)
	assert.ErrorIs(t, err, ErrSSHMissingHostKey,
		"a pin without a public key would pin nothing and must be refused")
}

func TestRunSSHKeysGenerate_RejectsUnsupportedAlgorithm(t *testing.T) {
	cmd, _ := sshTestCmd(t)
	setSSHFlags(t, cmd, map[string]string{"name": "laptop", "type": "dsa"})

	err := runSSHKeysGenerate(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSSHInvalidKeyType)
	assert.Contains(t, err.Error(), `"dsa"`)
}

func TestRunSSHKeysImport_MissingFileIsReported(t *testing.T) {
	withEmbeddedSSHStore(t)
	cmd, _ := sshTestCmd(t)

	err := runSSHKeysImport(cmd, []string{filepath.Join(t.TempDir(), "absent.pem")})
	require.Error(t, err)

	var cfgErr *SSHConfigError
	require.ErrorAs(t, err, &cfgErr)
	assert.Equal(t, "read_pem", cfgErr.Op)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// --- embedded round trips ---

func TestSSHKeys_GenerateListGetExportDelete(t *testing.T) {
	withEmbeddedSSHStore(t)

	gen, genBuf := sshTestCmd(t)
	setSSHFlags(t, gen, map[string]string{
		"scope": "user", "owner": "alice", "name": "laptop",
		"type": "ed25519", "comment": "alice@laptop",
	})
	require.NoError(t, runSSHKeysGenerate(gen, nil))

	genOut := genBuf.String()
	assert.Contains(t, genOut, "Key: user/alice/laptop")
	assert.Contains(t, genOut, "Fingerprint: SHA256:")
	assert.Contains(t, genOut, "Comment:     alice@laptop")
	assert.Contains(t, genOut, "Public:      ssh-ed25519 ")

	list, listBuf := sshTestCmd(t)
	setSSHFlags(t, list, map[string]string{"scope": "user", "owner": "alice"})
	require.NoError(t, runSSHKeysList(list, nil))
	assert.Contains(t, listBuf.String(), "user/alice/laptop")

	get, getBuf := sshTestCmd(t)
	setSSHFlags(t, get, map[string]string{"scope": "user", "owner": "alice", "name": "laptop"})
	require.NoError(t, runSSHKeysGet(get, nil))
	assert.Contains(t, getBuf.String(), "Key: user/alice/laptop")

	export, exportBuf := sshTestCmd(t)
	setSSHFlags(t, export, map[string]string{"scope": "user", "owner": "alice", "name": "laptop"})
	require.NoError(t, runSSHKeysExport(export, nil))
	assert.True(t, strings.HasPrefix(strings.TrimSpace(exportBuf.String()), "ssh-ed25519 "),
		"export must emit an authorized_keys line, got %q", exportBuf.String())

	del, delBuf := sshTestCmd(t)
	setSSHFlags(t, del, map[string]string{"scope": "user", "owner": "alice", "name": "laptop"})
	require.NoError(t, runSSHKeysDelete(del, nil))
	assert.Contains(t, delBuf.String(), "Deleted user/alice/laptop")

	after, afterBuf := sshTestCmd(t)
	setSSHFlags(t, after, map[string]string{"scope": "user", "owner": "alice"})
	require.NoError(t, runSSHKeysList(after, nil))
	assert.Contains(t, afterBuf.String(), "No SSH keys found.")
}

func TestSSHKeys_GetMissingKeyFails(t *testing.T) {
	withEmbeddedSSHStore(t)

	cmd, _ := sshTestCmd(t)
	setSSHFlags(t, cmd, map[string]string{"scope": "user", "owner": "alice", "name": "absent"})
	assert.Error(t, runSSHKeysGet(cmd, nil))
}

func TestSSHKeys_GenerateDefaultsScopeOwnerAlgorithm(t *testing.T) {
	withEmbeddedSSHStore(t)
	t.Setenv("USER", "carol")

	gen, buf := sshTestCmd(t)
	setSSHFlags(t, gen, map[string]string{"name": "default-key"})
	require.NoError(t, runSSHKeysGenerate(gen, nil))

	out := buf.String()
	assert.Contains(t, out, "Key: user/carol/default-key",
		"scope must default to user and owner to $USER")
	assert.Contains(t, out, "Algorithm:   ed25519")
}

// randomHostKeyLine generates an ed25519 keypair and returns its
// authorized_keys-format line together with its OpenSSH SHA256
// fingerprint. Host-key pins now require the full key, so tests can no
// longer pin a synthetic fingerprint string.
func randomHostKeyLine(t *testing.T) (line, fingerprint string) {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)

	line = strings.TrimRight(string(gossh.MarshalAuthorizedKey(sshPub)), "\n")
	return line, gossh.FingerprintSHA256(sshPub)
}

func TestSSHHostKeys_AddListRemove(t *testing.T) {
	withEmbeddedSSHStore(t)

	line, fingerprint := randomHostKeyLine(t)

	add, addBuf := sshTestCmd(t)
	setSSHFlags(t, add, map[string]string{
		"scope": "user", "owner": "alice",
		"host": "bastion.example.com", "key": line,
		"source": "tofu",
	})
	require.NoError(t, runSSHHostKeysAdd(add, nil))
	assert.Contains(t, addBuf.String(), "Pinned bastion.example.com -> "+fingerprint)

	list, listBuf := sshTestCmd(t)
	setSSHFlags(t, list, map[string]string{"scope": "user", "owner": "alice"})
	require.NoError(t, runSSHHostKeysList(list, nil))
	listOut := listBuf.String()
	assert.Contains(t, listOut, "bastion.example.com")
	assert.Contains(t, listOut, fingerprint)
	assert.Contains(t, listOut, "ssh-ed25519")

	remove, removeBuf := sshTestCmd(t)
	setSSHFlags(t, remove, map[string]string{
		"scope": "user", "owner": "alice", "host": "bastion.example.com",
	})
	require.NoError(t, runSSHHostKeysRemove(remove, nil))
	assert.Contains(t, removeBuf.String(), "Removed pin for bastion.example.com")

	after, afterBuf := sshTestCmd(t)
	setSSHFlags(t, after, map[string]string{"scope": "user", "owner": "alice"})
	require.NoError(t, runSSHHostKeysList(after, nil))
	assert.Contains(t, afterBuf.String(), "No host-key pins found.")
}

func TestSSHAuthorizedKeys_AddListRemove(t *testing.T) {
	withEmbeddedSSHStore(t)

	// Generate a key so we have a genuine authorized_keys line to file.
	gen, genBuf := sshTestCmd(t)
	setSSHFlags(t, gen, map[string]string{
		"scope": "user", "owner": "alice", "name": "src", "type": "ed25519",
	})
	require.NoError(t, runSSHKeysGenerate(gen, nil))

	line := extractPublicLine(t, genBuf.String())

	add, addBuf := sshTestCmd(t)
	setSSHFlags(t, add, map[string]string{"scope": "user", "owner": "alice", "name": "entry1"})
	require.NoError(t, runSSHAuthorizedAdd(add, []string{line}))
	assert.Contains(t, addBuf.String(), "Added authorized entry user/alice/entry1")

	list, listBuf := sshTestCmd(t)
	setSSHFlags(t, list, map[string]string{"scope": "user", "owner": "alice"})
	require.NoError(t, runSSHAuthorizedList(list, nil))
	assert.Contains(t, listBuf.String(), "ssh-ed25519 ")

	remove, removeBuf := sshTestCmd(t)
	setSSHFlags(t, remove, map[string]string{"scope": "user", "owner": "alice", "name": "entry1"})
	require.NoError(t, runSSHAuthorizedRemove(remove, nil))
	assert.Contains(t, removeBuf.String(), "Removed authorized entry user/alice/entry1")

	after, afterBuf := sshTestCmd(t)
	setSSHFlags(t, after, map[string]string{"scope": "user", "owner": "alice"})
	require.NoError(t, runSSHAuthorizedList(after, nil))
	assert.Contains(t, afterBuf.String(), "No authorized entries.")
}

// extractPublicLine pulls the "Public:      <line>" value out of the
// generate command's output.
func extractPublicLine(t *testing.T, out string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if idx := strings.Index(l, "Public:"); idx >= 0 {
			return strings.TrimSpace(l[idx+len("Public:"):])
		}
	}
	t.Fatalf("no Public: line in %q", out)
	return ""
}

// --- barrier-encrypted store refusal ---

func TestSSHHandlers_RefuseBarrierEncryptedStore(t *testing.T) {
	home := withEmbeddedSSHStore(t)

	// Simulate an initialized barrier over the SSH store root.
	dataDir := filepath.Join(home, ".xkey-store")
	keyPath := filepath.Join(dataDir, defaultBarrierRootKeyPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(keyPath), 0700))
	require.NoError(t, os.WriteFile(keyPath, []byte("sealed"), 0600))

	tests := []struct {
		name  string
		run   func(*cobra.Command, []string) error
		flags map[string]string
		args  []string
	}{
		{"keys list", runSSHKeysList, nil, nil},
		{"keys generate", runSSHKeysGenerate, map[string]string{"name": "k"}, nil},
		{"host-keys list", runSSHHostKeysList, nil, nil},
		{"authorized list", runSSHAuthorizedList, nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, _ := sshTestCmd(t)
			setSSHFlags(t, cmd, tt.flags)
			err := tt.run(cmd, tt.args)
			assert.ErrorIs(t, err, ErrSSHStoreBarrierEncrypted,
				"the CLI must refuse rather than silently open a plaintext store")
		})
	}
}

// --- transport selection ---

func TestSSHClientForEndpoint_RejectsUnknownScheme(t *testing.T) {
	_, _, err := sshClientForEndpoint(XKMSdEndpoint{URL: "gopher://example.com"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSSHClientConstruct)
}

func TestSSHClientForEndpoint_BadTLSMaterialFails(t *testing.T) {
	_, _, err := sshClientForEndpoint(XKMSdEndpoint{URL: "grpcs://127.0.0.1:1", TLSCAFile: "/nonexistent/ca.pem"})
	assert.ErrorIs(t, err, ErrXKMSdTLSConfigFailed)
}

func TestSSHClient_ConfiguredServerPresentsStoredLogin(t *testing.T) {
	withEmbeddedSSHStore(t)
	target := newLoginTarget(t, `{"items":[]}`)
	t.Setenv(envXKMSdTLSCA, target.caFile)
	xkmsdURL = target.srv.URL
	storeLogin(t, &tokenstore.TokenEntry{ServerURL: target.srv.URL, ServerID: target.id(), Token: "login.jwt", ExpiresAt: time.Now().Add(time.Hour)})

	cmd, _ := sshTestCmd(t)
	client, closer, err := sshClient(cmd)
	require.NoError(t, err)
	defer closer()
	_, err = client.Keys().List(context.Background(), sshsdk.ListKeysRequest{Scope: "user", Owner: "alice"})
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer login.jwt"}, target.authorizations())
}

func TestSSHClient_LocalFlagKeepsLocalStore(t *testing.T) {
	withEmbeddedSSHStore(t)
	target := newLoginTarget(t, `{"items":[]}`)
	xkmsdURL = target.srv.URL

	cmd, _ := sshTestCmd(t)
	setSSHFlags(t, cmd, map[string]string{"local": "true"})
	client, closer, err := sshClient(cmd)
	require.NoError(t, err)
	defer closer()
	_, err = client.Keys().List(context.Background(), sshsdk.ListKeysRequest{Scope: "user", Owner: "alice"})
	require.NoError(t, err)
	assert.Empty(t, target.authorizations(), "--local never reaches the configured server")
}

func TestSSHClient_ExpiredLoginFails(t *testing.T) {
	withEmbeddedSSHStore(t)
	target := newLoginTarget(t, `{"items":[]}`)
	t.Setenv(envXKMSdTLSCA, target.caFile)
	xkmsdURL = target.srv.URL
	storeLogin(t, &tokenstore.TokenEntry{ServerURL: target.srv.URL, ServerID: target.id(), Token: "old", ExpiresAt: time.Now().Add(-time.Minute)})

	cmd, _ := sshTestCmd(t)
	_, _, err := sshClient(cmd)
	assert.ErrorIs(t, err, tokenstore.ErrTokenExpired)
}

func TestSSHTestCmdFlagsMatchRealCommandFlags(t *testing.T) {
	// Guard the test harness itself: if a handler starts reading a flag the
	// harness does not define, cmd.Flags().GetString silently returns "" and
	// the tests above would stop proving anything.
	defined := map[string]bool{}
	cmd, _ := sshTestCmd(t)
	cmd.Flags().VisitAll(func(f *pflag.Flag) { defined[f.Name] = true })

	for _, sub := range []*cobra.Command{
		sshKeysGenerateCmd, sshKeysImportCmd, sshKeysListCmd, sshKeysGetCmd,
		sshKeysDeleteCmd, sshKeysExportCmd,
	} {
		sub.Flags().VisitAll(func(f *pflag.Flag) {
			assert.True(t, defined[f.Name],
				"%s defines --%s which the test harness does not model", sub.Name(), f.Name)
		})
	}
}
