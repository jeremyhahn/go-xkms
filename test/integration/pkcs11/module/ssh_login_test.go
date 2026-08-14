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

//go:build integration && pkcs11 && pkcs11_tool
// +build integration,pkcs11,pkcs11_tool

// Package module authenticates to a real sshd with private keys that never
// leave the module, across every key type and signature algorithm OpenSSH will
// negotiate for a PKCS#11 token.
//
// openssl_ssh_test.go proves ssh-keygen -D can LIST a token key of each type,
// and completes one real login — with Ed25519. Listing a public key exercises
// C_GetAttributeValue and nothing else; it says nothing about whether the token
// can sign an SSH authentication request. So RSA and ECDSA, the two key types
// overwhelmingly deployed on smartcards and HSMs, had no end-to-end proof at
// all.
//
// The RSA case matters most and is the reason this file exists. OpenSSH has
// deprecated the SHA-1 "ssh-rsa" signature algorithm, and a current sshd
// negotiates rsa-sha2-256 or rsa-sha2-512 with the same ssh-rsa public key.
// Those are different PKCS#11 mechanisms (CKM_SHA256_RSA_PKCS,
// CKM_SHA512_RSA_PKCS), so a module that only implements the SHA-1 form lists
// correctly, loads into the agent correctly, and then cannot log in anywhere
// modern. Each algorithm is therefore pinned on both ends — sshd's
// PubkeyAcceptedAlgorithms and the client's — so a successful login cannot have
// used a different one.
//
// Every case here restricts authorized_keys to the single key under test, so a
// login is attributable to that key and no other.
//
// Build tags: integration,pkcs11,pkcs11_tool
package module

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestSSH_AuthenticatesWithRSATokenKey logs into a real sshd with an RSA key
// held in the module, once per signature algorithm OpenSSH offers for it.
func TestSSH_AuthenticatesWithRSATokenKey(t *testing.T) {
	requireFilePersistence(t)
	requireSSHKeygen(t)
	requireTool(t)

	cfg := NewSSHTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const keyLabel = "ssh-login-rsa"
	_, stderr, err := runPKCS11ToolCommand(t, p11,
		"--login", "--pin", p11.PIN, "--slot", p11.SlotID,
		"--keypairgen", "--key-type", "rsa:2048",
		"--label", keyLabel, "--id", "a0",
	)
	require.NoErrorf(t, err, "generating the RSA login key failed: %s", stderr)

	keys := listSSHTokenKeys(t, cfg.ModulePath)
	key := findSSHTokenKey(t, keys, keyLabel)
	require.Equal(t, ssh.KeyAlgoRSA, key.Algo,
		"a 2048-bit RSA token key must be published as %s", ssh.KeyAlgoRSA)

	// The public key ssh-keygen exported must be the one the token holds, or a
	// login below would prove only that some key on the token works.
	requireSSHKeyMatchesToken(t, p11, key, keyLabel)

	startTokenSSHAgent(t, cfg.ModulePath, cfg.PIN)

	// rsa-sha2-512 and rsa-sha2-256 are what a current sshd negotiates; ssh-rsa
	// is the SHA-1 form, still needed by older peers and still advertised by
	// this module, so all three are exercised rather than assumed.
	for _, algo := range []string{
		ssh.KeyAlgoRSASHA512,
		ssh.KeyAlgoRSASHA256,
		ssh.KeyAlgoRSA,
	} {
		t.Run(algo, func(t *testing.T) {
			output := sshLoginWithAlgorithm(t, key, algo)
			assert.Contains(t, output, sshLoginMarker,
				"the remote command did not run, so the login did not complete")
		})
	}
}

// TestSSH_AuthenticatesWithECDSATokenKey logs into a real sshd with an ECDSA key
// held in the module, on each curve OpenSSH supports.
//
// Each curve is a distinct SSH algorithm name bound to a distinct digest
// (nistp256/SHA-256, nistp384/SHA-384, nistp521/SHA-512), and OpenSSH rejects a
// signature made under the wrong pairing, so a login is proof the module chose
// the right mechanism for the curve.
func TestSSH_AuthenticatesWithECDSATokenKey(t *testing.T) {
	requireFilePersistence(t)
	requireSSHKeygen(t)
	requireTool(t)

	cfg := NewSSHTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	curves := []struct {
		label   string
		keyType string
		id      string
		algo    string
	}{
		{"ssh-login-p256", "EC:secp256r1", "a1", ssh.KeyAlgoECDSA256},
		{"ssh-login-p384", "EC:secp384r1", "a2", ssh.KeyAlgoECDSA384},
		{"ssh-login-p521", "EC:secp521r1", "a3", ssh.KeyAlgoECDSA521},
	}

	for _, c := range curves {
		_, stderr, err := runPKCS11ToolCommand(t, p11,
			"--login", "--pin", p11.PIN, "--slot", p11.SlotID,
			"--keypairgen", "--key-type", c.keyType,
			"--label", c.label, "--id", c.id,
		)
		require.NoErrorf(t, err, "generating %s failed: %s", c.label, stderr)
	}

	keys := listSSHTokenKeys(t, cfg.ModulePath)

	// One agent for all three: it is loaded with the module, not with
	// individual keys, so every token key is reachable through it.
	startTokenSSHAgent(t, cfg.ModulePath, cfg.PIN)

	for _, c := range curves {
		t.Run(c.algo, func(t *testing.T) {
			key := findSSHTokenKey(t, keys, c.label)
			require.Equalf(t, c.algo, key.Algo,
				"the token key %q was generated as %s, so ssh-keygen must publish "+
					"it as %s", c.label, c.keyType, c.algo)

			output := sshLoginWithAlgorithm(t, key, c.algo)
			assert.Contains(t, output, sshLoginMarker,
				"the remote command did not run, so the login did not complete")
		})
	}
}

// TestSSH_AuthenticatesWithoutAgent logs in with `ssh -I <module>`, which loads
// the PKCS#11 library into the ssh client itself.
//
// Every other SSH test in this suite reaches the token through ssh-agent, which
// forks ssh-pkcs11-helper as a separate process. `ssh -I` is the other supported
// route and a different consumer: the ssh client dlopen()s the module in its own
// address space and drives it directly, with no helper and no agent protocol in
// between. A module that is only ever exercised under the helper has not been
// shown to work here.
//
// BatchMode is deliberately not used. The ssh client reads the token PIN through
// the ordinary passphrase path, which BatchMode suppresses outright, and the
// client then reports "provider returned no keys" and falls through to a denial
// — SoftHSM behaves identically under the same invocation, so this is OpenSSH's
// behaviour and not the module's. NumberOfPasswordPrompts=0 keeps the run
// non-interactive without disabling the askpass helper.
func TestSSH_AuthenticatesWithoutAgent(t *testing.T) {
	requireFilePersistence(t)
	requireSSHKeygen(t)
	requireTool(t)

	cfg := NewSSHTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const keyLabel = "ssh-login-direct"
	_, stderr, err := runPKCS11ToolCommand(t, p11,
		"--login", "--pin", p11.PIN, "--slot", p11.SlotID,
		"--keypairgen", "--key-type", "EC:secp256r1",
		"--label", keyLabel, "--id", "a4",
	)
	require.NoErrorf(t, err, "generating the direct-login key failed: %s", stderr)

	keys := listSSHTokenKeys(t, cfg.ModulePath)
	key := findSSHTokenKey(t, keys, keyLabel)
	require.Equal(t, ssh.KeyAlgoECDSA256, key.Algo)

	server := startTestSSHD(t, key, ssh.KeyAlgoECDSA256)

	me, err := user.Current()
	require.NoError(t, err)

	login := exec.Command("ssh",
		"-F", "/dev/null",
		"-p", strconv.Itoa(server.Port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "NumberOfPasswordPrompts=0",
		"-o", "PubkeyAcceptedAlgorithms="+ssh.KeyAlgoECDSA256,
		// No agent: the module must be driven by the ssh client itself.
		"-o", "IdentityAgent=none",
		"-I", cfg.ModulePath,
		me.Username+"@127.0.0.1",
		"echo "+sshLoginMarker,
	)
	login.Env = askpassEnv(t, cfg.PIN)
	login.Stdin = bytes.NewReader(nil)

	out, err := login.CombinedOutput()
	require.NoErrorf(t, err,
		"logging in with `ssh -I %s` failed: %v\nssh output:\n%s\nsshd log:\n%s",
		cfg.ModulePath, err, out, server.Log())

	assert.Contains(t, string(out), sshLoginMarker,
		"the remote command did not run, so the login did not complete")
}

// testSSHD is a running sshd owned by a test.
type testSSHD struct {
	// Port is the loopback port it accepts on.
	Port int

	// output accumulates its log, which is the only useful evidence when an
	// authentication is refused.
	output *bytes.Buffer
}

// Log returns everything the server has written so far.
func (s *testSSHD) Log() string {
	return s.output.String()
}

// startTestSSHD stands up an sshd that trusts exactly one key and accepts
// exactly one public-key algorithm, and stops it when the test ends.
//
// Restricting both is what makes a successful login attributable: authorized_keys
// holds nothing but this key, and PubkeyAcceptedAlgorithms admits nothing but
// this algorithm, so the token must have produced a valid signature of that
// exact form.
func startTestSSHD(t *testing.T, key sshTokenKey, algorithm string) *testSSHD {
	t.Helper()

	dir := shortTempDir(t, "p11sshd")
	hostKey := filepath.Join(dir, "hostkey")
	authKeys := filepath.Join(dir, "authorized_keys")
	sshdConf := filepath.Join(dir, "sshd_config")

	_, stderr, err := runSSHKeygenCommand(t, "-q", "-t", "ed25519", "-f", hostKey, "-N", "")
	require.NoErrorf(t, err, "generating a host key for the test sshd: %s", stderr)

	require.NoError(t, os.WriteFile(authKeys, []byte(key.Line+"\n"), 0o600))

	me, err := user.Current()
	require.NoError(t, err, "determining the user the test sshd must authenticate")

	port := freeTCPPort(t)
	conf := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
AuthorizedKeysFile %s
AllowUsers %s
PubkeyAuthentication yes
PubkeyAcceptedAlgorithms %s
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
MaxAuthTries 50
LogLevel VERBOSE
`, port, hostKey, authKeys, me.Username, algorithm)
	require.NoError(t, os.WriteFile(sshdConf, []byte(conf), 0o600))

	output := &bytes.Buffer{}

	// -D keeps sshd in the foreground so the test owns its lifetime; -e sends
	// its log to stderr, which is captured for the failure message.
	sshd := exec.Command(sshdBinary(t), "-D", "-e", "-f", sshdConf)
	sshd.Stdout = output
	sshd.Stderr = output
	require.NoError(t, sshd.Start(), "starting the test sshd")
	t.Cleanup(func() {
		if err := sshd.Process.Kill(); err != nil {
			t.Logf("stopping the test sshd: %v", err)
		}
		_ = sshd.Wait()
	})

	waitForTCP(t, port)

	return &testSSHD{Port: port, output: output}
}

// sshLoginWithAlgorithm logs into a purpose-built sshd using the agent-held
// token key, pinned to one public-key algorithm on both ends, and returns the
// remote command's output.
//
// The caller must have started an ssh-agent holding the module
// (startTokenSSHAgent), which sets SSH_AUTH_SOCK for the rest of the test.
func sshLoginWithAlgorithm(t *testing.T, key sshTokenKey, algorithm string) string {
	t.Helper()

	server := startTestSSHD(t, key, algorithm)

	me, err := user.Current()
	require.NoError(t, err)

	agentSock := os.Getenv("SSH_AUTH_SOCK")
	require.NotEmpty(t, agentSock,
		"no ssh-agent is running for this test; call startTokenSSHAgent first")

	login := exec.Command("ssh",
		"-F", "/dev/null",
		"-p", strconv.Itoa(server.Port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "PubkeyAcceptedAlgorithms="+algorithm,
		"-o", "IdentityAgent="+agentSock,
		me.Username+"@127.0.0.1",
		"echo "+sshLoginMarker,
	)
	login.Env = os.Environ()

	out, err := login.CombinedOutput()
	require.NoErrorf(t, err,
		"logging in with the token-resident key under %s failed: %v\n"+
			"ssh output:\n%s\nsshd log:\n%s",
		algorithm, err, out, server.Log())

	return string(out)
}
