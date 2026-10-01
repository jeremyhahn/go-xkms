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

//go:build integration && passwordvault

package password

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// softhsmLibrary is the SoftHSM PKCS#11 module of the devcontainer.
const softhsmLibrary = "/usr/lib/softhsm/libsofthsm2.so"

// pivPIN is the user PIN of the test tokens.
const pivPIN = "123456"

// softToken is a SoftHSM token standing in for a PIV card: its own token
// directory and configuration, so tokens of different tests never mix.
type softToken struct {
	label string
	conf  string
}

// newSoftToken initializes an empty SoftHSM token labelled label.
func newSoftToken(t *testing.T, label string) *softToken {
	t.Helper()
	dir := t.TempDir()
	tokens := filepath.Join(dir, "tokens")
	require.NoError(t, os.MkdirAll(tokens, 0o700))
	conf := filepath.Join(dir, "softhsm2.conf")
	require.NoError(t, os.WriteFile(conf, []byte(fmt.Sprintf("directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n", tokens)), 0o600))
	cmd := exec.Command("softhsm2-util", "--init-token", "--free", "--label", label, "--so-pin", "12345678", "--pin", pivPIN)
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+conf)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "softhsm2-util --init-token:\n%s", out)
	return &softToken{label: label, conf: conf}
}

// env is the environment that points xkey's PIV backend at the token.
func (s *softToken) env() []string {
	return []string{
		"SOFTHSM2_CONF=" + s.conf,
		"XKEY_PIV_PKCS11_PIN=" + pivPIN,
	}
}

// pivArgs are the PIV flags naming the token.
func (s *softToken) pivArgs() []string {
	return []string{"--backend", "pkcs11", "--pkcs11-library", softhsmLibrary, "--pkcs11-token", s.label}
}

// generate9d generates the token's key management key, PIV slot 9d, with
// "xkey piv generate", as an operator provisions a card.
func (s *softToken) generate9d(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	vars := append([]string{"HOME=" + home, "XKEY_HOME=" + home, "XKEY_DATA_DIR=" + filepath.Join(home, "data"), "XKMSD_URL="}, s.env()...)
	args := append([]string{"piv", "generate", "9d", "--algorithm", "ECCP256"}, s.pivArgs()...)
	out, err := runXKey(t, vars, "", args...)
	require.NoError(t, err, "xkey piv generate 9d:\n%s", out)
}

// xkey runs xkey as the user against the server, with vars added to its
// environment.
func (u *vaultUser) xkey(t *testing.T, vars []string, stdin string, args ...string) (string, error) {
	t.Helper()
	env := append([]string{
		"HOME=" + u.home, "XKEY_HOME=" + u.home, "XKEY_DATA_DIR=" + filepath.Join(u.home, "data"),
		"XKMSD_URL=" + vault.server.URL,
		"XKMSD_TLS_CA=" + vault.server.CAFile,
		"XKMSD_TLS_CERT=" + u.cert,
		"XKMSD_TLS_KEY=" + u.key,
	}, vars...)
	return runXKey(t, env, stdin, args...)
}

// TestVault_PIVOnPKCS11 enrolls the PIV slot 9d key of a SoftHSM token with
// xkey -- PIV and PKCS#11 factors are xkey's, xkmsctl has no PKCS#11 -- and
// unlocks with the token; another token's 9d key, and a token without one,
// are refused.
func TestVault_PIVOnPKCS11(t *testing.T) {
	u := newUser(t, "vault-piv")
	card := newSoftToken(t, "vault-piv")
	card.generate9d(t)

	out, err := u.xkey(t, card.env(), "", append([]string{"password", "vault", "enroll", "--key-factor", "piv",
		"--key-backend", "pkcs11", "--label", "PIV card"}, card.pivArgs()[2:]...)...)
	require.NoError(t, err, out)
	recoveryCodeOf(t, out)
	assert.Equal(t, 1, u.factors(t, "piv"))
	u.lock(t)

	unlockWith := func(token *softToken) (string, error) {
		return u.xkey(t, token.env(), "", append([]string{"password", "unlock", "--key"}, token.pivArgs()[2:]...)...)
	}
	t.Run("wrong token", func(t *testing.T) {
		other := newSoftToken(t, "vault-piv")
		other.generate9d(t)
		out, err := unlockWith(other)
		require.Error(t, err, out)
		assert.Contains(t, out, "none of the vault's key factors has its token here")
		u.requireLocked(t)
	})
	t.Run("missing token", func(t *testing.T) {
		out, err := unlockWith(newSoftToken(t, "vault-piv"))
		require.Error(t, err, out)
		assert.Contains(t, out, "none of the vault's key factors has its token here")
		u.requireLocked(t)
	})
	t.Run("right token", func(t *testing.T) {
		out, err := unlockWith(card)
		require.NoError(t, err, out)
		u.requireUnlocked(t)
	})
}
