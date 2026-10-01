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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// vaultUser is a user of the test server: an account activated with a
// client certificate the server's CA issued, as an operator onboards one
// (xkmsctl ca sign-csr, user register, invite redeem --method piv).
type vaultUser struct {
	name string
	cert string
	key  string
	// home is the user's xkey home.
	home string
}

// passphrase is the vault passphrase the tests enroll.
const passphrase = "correct horse battery staple"

// newUser onboards a fresh user with the built-in "user" role, so every test
// starts with an empty vault.
func newUser(t *testing.T, name string) *vaultUser {
	t.Helper()
	return newUserWithRole(t, name, "user")
}

// newUserWithRole onboards a fresh user holding role. Storing an entry
// takes passwords:write, which the built-in "user" role does not hold.
func newUserWithRole(t *testing.T, name, role string) *vaultUser {
	t.Helper()
	dir := t.TempDir()
	u := &vaultUser{
		name: name,
		cert: filepath.Join(dir, "client.pem"),
		key:  filepath.Join(dir, "client.key"),
		home: filepath.Join(dir, "xkey"),
	}
	require.NoError(t, os.MkdirAll(u.home, 0o700))

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	writePEM(t, u.key, "PRIVATE KEY", der)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, priv)
	require.NoError(t, err)
	csrFile := filepath.Join(dir, "client.csr")
	writePEM(t, csrFile, "CERTIFICATE REQUEST", csr)

	admin := &vaultUser{name: "admin", cert: vault.server.AdminCert, key: vault.server.AdminKey}
	admin.mustCtl(t, "", "ca", "sign-csr", "--csr", csrFile, "--profile", "client", "--output", u.cert)
	out := admin.mustCtl(t, "", "user", "register", name, "--email", name+"@vault.test", "--role", role, "-o", "json")
	tenant, token := inviteOf(t, out)
	anon := &vaultUser{name: "invitee"}
	anon.mustCtl(t, "", "user", "invite", "redeem", token, "--tenant-id", tenant, "--method", "piv", "--piv-cert-file", u.cert)
	return u
}

// inviteOf returns the tenant and token of the invitation in the JSON
// documents "xkmsctl user register -o json" prints.
func inviteOf(t *testing.T, out string) (tenant, token string) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(out))
	for {
		var doc struct {
			Token string `json:"invite_token"`
			URL   string `json:"invite_url"`
		}
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, out)
		if doc.Token != "" {
			// The link is /#/invite/<tenant>/<token>.
			parts := strings.Split(strings.Trim(doc.URL, "/"), "/")
			require.GreaterOrEqual(t, len(parts), 2, doc.URL)
			return parts[len(parts)-2], doc.Token
		}
	}
	require.Fail(t, "no invitation in the register output", out)
	return "", ""
}

// ctl runs xkmsctl as the user against the server, with stdin, and returns
// its combined output.
func (u *vaultUser) ctl(stdin string, args ...string) (string, error) {
	full := []string{"--server", vault.server.URL, "--tls-ca", vault.server.CAFile}
	if u.cert != "" {
		full = append(full, "--tls-cert", u.cert, "--tls-key", u.key)
	}
	cmd := exec.Command(vault.xkmsctl, append(full, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// mustCtl is ctl, failing the test unless xkmsctl succeeds.
func (u *vaultUser) mustCtl(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	out, err := u.ctl(stdin, args...)
	require.NoError(t, err, "xkmsctl %s:\n%s", strings.Join(args, " "), out)
	return out
}

// vaultStatus is the JSON of "xkmsctl password vault status".
type vaultStatus struct {
	Initialized bool `json:"initialized"`
	Unlocked    bool `json:"unlocked"`
	Factors     []struct {
		ID     string `json:"id"`
		Factor string `json:"factor"`
		Label  string `json:"label"`
		KeyRef struct {
			Backend   string `json:"backend"`
			KeyID     string `json:"key_id"`
			TPMPolicy string `json:"tpm_policy"`
		} `json:"key_ref"`
	} `json:"factors"`
	PasskeyRPID string `json:"passkey_rp_id"`
}

// status returns the user's vault status.
func (u *vaultUser) status(t *testing.T) vaultStatus {
	t.Helper()
	out := u.mustCtl(t, "", "password", "vault", "status", "-o", "json")
	var s vaultStatus
	require.NoError(t, json.Unmarshal([]byte(out), &s), out)
	return s
}

// factors returns the user's vault factors of type factor.
func (u *vaultUser) factors(t *testing.T, factor string) int {
	t.Helper()
	n := 0
	for _, f := range u.status(t).Factors {
		if f.Factor == factor {
			n++
		}
	}
	return n
}

// lock ends the user's vault session.
func (u *vaultUser) lock(t *testing.T) {
	t.Helper()
	u.mustCtl(t, "", "password", "lock")
	require.False(t, u.status(t).Unlocked, "the vault is locked")
}

// requireLocked fails the test unless the user's vault is locked: a refused
// unlock must not open it.
func (u *vaultUser) requireLocked(t *testing.T) {
	t.Helper()
	require.False(t, u.status(t).Unlocked, "the refused unlock left the vault locked")
}

// requireUnlocked fails the test unless the user's vault is unlocked.
func (u *vaultUser) requireUnlocked(t *testing.T) {
	t.Helper()
	require.True(t, u.status(t).Unlocked, "the vault is unlocked")
}

// enrollPassphrase enrolls the user's first factor, the passphrase, and
// returns the recovery code the first enrollment prints.
func (u *vaultUser) enrollPassphrase(t *testing.T) string {
	t.Helper()
	out := u.mustCtl(t, passphrase, "password", "vault", "enroll", "--label", "laptop", "--passphrase", "-")
	return recoveryCodeOf(t, out)
}

// recoveryCodeRE matches a recovery code: eight groups of four characters.
var recoveryCodeRE = regexp.MustCompile(`\b[A-Z0-9]{4}(?:-[A-Z0-9]{4}){7}\b`)

// recoveryCodeOf returns the recovery code an enrollment printed.
func recoveryCodeOf(t *testing.T, out string) string {
	t.Helper()
	require.Contains(t, out, "RECOVERY CODE", out)
	code := recoveryCodeRE.FindString(out)
	require.NotEmpty(t, code, out)
	return code
}

// writePEM writes one PEM block to path.
func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600))
}

// writeKeyPair writes an EC P-256 key and a self-signed certificate for it
// to dir, as an operator's client certificate would be, and returns the
// paths.
func writeKeyPair(t *testing.T, dir, name string) (keyFile, certFile string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	keyFile = filepath.Join(dir, name+".key")
	writePEM(t, keyFile, "PRIVATE KEY", der)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certFile = filepath.Join(dir, name+".pem")
	writePEM(t, certFile, "CERTIFICATE", certDER)
	return keyFile, certFile
}

// runXKeyIn runs xkey locally -- no xkmsd -- with its data directory in
// dataDir and a home of its own, and returns its combined output.
func runXKeyIn(t *testing.T, dataDir string, args ...string) (string, error) {
	t.Helper()
	home := t.TempDir()
	return runXKey(t, []string{"HOME=" + home, "XKEY_HOME=" + home, "XKEY_DATA_DIR=" + dataDir, "XKMSD_URL="}, "", args...)
}

// runXKey runs xkey with vars added to its environment and stdin as its
// standard input, and returns its combined output.
func runXKey(t *testing.T, vars []string, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(vault.xkey, args...)
	cmd.Env = append(os.Environ(), vars...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}
