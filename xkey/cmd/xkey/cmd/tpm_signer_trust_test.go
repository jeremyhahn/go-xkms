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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// recordingTPMSigner captures the options the tpmSigner adapter forwards to
// the TPM so the PSS wiring can be verified without a device.
type recordingTPMSigner struct {
	digest []byte
	opts   crypto.SignerOpts
	sig    []byte
	err    error
}

func (r *recordingTPMSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r.digest = digest
	r.opts = opts
	return r.sig, r.err
}

func TestTPMSigner_PublicReturnsConfiguredKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := &tpmSigner{pubKey: &key.PublicKey}
	assert.Equal(t, &key.PublicKey, signer.Public())
	assert.Implements(t, (*crypto.Signer)(nil), signer)
}

func TestTPMSigner_SignForwardsKeyAttributes(t *testing.T) {
	attrs := &xkms.KeyAttributes{CN: "idevid"}
	backend := &recordingTPMSigner{sig: []byte("signature")}
	signer := &tpmSigner{tpm: backend, keyAttrs: attrs}

	digest := []byte("0123456789abcdef0123456789abcdef")
	got, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, []byte("signature"), got)
	assert.Equal(t, digest, backend.digest)

	tpmOpts, ok := backend.opts.(*xkms.TPMSignerOpts)
	require.True(t, ok, "the adapter must wrap the caller's opts in TPMSignerOpts")
	assert.Same(t, attrs, tpmOpts.KeyAttributes,
		"the key attributes select which TPM key signs; they must be forwarded")
	assert.Nil(t, tpmOpts.PSSOptions, "PKCS#1 v1.5 signing must not set PSS options")
}

func TestTPMSigner_SignPropagatesPSSOptions(t *testing.T) {
	pss := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	backend := &recordingTPMSigner{sig: []byte("pss-signature")}
	signer := &tpmSigner{tpm: backend, keyAttrs: &xkms.KeyAttributes{CN: "idevid"}}

	_, err := signer.Sign(rand.Reader, []byte("digest"), pss)
	require.NoError(t, err)

	tpmOpts, ok := backend.opts.(*xkms.TPMSignerOpts)
	require.True(t, ok)
	assert.Same(t, pss, tpmOpts.PSSOptions,
		"IDevID uses SHA256-RSA-PSS; dropping the PSS options would produce a PKCS#1 v1.5 signature")
}

func TestTPMSigner_SignPropagatesError(t *testing.T) {
	backend := &recordingTPMSigner{err: errors.New("TPM_RC_AUTH_FAIL")}
	signer := &tpmSigner{tpm: backend, keyAttrs: &xkms.KeyAttributes{CN: "idevid"}}

	_, err := signer.Sign(rand.Reader, []byte("digest"), crypto.SHA256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TPM_RC_AUTH_FAIL")
}

// --- trust install / uninstall preconditions ---

func trustTestCmd(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: "trust-test"}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

func TestRunTrustInstall_RejectsUnknownFingerprint(t *testing.T) {
	resetViperForTest(t)
	viper.Set("trust.store_path", t.TempDir())

	cmd, _ := trustTestCmd(t)
	err := runTrustInstall(cmd, []string{strings.Repeat("ab", 32)})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTrustCertificateNotFound,
		"the OS trust store must not be touched for a certificate xkey does not hold")
}

func TestRunTrustUninstall_RejectsUnknownFingerprint(t *testing.T) {
	resetViperForTest(t)
	viper.Set("trust.store_path", t.TempDir())

	cmd, _ := trustTestCmd(t)
	err := runTrustUninstall(cmd, []string{strings.Repeat("cd", 32)})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTrustCertificateNotFound)
}

func TestRunTrustInstall_NormalisesFingerprintCase(t *testing.T) {
	resetViperForTest(t)
	viper.Set("trust.store_path", t.TempDir())

	upper := strings.ToUpper(strings.Repeat("ab", 32))

	cmd, _ := trustTestCmd(t)
	err := runTrustInstall(cmd, []string{"  " + upper + "  "})
	require.Error(t, err)
	// The reported fingerprint is lower-cased and trimmed, proving the
	// argument was normalised before the store lookup.
	assert.Contains(t, err.Error(), strings.ToLower(upper))
}
