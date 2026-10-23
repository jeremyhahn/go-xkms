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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

var errC704gTPMClose = errors.New("tpm close failure")

// c704gCertTPM answers IAKCertificate with a fixed certificate. Every other
// method is left to the nil embedded interface, so a call to one fails the
// test with a panic.
type c704gCertTPM struct {
	xkms.TrustedPlatformModule
	cert     *x509.Certificate
	closeErr error
	closed   bool
}

func (c *c704gCertTPM) IAKCertificate() (*x509.Certificate, error) { return c.cert, nil }

func (c *c704gCertTPM) Close() error {
	c.closed = true
	return c.closeErr
}

// c704gIAKCertificate returns a self-signed certificate to stand in for the
// one the TPM holds.
func c704gIAKCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(704),
		Subject:      pkix.Name{CommonName: "iak"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// c704gIAKExport runs runIAKExport against a TPM holding cert and returns
// the TPM and the command output.
func c704gIAKExport(t *testing.T, output string, closeErr error) (*c704gCertTPM, *x509.Certificate, string, error) {
	t.Helper()
	cert := c704gIAKCertificate(t)
	tpm := &c704gCertTPM{cert: cert, closeErr: closeErr}
	setVar(t, &openTPM, func() (xkms.TrustedPlatformModule, error) { return tpm, nil })
	setVar(t, &iakExportOutput, output)
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := runIAKExport(cmd, nil)
	return tpm, cert, out.String(), err
}

func TestRunIAKExport_WritesThePEMToStdout(t *testing.T) {
	tpm, cert, out, err := c704gIAKExport(t, "-", nil)

	require.NoError(t, err)
	block, rest := pem.Decode([]byte(out))
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Equal(t, cert.Raw, block.Bytes)
	assert.Empty(t, rest)
	assert.True(t, tpm.closed)
}

func TestRunIAKExport_WritesThePEMToAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "iak.pem")

	tpm, cert, out, err := c704gIAKExport(t, path, nil)

	require.NoError(t, err)
	data, rerr := os.ReadFile(path)
	require.NoError(t, rerr)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	assert.Equal(t, cert.Raw, block.Bytes)
	assert.Contains(t, out, "IAK certificate exported to: "+path)
	info, serr := os.Stat(path)
	require.NoError(t, serr)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assert.True(t, tpm.closed)
}

func TestRunIAKExport_UnwritableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "iak.pem")

	tpm, _, out, err := c704gIAKExport(t, path, nil)

	assert.ErrorIs(t, err, ErrExportFailed)
	assert.NotContains(t, out, "exported to")
	assert.NoFileExists(t, path)
	assert.True(t, tpm.closed)
}

func TestRunIAKExport_ReportsACloseFailure(t *testing.T) {
	_, _, out, err := c704gIAKExport(t, "-", errC704gTPMClose)

	assert.ErrorIs(t, err, errC704gTPMClose)
	assert.Contains(t, out, "BEGIN CERTIFICATE", "the certificate is still written")
}
