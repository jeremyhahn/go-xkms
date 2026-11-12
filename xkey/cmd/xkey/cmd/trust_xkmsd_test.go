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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	sdkxkms "github.com/jeremyhahn/go-xkms/sdk/go"
	sdktruststore "github.com/jeremyhahn/go-xkms/sdk/go/truststore"
)

// selfSignedTrustPEM returns a PEM-encoded self-signed P-256 CA certificate
// with the given common name.
func selfSignedTrustPEM(t *testing.T, cn string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"xkey"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// trustPEMFingerprint returns the trust-store fingerprint of a PEM certificate.
func trustPEMFingerprint(t *testing.T, pemData []byte) string {
	t.Helper()

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return sdktruststore.Fingerprint(cert)
}

// newTrustRootTestStore builds a DAO-backed trust-root store on in-memory
// storage through sdk/go.
func newTrustRootTestStore(t *testing.T) *sdktruststore.DAOStore {
	t.Helper()

	factory, err := sdkxkms.NewBackendDAOFactory(sdkxkms.NewStorageMemory())
	require.NoError(t, err)
	store, err := sdktruststore.NewDAOStore(factory)
	require.NoError(t, err)
	return store
}

// isolateLocalTrustStore points the local FileStore at a temp dir holding one
// root with the given common name.
func isolateLocalTrustStore(t *testing.T, cn string) {
	t.Helper()

	previous := viper.Get("trust.store_path")
	viper.Set("trust.store_path", t.TempDir())
	t.Cleanup(func() { viper.Set("trust.store_path", previous) })

	store, err := openTrustStore()
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()

	_, err = store.ImportPEM(selfSignedTrustPEM(t, cn), &sdktruststore.AddCertificateOptions{})
	require.NoError(t, err)
}

// startTrustXKMSd starts a harness xkmsd whose trust-root store holds one
// root (CN "strotb server root") and returns that root's fingerprint.
func startTrustXKMSd(t *testing.T) string {
	t.Helper()

	isolateXKMSdEndpoint(t)
	isolateLocalTrustStore(t, "strotb local root")

	svc := newTestXKMSService(t)
	store := newTrustRootTestStore(t)
	rootPEM := selfSignedTrustPEM(t, "strotb server root")
	_, err := store.ImportPEM(context.Background(), rootPEM, &sdktruststore.AddCertificateOptions{})
	require.NoError(t, err)
	svc.SetTrustRootStore(store)

	address, _ := startTestXKMSdService(t, svc)
	xkmsdURL = address
	return trustPEMFingerprint(t, rootPEM)
}

func TestTrustListXKMSd_ShowsServerRoots(t *testing.T) {
	startTrustXKMSd(t)

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	require.NoError(t, runTrustList(cmd, nil))

	out := buf.String()
	require.Contains(t, out, "strotb server root")
	require.NotContains(t, out, "strotb local root")
}

func TestTrustShowXKMSd_ByFingerprint(t *testing.T) {
	fingerprint := startTrustXKMSd(t)

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	require.NoError(t, runTrustShow(cmd, []string{fingerprint}))

	out := buf.String()
	require.Contains(t, out, fingerprint)
	require.Contains(t, out, "strotb server root")
}

func TestTrustListXKMSd_NotConfigured(t *testing.T) {
	isolateXKMSdEndpoint(t)
	isolateLocalTrustStore(t, "strotb local root")

	svc := newTestXKMSService(t)
	address, _ := startTestXKMSdService(t, svc)
	xkmsdURL = address

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	require.Error(t, runTrustList(cmd, nil))
	require.Empty(t, buf.String())
}
