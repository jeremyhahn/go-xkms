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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	sdkxkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
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

// newTrustAddTestCommand returns a command carrying the trust add flags,
// writing its output to buf.
func newTrustAddTestCommand(t *testing.T, buf *bytes.Buffer, purpose, source string) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.Flags().String("purpose", "", "")
	cmd.Flags().String("source", "", "")
	if purpose != "" {
		require.NoError(t, cmd.Flags().Set("purpose", purpose))
	}
	if source != "" {
		require.NoError(t, cmd.Flags().Set("source", source))
	}
	return cmd
}

// writeTrustPEMFile writes a fresh self-signed root to a temp file and
// returns its path and fingerprint.
func writeTrustPEMFile(t *testing.T, cn string) (string, string) {
	t.Helper()

	pemData := selfSignedTrustPEM(t, cn)
	path := filepath.Join(t.TempDir(), "root.pem")
	require.NoError(t, os.WriteFile(path, pemData, 0o600))
	return path, trustPEMFingerprint(t, pemData)
}

// getServerTrustRoot fetches a root from the running xkmsd.
func getServerTrustRoot(t *testing.T, fingerprint string) (*transport.TrustRoot, error) {
	t.Helper()

	client, err := connectXKMSdClient(&cobra.Command{})
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()
	return client.TrustRootGet(context.Background(), &transport.TrustRootRequest{Fingerprint: fingerprint})
}

// requireLocalTrustStoreUntouched checks the local store holds only the
// root isolateLocalTrustStore seeded.
func requireLocalTrustStoreUntouched(t *testing.T) {
	t.Helper()

	store, err := openTrustStore()
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	certs, err := store.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)
}

func TestTrustAddXKMSd_ImportsToServer(t *testing.T) {
	startTrustXKMSd(t)
	pemFile, fingerprint := writeTrustPEMFile(t, "strotc added root")

	var buf bytes.Buffer
	cmd := newTrustAddTestCommand(t, &buf, "user-ca", "test")
	require.NoError(t, runTrustAdd(cmd, []string{pemFile}))
	require.Contains(t, buf.String(), "Certificates added: 1")

	root, err := getServerTrustRoot(t, fingerprint)
	require.NoError(t, err)
	require.Equal(t, "user-ca", string(root.Purpose))
	require.Equal(t, "test", root.Source)

	requireLocalTrustStoreUntouched(t)
}

func TestTrustAddXKMSd_SkipsExisting(t *testing.T) {
	startTrustXKMSd(t)
	pemFile, _ := writeTrustPEMFile(t, "strotc twice root")

	var first bytes.Buffer
	require.NoError(t, runTrustAdd(newTrustAddTestCommand(t, &first, "", ""), []string{pemFile}))
	require.Contains(t, first.String(), "Certificates added: 1")

	var second bytes.Buffer
	require.NoError(t, runTrustAdd(newTrustAddTestCommand(t, &second, "", ""), []string{pemFile}))
	require.Contains(t, second.String(), "Certificates skipped (already present): 1")

	requireLocalTrustStoreUntouched(t)
}

func TestTrustAddXKMSd_BadPurpose(t *testing.T) {
	startTrustXKMSd(t)
	pemFile, fingerprint := writeTrustPEMFile(t, "strotc bad purpose root")

	var buf bytes.Buffer
	err := runTrustAdd(newTrustAddTestCommand(t, &buf, "nope", ""), []string{pemFile})
	require.ErrorIs(t, err, ErrTrustAddFailed)
	require.Empty(t, buf.String())

	_, err = getServerTrustRoot(t, fingerprint)
	require.Error(t, err)
	requireLocalTrustStoreUntouched(t)
}

func TestTrustRemoveXKMSd_RemovesServerRoot(t *testing.T) {
	fingerprint := startTrustXKMSd(t)

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	require.NoError(t, runTrustRemove(cmd, []string{fingerprint}))
	require.Contains(t, buf.String(), "Certificate removed: "+fingerprint)

	_, err := getServerTrustRoot(t, fingerprint)
	require.Error(t, err)

	err = runTrustRemove(cmd, []string{strings.Repeat("ab", 32)})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrTrustRemoveFailed)
	require.Contains(t, err.Error(), "TrustRootRemove")

	requireLocalTrustStoreUntouched(t)
}

func TestTrustAddXKMSd_NotConfigured(t *testing.T) {
	isolateXKMSdEndpoint(t)
	isolateLocalTrustStore(t, "strotc local root")

	svc := newTestXKMSService(t)
	address, _ := startTestXKMSdService(t, svc)
	xkmsdURL = address

	pemFile, _ := writeTrustPEMFile(t, "strotc unconfigured root")

	var buf bytes.Buffer
	require.Error(t, runTrustAdd(newTrustAddTestCommand(t, &buf, "", ""), []string{pemFile}))
	require.Empty(t, buf.String())

	requireLocalTrustStoreUntouched(t)
}
