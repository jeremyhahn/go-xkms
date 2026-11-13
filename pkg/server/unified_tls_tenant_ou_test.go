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

package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

func tenantOUTestServer(t *testing.T) *Server {
	t.Helper()
	var logBuf bytes.Buffer
	return &Server{
		config: &config.Config{
			Server:    config.ServerConfig{Host: "127.0.0.1"},
			TLS:       config.TLSConfig{ServerCN: "unit.example"},
			Datastore: config.DatastoreConfig{Path: t.TempDir()},
		},
		logger: slog.New(slog.NewTextHandler(&logBuf, nil)),
	}
}

// The bootstrap listener certificate names the system tenant as OU[0], as
// every other node certificate does.
func TestEnsureBootstrapCert_SystemTenantOU(t *testing.T) {
	s := tenantOUTestServer(t)

	cert, err := s.ensureBootstrapCert()
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, []string{qrdbsdk.SystemTenantID}, leaf.Subject.OrganizationalUnit)
	require.Equal(t, "unit.example", leaf.Subject.CommonName)
}

// A persisted bootstrap certificate that does not name the system tenant is
// regenerated, not reused, even when its SANs still match.
func TestEnsureBootstrapCert_RegeneratesWithoutTenantOU(t *testing.T) {
	s := tenantOUTestServer(t)
	dir := filepath.Join(s.config.Datastore.Path, unifiedBootstrapCertDir)
	require.NoError(t, os.MkdirAll(dir, 0o700))

	dnsNames, ips := s.serverCertSANs("unit.example", true)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "unit.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cert.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "key.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))

	cert, err := s.ensureBootstrapCert()
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	require.NotEqual(t, 0, leaf.SerialNumber.Cmp(big.NewInt(4242)), "a certificate without the tenant OU must not be reused")
	require.Equal(t, []string{qrdbsdk.SystemTenantID}, leaf.Subject.OrganizationalUnit)
}
