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

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTestCABundle(t *testing.T, dir, name string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(dir, name+".pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return path
}

func TestLoadPIVAttestationPools_LoadsRootsAndIntermediates(t *testing.T) {
	dir := t.TempDir()
	roots, intermediates, err := LoadPIVAttestationPools(&PIVLoginConfig{
		AttestationRoots:         writeTestCABundle(t, dir, "root"),
		AttestationIntermediates: []string{writeTestCABundle(t, dir, "intermediate")},
	})
	require.NoError(t, err)
	require.NotNil(t, roots)
	require.NotNil(t, intermediates)
	assert.False(t, roots.Equal(x509.NewCertPool()), "the root bundle must load its certificate")
	assert.False(t, intermediates.Equal(x509.NewCertPool()), "the intermediate bundle must load its certificate")

	roots, intermediates, err = LoadPIVAttestationPools(&PIVLoginConfig{AttestationRoots: writeTestCABundle(t, dir, "only-root")})
	require.NoError(t, err)
	require.NotNil(t, roots)
	assert.Nil(t, intermediates, "no intermediates listed means no pool, not an empty one")
}

func TestLoadPIVAttestationPools_NoBundleIsNoAnchor(t *testing.T) {
	roots, intermediates, err := LoadPIVAttestationPools(nil)
	require.NoError(t, err)
	assert.Nil(t, roots)
	assert.Nil(t, intermediates)

	roots, intermediates, err = LoadPIVAttestationPools(&PIVLoginConfig{Enabled: true, AllowUnattested: true})
	require.NoError(t, err)
	assert.Nil(t, roots)
	assert.Nil(t, intermediates)
}

func TestLoadPIVAttestationPools_BadBundleIsAnError(t *testing.T) {
	dir := t.TempDir()
	_, _, err := LoadPIVAttestationPools(&PIVLoginConfig{AttestationRoots: filepath.Join(dir, "missing.pem")})
	require.Error(t, err, "a named bundle that does not exist must not load as no anchor")

	garbage := filepath.Join(dir, "garbage.pem")
	require.NoError(t, os.WriteFile(garbage, []byte("not a certificate"), 0o600))
	_, _, err = LoadPIVAttestationPools(&PIVLoginConfig{AttestationRoots: garbage})
	require.Error(t, err)

	_, _, err = LoadPIVAttestationPools(&PIVLoginConfig{
		AttestationRoots:         writeTestCABundle(t, dir, "root"),
		AttestationIntermediates: []string{garbage},
	})
	require.Error(t, err, "a bad intermediate bundle fails the whole load")
}

// pivLoginTestConfig is a config that validates with PIV login enabled apart
// from the attestation fields under test: CA-backed TLS requesting client
// certificates, the shape a PIV deployment has.
func pivLoginTestConfig() *Config {
	return &Config{
		Protocols: ProtocolsConfig{REST: true},
		Server:    ServerConfig{RESTPort: 8443},
		Logging:   LoggingConfig{Level: "info", Format: "json"},
		TLS:       TLSConfig{Enabled: true, ServerCN: "test-server", ClientAuth: "verify"},
		Datastore: DatastoreConfig{Path: "/data"},
		Default:   "pkcs8",
		Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
		CA:        &ca.MultiIdentityCAConfig{},
		Auth:      AuthConfig{PIVLogin: &PIVLoginConfig{Enabled: true}},
	}
}

func TestValidate_PIVLoginRequiresAnAnchorOrAnExplicitOptOut(t *testing.T) {
	cfg := pivLoginTestConfig()
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attestation_roots")

	cfg = pivLoginTestConfig()
	cfg.Auth.PIVLogin.AllowUnattested = true
	assert.NoError(t, cfg.Validate())

	cfg = pivLoginTestConfig()
	cfg.Auth.PIVLogin.AttestationRoots = "/etc/xkms/piv-attestation-root.pem"
	assert.NoError(t, cfg.Validate(), "validation checks the shape; the bundle is loaded at composition")

	cfg = pivLoginTestConfig()
	cfg.Auth.PIVLogin.Enabled = false
	assert.NoError(t, cfg.Validate(), "a disabled exchange needs no anchor")
}
