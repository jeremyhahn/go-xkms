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
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/require"
)

// go-xkms#793: xkmsd never reloaded the CA it persisted in an earlier run on
// the same data directory. initializeCA (server.go) called trustedCA.Load,
// and treated ANY Load failure -- not only a genuine "never initialized"
// signal -- as license to call Init and mint a brand new self-signed root.
// The root cause was in pkg/ca.CA.Load: it resolved an identity's key
// attributes via the bare Identity.ToKeyAttributes instead of the
// CA-key-type-defaulting getCAKeyAttributes Init uses, so a root identity
// whose KeyConfig left key-type unset (as the shipped qrdb configs do not --
// but many operator configs, and go-xkms's own default xkmsd.yaml/
// xkmsd-dev.yaml, key the YAML field "key_type" instead of the "key-type"
// the struct tag actually binds, silently leaving it unset) failed Load with
// a KeyAttributes.Validate error on every restart. These tests exercise the
// fix at the pkg/server.initializeCA level, over the embedded qrdb storage
// backend two of the shipped configs (xkmsd-local.yaml, xkmsd-integration.yaml)
// use.

// reproCA793Config returns a minimal server configuration backed by the
// embedded qrdb storage engine rooted at dataDir, with a software-backed CA
// identity whose KeyConfig leaves key-type unset -- the exact condition
// go-xkms#793 reproduces.
func reproCA793Config(dataDir string) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Host:     "127.0.0.1",
			RESTPort: 18080,
			GRPCPort: 19090,
			QUICPort: 18443,
			MCPPort:  13000,
		},
		Protocols: config.ProtocolsConfig{Unix: true},
		Unix: config.UnixConfig{
			Enabled:    true,
			SocketPath: filepath.Join(dataDir, "xkms.sock"),
			Protocol:   "grpc",
		},
		Logging:   config.LoggingConfig{Level: "info", Format: "json"},
		TLS:       config.TLSConfig{Enabled: false},
		Auth:      config.AuthConfig{Enabled: false},
		Datastore: config.DatastoreConfig{Path: filepath.Join(dataDir, "storage")},
		Default:   config.DefaultConfig("software"),
		Backends: config.BackendsConfig{
			Software: &config.SoftwareConfig{
				Enabled: true,
				Path:    filepath.Join(dataDir, "keys", "software"),
			},
		},
		CA: &ca.MultiIdentityCAConfig{
			SelectedCA:          0,
			DefaultValidityDays: 365,
			Identity: []ca.Identity{
				{
					IsRoot: true,
					Valid:  1,
					Subject: ca.Subject{
						CommonName:   "793 Repro Root CA",
						Organization: "Test Org",
						Country:      "US",
					},
					Keys: []*types.KeyConfig{
						{
							KeyAlgorithm: types.AlgorithmECDSA,
							ECCConfig:    &types.ECCConfig{Curve: types.CurveP256},
							// key-type deliberately left unset.
						},
					},
				},
			},
		},
	}
}

// TestInitializeCA_QRDB_ReloadsPersistedCAAcrossRestarts is the go-xkms#793
// regression: a second server built with New() over the same qrdb data
// directory as an already-initialized CA must Load the persisted CA rather
// than log "No existing CA found, initializing new CA" and mint a new root.
// The certificate serial and SPKI must survive the restart exactly.
func TestInitializeCA_QRDB_ReloadsPersistedCAAcrossRestarts(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	dataDir := t.TempDir()

	s1, err := New(reproCA793Config(dataDir))
	require.NoError(t, err)
	require.NotNil(t, s1.ca)
	cert1, err := s1.ca.CACertificate()
	require.NoError(t, err)
	require.NoError(t, s1.Shutdown())

	xkms.Reset()
	s2, err := New(reproCA793Config(dataDir))
	require.NoError(t, err)
	require.NotNil(t, s2.ca)
	cert2, err := s2.ca.CACertificate()
	require.NoError(t, err)
	require.NoError(t, s2.Shutdown())

	require.Equal(t, cert1.SerialNumber.String(), cert2.SerialNumber.String(),
		"the CA serial must survive a restart over the same data directory, not be re-minted")
	require.Equal(t, cert1.RawSubjectPublicKeyInfo, cert2.RawSubjectPublicKeyInfo,
		"the CA (and its TLS SPKI) must survive a restart over the same data directory")
}

// TestInitializeCA_QRDB_CorruptPersistedCertificateFailsClosed proves the
// defense-in-depth half of the go-xkms#793 fix: when the persisted root
// certificate exists but cannot be parsed, initializeCA must fail server
// startup with a typed error instead of silently treating the damaged
// record as "never initialized" and replacing it with a freshly minted CA.
func TestInitializeCA_QRDB_CorruptPersistedCertificateFailsClosed(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	dataDir := t.TempDir()

	s1, err := New(reproCA793Config(dataDir))
	require.NoError(t, err)
	require.NoError(t, s1.Shutdown())

	// Reopen the same qrdb data directory out-of-band and damage the
	// persisted certificate records in the CA database in place -- modeling
	// bit rot or a truncated write, not a missing key.
	ctx := context.Background()
	corrupt, records := openCADatabaseOutOfBand(t, dataDir)
	keys, err := records.List(ctx, "")
	require.NoError(t, err)
	require.NotEmpty(t, keys, "the first start must have persisted the root certificate")
	for _, key := range keys {
		require.NoError(t, records.Put(ctx, key, []byte("not a certificate")))
	}
	require.NoError(t, corrupt.closeQRDBStorage())

	xkms.Reset()
	s2, err := New(reproCA793Config(dataDir))
	require.Error(t, err, "startup must fail closed rather than silently replace a damaged CA")
	if s2 != nil {
		defer func() { _ = s2.Shutdown() }()
	}

	var caInitErr *ErrCAInit
	require.True(t, errors.As(err, &caInitErr), "error must unwrap to *ErrCAInit, got %T: %v", err, err)

	// The damaged certificate must never have been silently discarded and
	// replaced: re-reading it out-of-band still returns the same broken
	// bytes, not a freshly minted certificate.
	readBack, records := openCADatabaseOutOfBand(t, dataDir)
	defer func() { _ = readBack.closeQRDBStorage() }()
	for _, key := range keys {
		raw, err := records.Get(ctx, key)
		require.NoError(t, err)
		require.Equal(t, []byte("not a certificate"), raw, "the damaged record must be left untouched, not overwritten by a new Init")
	}
}

// openCADatabaseOutOfBand opens the shared datastore under dataDir the way
// a stopped server's would be opened, and returns the server holding it and
// the raw records of the CA's certificate database.
func openCADatabaseOutOfBand(t *testing.T, dataDir string) (*Server, qrdbsdk.KVStore) {
	t.Helper()
	s := &Server{
		config: &config.Config{
			Datastore: config.DatastoreConfig{Path: filepath.Join(dataDir, "storage")},
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	require.NoError(t, s.initializeQRDBStorage())
	records, err := s.datastore.DatabaseKVStore(context.Background(), certstore.DatabaseName)
	require.NoError(t, err)
	return s, records
}
