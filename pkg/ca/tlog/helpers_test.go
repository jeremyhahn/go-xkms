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

package tlog

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
)

const (
	testKeyName = "ca.example.com/tlog"
	testOrigin  = "ca.example.com/tlog"
)

// caKeyTypes are the CA key types go-qrdb can record as head-signing keys.
var caKeyTypes = map[string]func(t *testing.T) crypto.Signer{
	"ed25519":    newEd25519,
	"ecdsa-p256": newP256,
}

func newEd25519(t *testing.T) crypto.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return key
}

func newP256(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// newCAKeys returns go-qrdb's static CA key provider over signer and a
// self-signed CA certificate for it.
func newCAKeys(t *testing.T, signer crypto.Signer) qrdbsdk.CAKeyProvider {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tlog test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	keys, err := qrdbsdk.NewCAKeyStaticProvider(signer, cert)
	require.NoError(t, err)
	return keys
}

// newProvider returns the head-signer provider over a CA key of signer.
func newProvider(t *testing.T, signer crypto.Signer) *HeadSignerProvider {
	t.Helper()
	p, err := NewHeadSignerProvider(newCAKeys(t, signer), testKeyName)
	require.NoError(t, err)
	return p
}

// newVlogClient starts an in-memory standalone go-qrdb node whose logs are
// signed by p, and returns its verifiable-log client with a context carrying
// the node's service principal.
func newVlogClient(t *testing.T, p *HeadSignerProvider) (transport.VlogClient, context.Context) {
	t.Helper()
	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false

	node, err := qrdbnode.NewStandaloneNode(context.Background(), cfg, nil,
		serviceprincipal.Option(), qrdbnode.WithHeadSignerProvider(p))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })
	ctx, err := node.ServiceContext(t.Context())
	require.NoError(t, err)
	return node.Client().Vlog(), ctx
}

// newLog creates a log on a fresh node, signed by a CA key of signer.
func newLog(t *testing.T, signer crypto.Signer) (*Log, transport.VlogClient, context.Context) {
	t.Helper()
	p := newProvider(t, signer)
	client, ctx := newVlogClient(t, p)
	l, err := Create(ctx, client, Config{Name: "certs", Origin: testOrigin}, p)
	require.NoError(t, err)
	return l, client, ctx
}
