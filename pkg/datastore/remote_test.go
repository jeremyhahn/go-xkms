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

package datastore

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"
	"github.com/jeremyhahn/go-qrdb/sdk/go/testutil/qrdbdharness"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
)

// remoteNode is an in-process go-qrdb node serving REST and gRPC over TLS
// on loopback, standing in for a remote cluster.
type remoteNode struct {
	node      *qrdbnode.Node
	clientTLS config.TLSConfig
}

// startRemoteNode starts the node with authentication off: these tests
// prove the dial and the DAO factory over a network transport, not the
// node's login policy.
func startRemoteNode(t *testing.T) *remoteNode {
	t.Helper()
	certDir := t.TempDir()
	ca, err := qrdbdharness.NewCA(certDir)
	require.NoError(t, err)
	serverKP, err := ca.Issue(certDir, qrdbdharness.WithSubject("node", ""), qrdbdharness.WithServerAuth())
	require.NoError(t, err)
	serverCert, err := serverKP.TLSCertificate()
	require.NoError(t, err)
	clientKP, err := ca.Issue(certDir, qrdbdharness.WithSubject("xkms", ""))
	require.NoError(t, err)
	ports, err := qrdbdharness.ReserveTCPPorts(2)
	require.NoError(t, err)

	qcfg := &qrdbsdk.DaemonConfig{}
	qcfg.Auth.Enabled = qrdbsdk.BoolPtr(false)
	qcfg.Raft.DataDir = t.TempDir()
	qcfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	qcfg.Protocols.REST = true
	qcfg.Protocols.GRPC = true
	qcfg.Server.Host = "127.0.0.1"
	qcfg.Server.AdminPort = ports[0]
	qcfg.Server.GRPCPort = ports[1]

	res, err := embeddednode.NewNode(context.Background(), &embeddednode.NodeOptions{
		QRDB:   qcfg,
		Logger: testLogger(),
		ServerOptions: []qrdbserver.ServerOption{qrdbserver.WithServerTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    ca.Pool,
			ClientAuth:   tls.VerifyClientCertIfGiven,
			MinVersion:   tls.VersionTLS13,
		})},
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, res.Node.Close()) })

	return &remoteNode{
		node: res.Node,
		clientTLS: config.TLSConfig{
			Enabled:  true,
			CAFile:   ca.CertPath,
			CertFile: clientKP.CertPath,
			KeyFile:  clientKP.KeyPath,
		},
	}
}

// remoteConfig is the datastore config that dials the node over transport.
func (r *remoteNode) remoteConfig(transport string) config.DatastoreRemoteConfig {
	address := r.node.Server().GRPCAddr()
	if transport == "rest" {
		address = "https://" + r.node.Server().RESTAddr()
	}
	return config.DatastoreRemoteConfig{Transport: transport, Address: address, TLS: r.clientTLS}
}

// TestOpen_RemoteYieldsClientAndDAOFactory proves a remote datastore hands
// out a client and a DAO factory over each network transport: what one
// transport's DAO writes -- in the default database and in a named one it
// creates -- the other transport's datastore reads back from the node.
func TestOpen_RemoteYieldsClientAndDAOFactory(t *testing.T) {
	remote := startRemoteNode(t)
	open := func(transport string) *Datastore {
		return openTestDatastore(t, &config.Config{Datastore: config.DatastoreConfig{
			Mode:   "remote",
			Engine: "memory",
			Remote: remote.remoteConfig(transport),
		}})
	}
	stores := map[string]*Datastore{"rest": open("rest"), "grpc": open("grpc")}
	readers := map[string]string{"rest": "grpc", "grpc": "rest"}

	for writer, reader := range readers {
		t.Run(writer, func(t *testing.T) {
			ctx := t.Context()
			w, r := stores[writer], stores[reader]

			id := saveNote(t, w, "", "notes-"+writer, "default")
			assert.Equal(t, "default", loadNote(t, r, "", "notes-"+writer, id))

			database := "oidc-" + writer
			for _, ds := range []*Datastore{w, r} {
				_, err := ds.DatabaseKVStore(ctx, database)
				require.NoError(t, err)
			}
			id = saveNote(t, w, database, "notes", "scoped")
			assert.Equal(t, "scoped", loadNote(t, r, database, "notes", id))

			info, err := r.Client().Database().GetDatabase(ctx, database)
			require.NoError(t, err)
			assert.Equal(t, "memory", info.Backend)
		})
	}
}

// TestDialRemote_UnsupportedTransport proves an unsupported transport name
// is rejected before any dial is attempted.
func TestDialRemote_UnsupportedTransport(t *testing.T) {
	client, err := DialRemote(context.Background(), config.DatastoreRemoteConfig{Transport: "carrier-pigeon"})
	assert.Nil(t, client)
	var unsupported *ErrUnsupportedStorageBackend
	require.ErrorAs(t, err, &unsupported)
}

// TestDialRemote_ConnectFails proves a dial against an address nothing
// listens on returns a typed error rather than a half-built client.
func TestDialRemote_ConnectFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	client, err := DialRemote(context.Background(), config.DatastoreRemoteConfig{
		Transport: "rest",
		Address:   addr,
	})
	assert.Nil(t, client)
	var dialErr *ErrDialRemote
	require.ErrorAs(t, err, &dialErr)
	assert.Equal(t, "rest", dialErr.Transport)
	assert.Equal(t, addr, dialErr.Address)
}

// TestTransportOptions pins which remote settings become transport options:
// the address when set, and TLS only when enabled with a CA file.
func TestTransportOptions(t *testing.T) {
	fullTLS := config.TLSConfig{
		Enabled:  true,
		CAFile:   "/path/to/ca.pem",
		CertFile: "/path/to/cert.pem",
		KeyFile:  "/path/to/key.pem",
	}
	tests := map[string]struct {
		cfg  config.DatastoreRemoteConfig
		want int
	}{
		"empty":            {cfg: config.DatastoreRemoteConfig{}, want: 0},
		"address":          {cfg: config.DatastoreRemoteConfig{Address: "kms.example.com:63002"}, want: 1},
		"address and TLS":  {cfg: config.DatastoreRemoteConfig{Address: "kms.example.com:63002", TLS: fullTLS}, want: 2},
		"TLS without a CA": {cfg: config.DatastoreRemoteConfig{TLS: config.TLSConfig{Enabled: true}}, want: 0},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Len(t, TransportOptions(tc.cfg), tc.want)
		})
	}
}
