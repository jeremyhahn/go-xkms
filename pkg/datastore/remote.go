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
	"errors"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	qrdbgrpc "github.com/jeremyhahn/go-qrdb/sdk/go/transport/grpc"
	qrdbrest "github.com/jeremyhahn/go-qrdb/sdk/go/transport/rest"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// remoteTransportFactory provides O(1) qrdb-transport dispatch for a remote
// datastore. Each constructor builds a transport.Transport from the supplied
// options.
var remoteTransportFactory = map[string]func(...qrdbtransport.Option) (qrdbtransport.Transport, error){
	"rest": func(opts ...qrdbtransport.Option) (qrdbtransport.Transport, error) { return qrdbrest.New(opts...) },
	"grpc": func(opts ...qrdbtransport.Option) (qrdbtransport.Transport, error) { return qrdbgrpc.New(opts...) },
}

// DialRemote dials an already-running qrdb cluster over cfg.Transport
// ("rest" or "grpc") and returns the connected SDK client, which the caller
// closes. It is the one implementation of remote-datastore dialing: Open
// uses it for datastore.mode "remote", for xkmsd and SDK callers alike.
func DialRemote(ctx context.Context, cfg config.DatastoreRemoteConfig) (*qrdbsdk.Client, error) {
	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	constructor, ok := remoteTransportFactory[transport]
	if !ok {
		return nil, &ErrUnsupportedStorageBackend{Backend: "qrdb:" + transport}
	}

	rt, err := constructor(TransportOptions(cfg)...)
	if err != nil {
		return nil, &ErrDialRemote{Transport: transport, Address: cfg.Address, Err: err}
	}

	client, err := qrdbsdk.NewClient(rt)
	if err != nil {
		return nil, &ErrDialRemote{Transport: transport, Address: cfg.Address, Err: errors.Join(err, rt.Close())}
	}

	if err := client.Connect(ctx); err != nil {
		return nil, &ErrDialRemote{Transport: transport, Address: cfg.Address, Err: errors.Join(err, client.Close())}
	}
	return client, nil
}

// TransportOptions builds the qrdb transport options from the datastore
// remote config: address plus TLS when a CA file is configured.
func TransportOptions(cfg config.DatastoreRemoteConfig) []qrdbtransport.Option {
	opts := make([]qrdbtransport.Option, 0, 2)

	if cfg.Address != "" {
		opts = append(opts, qrdbtransport.WithAddress(cfg.Address))
	}

	if cfg.TLS.Enabled && cfg.TLS.CAFile != "" {
		opts = append(opts, qrdbtransport.WithTLS(
			cfg.TLS.CertFile,
			cfg.TLS.KeyFile,
			cfg.TLS.CAFile,
		))
	}

	return opts
}
