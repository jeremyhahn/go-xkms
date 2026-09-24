// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh

import (
	"context"
	"time"

	pkgsession "github.com/jeremyhahn/go-xkms/pkg/ssh/session"
)

// dialNetworkSession is the transport-agnostic implementation of
// SessionClient.Dial shared by every network transport (REST/QUIC, gRPC/
// unix, MCP). The private key never leaves xkmsd: it resolves a
// forward-signing proxy through keys.Signer (each Sign call forwards the
// authentication digest to the server) and a host-key callback through
// hosts.Callback (each inbound host key is verified against the server's
// pins before the handshake completes). The SSH connection itself is
// dialed directly from the caller's own process — the network transport
// carries only the signing and verification RPCs, never the SSH byte
// stream, so this works identically over REST, gRPC, and MCP.
//
// Host-key verification fails closed: hosts.Callback (built by every
// network transport on top of KnownHostsClient.Verify) returns a typed
// *NotFoundError for an unrecognized host or a typed *MismatchError for a
// mismatched key, and DialClient aborts the handshake on that error. There
// is no trust-on-first-use path and no InsecureIgnoreHostKey.
//
// The returned Session owns no local key enclave — the signer is a
// stateless proxy — so it carries no closers; Close only tears down the
// TCP/SSH connection.
func dialNetworkSession(ctx context.Context, keys KeysClient, hosts KnownHostsClient, req SessionDialRequest) (Session, error) {
	hostScope := req.HostKeyScope
	if hostScope == "" {
		hostScope = req.KeyScope
	}
	hostOwner := req.HostKeyOwner
	if hostOwner == "" {
		hostOwner = req.KeyOwner
	}

	signer, err := keys.Signer(ctx, GetKeyRequest{Scope: req.KeyScope, Owner: req.KeyOwner, Name: req.KeyName})
	if err != nil {
		return nil, err
	}
	hostCallback := hosts.Callback(ctx, hostScope, hostOwner)

	client, err := pkgsession.DialClient(ctx, pkgsession.ClientParams{
		Host:            req.Host,
		Port:            req.Port,
		User:            req.User,
		Signer:          signer,
		HostKeyCallback: hostCallback,
		Timeout:         time.Duration(req.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return pkgsession.NewSession(req.Host, req.User, client), nil
}
