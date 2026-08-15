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

package transport

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// API protocol names used to look up a replica's advertised endpoint. They are
// derived from go-qrdb's canonical protocol vocabulary rather than retyped, so
// the names a transport asks for can never drift from the names replicas
// publish. A transport passes its OWN protocol when resolving a leader endpoint
// because a redirected client must reach the leader over the same protocol it
// is already speaking.
//
// The unix socket is absent by design: a socket path is meaningful only on the
// node that owns it, so a unix client cannot be redirected to a peer.
var (
	// APIProtocolREST names the HTTP/REST API.
	APIProtocolREST = string(qrdbsdk.APIProtocolREST)

	// APIProtocolGRPC names the gRPC API.
	APIProtocolGRPC = string(qrdbsdk.APIProtocolGRPC)

	// APIProtocolQUIC names the native QUIC API.
	APIProtocolQUIC = string(qrdbsdk.APIProtocolQUIC)

	// APIProtocolMCP names the Model Context Protocol API.
	APIProtocolMCP = string(qrdbsdk.APIProtocolMCP)
)
