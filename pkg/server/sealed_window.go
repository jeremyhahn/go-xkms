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

package server

import (
	"context"
	"fmt"
	"net"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// SealedWindowBindError is returned when the qrdb node's pre-boot
// sealed-window listener would bind a non-loopback Server.Host without the
// operator explicitly accepting the risk via
// barrier.sealed_window_allow_remote.
type SealedWindowBindError struct {
	// Host is the configured (and refused) Server.Host value.
	Host string
}

// Error implements the error interface.
func (e *SealedWindowBindError) Error() string {
	host := e.Host
	if host == "" {
		host = "<all interfaces>"
	}
	return fmt.Sprintf("qrdb node: sealed-window listener refused to bind %q: "+
		"while the barrier is sealed its allowlisted init verbs (barrier status/initialize/unseal, "+
		"ceremony, credentials) are deliberately unauthenticated — possession of the unseal "+
		"credential is the authorization, Vault-style — so binding it publicly exposes barrier "+
		"status and an unseal race to anyone who can reach it; set server.host to loopback "+
		"(127.0.0.1) or a trusted management interface, or set barrier.sealed_window_allow_remote "+
		"to accept the risk", host)
}

// isLoopbackHost reports whether host (a bare ServerConfig.Host bind
// address, no port) is the loopback interface: the literal "localhost", or
// an IP literal for which net.IP.IsLoopback reports true. An empty host
// (the wildcard bind — every interface) and any other literal or DNS
// hostname are NOT loopback: this fails closed for anything it cannot prove
// is local-only.
func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// serveSealedWindow brings up the qrdb node's pre-boot sealed-window
// listener when node-owned auto-unseal did not succeed at construction
// (initEmbeddedQRDBNode's caller supplies a node for which node.IsSealed()
// is true), blocking until an operator drives the barrier unsealed — through
// the listener or, per the SDK's own contract, any other path — or the
// server context is canceled or the configured sealed-window timeout
// elapses. On a clean unseal it completes the node's boot and returns nil.
//
// It consumes go-qrdb/sdk/go/node's ServeSealedWindow, which is documented
// to be a no-op — return nil immediately without starting a listener — when
// the node is not sealed (TestServeSealedWindow_UnsealedNodeIsNoOp verifies
// that contract directly against the SDK), so callers may invoke
// serveSealedWindow unconditionally on the sealed branch without duplicating
// the guard.
//
// The listener binds the SAME Server.Host/RESTPort the full API server uses
// once unsealed: go-qrdb's node.ServeSealedWindow reuses the node's own
// pending-boot configuration, and the barrier-service ServerOptions it needs
// (WithBarrierService / WithCeremonyService / WithCredentialService /
// WithBarrierRegistry) are not re-exported through sdk/go — only through
// node.ServeSealedWindow itself — so there is no SDK-supported way to serve
// the window on a different address without importing pkg/server directly,
// which the SDK boundary forbids. Because that address is reachable by an
// unauthenticated caller for as long as the barrier stays sealed, a
// non-loopback Server.Host is refused unless the operator opts in via
// barrier.sealed_window_allow_remote.
func (s *Server) serveSealedWindow(node *qrdbnode.Node) error {
	if !node.IsSealed() {
		return nil
	}

	host := s.config.Server.Host
	if !isLoopbackHost(host) && !s.config.Barrier.SealedWindowAllowRemote {
		return &SealedWindowBindError{Host: host}
	}

	timeout, err := s.config.Barrier.SealedWindowTimeoutDuration()
	if err != nil {
		return err
	}

	ctx := s.ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	s.logger.Warn("qrdb node barrier is sealed at startup; opening the sealed-window listener "+
		"until an operator unseals it",
		"host", host, "rest_port", s.config.Server.RESTPort, "timeout", timeout)

	// Blocks until an operator unseals the barrier or ctx is canceled/expires.
	// On cancellation this returns *qrdbserver.SealedWindowCanceledError, which
	// initEmbeddedQRDBNode wraps and propagates as a non-fatal, clearly
	// diagnosable startup failure rather than a panic or a silent hang.
	// The window serves the node's pending-boot transports, which are
	// TLS-only: it takes the same unified TLS material the full server will
	// serve (qrdb does not carry WithServerTLS from the node's construction
	// into the window).
	var windowOpts []qrdbserver.ServerOption
	if s.sealedWindowTLS != nil {
		windowOpts = append(windowOpts, qrdbserver.WithServerTLS(s.sealedWindowTLS))
	}
	if err := qrdbnode.ServeSealedWindow(ctx, node, windowOpts...); err != nil {
		return err
	}

	s.logger.Info("qrdb node barrier unsealed via the sealed-window listener; completing boot")

	// ServeSealedWindow only returns nil once the barrier itself reports
	// unsealed, so Unseal's own IsSealed check short-circuits straight to
	// completing the pending boot (BuildServices + server.New); empty
	// credentials are correct here.
	if err := node.Unseal(ctx, seal.Credentials{}); err != nil {
		return &QRDBNodeError{Stage: "complete boot after sealed window", Err: err}
	}
	return nil
}
