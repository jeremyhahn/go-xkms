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

package services

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverid"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// ConnectionInfo describes the current server connection state.
type ConnectionInfo struct {
	State    string `json:"state"` // disconnected, connecting, connected, error
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	TLS      bool   `json:"tls"`
	SPKIPin  string `json:"spki_pin,omitempty"`
	Version  string `json:"version,omitempty"`
	Error    string `json:"error,omitempty"`
}

// validProtocols maps protocol strings to SDK protocol constants.
var validProtocols = map[string]xkms.Protocol{
	"unix": xkms.ProtocolUnix,
	"rest": xkms.ProtocolREST,
	"grpc": xkms.ProtocolGRPC,
	"quic": xkms.ProtocolQUIC,
	"mcp":  xkms.ProtocolMCP,
}

// ConnectionService manages the SDK client lifecycle.
// It is bound to the Wails runtime so every exported method is
// callable from the frontend.
type ConnectionService struct {
	ctx     context.Context
	log     *slog.Logger
	mu      sync.RWMutex // protects client
	client  xkms.Client
	state   atomic.Value // stores *ConnectionInfo
	emitter func(events.Event)

	// tokens is the login token store `xkey auth login` writes; a
	// connection presents the login stored for its server. Nil presents
	// none.
	tokens tokenstore.TokenStore

	// serverName names the server reached without TLS, selecting its
	// stored login there (see SetServerName).
	serverName string

	// endpoint is the connected server's address and credentials, for the
	// service APIs dialed on their own (SSH). Nil when disconnected.
	endpoint atomic.Pointer[serverEndpoint]
}

// serverEndpoint is a connected server's URL and the credentials its
// connection presents.
type serverEndpoint struct {
	url       string
	tlsConfig *tls.Config
	token     string
}

// NewConnectionService creates a new ConnectionService with a disconnected
// initial state.
func NewConnectionService() *ConnectionService {
	s := &ConnectionService{
		log: slog.Default().With("component", "connection_service"),
	}
	info := &ConnectionInfo{State: "disconnected"}
	s.state.Store(info)
	return s
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *ConnectionService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetEventEmitter sets the callback used to emit events to the frontend.
func (s *ConnectionService) SetEventEmitter(fn func(events.Event)) {
	s.emitter = fn
}

// SetTokenStore sets the login token store a connection reads its bearer
// token from. It is called once at startup, before any Connect.
func (s *ConnectionService) SetTokenStore(store tokenstore.TokenStore) {
	s.tokens = store
}

// connectionURL is the scheme-qualified server URL of a connection, the
// key its login is stored under: the same URL forms the xkey CLI accepts
// in XKMSD_URL (https://, grpcs://, quic://, mcps://, unix://, ...).
func connectionURL(protocol, address string, tlsEnabled bool) string {
	if strings.Contains(address, "://") {
		return address
	}
	switch protocol {
	case "unix", "quic":
		// A Unix socket has no TLS to signal; QUIC always runs TLS.
		return protocol + "://" + address
	}
	scheme := protocol // grpc, mcp
	if protocol == "rest" {
		scheme = "http"
	}
	if tlsEnabled {
		scheme += "s"
	}
	return scheme + "://" + address
}

// loginToken returns the stored login for the endpoint's server, or ""
// when no store is set or no login is stored. The login is bound to the
// server's TLS identity, read from a handshake verified by the
// connection's own trust, so a login made over any transport serves this
// one; without TLS the configured server name selects it.
func (s *ConnectionService) loginToken(ep *serverEndpoint) (string, error) {
	if s.tokens == nil {
		return "", nil
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ref := tokenstore.ServerRef{Name: s.serverName}
	id, err := serverid.Probe(ctx, ep.url, ep.tlsConfig)
	switch {
	case err == nil:
		ref = tokenstore.ServerRef{ID: id}
	case !errors.Is(err, serverid.ErrNoTLS):
		return "", err
	}
	return tokenstore.LoginToken(ctx, s.tokens, ref)
}

// SetServerName sets the name of the server reached without TLS (a Unix
// socket), which selects its stored login. It is called once at startup
// from the xkmsd.server_name setting.
func (s *ConnectionService) SetServerName(name string) {
	s.serverName = name
}

// newServerEndpoint records a connection's URL and trust: the same trust
// the SDK connection applies (the SPKI pin when given, else the CA file or
// the system roots). Connect adds the login token.
func newServerEndpoint(protocol, address string, tlsEnabled bool, caFile, spkiPin string) (*serverEndpoint, error) {
	ep := &serverEndpoint{url: connectionURL(protocol, address, tlsEnabled)}
	switch {
	case !tlsEnabled:
	case spkiPin != "":
		ep.tlsConfig = xkms.NewSPKIPinnedTLSConfig(spkiPin)
	default:
		cfg, err := transport.BuildTLSConfig(transport.TLSOptions{CAFile: caFile})
		if err != nil {
			return nil, err
		}
		ep.tlsConfig = cfg
	}
	return ep, nil
}

// SSHClient dials the connected server's SSH API with the connection's
// address and credentials. The caller owns Close.
func (s *ConnectionService) SSHClient() (sshclient.Client, error) {
	ep := s.endpoint.Load()
	if ep == nil {
		return nil, ErrServerNotConnected
	}
	return sshclient.NewClientForServerWith(ep.url, sshclient.ServerOptions{TLSConfig: ep.tlsConfig, Token: ep.token})
}

// GetConnectionInfo returns the current connection state.
func (s *ConnectionService) GetConnectionInfo() *ConnectionInfo {
	return s.state.Load().(*ConnectionInfo)
}

// IsConnected returns true when the service holds an active server connection.
func (s *ConnectionService) IsConnected() bool {
	return s.GetConnectionInfo().State == "connected"
}

// GetClient returns the current SDK client, or nil when disconnected.
func (s *ConnectionService) GetClient() xkms.Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.client
}

// Connect establishes a new SDK client connection to a xkmsd server.
// It validates the protocol and address, creates a client via the SDK,
// and performs a health check to confirm the server is reachable.
// When spkiPin is non-empty, TLS is enabled automatically and the server
// certificate is verified against the SPKI pin instead of requiring a CA file.
func (s *ConnectionService) Connect(
	protocol, address string,
	tlsEnabled bool,
	caFile, spkiPin string,
) (*ConnectionInfo, error) {

	sdkProtocol, ok := validProtocols[protocol]
	if !ok {
		return nil, ErrInvalidProtocol
	}

	if address == "" {
		return nil, ErrInvalidAddress
	}

	if s.IsConnected() {
		return nil, ErrServerAlreadyConnected
	}

	// SPKI pin implies TLS is enabled.
	if spkiPin != "" {
		tlsEnabled = true
	}

	// Transition to connecting state.
	s.state.Store(&ConnectionInfo{
		State:    "connecting",
		Protocol: protocol,
		Address:  address,
		TLS:      tlsEnabled,
		SPKIPin:  spkiPin,
	})

	endpoint, err := newServerEndpoint(protocol, address, tlsEnabled, caFile, spkiPin)
	if err != nil {
		return s.setErrorState(protocol, address, tlsEnabled, "tls_config", err), err
	}
	token, err := s.loginToken(endpoint)
	if err != nil {
		return s.setErrorState(protocol, address, tlsEnabled, "login_token", err), err
	}
	endpoint.token = token

	var client xkms.Client

	if spkiPin != "" {
		// Use functional options with SPKI pinning for trust-on-first-use.
		opts := []xkms.Option{
			xkms.WithProtocol(sdkProtocol),
			xkms.WithAddress(address),
			xkms.WithSPKIPin(spkiPin),
		}
		if caFile != "" {
			opts = append(opts, xkms.WithTLSCAFile(caFile))
		}
		if token != "" {
			opts = append(opts, xkms.WithJWTToken(token))
		}
		client, err = xkms.NewWithOptions(opts...)
	} else {
		cfg := &xkms.BackendConfig{
			Protocol:   sdkProtocol,
			Address:    address,
			TLSEnabled: tlsEnabled,
			TLSCAFile:  caFile,
			JWTToken:   token,
		}
		client, err = xkms.New(cfg)
	}
	if err != nil {
		return s.setErrorState(protocol, address, tlsEnabled, "connect", err), err
	}

	if err := client.Connect(s.ctx); err != nil {
		return s.setErrorState(protocol, address, tlsEnabled, "connect", err), err
	}

	health, err := client.Health(s.ctx)
	if err != nil {
		return s.setErrorState(protocol, address, tlsEnabled, "health_check", err), err
	}

	// Store the connected client.
	s.mu.Lock()
	s.client = client
	s.mu.Unlock()
	s.endpoint.Store(endpoint)

	info := &ConnectionInfo{
		State:    "connected",
		Protocol: protocol,
		Address:  address,
		TLS:      tlsEnabled,
		SPKIPin:  spkiPin,
		Version:  health.Version,
	}
	s.state.Store(info)

	s.emit(events.NewEvent(events.EventServerConnected, events.ServerConnectedPayload{
		Protocol: protocol,
		Address:  address,
		Version:  health.Version,
	}))

	return info, nil
}

// Disconnect tears down the current server connection and resets state.
func (s *ConnectionService) Disconnect() error {
	s.mu.Lock()
	client := s.client
	if client == nil {
		s.mu.Unlock()
		return ErrServerNotConnected
	}
	s.client = nil
	s.mu.Unlock()
	s.endpoint.Store(nil)

	closeErr := client.Close()

	s.state.Store(&ConnectionInfo{State: "disconnected"})
	s.emit(events.NewEvent(events.EventServerDisconnected, nil))

	return closeErr
}

// HealthCheck performs a health check against the connected server.
func (s *ConnectionService) HealthCheck() (*xkms.HealthResponse, error) {
	client := s.GetClient()
	if client == nil {
		return nil, ErrServerNotConnected
	}
	return client.Health(s.ctx)
}

// setErrorState transitions the connection to an error state, emits a
// server error event, and returns the resulting ConnectionInfo.
func (s *ConnectionService) setErrorState(
	protocol, address string,
	tls bool,
	operation string,
	err error,
) *ConnectionInfo {

	info := &ConnectionInfo{
		State:    "error",
		Protocol: protocol,
		Address:  address,
		TLS:      tls,
		Error:    err.Error(),
	}
	s.state.Store(info)

	s.emit(events.NewEvent(events.EventServerError, events.ServerErrorPayload{
		Message:   err.Error(),
		Operation: operation,
	}))

	return info
}

// emit sends an event to the registered emitter, if one is set.
func (s *ConnectionService) emit(e events.Event) {
	if s.emitter != nil {
		s.emitter(e)
	}
}
