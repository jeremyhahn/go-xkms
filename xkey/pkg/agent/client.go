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

package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Client connects to a master xKey instance and exposes its services
// locally via gRPC reverse proxy. The client uses mTLS with the
// certificate issued during enrollment. Thread-safe.
type Client struct {
	config      *ClientConfig
	conn        *grpc.ClientConn
	logger      *slog.Logger
	running     atomic.Bool
	done        chan struct{}
	reconnectMu sync.Mutex
}

// NewClient creates a new agent client with the given configuration.
func NewClient(cfg *ClientConfig, logger *slog.Logger) (*Client, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}
	if logger == nil {
		return nil, ErrNilLogger
	}
	return &Client{
		config: cfg,
		logger: logger,
		done:   make(chan struct{}),
	}, nil
}

// Connect establishes a gRPC connection to the master agent server.
// If TLS credentials are configured, the connection uses mTLS.
func (c *Client) Connect(ctx context.Context) error {
	if c.running.Load() {
		return ErrClientAlreadyConnected
	}

	dialOpts, err := c.buildDialOptions()
	if err != nil {
		return &AgentError{Operation: "connect", Err: err}
	}

	conn, err := grpc.NewClient(c.config.MasterAddress, dialOpts...)
	if err != nil {
		return &AgentError{Operation: "connect", Err: err}
	}

	c.conn = conn
	c.running.Store(true)
	c.done = make(chan struct{})

	c.logger.Info("connected to master",
		"address", c.config.MasterAddress)

	// Start reconnection monitor if backoff is configured.
	if c.config.ReconnectBackoffMax > 0 {
		go c.monitorConnection(ctx)
	}

	return nil
}

// Disconnect gracefully disconnects from the master.
func (c *Client) Disconnect() error {
	if !c.running.CompareAndSwap(true, false) {
		return ErrClientNotConnected
	}

	c.logger.Info("disconnecting from master")

	var closeErr error
	if c.conn != nil {
		closeErr = c.conn.Close()
		c.conn = nil
	}

	close(c.done)

	if closeErr != nil {
		return &AgentError{Operation: "disconnect", Err: closeErr}
	}

	c.logger.Info("disconnected from master")
	return nil
}

// IsConnected reports whether the client has an active connection to
// the master.
func (c *Client) IsConnected() bool {
	if !c.running.Load() {
		return false
	}
	if c.conn == nil {
		return false
	}
	state := c.conn.GetState()
	return state == connectivity.Ready || state == connectivity.Idle
}

// Connection returns the underlying gRPC connection. Returns nil if
// not connected.
func (c *Client) Connection() *grpc.ClientConn {
	return c.conn
}

// monitorConnection watches the gRPC connection state and attempts
// reconnection with exponential backoff when the connection drops.
func (c *Client) monitorConnection(ctx context.Context) {
	backoff := 1 * time.Second
	maxBackoff := c.config.ReconnectBackoffMax

	for {
		select {
		case <-c.done:
			return
		case <-ctx.Done():
			return
		default:
		}

		if !c.running.Load() {
			return
		}

		if c.conn == nil {
			return
		}

		state := c.conn.GetState()
		if state == connectivity.TransientFailure || state == connectivity.Shutdown {
			c.reconnectMu.Lock()
			c.logger.Warn("connection lost, attempting reconnect",
				"backoff", backoff)

			// Wait for state change with timeout.
			waitCtx, cancel := context.WithTimeout(ctx, backoff)
			c.conn.WaitForStateChange(waitCtx, state)
			cancel()

			newState := c.conn.GetState()
			if newState == connectivity.Ready || newState == connectivity.Idle {
				c.logger.Info("reconnected to master")
				backoff = 1 * time.Second
			} else {
				// Exponential backoff with cap.
				backoff = time.Duration(math.Min(
					float64(backoff*2),
					float64(maxBackoff),
				))
			}
			c.reconnectMu.Unlock()
		} else {
			// Connection is healthy; reset backoff and wait for state change.
			backoff = 1 * time.Second
			waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			c.conn.WaitForStateChange(waitCtx, state)
			cancel()
		}
	}
}

// buildDialOptions constructs gRPC dial options based on the client
// configuration. Returns mTLS credentials when TLS files are configured.
func (c *Client) buildDialOptions() ([]grpc.DialOption, error) {
	var opts []grpc.DialOption

	if c.config.TLSCertFile != "" && c.config.TLSKeyFile != "" {
		tlsConfig, err := c.buildTLSConfig()
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	return opts, nil
}

// buildTLSConfig creates a TLS configuration for the client with the
// enrolled certificate and CA trust chain.
func (c *Client) buildTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.config.TLSCertFile, c.config.TLSKeyFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if c.config.TLSCAFile != "" {
		caCert, err := os.ReadFile(c.config.TLSCAFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, ErrCertificateInvalid
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}
