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

// Package loopback boots the full xkms engine on a loopback-only REST
// listener with a per-launch bearer token. It backs the desktop standalone
// ("MS Access") mode: the Wails shell embeds the engine in-process and the
// SPA drives it over 127.0.0.1, so there is no separate daemon and nothing is
// reachable off-box.
//
// The engine is the real pkg/server.Server — barrier, CA, qrdb identity
// plane, WebAuthn — not the software-only SDK embedded service, so the
// desktop experience is at parity with a remote xkmsd.
package loopback

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/server"
)

// Options configures a loopback launch.
type Options struct {
	// Config is the daemon configuration. It is copied and forced into a
	// loopback, REST-only posture; the caller's value is not mutated.
	Config *config.Config

	// Logger receives launch diagnostics. Defaults to slog.Default().
	Logger *slog.Logger
}

// Instance is a running loopback engine.
type Instance struct {
	// BaseURL is the loopback URL the SPA points at, e.g.
	// "https://127.0.0.1:54321" (or http:// when TLS is disabled).
	BaseURL string

	// Token is the per-launch bearer token the SPA must send as
	// Authorization: Bearer <Token>. Valid only over loopback.
	Token string

	// Port is the resolved ephemeral port.
	Port int

	srv    *server.Server
	logger *slog.Logger
}

// Launch boots the engine on a loopback listener and returns once it is
// serving. Close stops it.
func Launch(ctx context.Context, o Options) (*Instance, error) {
	if o.Config == nil {
		return nil, &LaunchError{Reason: "config is required"}
	}
	logger := o.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Per-launch token: 32 bytes of randomness, hex-encoded.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, &LaunchError{Reason: "generate token", Err: err}
	}
	token := hex.EncodeToString(tokenBytes)

	// Pre-bind the loopback listener so the ephemeral port is known before
	// the server starts and can be reported to the shell.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, &LaunchError{Reason: "bind loopback listener", Err: err}
	}
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return nil, &LaunchError{Reason: "unexpected listener address type"}
	}
	port := tcpAddr.Port

	// Derive a loopback, REST-only configuration from the caller's config.
	cfg := desktopConfig(o.Config, port)

	// Compose the configured authenticator with a loopback per-launch token
	// authenticator: the desktop owner authenticates by holding the token,
	// while the normal login flows remain available for remote-style use.
	decorator := func(base auth.Authenticator) auth.Authenticator {
		staticAuth := auth.NewStaticTokenAuthenticator(token, auth.Identity{
			Subject:  "desktop-owner",
			TenantID: "system",
			Roles:    []string{"admin"},
		})
		composite, cErr := auth.NewCompositeAuthenticator(staticAuth, base)
		if cErr != nil {
			// Fall back to the token authenticator alone; a desktop engine
			// with no working auth is worse than one the owner can reach.
			logger.Warn("loopback composite authenticator build failed; using token only", "error", cErr)
			return staticAuth
		}
		return composite
	}

	srv, err := server.New(cfg, server.WithAuthenticatorDecorator(decorator))
	if err != nil {
		_ = ln.Close()
		return nil, &LaunchError{Reason: "construct engine", Err: err}
	}
	srv.SetRESTListener(ln)

	scheme := "https"
	if !cfg.TLS.Enabled {
		scheme = "http"
	}

	inst := &Instance{
		BaseURL: scheme + "://127.0.0.1:" + itoa(port),
		Token:   token,
		Port:    port,
		srv:     srv,
		logger:  logger,
	}

	// Start the engine in the background; Start blocks while serving.
	go func() {
		if startErr := srv.Start(); startErr != nil {
			logger.Error("loopback engine stopped", "error", startErr)
		}
	}()

	logger.Info("loopback engine launched", "base_url", inst.BaseURL, "port", port)
	return inst, nil
}

// Close stops the engine and releases its resources.
func (i *Instance) Close(_ context.Context) error {
	if i.srv == nil {
		return nil
	}
	if err := i.srv.Shutdown(); err != nil {
		return &LaunchError{Reason: "shutdown engine", Err: err}
	}
	return nil
}

// desktopConfig copies cfg and forces the loopback, REST-only posture: only
// the REST protocol on 127.0.0.1 at the chosen port, no other transports.
func desktopConfig(src *config.Config, port int) *config.Config {
	cfg := *src // shallow copy is sufficient; we only overwrite value fields below
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.RESTPort = port
	cfg.Protocols = config.ProtocolsConfig{REST: true}
	return &cfg
}

// itoa avoids strconv import churn for a single small integer.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
