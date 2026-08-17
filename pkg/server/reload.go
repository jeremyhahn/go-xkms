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
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// Reload errors.
var (
	// ErrReloadNilConfig indicates Reload was called without a configuration.
	ErrReloadNilConfig = errors.New("server: reload requires a configuration")

	// ErrReloadNoAuthenticator indicates authentication setup reported success
	// but left no authenticator in place. Serving requests in that state would
	// admit every caller, so the reload is refused and the previous
	// authenticator is kept.
	ErrReloadNoAuthenticator = errors.New("server: reload produced no authenticator")
)

// Reload applies a new configuration to a running server without restarting it.
//
// Two subsystems are re-applied in place: logging and authentication. The
// authenticator is rebuilt from the new configuration through the same
// fail-closed initializeAuthentication used at startup, so tightening auth.*
// and sending SIGHUP cannot leave the previous authenticator silently in force.
// A configuration that cannot produce a valid authenticator fails the whole
// reload and restores the previous configuration, logger and authenticator; the
// server never degrades to a no-op authenticator or an unset one on a bad
// reload.
//
// A rebuilt authenticator reaches listeners that are already serving. Every
// transport is constructed with the server's auth.LiveAuthenticator rather
// than a captured authenticator, so publishing the new one swaps what those
// listeners enforce on their next request. This is what makes tightening
// auth.* over SIGHUP take effect; before it, a listener kept the authenticator
// it was built with and the reload silently did nothing to live traffic.
//
// Everything else in the configuration is stored but NOT applied while the
// server runs, and changing it requires a restart: protocol enablement and
// listener addresses, TLS material and client-auth policy, backends and
// storage, the barrier/seal and PIN subsystems, the WebAuthn relying-party
// service, the CA, rate limiting, metrics, health and audit logging, and the
// process-wide crypto policy (crypto.allow_weak_hashes), which New applies to
// pkg/types once, before any request is served.
func (s *Server) Reload(cfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cfg == nil {
		return &ErrConfigReload{Component: "config", Err: ErrReloadNilConfig}
	}

	s.logger.Info("Reloading server configuration...")

	// Snapshot everything the reload mutates so a failure anywhere leaves the
	// server exactly as it was.
	previous := s.reloadState()
	authChanged := authConfigChanged(&s.config.Auth, &cfg.Auth)

	// Reload logging configuration. It compares against the current config, so
	// it runs before the new configuration is installed.
	if err := s.reloadLogging(cfg); err != nil {
		previous.restore(s)
		return &ErrConfigReload{Component: "logging", Err: err}
	}

	// initializeAuthentication reads s.config, so the new configuration is
	// installed first and rolled back if authentication cannot be rebuilt.
	s.config = cfg

	if err := s.initializeAuthentication(); err != nil {
		previous.restore(s)
		s.logger.Error("Authentication reload failed, keeping previous authenticator",
			slog.String("authenticator", s.authenticator.Name()),
			slog.Any("error", err))
		return &ErrConfigReload{Component: "authentication", Err: err}
	}

	// initializeAuthentication assigns an authenticator on every successful
	// path; an unset one would mean every request is served unauthenticated.
	if s.authenticator == nil {
		previous.restore(s)
		return &ErrConfigReload{Component: "authentication", Err: ErrReloadNoAuthenticator}
	}

	if authChanged {
		s.logger.Info("Authentication reloaded",
			slog.String("authenticator", s.authenticator.Name()),
			slog.Bool("enabled", cfg.Auth.Enabled),
			slog.String("type", cfg.Auth.Type))

		if s.listenersRunning() {
			s.logger.Info("Running protocol listeners picked up the new authenticator",
				slog.String("authenticator", s.authenticator.Name()))
		}
	}

	s.logger.Info("Server configuration reloaded successfully")

	return nil
}

// listenersRunning reports whether Start has constructed any protocol listener.
// Used only to decide whether a reload has live traffic worth reporting; a
// running listener does pick up a rebuilt authenticator, because it holds the
// server's auth.LiveAuthenticator rather than a captured one.
func (s *Server) listenersRunning() bool {
	return s.unixGRPCServer != nil ||
		s.restServer != nil ||
		s.qrdbNode != nil ||
		s.moduleMCP != nil
}

// reloadedState holds the parts of the server a reload replaces, so they can be
// restored when a later step of the same reload fails.
type reloadedState struct {
	config         *config.Config
	logger         *slog.Logger
	authenticator  auth.Authenticator
	webauthnConfig *webauthn.Config
}

// reloadState captures the current reloadable state of the server.
func (s *Server) reloadState() reloadedState {
	return reloadedState{
		config:         s.config,
		logger:         s.logger,
		authenticator:  s.authenticator,
		webauthnConfig: s.webauthnConfig,
	}
}

// restore puts the captured state back, undoing a partially applied reload.
//
// The restored authenticator is republished to the transports. A failed reload
// can get as far as installing a new authenticator before a later step fails,
// and without republishing here the running listeners would keep serving with
// the authenticator the reload just rejected -- exactly the silent
// authentication change Reload exists to prevent.
func (p reloadedState) restore(s *Server) {
	s.config = p.config
	s.logger = p.logger
	s.authenticator = p.authenticator
	s.webauthnConfig = p.webauthnConfig
	s.publishAuthenticator()
}

// authConfigChanged reports whether the authentication configuration differs in
// any field that selects or configures an authenticator.
func authConfigChanged(old, updated *config.AuthConfig) bool {
	if old.Enabled != updated.Enabled ||
		old.Type != updated.Type ||
		old.MTLS != updated.MTLS ||
		old.EnableRBAC != updated.EnableRBAC {
		return true
	}
	if jwtConfigChanged(old.JWT, updated.JWT) {
		return true
	}
	return compositeConfigChanged(old.Composite, updated.Composite)
}

// jwtConfigChanged reports whether the JWT verification configuration differs.
func jwtConfigChanged(old, updated *config.JWTConfig) bool {
	if old == nil || updated == nil {
		return old != updated
	}
	if old.Secret != updated.Secret ||
		old.PublicKeyFile != updated.PublicKeyFile ||
		old.Issuer != updated.Issuer ||
		old.Algorithm != updated.Algorithm ||
		len(old.Audience) != len(updated.Audience) {
		return true
	}
	for i, audience := range old.Audience {
		if audience != updated.Audience[i] {
			return true
		}
	}
	return false
}

// compositeConfigChanged reports whether the composite method chain differs.
func compositeConfigChanged(old, updated *config.CompositeAuthConfig) bool {
	if old == nil || updated == nil {
		return old != updated
	}
	if len(old.Methods) != len(updated.Methods) {
		return true
	}
	for i, method := range old.Methods {
		if method != updated.Methods[i] {
			return true
		}
	}
	return false
}

// reloadLogging updates the logging configuration
func (s *Server) reloadLogging(cfg *config.Config) error {
	// Only update if logging configuration changed
	if cfg.Logging.Level != s.config.Logging.Level ||
		cfg.Logging.Format != s.config.Logging.Format {

		s.logger.Info("Updating logging configuration",
			slog.String("old_level", s.config.Logging.Level),
			slog.String("new_level", cfg.Logging.Level),
			slog.String("old_format", s.config.Logging.Format),
			slog.String("new_format", cfg.Logging.Format))

		// Create new logger with updated configuration
		newLogger := setupLogger(cfg.Logging)

		// Update server logger
		s.logger = newLogger

		s.logger.Info("Logging configuration updated",
			slog.String("level", cfg.Logging.Level),
			slog.String("format", cfg.Logging.Format))
	}

	return nil
}
