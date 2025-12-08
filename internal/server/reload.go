// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package server

import (
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-keychain/internal/config"
)

// Reload attempts to reload the server configuration without restarting
// Currently supports reloading logging configuration
// Full server restart required for protocol/backend changes
func (s *Server) Reload(cfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("Reloading server configuration...")

	// Reload logging configuration
	if err := s.reloadLogging(cfg); err != nil {
		return fmt.Errorf("failed to reload logging configuration: %w", err)
	}

	// Store new configuration
	s.config = cfg

	s.logger.Info("Server configuration reloaded successfully")

	return nil
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
