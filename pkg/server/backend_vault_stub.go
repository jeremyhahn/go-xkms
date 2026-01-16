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

//go:build !vault

package server

// initVaultBackend is a stub when Vault support is not compiled in
func (s *Server) initVaultBackend() error {
	if s.config.Backends.Vault != nil && s.config.Backends.Vault.Enabled {
		s.logger.Warn("Vault backend enabled in config but not compiled in (use -tags vault)")
	}
	return nil
}
