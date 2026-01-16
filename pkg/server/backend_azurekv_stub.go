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

//go:build !azurekv

package server

// initAzureKVBackend is a stub when Azure Key Vault support is not compiled in
func (s *Server) initAzureKVBackend() error {
	if s.config.Backends.AzureKV != nil && s.config.Backends.AzureKV.Enabled {
		s.logger.Warn("Azure Key Vault backend enabled in config but not compiled in (use -tags azurekv)")
	}
	return nil
}
