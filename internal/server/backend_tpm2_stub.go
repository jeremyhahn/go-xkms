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

//go:build !tpm2

package server

// initTPM2Backend is a stub when TPM2 support is not compiled in
func (s *Server) initTPM2Backend() error {
	if s.config.Backends.TPM2 != nil && s.config.Backends.TPM2.Enabled {
		s.logger.Warn("TPM2 backend enabled in config but not compiled in (use -tags tpm2)")
	}
	return nil
}
