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

//go:build !pkcs11

package server

// initPKCS11Backend is a stub when PKCS#11 support is not compiled in
func (s *Server) initPKCS11Backend() error {
	if s.config.Backends.PKCS11 != nil && s.config.Backends.PKCS11.Enabled {
		s.logger.Warn("PKCS#11 backend enabled in config but not compiled in (use -tags pkcs11)")
	}
	return nil
}
