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

//go:build !awskms

package server

// initAWSKMSBackend is a stub when AWS KMS support is not compiled in
func (s *Server) initAWSKMSBackend() error {
	if s.config.Backends.AWSKMS != nil && s.config.Backends.AWSKMS.Enabled {
		s.logger.Warn("AWS KMS backend enabled in config but not compiled in (use -tags awskms)")
	}
	return nil
}
