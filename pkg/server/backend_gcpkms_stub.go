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

//go:build !gcpkms

package server

// initGCPKMSBackend is a stub when GCP KMS support is not compiled in
func (s *Server) initGCPKMSBackend() error {
	if s.config.Backends.GCPKMS != nil && s.config.Backends.GCPKMS.Enabled {
		s.logger.Warn("GCP KMS backend enabled in config but not compiled in (use -tags gcpkms)")
	}
	return nil
}
