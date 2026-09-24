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

//go:build !gcpkms

package server

import "github.com/jeremyhahn/go-xkms/pkg/types"

// buildGCPKMSPlatformSealer is a stub when GCP KMS support is not compiled
// in (build with -tags gcpkms).
func (s *Server) buildGCPKMSPlatformSealer() (types.Sealer, error) {
	return nil, &ErrNotCompiledIn{Backend: "GCP KMS", Tag: "gcpkms"}
}
