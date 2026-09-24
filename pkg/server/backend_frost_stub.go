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

//go:build !frost

package server

// initFrostBackend is a stub when FROST support is not compiled in. Unlike
// the warn-and-continue stubs for the other build-tagged backends, this one
// fails closed: a threshold-signing backend an operator has configured and
// believes is protecting key material must never silently vanish into "no
// FROST backend configured" (pkg/api/*/handlers_frost.go's getFrostBackend)
// just because this binary was built without -tags frost. A build without
// the tag that also has no backends.frost configured is unaffected.
func (s *Server) initFrostBackend() error {
	if s.config.Backends.Frost != nil && s.config.Backends.Frost.Enabled {
		return &ErrNotCompiledIn{Backend: "FROST", Tag: "frost"}
	}
	return nil
}
