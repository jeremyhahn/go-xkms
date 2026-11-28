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

//go:build !pkcs11

package server

import (
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// initPKCS11Backend is a stub when PKCS#11 support is not compiled in
func (s *Server) initPKCS11Backend() error {
	if s.config.Backends.PKCS11 != nil && s.config.Backends.PKCS11.Enabled {
		s.logger.Warn("PKCS#11 backend enabled in config but not compiled in (use -tags pkcs11)")
	}
	return nil
}

// defaultPKCS11PINOpener refuses: PKCS#11 is not compiled in.
func (s *Server) defaultPKCS11PINOpener(_ []byte) (types.KeyProvider, error) {
	return nil, errPKCS11NotCompiled
}

var errPKCS11NotCompiled = errors.New("server: PKCS#11 backend not compiled in (use -tags pkcs11)")

// openPreNodePKCS11Backend opens nothing without PKCS#11 support: a node key
// on key_backend pkcs11 is then refused (clusterca.ErrNodeKeyBackendNotConfigured).
func (s *Server) openPreNodePKCS11Backend() error {
	return nil
}
