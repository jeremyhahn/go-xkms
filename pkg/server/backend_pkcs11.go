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

//go:build pkcs11

package server

import (
	"github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
)

// initPKCS11Backend initializes the PKCS#11 backend if enabled in configuration
func (s *Server) initPKCS11Backend() error {
	if s.config.Backends.PKCS11 == nil || !s.config.Backends.PKCS11.Enabled {
		return nil
	}

	// Create key storage for PKCS#11 metadata
	keyStorage, err := s.createStorage("pkcs11/keys")
	if err != nil {
		return &ErrStorageCreate{Resource: "PKCS#11 key storage", Err: err}
	}

	// Create cert storage for PKCS#11 certificates
	certStorage, err := s.createStorage("pkcs11/certs")
	if err != nil {
		return &ErrStorageCreate{Resource: "PKCS#11 cert storage", Err: err}
	}

	pkcs11Backend, err := pkcs11.NewBackend(&pkcs11.Config{
		CN:          "pkcs11-backend",
		Library:     s.config.Backends.PKCS11.Library,
		TokenLabel:  s.config.Backends.PKCS11.Token,
		PIN:         s.config.Backends.PKCS11.Pin,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	})
	if err != nil {
		return &ErrBackendCreate{Backend: "PKCS#11", Err: err}
	}

	s.keyProviders["pkcs11"] = pkcs11Backend
	s.logger.Info("PKCS#11 backend initialized", "backend", "pkcs11", "library", s.config.Backends.PKCS11.Library, "token", s.config.Backends.PKCS11.Token)
	return nil
}
