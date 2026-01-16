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

//go:build pkcs11

package server

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

// initPKCS11Backend initializes the PKCS#11 backend if enabled in configuration
func (s *Server) initPKCS11Backend() error {
	if s.config.Backends.PKCS11 == nil || !s.config.Backends.PKCS11.Enabled {
		return nil
	}

	// Create key storage for PKCS#11 metadata
	keyStorage, err := file.New(s.config.Storage.Path + "/pkcs11")
	if err != nil {
		return fmt.Errorf("failed to create PKCS#11 key storage: %w", err)
	}

	var slot *int
	// PKCS#11 Config uses Token field, but we'll use slot 0 as default
	slotVal := 0
	slot = &slotVal

	pkcs11Backend, err := pkcs11.NewBackend(&pkcs11.Config{
		CN:         "pkcs11-backend",
		Library:    s.config.Backends.PKCS11.Library,
		Slot:       slot,
		PIN:        s.config.Backends.PKCS11.Pin,
		KeyStorage: keyStorage,
	})
	if err != nil {
		return fmt.Errorf("failed to create PKCS#11 backend: %w", err)
	}

	s.backends["pkcs11"] = pkcs11Backend
	s.logger.Info("PKCS#11 backend initialized", "backend", "pkcs11", "library", s.config.Backends.PKCS11.Library)
	return nil
}
