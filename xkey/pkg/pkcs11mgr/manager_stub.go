//go:build !pkcs11

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

package pkcs11mgr

import "errors"

// ErrPKCS11NotCompiled is returned by the stub manager when PKCS#11 support
// is not compiled in. Build with -tags pkcs11 to enable.
var ErrPKCS11NotCompiled = errors.New("pkcs11mgr: PKCS#11 support not compiled (build with -tags pkcs11)")

// StubManager is a no-op implementation of Manager used when the pkcs11
// build tag is not set.
type StubManager struct{}

// Compile-time interface check.
var _ Manager = (*StubManager)(nil)

// NewManager returns a stub manager that rejects all operations.
func NewManager(_ ...Option) Manager {
	return &StubManager{}
}

// RegisterModule returns ErrPKCS11NotCompiled.
func (s *StubManager) RegisterModule(_, _ string) (string, error) {
	return "", ErrPKCS11NotCompiled
}

// UnregisterModule returns ErrPKCS11NotCompiled.
func (s *StubManager) UnregisterModule(_ string) error {
	return ErrPKCS11NotCompiled
}

// RefreshSlots returns ErrPKCS11NotCompiled.
func (s *StubManager) RefreshSlots(_ string) ([]SlotInfo, error) {
	return nil, ErrPKCS11NotCompiled
}

// GetModule returns ErrPKCS11NotCompiled.
func (s *StubManager) GetModule(_ string) (*ModuleInfo, error) {
	return nil, ErrPKCS11NotCompiled
}

// ListModules returns an empty slice.
func (s *StubManager) ListModules() []ModuleInfo {
	return []ModuleInfo{}
}

// OpenSession returns ErrPKCS11NotCompiled.
func (s *StubManager) OpenSession(_ string, _ uint, _ string) (*SessionHandle, error) {
	return nil, ErrPKCS11NotCompiled
}

// CloseSession returns ErrPKCS11NotCompiled.
func (s *StubManager) CloseSession(_ *SessionHandle) error {
	return ErrPKCS11NotCompiled
}

// Close is a no-op for the stub manager.
func (s *StubManager) Close() error {
	return nil
}
