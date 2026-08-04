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

package manager

import (
	"log/slog"
)

// stubManager is the fallback implementation when PKCS#11 is not compiled in.
type stubManager struct {
	log *slog.Logger
}

// Compile-time interface check.
var _ Manager = (*stubManager)(nil)

// New creates a new PKCS#11 manager.
// When built without the pkcs11 tag, this returns a stub that returns
// ErrPKCS11Disabled for all operations.
func New(opts ...Option) Manager {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	logger := o.logger
	if logger == nil {
		logger = slog.Default()
	}

	return &stubManager{log: logger}
}

func (m *stubManager) IsAvailable() bool {
	return false
}

func (m *stubManager) RegisterModule(libraryPath, displayName string) (string, error) {
	return "", ErrPKCS11Disabled
}

func (m *stubManager) UnregisterModule(moduleID string) error {
	return ErrPKCS11Disabled
}

func (m *stubManager) RefreshSlots(moduleID string) ([]SlotInfo, error) {
	return nil, ErrPKCS11Disabled
}

func (m *stubManager) GetModule(moduleID string) (*ModuleInfo, error) {
	return nil, ErrPKCS11Disabled
}

func (m *stubManager) ListModules() []ModuleInfo {
	return nil
}

func (m *stubManager) ListTokens() []TokenInfo {
	return nil
}

func (m *stubManager) InitializeToken(moduleID string, slotID uint, label, soPin, userPin string) error {
	return ErrPKCS11Disabled
}

func (m *stubManager) TestLogin(moduleID string, slotID uint, userPin string) error {
	return ErrPKCS11Disabled
}

func (m *stubManager) Connect(moduleID string, slotID uint, userPin, soPin string) (Backend, error) {
	return nil, ErrPKCS11Disabled
}

func (m *stubManager) Disconnect(moduleID string, slotID uint) error {
	return ErrPKCS11Disabled
}

func (m *stubManager) GetConnection(moduleID string, slotID uint) (*Connection, error) {
	return nil, ErrPKCS11Disabled
}

func (m *stubManager) ListConnections() []*Connection {
	return nil
}

func (m *stubManager) Close() error {
	return nil
}
