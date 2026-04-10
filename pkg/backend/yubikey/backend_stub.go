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

package yubikey

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var errNotCompiled = errors.New("yubikey: PKCS#11 support not compiled in (build with -tags pkcs11)")

// PIV slots
const (
	SlotAuthentication     = 0x9A
	SlotSignature          = 0x9C
	SlotKeyManagement      = 0x9D
	SlotCardAuthentication = 0x9E
	SlotAttestation        = 0xF9
)

// Backend is a stub when PKCS#11 is not compiled in.
type Backend struct{}

// Config is a stub configuration.
type Config struct{}

// NewConfig returns a stub configuration.
func NewConfig() *Config { return &Config{} }

// Validate returns an error when not compiled in.
func (c *Config) Validate() error { return errNotCompiled }

// NewBackend returns an error when not compiled in.
func NewBackend(config *Config) (*Backend, error) {
	return nil, errNotCompiled
}

func (b *Backend) Type() types.BackendType              { return backend.BackendTypeYubiKey }
func (b *Backend) Capabilities() types.Capabilities     { return types.Capabilities{} }
func (b *Backend) Initialize(ctx context.Context) error { return errNotCompiled }
func (b *Backend) Close() error                         { return errNotCompiled }

func (b *Backend) GetAttestationCertificate(keySlot uint) (*x509.Certificate, error) {
	return nil, errNotCompiled
}
func (b *Backend) GenerateAttestationStatement(keySlot uint) ([]*x509.Certificate, error) {
	return nil, errNotCompiled
}
func (b *Backend) Sign(ctx context.Context, keyID string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errNotCompiled
}
func (b *Backend) Verify(ctx context.Context, keyID string, digest, signature []byte) (bool, error) {
	return false, errNotCompiled
}
func (b *Backend) Config() *Config            { return nil }
func (b *Backend) GetSerialNumber() string    { return "" }
func (b *Backend) GetFirmwareVersion() string { return "" }
