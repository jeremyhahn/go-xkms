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

//go:build !smartcardhsm

package smartcardhsm

import (
	"context"
	"crypto"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var errNotCompiled = errors.New("smartcardhsm: support not compiled in (build with -tags smartcardhsm)")

// Backend is a stub when SmartCard-HSM support is not compiled in.
type Backend struct{}

// NewBackend returns an error when SmartCard-HSM is not compiled in.
func NewBackend(config *Config) (*Backend, error) {
	return nil, errNotCompiled
}

func (b *Backend) Type() types.BackendType              { return backend.BackendTypeSmartCardHSM }
func (b *Backend) Capabilities() types.Capabilities     { return types.Capabilities{} }
func (b *Backend) Initialize(ctx context.Context) error { return errNotCompiled }
func (b *Backend) Close() error                         { return errNotCompiled }
func (b *Backend) IsConnected() bool                    { return false }
func (b *Backend) SupportsDKEK() bool                   { return false }

func (b *Backend) GetDKEKStatus() (*DKEKStatus, error)            { return nil, errNotCompiled }
func (b *Backend) ImportDKEKShare(share DKEKShare) (int, error)   { return 0, errNotCompiled }
func (b *Backend) WrapKey(keyRef byte) ([]byte, error)            { return nil, errNotCompiled }
func (b *Backend) UnwrapKey(keyRef byte, wrappedKey []byte) error { return errNotCompiled }
func (b *Backend) InitializeDevice(soPin, userPin string, retryCounter, dkekShares, dkekThreshold int) ([]DKEKShare, error) {
	return nil, errNotCompiled
}

func (b *Backend) Sign(ctx context.Context, keyID string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errNotCompiled
}
func (b *Backend) Verify(ctx context.Context, keyID string, digest, signature []byte) (bool, error) {
	return false, errNotCompiled
}
func (b *Backend) Config() *Config { return nil }
