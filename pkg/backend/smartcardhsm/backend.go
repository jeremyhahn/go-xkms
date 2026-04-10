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

//go:build smartcardhsm

// Package smartcardhsm implements a backend for SmartCard-HSM devices.
//
// SmartCard-HSM is a lightweight hardware security module available as a
// USB token or smart card. It supports M-of-N key splitting using DKEK
// (Device Key Encryption Key) for secure key backup and migration.
//
// This backend embeds the standard PKCS#11 backend for cryptographic
// operations and adds SmartCard-HSM specific features like DKEK management
// via direct PC/SC APDU communication.
//
// Supported devices:
//   - Nitrokey HSM (based on SmartCard-HSM)
//   - CardContact SmartCard-HSM
//   - Any OpenSC-compatible SmartCard-HSM
package smartcardhsm

import (
	"context"
	"crypto"
	"fmt"
	"sync"

	"github.com/ebfe/scard"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Backend implements the types.KeyProvider interface for SmartCard-HSM devices.
// It embeds the PKCS#11 backend for standard cryptographic operations and adds
// SmartCard-HSM specific features like DKEK management.
type Backend struct {
	*pkcs11backend.Backend // Embedded PKCS#11 backend for crypto operations

	config    *Config
	pcscCtx   *scard.Context
	card      *scard.Card
	mu        sync.RWMutex
	connected bool
}

// Compile-time interface checks.
var (
	_ types.KeyProvider = (*Backend)(nil)
)

// NewBackend creates a new SmartCard-HSM backend instance.
func NewBackend(config *Config) (*Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("smartcardhsm: %w", err)
	}

	// Create embedded PKCS#11 backend
	pkcs11Backend, err := pkcs11backend.NewBackend(config.Config)
	if err != nil {
		return nil, fmt.Errorf("smartcardhsm: failed to create PKCS#11 backend: %w", err)
	}

	return &Backend{
		Backend: pkcs11Backend,
		config:  config,
	}, nil
}

// Type returns the backend type identifier.
func (b *Backend) Type() types.BackendType {
	return backend.BackendTypeSmartCardHSM
}

// Capabilities returns the capabilities of this backend.
func (b *Backend) Capabilities() types.Capabilities {
	caps := b.Backend.Capabilities()

	// SmartCard-HSM specific capabilities
	caps.Sealing = true
	caps.HardwareBacked = true

	return caps
}

// Initialize initializes both the PKCS#11 backend and PC/SC connection.
func (b *Backend) Initialize(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Initialize PKCS#11 backend first
	if err := b.Backend.Initialize(ctx); err != nil {
		return fmt.Errorf("smartcardhsm: PKCS#11 initialization failed: %w", err)
	}

	// Initialize PC/SC context for APDU commands
	if err := b.initPCSC(); err != nil {
		// PC/SC is optional - DKEK operations won't work but crypto will
		// Log warning but don't fail
		b.pcscCtx = nil
	}

	b.connected = true
	return nil
}

// Close closes the backend and releases resources.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	var errs []error

	// Disconnect from card
	if b.card != nil {
		if err := b.card.Disconnect(scard.LeaveCard); err != nil {
			errs = append(errs, fmt.Errorf("card disconnect: %w", err))
		}
		b.card = nil
	}

	// Release PC/SC context
	if b.pcscCtx != nil {
		if err := b.pcscCtx.Release(); err != nil {
			errs = append(errs, fmt.Errorf("pcsc release: %w", err))
		}
		b.pcscCtx = nil
	}

	// Close PKCS#11 backend
	if err := b.Backend.Close(); err != nil {
		errs = append(errs, fmt.Errorf("pkcs11 close: %w", err))
	}

	b.connected = false

	if len(errs) > 0 {
		return fmt.Errorf("smartcardhsm: close errors: %v", errs)
	}
	return nil
}

// IsConnected returns whether the backend is connected.
func (b *Backend) IsConnected() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.connected
}

// SupportsDKEK returns whether DKEK operations are available.
// DKEK requires PC/SC connection for direct APDU communication.
func (b *Backend) SupportsDKEK() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.card != nil
}

// initPCSC initializes the PC/SC context and connects to the SmartCard-HSM.
func (b *Backend) initPCSC() error {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return fmt.Errorf("failed to establish PC/SC context: %w", err)
	}
	b.pcscCtx = ctx

	// Find SmartCard-HSM reader
	readers, err := ctx.ListReaders()
	if err != nil {
		return fmt.Errorf("failed to list readers: %w", err)
	}

	var readerName string
	if b.config.ReaderName != "" {
		// Use configured reader
		readerName = b.config.ReaderName
	} else {
		// Auto-detect SmartCard-HSM reader
		for _, r := range readers {
			if isSmartCardHSMReader(r) {
				readerName = r
				break
			}
		}
	}

	if readerName == "" {
		return ErrCardNotFound
	}

	// Connect to card
	card, err := ctx.Connect(readerName, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		return fmt.Errorf("failed to connect to card: %w", err)
	}
	b.card = card

	return nil
}

// transmit sends an APDU command to the card and returns the response.
func (b *Backend) transmit(apdu *APDU) (*Response, error) {
	if b.card == nil {
		return nil, ErrNotInitialized
	}

	raw, err := b.card.Transmit(apdu.Bytes())
	if err != nil {
		return nil, fmt.Errorf("transmit failed: %w", err)
	}

	return ParseResponse(raw), nil
}

// isSmartCardHSMReader checks if a reader name indicates a SmartCard-HSM.
func isSmartCardHSMReader(name string) bool {
	// Common SmartCard-HSM reader names
	patterns := []string{
		"Nitrokey",
		"SmartCard-HSM",
		"CardContact",
		"JCOP",
	}
	for _, p := range patterns {
		if containsIgnoreCase(name, p) {
			return true
		}
	}
	return false
}

// containsIgnoreCase checks if s contains substr (case-insensitive).
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > 0 && len(substr) > 0 &&
			(s[0]|0x20) == (substr[0]|0x20) && containsIgnoreCase(s[1:], substr[1:]) ||
		len(s) > 0 && containsIgnoreCase(s[1:], substr))
}

// InitializeDevice initializes a new SmartCard-HSM with optional DKEK.
// This is a destructive operation that will erase all keys on the device.
//
// Parameters:
//   - soPin: Security Officer PIN for the device
//   - userPin: User PIN for normal operations
//   - retryCounter: Number of PIN retry attempts (1-15)
//   - dkekShares: Total DKEK shares (0 to disable DKEK, 1-8 for M-of-N)
//   - dkekThreshold: Minimum shares required (must be <= dkekShares)
//
// Returns the generated DKEK shares if dkekShares > 0.
func (b *Backend) InitializeDevice(soPin, userPin string, retryCounter, dkekShares, dkekThreshold int) ([]DKEKShare, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.card == nil {
		return nil, ErrNotInitialized
	}

	if retryCounter < 1 || retryCounter > 15 {
		retryCounter = 3
	}

	var shares []DKEKShare

	// Generate DKEK shares if requested
	if dkekShares > 0 {
		var err error
		shares, err = GenerateDKEKShares(dkekShares, dkekThreshold)
		if err != nil {
			return nil, err
		}
	}

	// Build and send initialize APDU
	options := byte(0x00) // Default options
	apdu := BuildInitializeAPDU(byte(retryCounter), options, byte(dkekShares), byte(dkekThreshold))

	resp, err := b.transmit(apdu)
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, NewAPDUError("InitializeDevice", resp.StatusWord())
	}

	return shares, nil
}

// Sign delegates to the embedded PKCS#11 backend.
func (b *Backend) Sign(ctx context.Context, keyID string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return b.Backend.Sign(ctx, keyID, digest, opts)
}

// Verify delegates to the embedded PKCS#11 backend.
func (b *Backend) Verify(ctx context.Context, keyID string, digest, signature []byte) (bool, error) {
	return b.Backend.Verify(ctx, keyID, digest, signature)
}

// Config returns the backend configuration.
func (b *Backend) Config() *Config {
	return b.config
}
