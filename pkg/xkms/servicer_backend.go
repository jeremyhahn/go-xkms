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

package xkms

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/validation"
)

// ListBackends returns information about all registered backends.
// Implements the BackendServicer interface.
func (s *XKMSService) ListBackends(ctx context.Context, opts ...transport.ListOption) ([]transport.BackendInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	backends := make([]transport.BackendInfo, 0, len(s.backends))
	for id, b := range s.backends {
		kp := b.KeyProvider()
		caps := kp.Capabilities()

		backends = append(backends, transport.BackendInfo{
			ID:             id,
			Type:           string(kp.Type()),
			HardwareBacked: caps.HardwareBacked,
			Capabilities:   capabilitiesToTransport(caps),
		})
	}

	return backends, nil
}

// GetBackend returns information about a specific backend by ID.
// Implements the BackendServicer interface.
func (s *XKMSService) GetBackend(ctx context.Context, backendID string) (*transport.BackendInfo, error) {
	if err := validation.ValidateBackendName(backendID); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	b, ok := s.backends[backendID]
	if !ok {
		return nil, &ErrBackendLookup{Sentinel: ErrBackendNotFound, Name: validation.SanitizeForLog(backendID)}
	}

	kp := b.KeyProvider()
	caps := kp.Capabilities()

	return &transport.BackendInfo{
		ID:             backendID,
		Type:           string(kp.Type()),
		HardwareBacked: caps.HardwareBacked,
		Capabilities:   capabilitiesToTransport(caps),
	}, nil
}

// capabilitiesToTransport converts a types.Capabilities to a transport.BackendCapabilities.
func capabilitiesToTransport(caps types.Capabilities) transport.BackendCapabilities {
	return transport.BackendCapabilities{
		Keys:                caps.Keys,
		HardwareBacked:      caps.HardwareBacked,
		Signing:             caps.Signing,
		Decryption:          caps.Decryption,
		KeyRotation:         caps.KeyRotation,
		SymmetricEncryption: caps.SymmetricEncryption,
		Sealing:             caps.Sealing,
		Import:              caps.Import,
		Export:              caps.Export,
		KeyAgreement:        caps.KeyAgreement,
		ECIES:               caps.ECIES,
		Attestation:         caps.Attestation,
		QuantumSigning:      caps.QuantumSigning,
		KeyEncapsulation:    caps.KeyEncapsulation,
	}
}
