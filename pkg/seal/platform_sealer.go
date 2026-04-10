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

package seal

import (
	"context"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// strategyMetadataKey is the metadata key used to tag sealed data with the
// strategy that produced it. This enables automatic strategy selection on unseal.
const strategyMetadataKey = "seal:strategy"

// Compile-time interface check.
var _ types.Sealer = (*PlatformSealer)(nil)

// PlatformSealer orchestrates data sealing across multiple backend sealers.
// It implements the types.Sealer interface with automatic strategy selection
// based on a configurable preference order.
type PlatformSealer struct {
	logger    *slog.Logger
	config    SealerConfig
	sealers   map[StrategyID]types.Sealer
	prefOrder []StrategyID
}

// NewPlatformSealer creates a PlatformSealer from the given sealer map.
// At least one sealer must be provided.
func NewPlatformSealer(
	logger *slog.Logger,
	config SealerConfig,
	sealers map[StrategyID]types.Sealer,
) (*PlatformSealer, error) {
	if len(sealers) == 0 {
		return nil, ErrNoAvailableStrategy
	}

	prefOrder := config.PreferenceOrder
	if len(prefOrder) == 0 {
		prefOrder = DefaultPreferenceOrder
	}

	return &PlatformSealer{
		logger:    logger,
		config:    config,
		sealers:   sealers,
		prefOrder: prefOrder,
	}, nil
}

// Seal encrypts data using the best available strategy. The chosen strategy
// is recorded in the sealed data metadata for automatic selection on unseal.
func (p *PlatformSealer) Seal(
	ctx context.Context,
	data []byte,
	opts *types.SealOptions,
) (*types.SealedData, error) {
	id, err := p.BestStrategy()
	if err != nil {
		return nil, err
	}
	return p.sealWith(ctx, id, data, opts)
}

// Unseal decrypts data by reading the strategy tag from metadata and
// delegating to the appropriate sealer.
func (p *PlatformSealer) Unseal(
	ctx context.Context,
	sealed *types.SealedData,
	opts *types.UnsealOptions,
) ([]byte, error) {
	if sealed == nil {
		return nil, ErrNilSealedData
	}

	// Read strategy from metadata.
	stratBytes, ok := sealed.Metadata[strategyMetadataKey]
	if !ok {
		return nil, ErrStrategyMismatch
	}
	id := StrategyID(stratBytes)

	sealer, found := p.sealers[id]
	if !found {
		emitAudit(p.config.AuditLogger, "unseal", "platform_sealer", string(id),
			"deny", map[string]string{"error": ErrStrategyNotFound.Error()})
		return nil, ErrStrategyNotFound
	}

	plaintext, err := sealer.Unseal(ctx, sealed, opts)
	if err != nil {
		emitAudit(p.config.AuditLogger, "unseal", "platform_sealer", string(id),
			"deny", map[string]string{"error": err.Error()})
		return nil, err
	}

	emitAudit(p.config.AuditLogger, "unseal", "platform_sealer", string(id),
		"allow", nil)
	return plaintext, nil
}

// CanSeal returns true if at least one registered sealer can seal data.
func (p *PlatformSealer) CanSeal() bool {
	for _, sealer := range p.sealers {
		if sealer.CanSeal() {
			return true
		}
	}
	return false
}

// SealWith encrypts data using a specific named strategy.
func (p *PlatformSealer) SealWith(
	ctx context.Context,
	id StrategyID,
	data []byte,
	opts *types.SealOptions,
) (*types.SealedData, error) {
	if _, ok := p.sealers[id]; !ok {
		return nil, ErrStrategyNotFound
	}
	return p.sealWith(ctx, id, data, opts)
}

// BestStrategy returns the first available strategy in preference order.
func (p *PlatformSealer) BestStrategy() (StrategyID, error) {
	for _, id := range p.prefOrder {
		if sealer, ok := p.sealers[id]; ok && sealer.CanSeal() {
			return id, nil
		}
	}
	return "", ErrNoAvailableStrategy
}

// AvailableStrategies returns all strategy IDs whose sealers report CanSeal.
func (p *PlatformSealer) AvailableStrategies() []StrategyID {
	available := make([]StrategyID, 0, len(p.sealers))
	for id, sealer := range p.sealers {
		if sealer.CanSeal() {
			available = append(available, id)
		}
	}
	return available
}

// sealWith performs the actual seal operation for a given strategy.
func (p *PlatformSealer) sealWith(
	ctx context.Context,
	id StrategyID,
	data []byte,
	opts *types.SealOptions,
) (*types.SealedData, error) {
	sealer := p.sealers[id]

	sealed, err := sealer.Seal(ctx, data, opts)
	if err != nil {
		emitAudit(p.config.AuditLogger, "seal", "platform_sealer", string(id),
			"deny", map[string]string{"error": err.Error()})
		return nil, err
	}

	// Tag the sealed data with the strategy for unseal routing.
	if sealed.Metadata == nil {
		sealed.Metadata = make(map[string][]byte)
	}
	sealed.Metadata[strategyMetadataKey] = []byte(id)

	emitAudit(p.config.AuditLogger, "seal", "platform_sealer", string(id),
		"allow", nil)

	return sealed, nil
}
