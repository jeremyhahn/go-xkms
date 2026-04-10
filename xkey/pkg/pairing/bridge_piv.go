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

package pairing

import (
	"context"
	"encoding/json"
)

// handlePIVListSlots handles remote.pivListSlots - the phone asks the laptop
// to enumerate its PIV slot contents.
//
// This is a placeholder implementation. The bridge will be connected to the
// PIV service in the CLI layer when the PIV command is invoked. The actual
// slot enumeration logic (reading key metadata, certificate info) will be
// implemented in the PIV service and wired in via functional options or a
// setter on the Bridge.
func (b *Bridge) handlePIVListSlots(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemotePIVListSlotsParams
	if params != nil && len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, ErrBridgeInvalidParams
		}
	}

	b.logger.Info("PIV list slots requested",
		"backend", p.Backend)

	return &RemotePIVListSlotsResult{
		Slots: []PIVSlotInfo{},
	}, nil
}

// handlePIVSign handles remote.pivSign - the phone requests the laptop to
// sign data using a key in a PIV slot.
//
// This is a placeholder implementation. The actual signing logic (slot lookup,
// key access, signature generation) will be implemented in the PIV service
// and wired in when the PIV sign command is invoked.
func (b *Bridge) handlePIVSign(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemotePIVSignParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	if p.Slot == "" {
		return nil, ErrPIVInvalidSlot
	}
	if len(p.Data) == 0 {
		return nil, ErrBridgeInvalidParams
	}

	b.logger.Info("PIV sign requested",
		"slot", p.Slot,
		"dataLen", len(p.Data),
		"algorithm", p.Algorithm,
		"backend", p.Backend)

	return &RemotePIVSignResult{
		Signature: nil,
		Algorithm: p.Algorithm,
	}, nil
}

// handlePIVGetCert handles remote.pivGetCert - the phone requests a
// certificate from a PIV slot on the laptop.
//
// This is a placeholder implementation. The actual certificate retrieval
// logic (slot lookup, certificate extraction) will be implemented in the
// PIV service and wired in when the PIV get-cert command is invoked.
func (b *Bridge) handlePIVGetCert(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemotePIVGetCertParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	if p.Slot == "" {
		return nil, ErrPIVInvalidSlot
	}

	b.logger.Info("PIV get certificate requested",
		"slot", p.Slot,
		"backend", p.Backend)

	return &RemotePIVGetCertResult{
		CertificateDER: nil,
	}, nil
}
