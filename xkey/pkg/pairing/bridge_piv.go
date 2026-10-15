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
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// DefaultPIVBackend is the PIV backend name used when a request does not
// name one, matching the "xkey piv" command family's own default.
const DefaultPIVBackend = "software"

// PIVStorageProvider resolves the certificate storage for a named PIV
// backend (e.g. "software", "tpm2", "pkcs11") so the bridge can serve
// remote.pivListSlots and remote.pivGetCert. The concrete storage
// construction (file/tpm2/pkcs11 selection, paths, PKCS#11 session) lives in
// the CLI layer, which already builds it for the "xkey piv" command family
// (see cmd/xkey/cmd/piv.go's createPIVStorage). The bridge closes the
// returned storage after each request.
type PIVStorageProvider func(backend string) (xkms.PIVCertificateStorage, error)

// pivBackendOrDefault returns backend, or DefaultPIVBackend when the phone
// did not name one.
func pivBackendOrDefault(backend string) string {
	if backend == "" {
		return DefaultPIVBackend
	}
	return backend
}

// handlePIVListSlots handles remote.pivListSlots - the phone asks the laptop
// to enumerate its PIV slot contents.
//
// Slot/certificate metadata comes from the Bridge's configured
// PIVStorageProvider (see BridgeConfig.PIVStorage). Whether a slot also has a
// private key is answered by Client.ListKeys on the same backend, since PIV
// keys are stored under KeyID == slot alongside every other key that backend
// holds. When no storage provider is configured, ErrPIVNotConfigured is
// returned.
func (b *Bridge) handlePIVListSlots(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p pairingproto.RemotePIVListSlotsParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, pairingproto.ErrBridgeInvalidParams
		}
	}

	backend := pivBackendOrDefault(p.Backend)

	b.logger.Info("PIV list slots requested",
		"backend", backend)

	if b.pivStorage == nil {
		return nil, pairingproto.ErrPIVNotConfigured
	}

	storage, err := b.pivStorage(backend)
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrPIVNotConfigured, Cause: err}
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			b.logger.Warn("failed to close PIV storage", "backend", backend, "error", closeErr)
		}
	}()

	slots, err := storage.List()
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrPIVSlotNotFound, Cause: err}
	}

	keysWithSlot := b.pivBackendKeyIDs(ctx, backend)

	result := make([]pairingproto.PIVSlotInfo, 0, len(slots))
	for _, slot := range slots {
		_, hasKey := keysWithSlot[string(slot.Slot)]
		result = append(result, pairingproto.PIVSlotInfo{
			Slot:           string(slot.Slot),
			Label:          xkms.PIVSlotName(slot.Slot),
			Algorithm:      slot.Algorithm,
			HasKey:         hasKey,
			HasCertificate: true,
			CertSubject:    slot.Subject,
			CertExpiry:     slot.NotAfter,
		})
	}

	return &pairingproto.RemotePIVListSlotsResult{Slots: result}, nil
}

// pivBackendKeyIDs returns the set of KeyIDs present in backend, via the same
// Client.ListKeys the generic remote.listKeys method uses. A lookup failure
// is logged and treated as "no keys known" rather than failing the whole
// slot listing: certificate metadata is still useful to the phone even when
// the key-presence hint cannot be computed.
func (b *Bridge) pivBackendKeyIDs(ctx context.Context, backend string) map[string]struct{} {
	ids := make(map[string]struct{})
	resp, err := b.client.ListKeys(ctx, backend)
	if err != nil || resp == nil {
		if err != nil {
			b.logger.Warn("failed to list keys for PIV slot key-presence check",
				"backend", backend, "error", err)
		}
		return ids
	}
	for i := range resp.Keys {
		ids[resp.Keys[i].KeyID] = struct{}{}
	}
	return ids
}

// handlePIVSign handles remote.pivSign - the phone requests the laptop to
// sign data using a key in a PIV slot.
//
// PIV keys are stored under KeyID == slot in the named key backend, so
// signing is served by Client.Sign exactly like remote.sign: no separate PIV
// signer plumbing is needed on the bridge.
func (b *Bridge) handlePIVSign(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p pairingproto.RemotePIVSignParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, pairingproto.ErrBridgeInvalidParams
	}

	if p.Slot == "" {
		return nil, pairingproto.ErrPIVInvalidSlot
	}
	if len(p.Data) == 0 {
		return nil, pairingproto.ErrBridgeInvalidParams
	}

	backend := pivBackendOrDefault(p.Backend)

	if err := b.checkBackendAccess(backend); err != nil {
		return nil, err
	}

	b.logger.Info("PIV sign requested",
		"slot", p.Slot,
		"dataLen", len(p.Data),
		"algorithm", p.Algorithm,
		"backend", backend)

	resp, err := b.client.Sign(ctx, &transport.SignRequest{
		Backend: backend,
		KeyID:   p.Slot,
		Data:    p.Data,
		Hash:    p.Algorithm,
	})
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrPIVSignFailed, Cause: err}
	}

	algorithm := resp.Algorithm
	if algorithm == "" {
		algorithm = p.Algorithm
	}

	return &pairingproto.RemotePIVSignResult{
		Signature: resp.Signature,
		Algorithm: algorithm,
	}, nil
}

// handlePIVGetCert handles remote.pivGetCert - the phone requests a
// certificate from a PIV slot on the laptop.
//
// The certificate comes from the Bridge's configured PIVStorageProvider.
// When no storage provider is configured, ErrPIVNotConfigured is returned.
func (b *Bridge) handlePIVGetCert(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p pairingproto.RemotePIVGetCertParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, pairingproto.ErrBridgeInvalidParams
	}

	if p.Slot == "" {
		return nil, pairingproto.ErrPIVInvalidSlot
	}

	backend := pivBackendOrDefault(p.Backend)

	b.logger.Info("PIV get certificate requested",
		"slot", p.Slot,
		"backend", backend)

	if b.pivStorage == nil {
		return nil, pairingproto.ErrPIVNotConfigured
	}

	storage, err := b.pivStorage(backend)
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrPIVNotConfigured, Cause: err}
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			b.logger.Warn("failed to close PIV storage", "backend", backend, "error", closeErr)
		}
	}()

	cert, err := storage.Retrieve(xkms.PIVSlot(p.Slot))
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrPIVSlotNotFound, Cause: err}
	}

	return &pairingproto.RemotePIVGetCertResult{
		CertificateDER: cert.Raw,
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		Expiry:         cert.NotAfter.UTC().Format(time.RFC3339),
	}, nil
}
