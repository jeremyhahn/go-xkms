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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// handleSharePublicKey imports a public key (and optional certificate) from the
// phone into a xkmsd backend on the laptop. The phone sends its public key
// PEM and optional certificate PEM; the bridge imports them via the SDK.
func (b *Bridge) handleSharePublicKey(ctx context.Context, params json.RawMessage) (interface{}, error) {
	start := time.Now()

	var p RemoteSharePublicKeyParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	// Validate required fields.
	if len(p.PublicKeyPEM) == 0 {
		return nil, ErrInvalidPublicKey
	}
	if p.Algorithm == "" {
		return nil, ErrBridgeInvalidParams
	}

	// Determine target backend (use specified or default to "software").
	targetBackend := p.Backend
	if targetBackend == "" {
		targetBackend = "software"
	}

	if err := b.checkBackendAccess(targetBackend); err != nil {
		return nil, err
	}

	// Derive a key label for the import.
	keyID := p.Label
	if keyID == "" {
		keyID = "shared-" + p.KeyID
	}

	// Import the public key via the SDK.
	resp, err := b.client.ImportKey(ctx, &transport.ImportKeyRequest{
		Backend:            targetBackend,
		KeyID:              keyID,
		WrappedKeyMaterial: p.PublicKeyPEM,
		Algorithm:          p.Algorithm,
		KeyType:            "public",
	})

	durationMs := time.Since(start).Milliseconds()

	if err != nil {
		b.logger.Error("failed to import shared public key",
			"backend", targetBackend,
			"keyID", keyID,
			"error", err)
		return nil, err
	}

	// If a certificate was provided, save it alongside the key.
	if len(p.CertificatePEM) > 0 {
		certErr := b.client.SaveCertificate(ctx, &transport.SaveCertificateRequest{
			Backend:        targetBackend,
			KeyID:          resp.KeyID,
			CertificatePEM: string(p.CertificatePEM),
		})
		if certErr != nil {
			b.logger.Warn("failed to save certificate for shared key",
				"backend", targetBackend,
				"keyID", resp.KeyID,
				"error", certErr)
		}
	}

	// Audit log the key import.
	if b.auditLogger != nil {
		b.auditLogger.LogKeyOperation(
			audit.OpKeyCreated,
			targetBackend,
			resp.KeyID,
			true,
			nil,
			durationMs,
		)
	}

	return &RemoteSharePublicKeyResult{
		Accepted: true,
		ImportID: resp.KeyID,
		Backend:  targetBackend,
	}, nil
}

// handleShareSymmetric imports a wrapped symmetric key from the phone into a
// xkmsd backend on the laptop. The phone sends the wrapped key material,
// algorithm, and key size; the bridge imports via the SDK.
func (b *Bridge) handleShareSymmetric(ctx context.Context, params json.RawMessage) (interface{}, error) {
	start := time.Now()

	var p RemoteShareSymmetricParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	if len(p.WrappedKey) == 0 {
		return nil, ErrBridgeInvalidParams
	}
	if p.Algorithm == "" {
		return nil, ErrBridgeInvalidParams
	}

	targetBackend := p.Backend
	if targetBackend == "" {
		targetBackend = "software"
	}

	if err := b.checkBackendAccess(targetBackend); err != nil {
		return nil, err
	}

	keyID := p.Label
	if keyID == "" {
		keyID = "shared-sym-" + p.KeyID
	}

	resp, err := b.client.ImportKey(ctx, &transport.ImportKeyRequest{
		Backend:            targetBackend,
		KeyID:              keyID,
		WrappedKeyMaterial: p.WrappedKey,
		Algorithm:          p.Algorithm,
		KeyType:            "symmetric",
		KeySize:            p.KeySize,
	})

	durationMs := time.Since(start).Milliseconds()

	if err != nil {
		b.logger.Error("failed to import shared symmetric key",
			"backend", targetBackend,
			"keyID", keyID,
			"error", err)
		return nil, err
	}

	// Audit log the symmetric key import.
	if b.auditLogger != nil {
		b.auditLogger.LogKeyOperation(
			audit.OpKeyCreated,
			targetBackend,
			resp.KeyID,
			true,
			nil,
			durationMs,
		)
	}

	return &RemoteShareSymmetricResult{
		Accepted: true,
		ImportID: resp.KeyID,
		Backend:  targetBackend,
	}, nil
}

// handleImportSharedKey exports a key from a xkmsd backend so the phone
// can import it. For asymmetric keys, the public key and optional certificate
// are returned. For symmetric/exportable keys, the wrapped key material is
// also included if the export succeeds.
func (b *Bridge) handleImportSharedKey(ctx context.Context, params json.RawMessage) (interface{}, error) {
	start := time.Now()

	var p RemoteImportSharedKeyParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	if p.Backend == "" || p.KeyID == "" {
		return nil, ErrBridgeInvalidParams
	}

	if err := b.checkBackendAccess(p.Backend); err != nil {
		return nil, err
	}

	// Get key info to determine type and exportability.
	keyResp, err := b.client.GetKey(ctx, p.Backend, p.KeyID)
	if err != nil {
		return nil, err
	}

	result := &RemoteImportSharedKeyResult{
		Algorithm: keyResp.Algorithm,
	}

	// Always export the public key if available.
	if keyResp.PublicKeyPEM != "" {
		result.PublicKeyPEM = []byte(keyResp.PublicKeyPEM)
		result.KeyType = "public"
		result.Exportable = true
	}

	// Try to get the certificate.
	certResp, certErr := b.client.GetCertificate(ctx, p.Backend, p.KeyID)
	if certErr == nil && certResp != nil {
		result.CertificatePEM = []byte(certResp.CertificatePEM)
	}

	// For symmetric or unknown algorithm keys, try to export key material.
	if keyResp.Algorithm == "" || isSymmetricAlgorithm(keyResp.Algorithm) {
		exportResp, exportErr := b.client.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{
			Backend: p.Backend,
			KeyID:   p.KeyID,
		})
		if exportErr == nil && exportResp != nil {
			result.WrappedKey = exportResp.KeyMaterial
			result.KeyType = "symmetric"
			result.KeySize = exportResp.KeySize
			result.Exportable = true
		}
	}

	durationMs := time.Since(start).Milliseconds()

	// Audit log the export.
	if b.auditLogger != nil {
		b.auditLogger.LogKeyOperation(
			audit.OpKeyAccessed,
			p.Backend,
			p.KeyID,
			true,
			nil,
			durationMs,
		)
	}

	return result, nil
}

// generateImportID creates a deterministic import ID from key material
// by computing a truncated SHA-256 hash.
func generateImportID(keyData []byte) string {
	h := sha256.Sum256(keyData)
	return hex.EncodeToString(h[:8])
}

// isSymmetricAlgorithm checks if the algorithm name indicates a symmetric key.
func isSymmetricAlgorithm(alg string) bool {
	upper := strings.ToUpper(alg)
	symmetricPrefixes := [4]string{"AES", "CHACHA", "HMAC", "SYMMETRIC"}
	for _, prefix := range symmetricPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}
