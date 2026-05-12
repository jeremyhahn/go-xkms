// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/jeremyhahn/go-objstore/pkg/common"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// kmsService implements the KMSService interface using go-xkms.
type kmsService struct {
	keyStore    xkmssdk.ServiceBackend
	objectStore common.Storage
	logger      *slog.Logger
}

// NewKMSService creates a new KMS service backed by go-xkms.
// The keyStore is used for key generation and signing operations.
// The objectStore is used for storing key metadata.
func NewKMSService(ks xkmssdk.ServiceBackend, os common.Storage, logger *slog.Logger) KMSService {
	if logger == nil {
		logger = slog.Default()
	}
	return &kmsService{
		keyStore:    ks,
		objectStore: os,
		logger:      logger,
	}
}

// CreateSigningKey creates a new signing key for the specified tenant and purpose.
func (s *kmsService) CreateSigningKey(ctx context.Context, tenantID string, purpose KeyPurpose, algorithm string) (*KeyMetadata, error) {
	if tenantID == "" {
		return nil, ErrInvalidInput.WithContext("tenant_id", "tenant ID is required")
	}
	if purpose == "" {
		return nil, ErrInvalidInput.WithContext("purpose", "key purpose is required")
	}
	if algorithm == "" {
		return nil, ErrInvalidInput.WithContext("algorithm", "algorithm is required")
	}

	// Generate key ID
	keyID := fmt.Sprintf("%s-%s-%d", tenantID, purpose, time.Now().UnixNano())

	// Create key attributes based on algorithm
	attrs, err := s.createKeyAttributes(keyID, algorithm)
	if err != nil {
		return nil, ErrInvalidInput.WithContext("algorithm", err.Error())
	}

	// Generate key pair based on algorithm type
	switch {
	case strings.HasPrefix(strings.ToUpper(algorithm), "RSA"):
		if _, err := s.keyStore.GenerateRSA(attrs); err != nil {
			return nil, ErrInternal.WithContext("operation", "generate RSA key").WithCause(err)
		}
	case strings.HasPrefix(strings.ToUpper(algorithm), "EC") ||
		strings.HasPrefix(strings.ToUpper(algorithm), "ECDSA"):
		if _, err := s.keyStore.GenerateECDSA(attrs); err != nil {
			return nil, ErrInternal.WithContext("operation", "generate ECDSA key").WithCause(err)
		}
	case strings.ToUpper(algorithm) == "ED25519":
		if _, err := s.keyStore.GenerateEd25519(attrs); err != nil {
			return nil, ErrInternal.WithContext("operation", "generate Ed25519 key").WithCause(err)
		}
	default:
		return nil, ErrInvalidInput.WithContext("algorithm", fmt.Sprintf("unsupported algorithm: %s", algorithm))
	}

	// Create metadata
	metadata := &KeyMetadata{
		KeyID:     keyID,
		TenantID:  tenantID,
		Purpose:   purpose,
		Algorithm: algorithm,
		Enabled:   true,
		CreatedAt: time.Now().Unix(),
	}

	// Store metadata in object store
	if err := s.storeKeyMetadata(ctx, metadata); err != nil {
		s.logger.Warn("failed to store key metadata, key was created but metadata may be lost",
			slog.String("key_id", keyID),
			slog.String("error", err.Error()))
	}

	s.logger.Info("created signing key",
		slog.String("tenant_id", tenantID),
		slog.String("purpose", string(purpose)),
		slog.String("algorithm", algorithm),
		slog.String("key_id", keyID))

	return metadata, nil
}

// GetSigningKey retrieves a signing key for the specified tenant and purpose.
func (s *kmsService) GetSigningKey(ctx context.Context, tenantID string, purpose KeyPurpose) (crypto.Signer, error) {
	if tenantID == "" {
		return nil, ErrInvalidInput.WithContext("tenant_id", "tenant ID is required")
	}
	if purpose == "" {
		return nil, ErrInvalidInput.WithContext("purpose", "key purpose is required")
	}

	// List keys for tenant and find matching purpose
	keys, err := s.ListSigningKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Find the first enabled key with matching purpose
	var keyID string
	for _, key := range keys {
		if key.Purpose == purpose && key.Enabled {
			keyID = key.KeyID
			break
		}
	}

	if keyID == "" {
		return nil, ErrKeyNotFound.WithContext("tenant_id", tenantID).WithContext("purpose", string(purpose))
	}

	// Get signer from xkms
	attrs := &xkmssdk.KeyAttributes{
		CN: keyID,
	}

	signer, err := s.keyStore.Signer(attrs)
	if err != nil {
		return nil, ErrInternal.WithContext("operation", "get signer").WithCause(err)
	}

	return signer, nil
}

// ListSigningKeys lists all signing keys for a tenant.
func (s *kmsService) ListSigningKeys(ctx context.Context, tenantID string) ([]*KeyMetadata, error) {
	if tenantID == "" {
		return nil, ErrInvalidInput.WithContext("tenant_id", "tenant ID is required")
	}

	if s.objectStore == nil {
		return []*KeyMetadata{}, nil
	}

	// List all key metadata for tenant
	prefix := fmt.Sprintf("kms/keys/%s/", tenantID)
	blobs, err := s.objectStore.List(prefix)
	if err != nil {
		// If no blobs found, return empty list
		return []*KeyMetadata{}, nil
	}

	var keys []*KeyMetadata
	for _, blobPath := range blobs {
		reader, err := s.objectStore.Get(blobPath)
		if err != nil {
			s.logger.Warn("failed to read key metadata",
				slog.String("path", blobPath),
				slog.String("error", err.Error()))
			continue
		}
		data, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			s.logger.Warn("failed to read key metadata data",
				slog.String("path", blobPath),
				slog.String("error", err.Error()))
			continue
		}

		var metadata KeyMetadata
		if err := json.Unmarshal(data, &metadata); err != nil {
			s.logger.Warn("failed to parse key metadata",
				slog.String("path", blobPath),
				slog.String("error", err.Error()))
			continue
		}

		keys = append(keys, &metadata)
	}

	return keys, nil
}

// DeleteSigningKey deletes a signing key.
func (s *kmsService) DeleteSigningKey(ctx context.Context, tenantID string, keyID string) error {
	if tenantID == "" {
		return ErrInvalidInput.WithContext("tenant_id", "tenant ID is required")
	}
	if keyID == "" {
		return ErrInvalidInput.WithContext("key_id", "key ID is required")
	}

	// Verify key belongs to tenant
	if !strings.HasPrefix(keyID, tenantID+"-") {
		return ErrKeyNotFound.WithContext("key_id", keyID).WithContext("tenant_id", tenantID)
	}

	// Delete from keystore
	attrs := &xkmssdk.KeyAttributes{
		CN: keyID,
	}

	if err := s.keyStore.DeleteKey(attrs); err != nil {
		return ErrInternal.WithContext("operation", "delete key").WithCause(err)
	}

	// Delete metadata
	if s.objectStore != nil {
		metadataPath := fmt.Sprintf("kms/keys/%s/%s.json", tenantID, keyID)
		if err := s.objectStore.Delete(metadataPath); err != nil {
			s.logger.Warn("failed to delete key metadata",
				slog.String("path", metadataPath),
				slog.String("error", err.Error()))
		}
	}

	s.logger.Info("deleted signing key",
		slog.String("tenant_id", tenantID),
		slog.String("key_id", keyID))

	return nil
}

// EnableSigningKey enables a previously disabled key.
func (s *kmsService) EnableSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return s.setKeyEnabled(ctx, tenantID, keyID, true)
}

// DisableSigningKey disables a key without deleting it.
func (s *kmsService) DisableSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return s.setKeyEnabled(ctx, tenantID, keyID, false)
}

// setKeyEnabled updates the enabled state of a key.
func (s *kmsService) setKeyEnabled(ctx context.Context, tenantID string, keyID string, enabled bool) error {
	if tenantID == "" {
		return ErrInvalidInput.WithContext("tenant_id", "tenant ID is required")
	}
	if keyID == "" {
		return ErrInvalidInput.WithContext("key_id", "key ID is required")
	}

	// Verify key belongs to tenant
	if !strings.HasPrefix(keyID, tenantID+"-") {
		return ErrKeyNotFound.WithContext("key_id", keyID).WithContext("tenant_id", tenantID)
	}

	if s.objectStore == nil {
		return ErrInternal.WithContext("operation", "object store not configured")
	}

	// Load metadata
	metadataPath := fmt.Sprintf("kms/keys/%s/%s.json", tenantID, keyID)
	reader, err := s.objectStore.Get(metadataPath)
	if err != nil {
		return ErrKeyNotFound.WithContext("key_id", keyID)
	}
	data, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		return ErrInternal.WithContext("operation", "read metadata").WithCause(err)
	}

	var metadata KeyMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return ErrInternal.WithContext("operation", "parse metadata").WithCause(err)
	}

	// Update enabled state
	metadata.Enabled = enabled

	// Save metadata
	if err := s.storeKeyMetadata(ctx, &metadata); err != nil {
		return err
	}

	action := "enabled"
	if !enabled {
		action = "disabled"
	}
	s.logger.Info(action+" signing key",
		slog.String("tenant_id", tenantID),
		slog.String("key_id", keyID))

	return nil
}

// storeKeyMetadata stores key metadata in the object store.
func (s *kmsService) storeKeyMetadata(ctx context.Context, metadata *KeyMetadata) error {
	if s.objectStore == nil {
		return nil // No object store, skip metadata storage
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return ErrInternal.WithContext("operation", "marshal metadata").WithCause(err)
	}

	metadataPath := fmt.Sprintf("kms/keys/%s/%s.json", metadata.TenantID, metadata.KeyID)
	if err := s.objectStore.Put(metadataPath, bytes.NewReader(data)); err != nil {
		return ErrInternal.WithContext("operation", "store metadata").WithCause(err)
	}

	return nil
}

// createKeyAttributes creates key attributes for the given algorithm.
func (s *kmsService) createKeyAttributes(keyID, algorithm string) (*xkmssdk.KeyAttributes, error) {
	attrs := &xkmssdk.KeyAttributes{
		CN: keyID,
	}

	switch strings.ToUpper(algorithm) {
	case "RSA-2048":
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{KeySize: 2048}
	case "RSA-4096":
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{KeySize: 4096}
	case "RSA-8192":
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{KeySize: 8192}
	case "ECDSA-P256", "EC-P256":
		attrs.ECCAttributes = &xkmssdk.ECCAttributes{Curve: elliptic.P256()}
	case "ECDSA-P384", "EC-P384":
		attrs.ECCAttributes = &xkmssdk.ECCAttributes{Curve: elliptic.P384()}
	case "ECDSA-P521", "EC-P521":
		attrs.ECCAttributes = &xkmssdk.ECCAttributes{Curve: elliptic.P521()}
	case "ED25519":
		// Ed25519 doesn't need additional attributes
	default:
		return nil, caerrors.MalformedError("unsupported algorithm: %s", algorithm)
	}

	return attrs, nil
}

// StoreCertificate stores a certificate for a tenant's CA.
func (s *kmsService) StoreCertificate(ctx context.Context, tenantID string, purpose KeyPurpose, certDER []byte) error {
	if tenantID == "" {
		return ErrInvalidInput.WithContext("tenant_id", "tenant ID is required")
	}
	if purpose == "" {
		return ErrInvalidInput.WithContext("purpose", "key purpose is required")
	}
	if len(certDER) == 0 {
		return ErrInvalidInput.WithContext("cert_der", "certificate data is required")
	}
	if s.objectStore == nil {
		return ErrInternal.WithContext("operation", "object store not configured")
	}

	// Store certificate in object store
	certPath := fmt.Sprintf("kms/certs/%s/%s.der", tenantID, purpose)
	if err := s.objectStore.Put(certPath, bytes.NewReader(certDER)); err != nil {
		return ErrInternal.WithContext("operation", "store certificate").WithCause(err)
	}

	s.logger.Info("stored tenant CA certificate",
		slog.String("tenant_id", tenantID),
		slog.String("purpose", string(purpose)),
		slog.Int("cert_size", len(certDER)))

	return nil
}

// GetCertificate retrieves a certificate for a tenant's CA.
func (s *kmsService) GetCertificate(ctx context.Context, tenantID string, purpose KeyPurpose) ([]byte, error) {
	if tenantID == "" {
		return nil, ErrInvalidInput.WithContext("tenant_id", "tenant ID is required")
	}
	if purpose == "" {
		return nil, ErrInvalidInput.WithContext("purpose", "key purpose is required")
	}
	if s.objectStore == nil {
		return nil, ErrInternal.WithContext("operation", "object store not configured")
	}

	// Retrieve certificate from object store
	certPath := fmt.Sprintf("kms/certs/%s/%s.der", tenantID, purpose)
	reader, err := s.objectStore.Get(certPath)
	if err != nil {
		return nil, ErrNotFound.WithContext("tenant_id", tenantID).WithContext("purpose", string(purpose))
	}
	defer func() { _ = reader.Close() }()

	certDER, err := io.ReadAll(reader)
	if err != nil {
		return nil, ErrInternal.WithContext("operation", "read certificate").WithCause(err)
	}

	return certDER, nil
}

// DeleteCertificate deletes a tenant's CA certificate.
func (s *kmsService) DeleteCertificate(ctx context.Context, tenantID string, purpose KeyPurpose) error {
	if tenantID == "" {
		return ErrInvalidInput.WithContext("tenant_id", "tenant ID is required")
	}
	if purpose == "" {
		return ErrInvalidInput.WithContext("purpose", "key purpose is required")
	}
	if s.objectStore == nil {
		return ErrInternal.WithContext("operation", "object store not configured")
	}

	certPath := fmt.Sprintf("kms/certs/%s/%s.der", tenantID, purpose)
	if err := s.objectStore.Delete(certPath); err != nil {
		s.logger.Warn("failed to delete certificate",
			slog.String("path", certPath),
			slog.String("error", err.Error()))
	}

	s.logger.Info("deleted tenant CA certificate",
		slog.String("tenant_id", tenantID),
		slog.String("purpose", string(purpose)))

	return nil
}

// Verify interface compliance.
var _ KMSService = (*kmsService)(nil)
