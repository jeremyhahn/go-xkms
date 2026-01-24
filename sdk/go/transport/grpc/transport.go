// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package grpc provides a gRPC transport implementation for the keychain SDK.
package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/jeremyhahn/go-keychain/sdk/go/transport"

	pb "github.com/jeremyhahn/go-keychain/pkg/api/grpc/proto/keychainv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = errors.New("client not connected")
	// ErrNotSupported is returned when an operation is not supported.
	ErrNotSupported = errors.New("operation not supported by this protocol")
	// ErrConnectionFailed is returned when a connection fails.
	ErrConnectionFailed = errors.New("connection failed")
)

// Transport implements the transport.Client interface using gRPC.
type Transport struct {
	config    *transport.Config
	conn      *grpc.ClientConn
	client    pb.KeystoreServiceClient
	connected bool
}

// New creates a new gRPC transport with the given options.
func New(opts ...transport.Option) (*Transport, error) {
	cfg := transport.DefaultConfig()
	if err := transport.ApplyOptions(cfg, opts...); err != nil {
		return nil, err
	}

	return &Transport{
		config: cfg,
	}, nil
}

// NewWithConfig creates a new gRPC transport with the given configuration.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	if cfg == nil {
		cfg = transport.DefaultConfig()
	}

	return &Transport{
		config: cfg,
	}, nil
}

// Connect establishes a connection to the keychain server via gRPC.
func (t *Transport) Connect(ctx context.Context) error {
	var opts []grpc.DialOption

	if t.config.TLSEnabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: t.config.TLSInsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}

		// Load CA certificate if specified
		if t.config.TLSCAFile != "" {
			caCert, err := os.ReadFile(t.config.TLSCAFile)
			if err != nil {
				return fmt.Errorf("failed to read CA certificate: %w", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("failed to parse CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}

		// Load client certificate if specified (mTLS)
		if t.config.TLSCertFile != "" && t.config.TLSKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(t.config.TLSCertFile, t.config.TLSKeyFile)
			if err != nil {
				return fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Connect to the server
	conn, err := grpc.NewClient(t.config.Address, opts...)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	t.conn = conn
	t.client = pb.NewKeystoreServiceClient(conn)

	// Test connection with health check
	_, err = t.Health(ctx)
	if err != nil {
		if closeErr := t.conn.Close(); closeErr != nil {
			log.Printf("failed to close gRPC connection after health check failure: %v", closeErr)
		}
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	t.connected = true
	return nil
}

// Close closes the gRPC connection.
func (t *Transport) Close() error {
	if t.conn != nil {
		if err := t.conn.Close(); err != nil {
			return err
		}
	}
	t.connected = false
	return nil
}

// Conn returns the underlying gRPC connection.
func (t *Transport) Conn() *grpc.ClientConn {
	return t.conn
}

// Client returns the gRPC client for direct access.
func (t *Transport) Client() pb.KeystoreServiceClient {
	return t.client
}

// Config returns the transport configuration.
func (t *Transport) Config() *transport.Config {
	return t.config
}

// Health checks the health of the server.
func (t *Transport) Health(ctx context.Context) (*transport.HealthResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return nil, err
	}

	return &transport.HealthResponse{
		Status:  resp.Status,
		Version: resp.Version,
	}, nil
}

// ListBackends returns a list of available backends.
func (t *Transport) ListBackends(ctx context.Context) (*transport.ListBackendsResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.ListBackends(ctx, &pb.ListBackendsRequest{})
	if err != nil {
		return nil, err
	}

	backends := make([]transport.BackendInfo, len(resp.Backends))
	for i, b := range resp.Backends {
		backends[i] = transport.BackendInfo{
			ID:             b.Name,
			Type:           b.Type,
			HardwareBacked: b.HardwareBacked,
			Capabilities: map[string]interface{}{
				"signing":              b.SupportsSigning,
				"decryption":           b.SupportsDecryption,
				"rotation":             b.SupportsRotation,
				"symmetric_encryption": b.SupportsSymmetricEncryption,
			},
		}
	}

	return &transport.ListBackendsResponse{
		Backends: backends,
	}, nil
}

// GetBackend returns information about a specific backend.
func (t *Transport) GetBackend(ctx context.Context, backendID string) (*transport.BackendInfo, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GetBackendInfo(ctx, &pb.GetBackendInfoRequest{Name: backendID})
	if err != nil {
		return nil, err
	}

	return &transport.BackendInfo{
		ID:             resp.Backend.Name,
		Type:           resp.Backend.Type,
		HardwareBacked: resp.Backend.HardwareBacked,
		Capabilities: map[string]interface{}{
			"signing":              resp.Backend.SupportsSigning,
			"decryption":           resp.Backend.SupportsDecryption,
			"rotation":             resp.Backend.SupportsRotation,
			"symmetric_encryption": resp.Backend.SupportsSymmetricEncryption,
		},
	}, nil
}

// GenerateKey generates a new key.
func (t *Transport) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.GenerateKeyRequest{
		KeyId:      req.KeyID,
		Backend:    req.Backend,
		KeyType:    req.KeyType,
		KeySize:    int32(req.KeySize),
		Curve:      req.Curve,
		Hash:       req.Hash,
		Algorithm:  req.Algorithm,
		Exportable: req.Exportable,
	}

	resp, err := t.client.GenerateKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.GenerateKeyResponse{
		KeyID:        resp.KeyId,
		KeyType:      resp.KeyType,
		PublicKeyPEM: resp.PublicKeyPem,
	}, nil
}

// ListKeys returns a list of keys in the specified backend.
func (t *Transport) ListKeys(ctx context.Context, backend string) (*transport.ListKeysResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.ListKeys(ctx, &pb.ListKeysRequest{Backend: backend})
	if err != nil {
		return nil, err
	}

	keys := make([]transport.KeyInfo, len(resp.Keys))
	for i, k := range resp.Keys {
		keys[i] = transport.KeyInfo{
			KeyID:     k.KeyId,
			KeyType:   k.KeyType,
			Algorithm: k.Algorithm,
			Backend:   k.Backend,
		}
	}

	return &transport.ListKeysResponse{
		Keys: keys,
	}, nil
}

// GetKey returns information about a specific key.
func (t *Transport) GetKey(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GetKey(ctx, &pb.GetKeyRequest{
		KeyId:   keyID,
		Backend: backend,
	})
	if err != nil {
		return nil, err
	}

	return &transport.GetKeyResponse{
		KeyInfo: transport.KeyInfo{
			KeyID:     resp.Key.KeyId,
			KeyType:   resp.Key.KeyType,
			Algorithm: resp.Key.Algorithm,
			Backend:   resp.Key.Backend,
		},
	}, nil
}

// DeleteKey deletes a key.
func (t *Transport) DeleteKey(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.DeleteKey(ctx, &pb.DeleteKeyRequest{
		KeyId:   keyID,
		Backend: backend,
	})
	if err != nil {
		return nil, err
	}

	return &transport.DeleteKeyResponse{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// Sign signs data with the specified key.
func (t *Transport) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.SignRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
		Data:    req.Data,
		Hash:    req.Hash,
	}

	resp, err := t.client.Sign(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.SignResponse{
		Signature: resp.Signature,
	}, nil
}

// Verify verifies a signature.
func (t *Transport) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.VerifyRequest{
		KeyId:     req.KeyID,
		Backend:   req.Backend,
		Data:      req.Data,
		Signature: req.Signature,
		Hash:      req.Hash,
	}

	resp, err := t.client.Verify(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.VerifyResponse{
		Valid:   resp.Valid,
		Message: resp.Message,
	}, nil
}

// Encrypt encrypts data with the specified key.
func (t *Transport) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.EncryptRequest{
		KeyId:          req.KeyID,
		Backend:        req.Backend,
		Plaintext:      req.Plaintext,
		AdditionalData: req.AdditionalData,
	}

	resp, err := t.client.Encrypt(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.EncryptResponse{
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Tag:        resp.Tag,
	}, nil
}

// Decrypt decrypts data with the specified key.
func (t *Transport) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.DecryptRequest{
		KeyId:          req.KeyID,
		Backend:        req.Backend,
		Ciphertext:     req.Ciphertext,
		Nonce:          req.Nonce,
		Tag:            req.Tag,
		AdditionalData: req.AdditionalData,
	}

	resp, err := t.client.Decrypt(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.DecryptResponse{
		Plaintext: resp.Plaintext,
	}, nil
}

// EncryptAsym encrypts data with RSA public key (asymmetric encryption).
func (t *Transport) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.EncryptAsym(ctx, &pb.EncryptAsymRequest{
		KeyId:     req.KeyID,
		Backend:   req.Backend,
		Plaintext: req.Plaintext,
		Hash:      req.Hash,
	})
	if err != nil {
		return nil, err
	}

	return &transport.EncryptAsymResponse{
		Ciphertext: resp.Ciphertext,
	}, nil
}

// GetCertificate returns the certificate for a key.
func (t *Transport) GetCertificate(ctx context.Context, backend, keyID string) (*transport.GetCertificateResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GetCert(ctx, &pb.GetCertRequest{KeyId: keyID})
	if err != nil {
		return nil, err
	}

	return &transport.GetCertificateResponse{
		KeyID:          keyID,
		CertificatePEM: resp.CertPem,
	}, nil
}

// SaveCertificate saves a certificate for a key.
func (t *Transport) SaveCertificate(ctx context.Context, req *transport.SaveCertificateRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}

	_, err := t.client.SaveCert(ctx, &pb.SaveCertRequest{
		KeyId:   req.KeyID,
		CertPem: req.CertificatePEM,
	})
	return err
}

// DeleteCertificate deletes a certificate.
func (t *Transport) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	if t.client == nil {
		return ErrNotConnected
	}

	_, err := t.client.DeleteCert(ctx, &pb.DeleteCertRequest{KeyId: keyID})
	return err
}

// CertificateExists checks if a certificate exists for a key.
func (t *Transport) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	if t.client == nil {
		return false, ErrNotConnected
	}

	// Try to get the certificate - if it fails, it doesn't exist
	_, err := t.client.GetCert(ctx, &pb.GetCertRequest{KeyId: keyID})
	if err != nil {
		return false, nil
	}
	return true, nil
}

// ImportKey imports a key.
func (t *Transport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.ImportKeyRequest{
		KeyId:      req.KeyID,
		Backend:    req.Backend,
		WrappedKey: req.WrappedKeyMaterial,
		Algorithm:  req.Algorithm,
		KeyType:    req.KeyType,
		KeySize:    int32(req.KeySize),
		Curve:      req.Curve,
		Hash:       req.Hash,
	}

	resp, err := t.client.ImportKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.ImportKeyResponse{
		Success:      resp.Success,
		KeyID:        resp.KeyId,
		Message:      resp.Message,
		PublicKeyPEM: "", // Not returned in gRPC response
	}, nil
}

// ExportKey exports a key.
func (t *Transport) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.ExportKeyRequest{
		KeyId:             req.KeyID,
		Backend:           req.Backend,
		WrappingAlgorithm: req.Algorithm,
	}

	resp, err := t.client.ExportKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.ExportKeyResponse{
		KeyID:              req.KeyID,
		WrappedKeyMaterial: resp.WrappedKey,
		Algorithm:          resp.Algorithm,
	}, nil
}

// RotateKey rotates a key.
func (t *Transport) RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.RotateKeyRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
	}

	resp, err := t.client.RotateKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.RotateKeyResponse{
		Success:      true,
		KeyID:        resp.KeyId,
		Message:      "Key rotated successfully",
		PublicKeyPEM: resp.PublicKeyPem,
	}, nil
}

// ListKeyVersions lists all versions of a key.
func (t *Transport) ListKeyVersions(ctx context.Context, req *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.ListKeyVersionsRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
	}

	resp, err := t.client.ListKeyVersions(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	versions := make([]*transport.KeyVersion, len(resp.Versions))
	for i, v := range resp.Versions {
		versions[i] = &transport.KeyVersion{
			Version:   uint64(v.Version),
			Status:    v.Status,
			CreatedAt: v.CreatedAt,
			CreatedBy: v.CreatedBy,
		}
	}

	return &transport.ListKeyVersionsResponse{
		KeyID:    resp.KeyId,
		Versions: versions,
		Total:    int(resp.Total),
	}, nil
}

// EnableKeyVersion enables a specific version of a key.
func (t *Transport) EnableKeyVersion(ctx context.Context, req *transport.EnableKeyVersionRequest) (*transport.EnableKeyVersionResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.EnableKeyVersionRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
		Version: int32(req.Version),
	}

	resp, err := t.client.EnableKeyVersion(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.EnableKeyVersionResponse{
		KeyID:   resp.KeyId,
		Version: uint64(resp.Version),
		Status:  resp.Status,
	}, nil
}

// DisableKeyVersion disables a specific version of a key.
func (t *Transport) DisableKeyVersion(ctx context.Context, req *transport.DisableKeyVersionRequest) (*transport.DisableKeyVersionResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.DisableKeyVersionRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
		Version: int32(req.Version),
	}

	resp, err := t.client.DisableKeyVersion(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.DisableKeyVersionResponse{
		KeyID:   resp.KeyId,
		Version: uint64(resp.Version),
		Status:  resp.Status,
	}, nil
}

// EnableAllKeyVersions enables all versions of a key.
func (t *Transport) EnableAllKeyVersions(ctx context.Context, req *transport.EnableAllKeyVersionsRequest) (*transport.EnableAllKeyVersionsResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.EnableAllKeyVersionsRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
	}

	resp, err := t.client.EnableAllKeyVersions(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.EnableAllKeyVersionsResponse{
		KeyID:   resp.KeyId,
		Count:   int(resp.Count),
		Message: resp.Message,
	}, nil
}

// DisableAllKeyVersions disables all versions of a key.
func (t *Transport) DisableAllKeyVersions(ctx context.Context, req *transport.DisableAllKeyVersionsRequest) (*transport.DisableAllKeyVersionsResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.DisableAllKeyVersionsRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
	}

	resp, err := t.client.DisableAllKeyVersions(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.DisableAllKeyVersionsResponse{
		KeyID:   resp.KeyId,
		Count:   int(resp.Count),
		Message: resp.Message,
	}, nil
}

// GetImportParameters gets the parameters needed to import a key.
func (t *Transport) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.GetImportParametersRequest{
		Backend:           req.Backend,
		KeyId:             req.KeyID,
		WrappingAlgorithm: req.Algorithm,
		KeyType:           req.KeyType,
		KeySize:           int32(req.KeySize),
		Curve:             req.Curve,
	}

	resp, err := t.client.GetImportParameters(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	expiresAt := ""
	if resp.ExpiresAt != nil {
		expiresAt = resp.ExpiresAt.AsTime().String()
	}

	return &transport.GetImportParametersResponse{
		WrappingPublicKey: resp.WrappingPublicKey,
		ImportToken:       resp.ImportToken,
		Algorithm:         resp.Algorithm,
		ExpiresAt:         expiresAt,
	}, nil
}

// WrapKey wraps key material for secure transport.
func (t *Transport) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.WrapKeyRequest{
		KeyMaterial:       req.KeyMaterial,
		Algorithm:         req.Algorithm,
		ImportToken:       req.ImportToken,
		WrappingPublicKey: req.WrappingPublicKey,
	}

	resp, err := t.client.WrapKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.WrapKeyResponse{
		WrappedKeyMaterial: resp.WrappedKey,
		Algorithm:          resp.Algorithm,
	}, nil
}

// UnwrapKey unwraps key material.
func (t *Transport) UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.UnwrapKeyRequest{
		WrappedKey:  req.WrappedKeyMaterial,
		Algorithm:   req.Algorithm,
		ImportToken: req.ImportToken,
	}

	resp, err := t.client.UnwrapKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.UnwrapKeyResponse{
		KeyMaterial: resp.KeyMaterial,
	}, nil
}

// CopyKey copies a key from one backend to another.
func (t *Transport) CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.CopyKeyRequest{
		SourceBackend:     req.SourceBackend,
		SourceKeyId:       req.SourceKeyID,
		DestBackend:       req.DestBackend,
		DestKeyId:         req.DestKeyID,
		WrappingAlgorithm: req.Algorithm,
	}

	resp, err := t.client.CopyKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.CopyKeyResponse{
		Success: resp.Success,
		KeyID:   resp.DestKeyId,
		Message: resp.Message,
	}, nil
}

// ListCertificates lists all certificates in the specified backend.
func (t *Transport) ListCertificates(ctx context.Context, backend string) (*transport.ListCertificatesResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.ListCertsRequest{}

	resp, err := t.client.ListCerts(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	certs := make([]transport.CertificateInfo, len(resp.KeyIds))
	for i, keyID := range resp.KeyIds {
		certs[i] = transport.CertificateInfo{
			KeyID: keyID,
		}
	}

	return &transport.ListCertificatesResponse{
		Certificates: certs,
	}, nil
}

// SaveCertificateChain saves a certificate chain for a key.
func (t *Transport) SaveCertificateChain(ctx context.Context, req *transport.SaveCertificateChainRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}

	pbReq := &pb.SaveCertChainRequest{
		KeyId:        req.KeyID,
		CertChainPem: req.ChainPEM,
	}

	_, err := t.client.SaveCertChain(ctx, pbReq)
	return err
}

// GetCertificateChain returns the certificate chain for a key.
func (t *Transport) GetCertificateChain(ctx context.Context, backend, keyID string) (*transport.GetCertificateChainResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.GetCertChainRequest{
		KeyId: keyID,
	}

	resp, err := t.client.GetCertChain(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.GetCertificateChainResponse{
		KeyID:    keyID,
		ChainPEM: resp.CertChainPem,
	}, nil
}

// GetTLSCertificate returns the TLS certificate bundle for a key.
func (t *Transport) GetTLSCertificate(ctx context.Context, backend, keyID string) (*transport.GetTLSCertificateResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.GetTLSCertificateRequest{
		Backend: backend,
		KeyId:   keyID,
	}

	resp, err := t.client.GetTLSCertificate(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	chainPEM := ""
	if len(resp.CertChainPem) > 0 {
		chainPEM = resp.CertChainPem[0]
	}

	return &transport.GetTLSCertificateResponse{
		KeyID:          keyID,
		PrivateKeyPEM:  resp.PrivateKeyPem,
		CertificatePEM: resp.CertPem,
		ChainPEM:       chainPEM,
	}, nil
}

// Seal seals data using the backend's sealing mechanism.
func (t *Transport) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.Seal(ctx, &pb.SealRequest{
		Backend: req.Backend,
		KeyId:   req.KeyID,
		Data:    req.Data,
		Aad:     req.AAD,
	})
	if err != nil {
		return nil, fmt.Errorf("seal failed: %w", err)
	}

	return &transport.SealResponse{
		Backend:    resp.Backend,
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Tag:        resp.Tag,
	}, nil
}

// Unseal unseals previously sealed data.
func (t *Transport) Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.Unseal(ctx, &pb.UnsealRequest{
		Backend:    req.Backend,
		KeyId:      req.KeyID,
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Tag:        req.Tag,
		Aad:        req.AAD,
	})
	if err != nil {
		return nil, fmt.Errorf("unseal failed: %w", err)
	}

	return &transport.UnsealResponse{
		Plaintext: resp.Plaintext,
	}, nil
}

// CanSeal checks if the backend supports sealing operations.
func (t *Transport) CanSeal(ctx context.Context, backend string) (*transport.CanSealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.CanSeal(ctx, &pb.CanSealRequest{
		Backend: backend,
	})
	if err != nil {
		return nil, fmt.Errorf("can seal check failed: %w", err)
	}

	return &transport.CanSealResponse{
		CanSeal: resp.CanSeal,
		Backend: backend,
	}, nil
}

// ListUsers returns a list of all users.
// Note: This is a stub implementation that returns ErrNotSupported.
// User management will be implemented in a future version.
func (t *Transport) ListUsers(_ context.Context) (*transport.ListUsersResponse, error) {
	return nil, ErrNotSupported
}

// GetUser returns information about a specific user.
// Note: This is a stub implementation that returns ErrNotSupported.
// User management will be implemented in a future version.
func (t *Transport) GetUser(_ context.Context, _ string) (*transport.GetUserResponse, error) {
	return nil, ErrNotSupported
}

// DeleteUser deletes a user.
// Note: This is a stub implementation that returns ErrNotSupported.
// User management will be implemented in a future version.
func (t *Transport) DeleteUser(_ context.Context, _ string) error {
	return ErrNotSupported
}

// EnableUser enables a user account.
// Note: This is a stub implementation that returns ErrNotSupported.
// User management will be implemented in a future version.
func (t *Transport) EnableUser(_ context.Context, _ string) error {
	return ErrNotSupported
}

// DisableUser disables a user account.
// Note: This is a stub implementation that returns ErrNotSupported.
// User management will be implemented in a future version.
func (t *Transport) DisableUser(_ context.Context, _ string) error {
	return ErrNotSupported
}

// ListUserCredentials returns a list of credentials for a user.
// Note: This is a stub implementation that returns ErrNotSupported.
// User management will be implemented in a future version.
func (t *Transport) ListUserCredentials(_ context.Context, _ string) (*transport.ListUserCredentialsResponse, error) {
	return nil, ErrNotSupported
}

// BeginRegistration begins a WebAuthn registration flow.
// Note: This is a stub implementation that returns ErrNotSupported.
// Authentication flow will be implemented in a future version.
func (t *Transport) BeginRegistration(_ context.Context, _ *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return nil, ErrNotSupported
}

// FinishRegistration completes a WebAuthn registration flow.
// Note: This is a stub implementation that returns ErrNotSupported.
// Authentication flow will be implemented in a future version.
func (t *Transport) FinishRegistration(_ context.Context, _ *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return nil, ErrNotSupported
}

// BeginAuthentication begins a WebAuthn authentication flow.
// Note: This is a stub implementation that returns ErrNotSupported.
// Authentication flow will be implemented in a future version.
func (t *Transport) BeginAuthentication(_ context.Context, _ *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return nil, ErrNotSupported
}

// FinishAuthentication completes a WebAuthn authentication flow.
// Note: This is a stub implementation that returns ErrNotSupported.
// Authentication flow will be implemented in a future version.
func (t *Transport) FinishAuthentication(_ context.Context, _ *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return nil, ErrNotSupported
}

// Helper functions for converting between SDK types and protobuf types

// ConvertJSONToBytes converts json.RawMessage to bytes, handling both
// base64-encoded strings and raw byte arrays.
func ConvertJSONToBytes(data json.RawMessage) []byte {
	if len(data) == 0 {
		return nil
	}

	var bytes []byte
	if err := json.Unmarshal(data, &bytes); err != nil {
		// Try using directly as bytes
		return data
	}
	return bytes
}
