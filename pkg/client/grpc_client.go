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

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"os"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// grpcClient implements the Client interface using gRPC.
type grpcClient struct {
	config    *Config
	conn      *grpc.ClientConn
	client    pb.KeystoreServiceClient
	connected bool
}

// newGRPCClient creates a new gRPC client.
func newGRPCClient(cfg *Config) (*grpcClient, error) {
	return &grpcClient{
		config: cfg,
	}, nil
}

// Connect establishes a connection to the keychain server via gRPC.
func (c *grpcClient) Connect(ctx context.Context) error {
	var opts []grpc.DialOption

	if c.config.TLSEnabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.config.TLSInsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}

		// Load CA certificate if specified
		if c.config.TLSCAFile != "" {
			caCert, err := os.ReadFile(c.config.TLSCAFile)
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
		if c.config.TLSCertFile != "" && c.config.TLSKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(c.config.TLSCertFile, c.config.TLSKeyFile)
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
	conn, err := grpc.NewClient(c.config.Address, opts...)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	c.conn = conn
	c.client = pb.NewKeystoreServiceClient(conn)

	// Test connection with health check
	_, err = c.Health(ctx)
	if err != nil {
		if closeErr := c.conn.Close(); closeErr != nil {
			log.Printf("failed to close gRPC connection after health check failure: %v", closeErr)
		}
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	c.connected = true
	return nil
}

// Close closes the gRPC connection.
func (c *grpcClient) Close() error {
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return err
		}
	}
	c.connected = false
	return nil
}

// Health checks the health of the server.
func (c *grpcClient) Health(ctx context.Context) (*HealthResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := c.client.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return nil, err
	}

	return &HealthResponse{
		Status:  resp.Status,
		Version: resp.Version,
	}, nil
}

// ListBackends returns a list of available backends.
func (c *grpcClient) ListBackends(ctx context.Context) (*ListBackendsResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := c.client.ListBackends(ctx, &pb.ListBackendsRequest{})
	if err != nil {
		return nil, err
	}

	backends := make([]BackendInfo, len(resp.Backends))
	for i, b := range resp.Backends {
		backends[i] = BackendInfo{
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

	return &ListBackendsResponse{
		Backends: backends,
	}, nil
}

// GetBackend returns information about a specific backend.
func (c *grpcClient) GetBackend(ctx context.Context, backendID string) (*BackendInfo, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := c.client.GetBackendInfo(ctx, &pb.GetBackendInfoRequest{Name: backendID})
	if err != nil {
		return nil, err
	}

	return &BackendInfo{
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
func (c *grpcClient) GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.GenerateKeyRequest{
		KeyId:     req.KeyID,
		Backend:   req.Backend,
		KeyType:   req.KeyType,
		KeySize:   int32(req.KeySize),
		Curve:     req.Curve,
		Hash:      req.Hash,
		Algorithm: req.Algorithm,
	}

	resp, err := c.client.GenerateKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &GenerateKeyResponse{
		KeyID:        resp.KeyId,
		KeyType:      resp.KeyType,
		PublicKeyPEM: resp.PublicKeyPem,
	}, nil
}

// ListKeys returns a list of keys in the specified backend.
func (c *grpcClient) ListKeys(ctx context.Context, backend string) (*ListKeysResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := c.client.ListKeys(ctx, &pb.ListKeysRequest{Backend: backend})
	if err != nil {
		return nil, err
	}

	keys := make([]KeyInfo, len(resp.Keys))
	for i, k := range resp.Keys {
		keys[i] = KeyInfo{
			KeyID:     k.KeyId,
			KeyType:   k.KeyType,
			Algorithm: k.Algorithm,
			Backend:   k.Backend,
		}
	}

	return &ListKeysResponse{
		Keys: keys,
	}, nil
}

// GetKey returns information about a specific key.
func (c *grpcClient) GetKey(ctx context.Context, backend, keyID string) (*GetKeyResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := c.client.GetKey(ctx, &pb.GetKeyRequest{
		KeyId:   keyID,
		Backend: backend,
	})
	if err != nil {
		return nil, err
	}

	return &GetKeyResponse{
		KeyInfo: KeyInfo{
			KeyID:     resp.Key.KeyId,
			KeyType:   resp.Key.KeyType,
			Algorithm: resp.Key.Algorithm,
			Backend:   resp.Key.Backend,
		},
	}, nil
}

// DeleteKey deletes a key.
func (c *grpcClient) DeleteKey(ctx context.Context, backend, keyID string) (*DeleteKeyResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := c.client.DeleteKey(ctx, &pb.DeleteKeyRequest{
		KeyId:   keyID,
		Backend: backend,
	})
	if err != nil {
		return nil, err
	}

	return &DeleteKeyResponse{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// Sign signs data with the specified key.
func (c *grpcClient) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	// Convert json.RawMessage to bytes
	var data []byte
	if len(req.Data) > 0 {
		if err := json.Unmarshal(req.Data, &data); err != nil {
			// Try using directly as bytes
			data = req.Data
		}
	}

	pbReq := &pb.SignRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
		Data:    data,
		Hash:    req.Hash,
	}

	resp, err := c.client.Sign(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &SignResponse{
		Signature: resp.Signature,
	}, nil
}

// Verify verifies a signature.
func (c *grpcClient) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	// Convert json.RawMessage to bytes
	var data []byte
	if len(req.Data) > 0 {
		if err := json.Unmarshal(req.Data, &data); err != nil {
			data = req.Data
		}
	}

	var signature []byte
	if len(req.Signature) > 0 {
		if err := json.Unmarshal(req.Signature, &signature); err != nil {
			signature = req.Signature
		}
	}

	pbReq := &pb.VerifyRequest{
		KeyId:     req.KeyID,
		Backend:   req.Backend,
		Data:      data,
		Signature: signature,
		Hash:      req.Hash,
	}

	resp, err := c.client.Verify(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &VerifyResponse{
		Valid:   resp.Valid,
		Message: resp.Message,
	}, nil
}

// Encrypt encrypts data with the specified key.
func (c *grpcClient) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	// Convert json.RawMessage to bytes
	var plaintext []byte
	if len(req.Plaintext) > 0 {
		if err := json.Unmarshal(req.Plaintext, &plaintext); err != nil {
			plaintext = req.Plaintext
		}
	}

	var additionalData []byte
	if len(req.AdditionalData) > 0 {
		if err := json.Unmarshal(req.AdditionalData, &additionalData); err != nil {
			additionalData = req.AdditionalData
		}
	}

	pbReq := &pb.EncryptRequest{
		KeyId:          req.KeyID,
		Backend:        req.Backend,
		Plaintext:      plaintext,
		AdditionalData: additionalData,
	}

	resp, err := c.client.Encrypt(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &EncryptResponse{
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Tag:        resp.Tag,
	}, nil
}

// Decrypt decrypts data with the specified key.
func (c *grpcClient) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	// Convert json.RawMessage to bytes
	var ciphertext []byte
	if len(req.Ciphertext) > 0 {
		if err := json.Unmarshal(req.Ciphertext, &ciphertext); err != nil {
			ciphertext = req.Ciphertext
		}
	}

	var nonce []byte
	if len(req.Nonce) > 0 {
		if err := json.Unmarshal(req.Nonce, &nonce); err != nil {
			nonce = req.Nonce
		}
	}

	var tag []byte
	if len(req.Tag) > 0 {
		if err := json.Unmarshal(req.Tag, &tag); err != nil {
			tag = req.Tag
		}
	}

	var additionalData []byte
	if len(req.AdditionalData) > 0 {
		if err := json.Unmarshal(req.AdditionalData, &additionalData); err != nil {
			additionalData = req.AdditionalData
		}
	}

	pbReq := &pb.DecryptRequest{
		KeyId:          req.KeyID,
		Backend:        req.Backend,
		Ciphertext:     ciphertext,
		Nonce:          nonce,
		Tag:            tag,
		AdditionalData: additionalData,
	}

	resp, err := c.client.Decrypt(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &DecryptResponse{
		Plaintext: resp.Plaintext,
	}, nil
}

// EncryptAsym encrypts data with RSA public key (asymmetric encryption).
// Note: This operation is not supported over gRPC. Use REST client or local mode.
func (c *grpcClient) EncryptAsym(ctx context.Context, req *EncryptAsymRequest) (*EncryptAsymResponse, error) {
	return nil, fmt.Errorf("%w: asymmetric encryption via gRPC, use REST API or local mode", ErrNotSupported)
}

// GetCertificate returns the certificate for a key.
func (c *grpcClient) GetCertificate(ctx context.Context, backend, keyID string) (*GetCertificateResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := c.client.GetCert(ctx, &pb.GetCertRequest{KeyId: keyID})
	if err != nil {
		return nil, err
	}

	return &GetCertificateResponse{
		KeyID:          keyID,
		CertificatePEM: resp.CertPem,
	}, nil
}

// SaveCertificate saves a certificate for a key.
func (c *grpcClient) SaveCertificate(ctx context.Context, req *SaveCertificateRequest) error {
	if c.client == nil {
		return ErrNotConnected
	}

	_, err := c.client.SaveCert(ctx, &pb.SaveCertRequest{
		KeyId:   req.KeyID,
		CertPem: req.CertificatePEM,
	})
	return err
}

// DeleteCertificate deletes a certificate.
func (c *grpcClient) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	if c.client == nil {
		return ErrNotConnected
	}

	_, err := c.client.DeleteCert(ctx, &pb.DeleteCertRequest{KeyId: keyID})
	return err
}

// ImportKey imports a key.
func (c *grpcClient) ImportKey(ctx context.Context, req *ImportKeyRequest) (*ImportKeyResponse, error) {
	if c.client == nil {
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

	resp, err := c.client.ImportKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &ImportKeyResponse{
		Success:      resp.Success,
		KeyID:        resp.KeyId,
		Message:      resp.Message,
		PublicKeyPEM: "", // Not returned in gRPC response
	}, nil
}

// ExportKey exports a key.
func (c *grpcClient) ExportKey(ctx context.Context, req *ExportKeyRequest) (*ExportKeyResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.ExportKeyRequest{
		KeyId:             req.KeyID,
		Backend:           req.Backend,
		WrappingAlgorithm: req.Algorithm,
	}

	resp, err := c.client.ExportKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &ExportKeyResponse{
		KeyID:              req.KeyID,
		WrappedKeyMaterial: resp.WrappedKey,
		Algorithm:          resp.Algorithm,
	}, nil
}

// RotateKey rotates a key.
func (c *grpcClient) RotateKey(ctx context.Context, req *RotateKeyRequest) (*RotateKeyResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.RotateKeyRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
	}

	resp, err := c.client.RotateKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &RotateKeyResponse{
		Success:      true,
		KeyID:        resp.KeyId,
		Message:      "Key rotated successfully",
		PublicKeyPEM: resp.PublicKeyPem,
	}, nil
}

// ListKeyVersions lists all versions of a key.
func (c *grpcClient) ListKeyVersions(ctx context.Context, req *ListKeyVersionsRequest) (*ListKeyVersionsResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.ListKeyVersionsRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
	}

	resp, err := c.client.ListKeyVersions(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	versions := make([]*KeyVersion, len(resp.Versions))
	for i, v := range resp.Versions {
		versions[i] = &KeyVersion{
			Version:   uint64(v.Version),
			Status:    v.Status,
			CreatedAt: v.CreatedAt,
			CreatedBy: v.CreatedBy,
		}
	}

	return &ListKeyVersionsResponse{
		KeyID:    resp.KeyId,
		Versions: versions,
		Total:    int(resp.Total),
	}, nil
}

// EnableKeyVersion enables a specific version of a key.
func (c *grpcClient) EnableKeyVersion(ctx context.Context, req *EnableKeyVersionRequest) (*EnableKeyVersionResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.EnableKeyVersionRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
		Version: int32(req.Version),
	}

	resp, err := c.client.EnableKeyVersion(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &EnableKeyVersionResponse{
		KeyID:   resp.KeyId,
		Version: uint64(resp.Version),
		Status:  resp.Status,
	}, nil
}

// DisableKeyVersion disables a specific version of a key.
func (c *grpcClient) DisableKeyVersion(ctx context.Context, req *DisableKeyVersionRequest) (*DisableKeyVersionResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.DisableKeyVersionRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
		Version: int32(req.Version),
	}

	resp, err := c.client.DisableKeyVersion(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &DisableKeyVersionResponse{
		KeyID:   resp.KeyId,
		Version: uint64(resp.Version),
		Status:  resp.Status,
	}, nil
}

// EnableAllKeyVersions enables all versions of a key.
func (c *grpcClient) EnableAllKeyVersions(ctx context.Context, req *EnableAllKeyVersionsRequest) (*EnableAllKeyVersionsResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.EnableAllKeyVersionsRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
	}

	resp, err := c.client.EnableAllKeyVersions(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &EnableAllKeyVersionsResponse{
		KeyID:   resp.KeyId,
		Count:   int(resp.Count),
		Message: resp.Message,
	}, nil
}

// DisableAllKeyVersions disables all versions of a key.
func (c *grpcClient) DisableAllKeyVersions(ctx context.Context, req *DisableAllKeyVersionsRequest) (*DisableAllKeyVersionsResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.DisableAllKeyVersionsRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
	}

	resp, err := c.client.DisableAllKeyVersions(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &DisableAllKeyVersionsResponse{
		KeyID:   resp.KeyId,
		Count:   int(resp.Count),
		Message: resp.Message,
	}, nil
}

// GetImportParameters gets the parameters needed to import a key.
func (c *grpcClient) GetImportParameters(ctx context.Context, req *GetImportParametersRequest) (*GetImportParametersResponse, error) {
	if c.client == nil {
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

	resp, err := c.client.GetImportParameters(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	expiresAt := ""
	if resp.ExpiresAt != nil {
		expiresAt = resp.ExpiresAt.AsTime().String()
	}

	return &GetImportParametersResponse{
		WrappingPublicKey: resp.WrappingPublicKey,
		ImportToken:       resp.ImportToken,
		Algorithm:         resp.Algorithm,
		ExpiresAt:         expiresAt,
	}, nil
}

// WrapKey wraps key material for secure transport.
func (c *grpcClient) WrapKey(ctx context.Context, req *WrapKeyRequest) (*WrapKeyResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.WrapKeyRequest{
		KeyMaterial:       req.KeyMaterial,
		Algorithm:         req.Algorithm,
		ImportToken:       req.ImportToken,
		WrappingPublicKey: req.WrappingPublicKey,
	}

	resp, err := c.client.WrapKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &WrapKeyResponse{
		WrappedKeyMaterial: resp.WrappedKey,
		Algorithm:          resp.Algorithm,
	}, nil
}

// UnwrapKey unwraps key material.
func (c *grpcClient) UnwrapKey(ctx context.Context, req *UnwrapKeyRequest) (*UnwrapKeyResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.UnwrapKeyRequest{
		WrappedKey:  req.WrappedKeyMaterial,
		Algorithm:   req.Algorithm,
		ImportToken: req.ImportToken,
	}

	resp, err := c.client.UnwrapKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &UnwrapKeyResponse{
		KeyMaterial: resp.KeyMaterial,
	}, nil
}

// CopyKey copies a key from one backend to another.
func (c *grpcClient) CopyKey(ctx context.Context, req *CopyKeyRequest) (*CopyKeyResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.CopyKeyRequest{
		SourceBackend:     req.SourceBackend,
		SourceKeyId:       req.SourceKeyID,
		DestBackend:       req.DestBackend,
		DestKeyId:         req.DestKeyID,
		WrappingAlgorithm: req.Algorithm,
	}

	resp, err := c.client.CopyKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &CopyKeyResponse{
		Success: resp.Success,
		KeyID:   resp.DestKeyId,
		Message: resp.Message,
	}, nil
}

// ListCertificates lists all certificates in the specified backend.
func (c *grpcClient) ListCertificates(ctx context.Context, backend string) (*ListCertificatesResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.ListCertsRequest{}

	resp, err := c.client.ListCerts(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	certs := make([]CertificateInfo, len(resp.KeyIds))
	for i, keyID := range resp.KeyIds {
		certs[i] = CertificateInfo{
			KeyID: keyID,
		}
	}

	return &ListCertificatesResponse{
		Certificates: certs,
	}, nil
}

// SaveCertificateChain saves a certificate chain for a key.
func (c *grpcClient) SaveCertificateChain(ctx context.Context, req *SaveCertificateChainRequest) error {
	if c.client == nil {
		return ErrNotConnected
	}

	pbReq := &pb.SaveCertChainRequest{
		KeyId:        req.KeyID,
		CertChainPem: req.ChainPEM,
	}

	_, err := c.client.SaveCertChain(ctx, pbReq)
	return err
}

// GetCertificateChain returns the certificate chain for a key.
func (c *grpcClient) GetCertificateChain(ctx context.Context, backend, keyID string) (*GetCertificateChainResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.GetCertChainRequest{
		KeyId: keyID,
	}

	resp, err := c.client.GetCertChain(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &GetCertificateChainResponse{
		KeyID:    keyID,
		ChainPEM: resp.CertChainPem,
	}, nil
}

// GetTLSCertificate returns the TLS certificate bundle for a key.
func (c *grpcClient) GetTLSCertificate(ctx context.Context, backend, keyID string) (*GetTLSCertificateResponse, error) {
	if c.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.GetTLSCertificateRequest{
		Backend: backend,
		KeyId:   keyID,
	}

	resp, err := c.client.GetTLSCertificate(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	chainPEM := ""
	if len(resp.CertChainPem) > 0 {
		chainPEM = resp.CertChainPem[0]
	}

	return &GetTLSCertificateResponse{
		KeyID:          keyID,
		PrivateKeyPEM:  resp.PrivateKeyPem,
		CertificatePEM: resp.CertPem,
		ChainPEM:       chainPEM,
	}, nil
}
