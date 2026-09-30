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

// Package unix provides a gRPC over Unix domain socket transport implementation
// for the xkms SDK. It connects to the xkms server through a local Unix socket
// using the same protobuf service as the standard gRPC transport.
package unix

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/spki"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = errors.New("unix transport: client not connected")
	// ErrNotSupported is returned when an operation is not supported.
	ErrNotSupported = errors.New("unix transport: operation not supported")
	// ErrConnectionFailed is returned when a connection fails.
	ErrConnectionFailed = errors.New("unix transport: connection failed")
	// ErrSocketPathRequired is returned when no socket path is provided.
	ErrSocketPathRequired = errors.New("unix transport: socket path is required")
)

// Transport implements the transport.Client interface using gRPC over Unix
// domain sockets. It provides the same protobuf-based functionality as the
// standard gRPC transport but connects through a local Unix socket instead
// of a TCP network connection.
type Transport struct {
	config     *transport.Config
	conn       *grpc.ClientConn
	client     pb.KeystoreServiceClient
	httpClient *http.Client
	connected  bool
}

// New creates a new Unix domain socket transport with the given options.
func New(opts ...transport.Option) (*Transport, error) {
	cfg := transport.DefaultConfig()
	if err := transport.ApplyOptions(cfg, opts...); err != nil {
		return nil, err
	}

	if cfg.Address == "" {
		return nil, ErrSocketPathRequired
	}

	return &Transport{
		config: cfg,
	}, nil
}

// NewWithConfig creates a new Unix domain socket transport with the given
// configuration. The config.Address field must contain the Unix socket path.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	if cfg == nil {
		cfg = transport.DefaultConfig()
	}

	if cfg.Address == "" {
		return nil, ErrSocketPathRequired
	}

	return &Transport{
		config: cfg,
	}, nil
}

// Connect establishes a gRPC connection over a Unix domain socket.
func (t *Transport) Connect(ctx context.Context) error {
	var opts []grpc.DialOption

	if t.config.TLSEnabled {
		var tlsConfig *tls.Config

		if t.config.TLSConfig != nil {
			tlsConfig = t.config.TLSConfig
		} else {
			tlsConfig = &tls.Config{
				MinVersion: tls.VersionTLS13,
			}

			if t.config.TLSCAFile != "" {
				caCert, err := os.ReadFile(t.config.TLSCAFile)
				if err != nil {
					return &errs.Wrapped{Msg: "failed to read CA certificate", Err: err}
				}
				caCertPool := x509.NewCertPool()
				if !caCertPool.AppendCertsFromPEM(caCert) {
					return &errs.Message{Msg: "failed to parse CA certificate"}
				}
				tlsConfig.RootCAs = caCertPool
			}

			if t.config.TLSCertFile != "" && t.config.TLSKeyFile != "" {
				cert, err := tls.LoadX509KeyPair(t.config.TLSCertFile, t.config.TLSKeyFile)
				if err != nil {
					return &errs.Wrapped{Msg: "failed to load client certificate", Err: err}
				}
				tlsConfig.Certificates = []tls.Certificate{cert}
			}

			// SPKI pin verification
			if t.config.SPKIPin != "" {
				if t.config.TLSCAFile == "" && tlsConfig.RootCAs == nil {
					// Trust bootstrap: no CA cert available, SPKI pin IS the trust anchor
					tlsConfig = spki.NewPinnedTLSConfig(t.config.SPKIPin)
				} else {
					// Additive: CA chain validated first, pin adds extra verification
					tlsConfig.VerifyConnection = spki.VerifyConnection(t.config.SPKIPin)
				}
			}
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		// This package dials only "unix://" addresses (see grpc.NewClient below):
		// a Unix domain socket, with no network path for a MITM.
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials())) // insecure-ok: Unix domain socket. Allowlisted in Makefile check-insecure-tls.
	}

	conn, err := grpc.NewClient("unix://"+t.config.Address, opts...)
	if err != nil {
		return &errs.Detail{Err: ErrConnectionFailed, Detail: fmt.Sprintf("%v", err)}
	}

	t.conn = conn
	t.client = pb.NewKeystoreServiceClient(conn)

	// Build an HTTP client that dials the same Unix socket. This allows REST
	// endpoints (init ceremony, credential management) that are not available
	// via gRPC to be reached over the same socket path.
	socketPath := t.config.Address
	t.httpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}

	_, err = t.Health(ctx)
	if err != nil {
		if closeErr := t.conn.Close(); closeErr != nil {
			slog.Error("failed to close Unix socket connection after health check failure",
				"error", closeErr)
		}
		t.conn = nil
		t.client = nil
		t.httpClient = nil
		return &errs.Detail{Err: ErrConnectionFailed, Detail: fmt.Sprintf("%v", err)}
	}

	t.connected = true
	return nil
}

// Close closes the gRPC connection over the Unix socket.
func (t *Transport) Close() error {
	t.httpClient = nil
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

// SocketPath returns the Unix socket path.
func (t *Transport) SocketPath() string {
	return t.config.Address
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
func (t *Transport) ListBackends(ctx context.Context, opts ...transport.ListOption) (*transport.ListBackendsResponse, error) {
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
			Capabilities: transport.BackendCapabilities{
				Keys:                true,
				HardwareBacked:      b.HardwareBacked,
				Signing:             b.SupportsSigning,
				Decryption:          b.SupportsDecryption,
				KeyRotation:         b.SupportsRotation,
				SymmetricEncryption: b.SupportsSymmetricEncryption,
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
		Capabilities: transport.BackendCapabilities{
			Keys:                true,
			HardwareBacked:      resp.Backend.HardwareBacked,
			Signing:             resp.Backend.SupportsSigning,
			Decryption:          resp.Backend.SupportsDecryption,
			KeyRotation:         resp.Backend.SupportsRotation,
			SymmetricEncryption: resp.Backend.SupportsSymmetricEncryption,
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
		Sensitive:  req.Sensitive,
		TpmPolicy:  req.TPMPolicy,
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
func (t *Transport) ListKeys(ctx context.Context, backend string, opts ...transport.ListOption) (*transport.ListKeysResponse, error) {
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
			KeyID:      k.KeyId,
			KeyType:    k.KeyType,
			Algorithm:  k.Algorithm,
			Backend:    k.Backend,
			KeyVersion: k.KeyVersion,
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
			KeyID:      resp.Key.KeyId,
			KeyType:    resp.Key.KeyType,
			Algorithm:  resp.Key.Algorithm,
			Backend:    resp.Key.Backend,
			KeyVersion: resp.Key.KeyVersion,
		},
		PublicKeyPEM: resp.PublicKeyPem,
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

// ImportKey imports a key.
func (t *Transport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.ImportKeyRequest{
		KeyId:       req.KeyID,
		Backend:     req.Backend,
		WrappedKey:  req.WrappedKeyMaterial,
		Algorithm:   req.Algorithm,
		ImportToken: req.ImportToken,
		KeyType:     req.KeyType,
		KeySize:     int32(req.KeySize),
		Curve:       req.Curve,
		Hash:        req.Hash,
		Partition:   req.Partition,
		Metadata:    req.Metadata,
		Exportable:  req.Exportable,
		Sensitive:   req.Sensitive,
	}

	resp, err := t.client.ImportKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.ImportKeyResponse{
		Success: resp.Success,
		KeyID:   resp.KeyId,
		Message: resp.Message,
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

// RotateKey rotates a key by generating a new version.
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
		Success:                    true,
		KeyID:                      resp.KeyId,
		Message:                    "Key rotated successfully",
		PublicKeyPEM:               resp.PublicKeyPem,
		KeyType:                    resp.KeyType,
		KeyVersion:                 resp.KeyVersion,
		CertificateReissueRequired: resp.CertificateReissueRequired,
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

// ExportKeyMaterial exports raw symmetric key bytes for extractable keys.
func (t *Transport) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.ExportKeyMaterialRequest{
		KeyId:   req.KeyID,
		Backend: req.Backend,
	}

	resp, err := t.client.ExportKeyMaterial(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.ExportKeyMaterialResponse{
		KeyMaterial: resp.KeyMaterial,
		KeyType:     resp.KeyType,
		KeySize:     int(resp.KeySize),
	}, nil
}

// WrapKey wraps key material for secure transport.
func (t *Transport) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.WrapKeyRequest{
		Backend:           req.Backend,
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
		Backend:     req.Backend,
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

// WrapKeyByID wraps a target key using a wrapping key, both identified by key IDs.
func (t *Transport) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.WrapKeyByIDRequest{
		WrappingKeyId:      req.WrappingKeyID,
		WrappingKeyBackend: req.WrappingKeyBackend,
		TargetKeyId:        req.TargetKeyID,
		TargetKeyBackend:   req.TargetKeyBackend,
		TargetKeyMaterial:  req.TargetKeyMaterial,
		Algorithm:          req.Algorithm,
		Iv:                 req.IV,
		Aad:                req.AAD,
		// #nosec G115 - CK_GCM_PARAMS.ulTagBits is one of 96..128.
		TagBits:   int32(req.TagBits),
		OaepLabel: req.OAEPLabel,
	}

	resp, err := t.client.WrapKeyByID(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.WrapKeyByIDResponse{
		WrappedKey:         resp.WrappedKey,
		Algorithm:          resp.Algorithm,
		WrappingKeyVersion: resp.WrappingKeyVersion,
	}, nil
}

// UnwrapKeyByID unwraps key material and imports it as a new key.
func (t *Transport) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.UnwrapKeyByIDRequest{
		WrappedKey:           req.WrappedKey,
		UnwrappingKeyId:      req.UnwrappingKeyID,
		UnwrappingKeyBackend: req.UnwrappingKeyBackend,
		Algorithm:            req.Algorithm,
		Iv:                   req.IV,
		Aad:                  req.AAD,
		// #nosec G115 - CK_GCM_PARAMS.ulTagBits is one of 96..128.
		TagBits:              int32(req.TagBits),
		OaepLabel:            req.OAEPLabel,
		TargetKeyId:          req.TargetKeyID,
		TargetKeyBackend:     req.TargetKeyBackend,
		TargetKeyType:        req.TargetKeyType,
		TargetKeySize:        int32(req.TargetKeySize),
		TargetCurve:          req.TargetCurve,
		TargetPartition:      req.TargetPartition,
		TargetExportable:     req.TargetExportable,
		UnwrappingKeyVersion: req.UnwrappingKeyVersion,
	}

	resp, err := t.client.UnwrapKeyByID(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.UnwrapKeyByIDResponse{
		KeyID:   resp.KeyId,
		Backend: resp.Backend,
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
		KeyId:        req.KeyID,
		Backend:      req.Backend,
		Data:         req.Data,
		Hash:         req.Hash,
		Padding:      req.Padding,
		SaltLength:   int32(req.SaltLength),
		DataIsDigest: req.DataIsDigest,
	}

	resp, err := t.client.Sign(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.SignResponse{
		Signature:  resp.Signature,
		KeyVersion: resp.KeyVersion,
	}, nil
}

// Verify verifies a signature.
func (t *Transport) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.VerifyRequest{
		KeyId:        req.KeyID,
		Backend:      req.Backend,
		Data:         req.Data,
		Signature:    req.Signature,
		Hash:         req.Hash,
		Padding:      req.Padding,
		SaltLength:   int32(req.SaltLength),
		DataIsDigest: req.DataIsDigest,
		KeyVersion:   req.KeyVersion,
	}

	resp, err := t.client.Verify(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.VerifyResponse{
		Valid:      resp.Valid,
		Message:    resp.Message,
		KeyVersion: resp.KeyVersion,
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
		Nonce:          req.Nonce,
		Mode:           req.Mode,
		Iv:             req.IV,
		TagSize:        int32(req.TagSize),
	}

	resp, err := t.client.Encrypt(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.EncryptResponse{
		Ciphertext:   resp.Ciphertext,
		Nonce:        resp.Nonce,
		Tag:          resp.Tag,
		IV:           resp.Iv,
		GCMNonceMode: resp.GcmNonceMode,
		KeyVersion:   resp.KeyVersion,
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
		GcmNonceMode:   req.GCMNonceMode,
		Mode:           req.Mode,
		Iv:             req.IV,
		Padding:        req.Padding,
		Hash:           req.Hash,
		Label:          req.Label,
		TagSize:        int32(req.TagSize),
		KeyVersion:     req.KeyVersion,
	}

	resp, err := t.client.Decrypt(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.DecryptResponse{
		Plaintext:  resp.Plaintext,
		KeyVersion: resp.KeyVersion,
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
		Label:     req.Label,
	})
	if err != nil {
		return nil, err
	}

	return &transport.EncryptAsymResponse{
		Ciphertext: resp.Ciphertext,
		KeyVersion: resp.KeyVersion,
	}, nil
}

// DeriveKey derives a key using the specified algorithm and parameters.
func (t *Transport) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.DeriveKeyRequest{
		Backend:          req.Backend,
		KeyId:            req.KeyID,
		Algorithm:        req.Algorithm,
		InputKeyMaterial: req.InputKeyMaterial,
		Salt:             req.Salt,
		Info:             req.Info,
		PeerPublicKey:    req.PeerPublicKey,
		KeyLength:        int32(req.KeyLength),
		Hash:             req.Hash,
		Iterations:       int32(req.Iterations),
		Prf:              req.PRF,
		Label:            req.Label,
		Context:          req.Context,
		Counter:          req.Counter,
		UseCofactor:      req.UseCofactor,
		StoreResult:      req.StoreResult,
		DerivedKeyId:     req.DerivedKeyID,
		DerivedKeyType:   req.DerivedKeyType,
		KeyVersion:       req.KeyVersion,
	}

	resp, err := t.client.DeriveKey(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.DeriveKeyResponse{
		DerivedKey: resp.DerivedKey,
		KeyID:      resp.KeyId,
		Algorithm:  resp.Algorithm,
		KeyLength:  int(resp.KeyLength),
		KeyVersion: resp.KeyVersion,
	}, nil
}

// DeriveKeyECDH performs ECDH key agreement and derives a symmetric key.
func (t *Transport) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.DeriveKeyECDHRequest{
		KeyId:         req.KeyID,
		Backend:       req.Backend,
		PeerPublicKey: req.PeerPublicKey,
		KdfAlgorithm:  req.KDFAlgorithm,
		KdfHash:       req.KDFHash,
		KdfSalt:       req.KDFSalt,
		KdfInfo:       req.KDFInfo,
		KdfLabel:      req.KDFLabel,
		KeyLength:     int32(req.KeyLength),
		KeyVersion:    req.KeyVersion,
	}

	resp, err := t.client.DeriveKeyECDH(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.DeriveKeyECDHResponse{
		DerivedKey: resp.DerivedKey,
		KeyVersion: resp.KeyVersion,
	}, nil
}

// AttestKey requests key attestation from a backend.
func (t *Transport) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.AttestKey(ctx, &pb.AttestKeyRequest{
		Backend: req.Backend,
		KeyId:   req.KeyID,
		Nonce:   req.Nonce,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "attest key failed", Err: err}
	}

	return &transport.AttestKeyResponse{
		Format:             resp.Format,
		CertificateChain:   resp.CertificateChain,
		AttestationData:    resp.AttestationData,
		Signature:          resp.Signature,
		SignatureAlgorithm: resp.SignatureAlgorithm,
		Nonce:              resp.Nonce,
		Backend:            resp.Backend,
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

	_, err := t.client.GetCert(ctx, &pb.GetCertRequest{KeyId: keyID})
	if err != nil {
		return false, nil
	}
	return true, nil
}

// ListCertificates lists all certificates in the specified backend.
func (t *Transport) ListCertificates(ctx context.Context, backend string, opts ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.ListCerts(ctx, &pb.ListCertsRequest{})
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

	resp, err := t.client.GetCertChain(ctx, &pb.GetCertChainRequest{
		KeyId: keyID,
	})
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

	resp, err := t.client.GetTLSCertificate(ctx, &pb.GetTLSCertificateRequest{
		Backend: backend,
		KeyId:   keyID,
	})
	if err != nil {
		return nil, err
	}

	return &transport.GetTLSCertificateResponse{
		KeyID:          keyID,
		CertificatePEM: resp.CertPem,
		ChainPEM:       resp.CertChainPem,
	}, nil
}

// Seal seals data using the backend's sealing mechanism.
func (t *Transport) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.Seal(ctx, pbconv.SealRequestToProto(req))
	if err != nil {
		return nil, &errs.Wrapped{Msg: "seal failed", Err: err}
	}
	return pbconv.SealResponseFromProto(resp)
}

// Unseal unseals previously sealed data.
func (t *Transport) Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.Unseal(ctx, pbconv.UnsealRequestToProto(req))
	if err != nil {
		return nil, &errs.Wrapped{Msg: "unseal failed", Err: err}
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
		return nil, &errs.Wrapped{Msg: "can seal check failed", Err: err}
	}

	return &transport.CanSealResponse{
		CanSeal: resp.CanSeal,
		Backend: backend,
	}, nil
}

// Barrier Operations

// BarrierInitialize initializes the barrier by generating a root key and sealing it.
func (t *Transport) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.BarrierInitialize(ctx, &pb.BarrierInitializeRequest{
		Secret: req.Secret,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "barrier initialize failed", Err: err}
	}

	return nil
}

// BarrierUnseal unseals the barrier by loading and decrypting the root key.
func (t *Transport) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.BarrierUnseal(ctx, &pb.BarrierUnsealRequest{
		Secret: req.Secret,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "barrier unseal failed", Err: err}
	}

	return nil
}

// BarrierSeal transitions the barrier to sealed state, zeroing the DEK.
func (t *Transport) BarrierSeal(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.BarrierSeal(ctx, &emptypb.Empty{})
	if err != nil {
		return &errs.Wrapped{Msg: "barrier seal failed", Err: err}
	}

	return nil
}

// BarrierStatus returns the current barrier status including seal state and active strategy.
func (t *Transport) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.BarrierStatus(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "barrier status failed", Err: err}
	}

	return &transport.BarrierStatusResponse{
		Sealed:         resp.Sealed,
		Strategy:       resp.Strategy,
		HardwareBacked: resp.HardwareBacked,
		InitializedAt:  resp.InitializedAt,
	}, nil
}

// BootstrapListenerKeys returns the running trust-bootstrap listener's
// public static keys.
func (t *Transport) BootstrapListenerKeys(ctx context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.BootstrapListenerKeys(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "bootstrap listener keys failed", Err: err}
	}

	return &transport.BootstrapListenerKeysResponse{
		NoisePublicKey: resp.NoisePublicKey,
		P256PublicKey:  resp.P256PublicKey,
	}, nil
}

// BarrierInitializeShamir initializes the barrier using Shamir secret sharing.
func (t *Transport) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{
		Secret: req.Secret,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "barrier initialize shamir failed", Err: err}
	}

	return &transport.BarrierInitializeShamirResponse{
		Threshold:   int(resp.Threshold),
		TotalShares: int(resp.TotalShares),
		ShareCount:  int(resp.ShareCount),
	}, nil
}

// BarrierUnsealWithShare submits a single Shamir share toward the quorum.
func (t *Transport) BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.BarrierUnsealShare(ctx, &pb.BarrierUnsealShareRequest{
		Share: req.Share,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "barrier unseal with share failed", Err: err}
	}

	return &transport.BarrierUnsealShareResponse{
		Required:  int(resp.Required),
		Submitted: int(resp.Submitted),
		Complete:  resp.Complete,
	}, nil
}

// BarrierUnsealWithShares submits all Shamir shares at once for batch unsealing.
func (t *Transport) BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.BarrierUnsealShares(ctx, &pb.BarrierUnsealSharesRequest{
		Shares: req.Shares,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "barrier unseal with shares failed", Err: err}
	}

	return nil
}

// BarrierRekey rotates Shamir shares while keeping the same root key.
func (t *Transport) BarrierRekey(ctx context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.BarrierRekey(ctx, &pb.BarrierRekeyRequest{
		Threshold: int32(req.Threshold),
		Total:     int32(req.Total),
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "barrier rekey failed", Err: err}
	}

	return &transport.BarrierRekeyResponse{
		Threshold:   int(resp.Threshold),
		TotalShares: int(resp.TotalShares),
		ShareCount:  int(resp.ShareCount),
	}, nil
}

// BarrierGenerateRecoveryKeys generates recovery keys for disaster recovery.
func (t *Transport) BarrierGenerateRecoveryKeys(ctx context.Context, req *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.BarrierGenerateRecoveryKeys(ctx, &pb.BarrierGenerateRecoveryKeysRequest{
		Threshold: int32(req.Threshold),
		Total:     int32(req.Total),
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "barrier generate recovery keys failed", Err: err}
	}

	return &transport.BarrierRecoveryKeysResponse{
		Threshold:   int(resp.Threshold),
		TotalShares: int(resp.TotalShares),
		ShareCount:  int(resp.ShareCount),
	}, nil
}

// BarrierEnableEncryption migrates a previously-unencrypted barrier to a keyed
// strategy in place.
func (t *Transport) BarrierEnableEncryption(ctx context.Context, req *transport.BarrierEnableEncryptionRequest) (*transport.BarrierEnableEncryptionResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.BarrierEnableEncryption(ctx, &pb.BarrierEnableEncryptionRequest{
		TenantId:        req.TenantID,
		Strategy:        req.Strategy,
		Mechanism:       req.Mechanism,
		Availability:    req.Availability,
		Passphrase:      req.Passphrase,
		ShamirThreshold: int32(req.ShamirThreshold),
		ShamirTotal:     int32(req.ShamirTotal),
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "barrier enable encryption failed", Err: err}
	}

	return &transport.BarrierEnableEncryptionResponse{
		Status: resp.Status,
		Scope:  resp.Scope,
	}, nil
}

// BarrierRecoverWithKeys unseals the barrier using recovery keys.
func (t *Transport) BarrierRecoverWithKeys(ctx context.Context, req *transport.BarrierRecoverWithKeysRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.BarrierRecoverWithKeys(ctx, &pb.BarrierRecoverWithKeysRequest{
		Keys: req.Keys,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "barrier recover with keys failed", Err: err}
	}

	return nil
}

// BarrierDeleteRecoveryKeys deletes stored recovery key metadata.
func (t *Transport) BarrierDeleteRecoveryKeys(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.BarrierDeleteRecoveryKeys(ctx, &emptypb.Empty{})
	if err != nil {
		return &errs.Wrapped{Msg: "barrier delete recovery keys failed", Err: err}
	}

	return nil
}

// BarrierHasRecoveryKeys checks if recovery keys exist.
func (t *Transport) BarrierHasRecoveryKeys(ctx context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	resp, err := t.client.BarrierHasRecoveryKeys(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "barrier has recovery keys failed", Err: err}
	}
	return &transport.BarrierHasRecoveryKeysResponse{HasKeys: resp.HasKeys}, nil
}

// BarrierGenerateRootToken generates a one-time root token by proving
// knowledge of the master key through Shamir share reconstruction.
func (t *Transport) BarrierGenerateRootToken(ctx context.Context, req *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.BarrierGenerateRootToken(ctx, &pb.BarrierGenerateRootTokenRequest{
		Shares: req.Shares,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "barrier generate root token failed", Err: err}
	}

	return &transport.BarrierRootTokenResponse{
		Token:     resp.Token,
		CreatedAt: resp.CreatedAt,
	}, nil
}

// PIV Operations

// ListPIVSlots lists all PIV slots and their status for the specified backend.
func (t *Transport) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.ListPIVSlots(ctx, &pb.ListPIVSlotsRequest{
		Backend: req.Backend,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "list PIV slots failed", Err: err}
	}

	slots := make([]transport.PIVSlotStatus, len(resp.Slots))
	for i, s := range resp.Slots {
		slots[i] = transport.PIVSlotStatus{
			Slot:        s.Slot,
			Name:        s.Name,
			Description: s.Description,
			HasCert:     s.HasCert,
			Subject:     s.Subject,
			Algorithm:   s.Algorithm,
			KeySize:     int(s.KeySize),
			NotAfter:    s.NotAfter,
			Fingerprint: s.Fingerprint,
		}
	}

	return &transport.ListPIVSlotsResponse{
		Slots: slots,
	}, nil
}

// GetPIVCertificate retrieves the certificate stored in the specified PIV slot.
func (t *Transport) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GetPIVCertificate(ctx, &pb.GetPIVCertificateRequest{
		Backend: req.Backend,
		Slot:    req.Slot,
		Format:  req.Format,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "get PIV certificate failed", Err: err}
	}

	return &transport.GetPIVCertificateResponse{
		Slot:        resp.Slot,
		Certificate: resp.Certificate,
		Format:      resp.Format,
	}, nil
}

// StorePIVCertificate stores a certificate into the specified PIV slot.
func (t *Transport) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.StorePIVCertificate(ctx, &pb.StorePIVCertificateRequest{
		Backend:     req.Backend,
		Slot:        req.Slot,
		Certificate: req.Certificate,
		Format:      req.Format,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "store PIV certificate failed", Err: err}
	}

	return nil
}

// DeletePIVCertificate removes the certificate from the specified PIV slot.
func (t *Transport) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.DeletePIVCertificate(ctx, &pb.DeletePIVCertificateRequest{
		Backend: req.Backend,
		Slot:    req.Slot,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "delete PIV certificate failed", Err: err}
	}

	return nil
}

// GeneratePIVKey generates a new asymmetric key pair in the specified PIV slot.
func (t *Transport) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GeneratePIVKey(ctx, &pb.GeneratePIVKeyRequest{
		Backend:   req.Backend,
		Slot:      req.Slot,
		Algorithm: req.Algorithm,
		Subject:   req.Subject,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "generate PIV key failed", Err: err}
	}

	return &transport.GeneratePIVKeyResponse{
		Slot:        resp.Slot,
		Certificate: resp.Certificate,
		PublicKey:   resp.PublicKey,
	}, nil
}

// ImportPIVCertificate imports an external certificate into the specified PIV slot.
func (t *Transport) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.ImportPIVCertificate(ctx, &pb.StorePIVCertificateRequest{
		Backend:     req.Backend,
		Slot:        req.Slot,
		Certificate: req.Certificate,
		Format:      req.Format,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "import PIV certificate failed", Err: err}
	}

	return nil
}

// ExportPIVCertificate exports the certificate from the specified PIV slot.
func (t *Transport) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.ExportPIVCertificate(ctx, &pb.GetPIVCertificateRequest{
		Backend: req.Backend,
		Slot:    req.Slot,
		Format:  req.Format,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "export PIV certificate failed", Err: err}
	}

	return &transport.GetPIVCertificateResponse{
		Slot:        resp.Slot,
		Certificate: resp.Certificate,
		Format:      resp.Format,
	}, nil
}

// GeneratePIVCSR generates a Certificate Signing Request for the key in the specified PIV slot.
func (t *Transport) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GeneratePIVCSR(ctx, &pb.GeneratePIVCSRRequest{
		Backend: req.Backend,
		Slot:    req.Slot,
		Subject: req.Subject,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "generate PIV CSR failed", Err: err}
	}

	return &transport.GeneratePIVCSRResponse{
		Slot: resp.Slot,
		CSR:  resp.Csr,
	}, nil
}

// FIDO2 Operations

// BeginRegistration begins a WebAuthn registration flow over the unix-socket
// gRPC transport. It returns the JSON-marshaled WebAuthn options plus an opaque
// session ID, mirroring the lossless SDK ceremony.
func (t *Transport) BeginRegistration(ctx context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	resp, err := t.client.BeginRegistration(ctx, &pb.BeginRegistrationRequest{
		Email:       req.Email,
		DisplayName: req.DisplayName,
	})
	if err != nil {
		return nil, err
	}
	return &transport.BeginRegistrationResponse{
		SessionID:   resp.SessionId,
		OptionsJSON: resp.OptionsJson,
	}, nil
}

// FinishRegistration completes a WebAuthn registration flow over the
// unix-socket gRPC transport. The request carries the session ID from
// BeginRegistration and the authenticator attestation as WebAuthn
// PublicKeyCredential JSON.
func (t *Transport) FinishRegistration(ctx context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	resp, err := t.client.FinishRegistration(ctx, &pb.FinishRegistrationRequest{
		SessionId:       req.SessionID,
		AttestationJson: req.AttestationJSON,
	})
	if err != nil {
		return nil, err
	}
	return &transport.FinishRegistrationResponse{
		Success:      resp.Success,
		CredentialID: resp.CredentialId,
		Token:        resp.Token,
		Message:      resp.Message,
	}, nil
}

// BeginAuthentication begins a WebAuthn authentication (login) flow over the
// unix-socket gRPC transport. It returns the JSON-marshaled WebAuthn assertion
// options plus an opaque session ID, mirroring the lossless SDK ceremony.
func (t *Transport) BeginAuthentication(ctx context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	resp, err := t.client.BeginAuthentication(ctx, &pb.BeginAuthenticationRequest{
		Email: req.Email,
	})
	if err != nil {
		return nil, err
	}
	return &transport.BeginAuthenticationResponse{
		SessionID:   resp.SessionId,
		OptionsJSON: resp.OptionsJson,
	}, nil
}

// FinishAuthentication completes a WebAuthn authentication (login) flow over the
// unix-socket gRPC transport. The request carries the session ID from
// BeginAuthentication and the authenticator assertion as WebAuthn
// PublicKeyCredential JSON.
func (t *Transport) FinishAuthentication(ctx context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	resp, err := t.client.FinishAuthentication(ctx, &pb.FinishAuthenticationRequest{
		SessionId:     req.SessionID,
		Email:         req.Email,
		AssertionJson: req.AssertionJSON,
	})
	if err != nil {
		return nil, err
	}
	return &transport.FinishAuthenticationResponse{
		Success:  resp.Success,
		Token:    resp.Token,
		Username: resp.Username,
		Message:  resp.Message,
	}, nil
}

// Invitation redemption (go-xkms#1294 part B). Every RPC is deliberately
// ungated on the server, mirroring the FIDO2/WebAuthn ceremony RPCs above.
// The Unix transport dials the same KeystoreService the gRPC transport
// does, just over a Unix socket (pkg/api/unix/grpc_server.go).

// GetInvite resolves a still-usable invitation's metadata without consuming it.
func (t *Transport) GetInvite(ctx context.Context, req *transport.GetInviteRequest) (*transport.GetInviteResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	resp, err := t.client.GetInvite(ctx, &pb.GetInviteRequest{TenantId: req.TenantID, Token: req.Token})
	if err != nil {
		return nil, err
	}
	return &transport.GetInviteResponse{
		Email:       resp.Email,
		DisplayName: resp.DisplayName,
		ExpiresAt:   resp.GetExpiresAt().AsTime(),
		Methods:     resp.Methods,
	}, nil
}

// BeginInviteRegistration opens the invite-authorized WebAuthn registration ceremony.
func (t *Transport) BeginInviteRegistration(ctx context.Context, req *transport.BeginInviteRegistrationRequest) (*transport.BeginInviteRegistrationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	resp, err := t.client.BeginInviteRegistration(ctx, &pb.BeginInviteRegistrationRequest{TenantId: req.TenantID, Token: req.Token})
	if err != nil {
		return nil, err
	}
	return &transport.BeginInviteRegistrationResponse{SessionID: resp.SessionId, OptionsJSON: resp.OptionsJson}, nil
}

// FinishInviteRegistration completes the invite-authorized WebAuthn registration ceremony.
func (t *Transport) FinishInviteRegistration(ctx context.Context, req *transport.FinishInviteRegistrationRequest) (*transport.FinishInviteRegistrationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	resp, err := t.client.FinishInviteRegistration(ctx, &pb.FinishInviteRegistrationRequest{
		TenantId:        req.TenantID,
		Token:           req.Token,
		SessionId:       req.SessionID,
		AttestationJson: req.AttestationJSON,
	})
	if err != nil {
		return nil, err
	}
	return &transport.FinishInviteRegistrationResponse{UserID: resp.UserId}, nil
}

// ActivateInvitePIV activates the account by verifying a presented PIV certificate.
func (t *Transport) ActivateInvitePIV(ctx context.Context, req *transport.ActivateInvitePIVRequest) (*transport.ActivateInvitePIVResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	resp, err := t.client.ActivateInvitePIV(ctx, &pb.ActivateInvitePIVRequest{
		TenantId: req.TenantID,
		Token:    req.Token,
		CertPem:  req.CertPEM,
	})
	if err != nil {
		return nil, err
	}
	return &transport.ActivateInvitePIVResponse{UserID: resp.UserId}, nil
}

// CA Operations

// GetCABundle retrieves the CA certificate bundle.
func (t *Transport) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GetCABundle(ctx, &pb.GetCABundleRequest{
		StoreType: req.StoreType,
		Algorithm: req.Algorithm,
	})
	if err != nil {
		return nil, err
	}

	return &transport.GetCABundleResponse{
		BundlePEM:    resp.GetBundlePem(),
		Certificates: resp.GetCertificates(),
		ContentType:  resp.GetContentType(),
	}, nil
}

// GetCACertificate retrieves the CA certificate.
func (t *Transport) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GetCACertificate(ctx, &pb.GetCACertificateRequest{
		Identity: req.Identity,
	})
	if err != nil {
		return nil, err
	}

	return &transport.GetCACertificateResponse{
		CertificatePEM: resp.GetCertificatePem(),
		Subject:        resp.GetSubject(),
		Issuer:         resp.GetIssuer(),
		SerialNumber:   resp.GetSerialNumber(),
		NotBefore:      resp.GetNotBefore(),
		NotAfter:       resp.GetNotAfter(),
		IsCA:           resp.GetIsCa(),
	}, nil
}

// SignCSR signs a certificate signing request using the CA.
func (t *Transport) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.SignCSR(ctx, &pb.SignCSRRequest{
		CsrPem:       req.CSRPEM,
		Profile:      req.Profile,
		ValidityDays: int32(req.ValidityDays),
	})
	if err != nil {
		return nil, err
	}

	return &transport.SignCSRResponse{
		CertificatePEM: resp.GetCertificatePem(),
		ChainPEM:       resp.GetChainPem(),
		SerialNumber:   resp.GetSerialNumber(),
	}, nil
}

// IssueCertificate issues a new certificate from the CA.
func (t *Transport) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.IssueCertificate(ctx, &pb.IssueCertificateRequest{
		Profile:      req.Profile,
		CommonName:   req.CommonName,
		Organization: req.Organization,
		Sans:         req.SANs,
		ValidityDays: int32(req.ValidityDays),
		Algorithm:    req.Algorithm,
	})
	if err != nil {
		return nil, err
	}

	return &transport.IssueCertificateResponse{
		CertificatePEM: resp.GetCertificatePem(),
		ChainPEM:       resp.GetChainPem(),
		PrivateKeyPEM:  resp.GetPrivateKeyPem(),
		SerialNumber:   resp.GetSerialNumber(),
	}, nil
}

// RevokeCertificate revokes a certificate by serial number.
func (t *Transport) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.RevokeCertificate(ctx, &pb.RevokeCertificateRequest{
		SerialNumber: req.SerialNumber,
		Reason:       int32(req.Reason),
	})
	if err != nil {
		return nil, err
	}

	return &transport.RevokeCertificateResponse{
		Success: resp.GetSuccess(),
		Message: resp.GetMessage(),
	}, nil
}

// GenerateCRL generates a certificate revocation list.
func (t *Transport) GenerateCRL(ctx context.Context, _ *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GenerateCRL(ctx, &pb.GenerateCRLRequest{})
	if err != nil {
		return nil, err
	}

	return &transport.GenerateCRLResponse{
		CRLPEM: resp.GetCrlPem(),
	}, nil
}

// IsRevoked checks if a certificate is revoked by serial number.
func (t *Transport) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.IsRevoked(ctx, &pb.IsRevokedRequest{
		SerialNumber: req.SerialNumber,
	})
	if err != nil {
		return nil, err
	}

	return &transport.IsRevokedResponse{
		Revoked: resp.GetRevoked(),
		Reason:  int(resp.GetReason()),
		Message: resp.GetMessage(),
	}, nil
}

// TCG CA Operations

// IssueEKCertificate issues an Endorsement Key certificate.
func (t *Transport) IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	body := map[string]interface{}{
		"common_name":   req.CommonName,
		"ek_public_key": req.EKPublicKey,
	}
	if req.Organization != "" {
		body["organization"] = req.Organization
	}
	if req.TenantID != "" {
		body["tenant_id"] = req.TenantID
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/tcg-ca/issue-ek-cert", body)
	if err != nil {
		return nil, err
	}

	var resp transport.IssueEKCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// IssueAKCertificate issues an Attestation Key certificate.
func (t *Transport) IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	body := map[string]interface{}{
		"common_name": req.CommonName,
		"public_key":  req.PublicKey,
	}
	if req.Organization != "" {
		body["organization"] = req.Organization
	}
	if req.TenantID != "" {
		body["tenant_id"] = req.TenantID
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/tcg-ca/issue-ak-cert", body)
	if err != nil {
		return nil, err
	}

	var resp transport.IssueAKCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// SignTCGCSR signs a TCG-CSR-IDEVID for device identity enrollment.
func (t *Transport) SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	body := map[string]interface{}{
		"common_name": req.CommonName,
		"tcg_csr":     req.TCGCSR,
	}
	if req.Organization != "" {
		body["organization"] = req.Organization
	}
	if req.TenantID != "" {
		body["tenant_id"] = req.TenantID
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/tcg-ca/sign-tcg-csr", body)
	if err != nil {
		return nil, err
	}

	var resp transport.SignTCGCSRResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// EnrollDevice performs complete TCG device enrollment.
func (t *Transport) EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	body := map[string]interface{}{
		"common_name": req.CommonName,
		"packed_csr":  req.PackedCSR,
	}
	if req.Organization != "" {
		body["organization"] = req.Organization
	}
	if req.TenantID != "" {
		body["tenant_id"] = req.TenantID
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/tcg-ca/enroll-device", body)
	if err != nil {
		return nil, err
	}

	var resp transport.EnrollDeviceResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// PIN Operations

// SetSOPIN sets the Security Officer PIN.
func (t *Transport) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.SetSOPIN(ctx, &pb.SetSOPINRequest{
		CurrentSoPin: req.CurrentSOPIN,
		NewSoPin:     req.NewSOPIN,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "set SO PIN failed", Err: err}
	}

	return nil
}

// SetUserPIN sets the user PIN. Requires SO PIN authorization.
func (t *Transport) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.SetUserPIN(ctx, &pb.SetUserPINRequest{
		SoPin:      req.SOPIN,
		NewUserPin: req.NewUserPIN,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "set user PIN failed", Err: err}
	}

	return nil
}

// ChangeSOPIN changes the Security Officer PIN.
func (t *Transport) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.ChangeSOPIN(ctx, &pb.ChangeSOPINRequest{
		CurrentSoPin: req.CurrentSOPIN,
		NewSoPin:     req.NewSOPIN,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "change SO PIN failed", Err: err}
	}

	return nil
}

// ChangeUserPIN changes the user PIN.
func (t *Transport) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.ChangeUserPIN(ctx, &pb.ChangeUserPINRequest{
		CurrentUserPin: req.CurrentUserPIN,
		NewUserPin:     req.NewUserPIN,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "change user PIN failed", Err: err}
	}

	return nil
}

// VerifySOPIN verifies the Security Officer PIN.
func (t *Transport) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.VerifySOPIN(ctx, &pb.VerifySOPINRequest{
		SoPin: req.SOPIN,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "verify SO PIN failed", Err: err}
	}

	return nil
}

// VerifyUserPIN verifies the user PIN.
func (t *Transport) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.VerifyUserPIN(ctx, &pb.VerifyUserPINRequest{
		UserPin: req.UserPIN,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "verify user PIN failed", Err: err}
	}

	return nil
}

// GetLockoutStatus returns the current PIN lockout status.
func (t *Transport) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GetLockoutStatus(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "get lockout status failed", Err: err}
	}

	return &transport.LockoutStatusResponse{
		FailedAttempts:  int(resp.FailedAttempts),
		MaxAttempts:     int(resp.MaxAttempts),
		IsLocked:        resp.IsLocked,
		LockoutUntil:    resp.LockoutUntil,
		RecoverySeconds: int(resp.RecoverySeconds),
	}, nil
}

// ResetLockout resets the PIN lockout counter using SO PIN authorization.
func (t *Transport) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.client.ResetLockout(ctx, &pb.ResetLockoutRequest{
		SoPin: req.SOPIN,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "reset lockout failed", Err: err}
	}

	return nil
}

// Password Store Operations

// PasswordAdd adds a new static password.
func (t *Transport) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.PasswordAddRequest{
		Name:       req.Name,
		Username:   req.Username,
		Password:   req.Password,
		Url:        req.URL,
		Notes:      req.Notes,
		FolderPath: req.FolderPath,
		ExpiresAt:  req.ExpiresAt,
		Shared:     req.Shared,
	}

	resp, err := t.client.PasswordAdd(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.PasswordAddResponse{
		ID:        resp.Id,
		Name:      resp.Name,
		CreatedAt: resp.CreatedAt,
	}, nil
}

// PasswordGet retrieves a password entry.
func (t *Transport) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.PasswordGetRequest{
		Id: req.ID,
	}

	resp, err := t.client.PasswordGet(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return pbPasswordEntryToTransport(resp.Entry), nil
}

// PasswordList lists password entries.
func (t *Transport) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.PasswordListRequest{}
	if req != nil {
		pbReq.FolderPath = req.FolderPath
		pbReq.Scope = req.Scope
	}

	resp, err := t.client.PasswordList(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	passwords := make([]transport.PasswordGetResponse, len(resp.Passwords))
	for i, entry := range resp.Passwords {
		converted := pbPasswordEntryToTransport(entry)
		if converted != nil {
			passwords[i] = *converted
		}
	}

	return &transport.PasswordListResponse{
		Passwords:    passwords,
		PageResponse: transport.PageResponse{Total: int(resp.Total)},
	}, nil
}

// PasswordUpdate updates a password entry.
func (t *Transport) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}

	pbReq := &pb.PasswordUpdateRequest{
		Id:         req.ID,
		Name:       req.Name,
		Username:   req.Username,
		Password:   req.Password,
		Url:        req.URL,
		Notes:      req.Notes,
		FolderPath: req.FolderPath,
		ExpiresAt:  req.ExpiresAt,
	}

	_, err := t.client.PasswordUpdate(ctx, pbReq)
	return err
}

// PasswordDelete deletes a password entry.
func (t *Transport) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}

	pbReq := &pb.PasswordDeleteRequest{
		Id: req.ID,
	}

	_, err := t.client.PasswordDelete(ctx, pbReq)
	return err
}

// PasswordStoreUnlock unlocks the password store.
func (t *Transport) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}

	pbReq := &pb.PasswordStoreUnlockRequest{
		Credential: pbconv.VaultCredentialToPB(req.PasswordVaultCredential),
	}

	_, err := t.client.PasswordStoreUnlock(ctx, pbReq)
	return err
}

// PasswordStoreLock locks the password store.
func (t *Transport) PasswordStoreLock(ctx context.Context) error {
	if t.client == nil {
		return ErrNotConnected
	}

	_, err := t.client.PasswordStoreLock(ctx, &pb.PasswordStoreLockRequest{})
	return err
}

// PasswordStoreStatus returns the password store status.
func (t *Transport) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.PasswordStoreStatus(ctx, &pb.PasswordStoreStatusRequest{})
	if err != nil {
		return nil, err
	}

	return &transport.PasswordStoreStatusResponse{
		AccessMode:    resp.AccessMode,
		IsLocked:      resp.IsLocked,
		BarrierSealed: resp.BarrierSealed,
		AutoUnsealed:  resp.AutoUnsealed,
		PasswordCount: int(resp.PasswordCount),
	}, nil
}

// PasswordStoreSetAccessMode sets the password store access mode.
func (t *Transport) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}
	_, err := t.client.PasswordStoreSetAccessMode(ctx, &pb.PasswordStoreSetAccessModeRequest{Mode: req.Mode})
	return err
}

// PasswordGenerate generates a random password.
func (t *Transport) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.PasswordGenerateRequest{
		Length:  int32(req.Length),
		Upper:   req.Upper,
		Lower:   req.Lower,
		Digits:  req.Digits,
		Symbols: req.Symbols,
		Charset: req.Charset,
	}

	resp, err := t.client.PasswordGenerate(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.PasswordGenerateResponse{
		Password: resp.Password,
	}, nil
}

// Personal-vault operations are served by pbconv.PasswordVaultClient, shared
// with the gRPC transport, once this transport holds a connection.

// PasswordVaultStatus describes the caller's personal vault.
func (t *Transport) PasswordVaultStatus(ctx context.Context) (*transport.PasswordVaultStatusResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.PasswordVaultClient{Client: t.client}.PasswordVaultStatus(ctx)
}

// PasswordVaultEnroll enrolls a passphrase or passkey on the caller's vault.
func (t *Transport) PasswordVaultEnroll(ctx context.Context, req *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.PasswordVaultClient{Client: t.client}.PasswordVaultEnroll(ctx, req)
}

// PasswordVaultRotate replaces the secret of one of the caller's factors.
func (t *Transport) PasswordVaultRotate(ctx context.Context, req *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.PasswordVaultClient{Client: t.client}.PasswordVaultRotate(ctx, req)
}

// PasswordVaultRemoveFactor removes one of the caller's factors.
func (t *Transport) PasswordVaultRemoveFactor(ctx context.Context, req *transport.PasswordVaultRemoveFactorRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}
	return pbconv.PasswordVaultClient{Client: t.client}.PasswordVaultRemoveFactor(ctx, req)
}

// PasswordVaultRecover uses the caller's recovery code to enroll a new factor.
func (t *Transport) PasswordVaultRecover(ctx context.Context, req *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.PasswordVaultClient{Client: t.client}.PasswordVaultRecover(ctx, req)
}

// pbPasswordEntryToTransport converts a protobuf PasswordEntry to a transport PasswordGetResponse.
func pbPasswordEntryToTransport(entry *pb.PasswordEntry) *transport.PasswordGetResponse {
	if entry == nil {
		return nil
	}

	resp := &transport.PasswordGetResponse{
		ID:         entry.Id,
		Name:       entry.Name,
		Username:   entry.Username,
		Password:   entry.Password,
		URL:        entry.Url,
		Notes:      entry.Notes,
		FolderPath: entry.FolderPath,
		BackendID:  entry.BackendId,
		ReadOnly:   entry.ReadOnly,
		Encrypted:  entry.Encrypted,
		OwnerID:    entry.OwnerId,
		Shared:     entry.Shared,
	}

	if entry.ExpiresAt != nil {
		resp.ExpiresAt = entry.ExpiresAt.AsTime().Format(time.RFC3339)
	}
	if entry.CreatedAt != nil {
		resp.CreatedAt = entry.CreatedAt.AsTime().Format(time.RFC3339)
	}
	if entry.UpdatedAt != nil {
		resp.UpdatedAt = entry.UpdatedAt.AsTime().Format(time.RFC3339)
	}

	return resp
}

// Platform Store Operations

// SealStorePut stores a secret in the platform-sealed store.
func (t *Transport) SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}
	_, err := t.client.SealStorePut(ctx, &pb.SealStorePutRequest{Name: req.Name, Secret: req.Secret})
	return err
}

// SealStoreGet retrieves a secret from the platform-sealed store.
func (t *Transport) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.SealStoreGet(ctx, &pb.SealStoreGetRequest{Name: req.Name})
	if err != nil {
		return nil, err
	}
	return &transport.SealStoreGetResponse{Name: resp.Name, Secret: resp.Secret}, nil
}

// SealStoreDelete deletes a secret from the platform-sealed store.
func (t *Transport) SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}
	_, err := t.client.SealStoreDelete(ctx, &pb.SealStoreDeleteRequest{Name: req.Name})
	return err
}

// SealStoreList lists all stored secret names in the platform-sealed store.
func (t *Transport) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.SealStoreList(ctx, &pb.SealStoreListRequest{})
	if err != nil {
		return nil, err
	}
	return &transport.SealStoreListResponse{Names: resp.Names}, nil
}

// SealStoreReseal reseals a secret with the current platform sealing key.
func (t *Transport) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}
	_, err := t.client.SealStoreReseal(ctx, &pb.SealStoreResealRequest{Name: req.Name})
	return err
}

// SealStoreStatus returns the platform-sealed store status.
func (t *Transport) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.SealStoreStatus(ctx, &pb.SealStoreStatusRequest{})
	if err != nil {
		return nil, err
	}
	return &transport.SealStoreStatusResponse{
		Available:   resp.Available,
		SealerID:    resp.SealerId,
		SecretCount: int(resp.SecretCount),
		SecretNames: resp.SecretNames,
	}, nil
}

// External key escrow (pkg/escrow) is embedded-only (go-xkms#692): its RBAC
// model is undecided, so Transport does not implement EscrowKey/RecoverKey/
// ListEscrowed/RevokeEscrow at all. transport.EscrowService is no longer
// part of transport.Client — see docs/escrow/architecture.md.

// Key Version Operations
//
// The key-version API is served by pbconv.KeyVersionClient, shared with the
// gRPC transport, once this transport holds a connection.

// ListKeyVersions lists a key's versions.
func (t *Transport) ListKeyVersions(ctx context.Context, req *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.KeyVersionClient{Client: t.client}.ListKeyVersions(ctx, req)
}

// EnableKeyVersion enables a version of a key.
func (t *Transport) EnableKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.KeyVersionClient{Client: t.client}.EnableKeyVersion(ctx, req)
}

// DisableKeyVersion disables a version of a key.
func (t *Transport) DisableKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.KeyVersionClient{Client: t.client}.DisableKeyVersion(ctx, req)
}

// RetireKeyVersion retires a version of a key.
func (t *Transport) RetireKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.KeyVersionClient{Client: t.client}.RetireKeyVersion(ctx, req)
}

// EnableAllKeyVersions enables every disabled version of a key.
func (t *Transport) EnableAllKeyVersions(ctx context.Context, req *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.KeyVersionClient{Client: t.client}.EnableAllKeyVersions(ctx, req)
}

// DisableAllKeyVersions disables every non-current version of a key.
func (t *Transport) DisableAllKeyVersions(ctx context.Context, req *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.KeyVersionClient{Client: t.client}.DisableAllKeyVersions(ctx, req)
}

// RotateScopeKeys rotates every key of a tenant.
func (t *Transport) RotateScopeKeys(ctx context.Context, req *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.KeyVersionClient{Client: t.client}.RotateScopeKeys(ctx, req)
}

// TPM Policy Operations
//
// The TPM policy API is served by pbconv.TPMPolicyClient, shared with the
// gRPC transport, once this transport holds a connection.

// TPMPolicyCreate creates a named TPM policy.
func (t *Transport) TPMPolicyCreate(ctx context.Context, req *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TPMPolicyCreate(ctx, req)
}

// TPMPolicyGet returns a named TPM policy.
func (t *Transport) TPMPolicyGet(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TPMPolicyGet(ctx, req)
}

// TPMPolicyList returns a tenant's TPM policies.
func (t *Transport) TPMPolicyList(ctx context.Context, req *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TPMPolicyList(ctx, req)
}

// TPMPolicyUpdate re-captures and re-approves a TPM policy.
func (t *Transport) TPMPolicyUpdate(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TPMPolicyUpdate(ctx, req)
}

// TPMPolicyRevoke withdraws a TPM policy's approval.
func (t *Transport) TPMPolicyRevoke(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TPMPolicyRevoke(ctx, req)
}

// TPMPolicyVerify compares a TPM policy's PCR values with the live ones.
func (t *Transport) TPMPolicyVerify(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TPMPolicyVerify(ctx, req)
}

// TPMPolicyDelete deletes a TPM policy no object is assigned to.
func (t *Transport) TPMPolicyDelete(ctx context.Context, req *transport.TPMPolicyDeleteRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TPMPolicyDelete(ctx, req)
}

// TPMPolicyObjects lists the objects assigned to a TPM policy.
func (t *Transport) TPMPolicyObjects(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TPMPolicyObjects(ctx, req)
}

// TPMPolicySetAutoUnseal sets or clears a TPM policy's auto-unseal mark.
func (t *Transport) TPMPolicySetAutoUnseal(ctx context.Context, req *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TPMPolicySetAutoUnseal(ctx, req)
}

// TPMPolicySetDescription replaces a TPM policy's description.
func (t *Transport) TPMPolicySetDescription(ctx context.Context, req *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TPMPolicySetDescription(ctx, req)
}

// TPMObjectPolicy returns the TPM policy a key or sealed object was created under.
func (t *Transport) TPMObjectPolicy(ctx context.Context, req *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TPMObjectPolicy(ctx, req)
}

// TPMPolicyRotateAuthority rotates a tenant's TPM policy authority.
func (t *Transport) TPMPolicyRotateAuthority(ctx context.Context, req *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TPMPolicyRotateAuthority(ctx, req)
}

// GetTenantTPMMode returns a tenant's TPM mode.
func (t *Transport) GetTenantTPMMode(ctx context.Context, tenantID string) (*transport.TenantTPMModeResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.GetTenantTPMMode(ctx, tenantID)
}

// SetTenantTPMMode changes a tenant's TPM mode.
func (t *Transport) SetTenantTPMMode(ctx context.Context, req *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.SetTenantTPMMode(ctx, req)
}

// TenantVTPMStatus reports a tenant's virtual TPM.
func (t *Transport) TenantVTPMStatus(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TenantVTPMStatus(ctx, tenantID)
}

// TenantVTPMStart starts a tenant's virtual TPM.
func (t *Transport) TenantVTPMStart(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TenantVTPMStart(ctx, tenantID)
}

// TenantVTPMStop stops a tenant's virtual TPM.
func (t *Transport) TenantVTPMStop(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	return pbconv.TPMPolicyClient{Client: t.client}.TenantVTPMStop(ctx, tenantID)
}

// CustodianGroup Operations

// CreateCustodianGroup creates a new custodian group.
func (t *Transport) CreateCustodianGroup(ctx context.Context, req *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.CreateCustodianGroupRequest{
		Name:        req.Name,
		Description: req.Purpose,
		Threshold:   int32(req.Threshold),
	}

	resp, err := t.client.CreateCustodianGroup(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.CreateCustodianGroupResponse{
		Group: pbCustodianGroupToTransport(resp.GetGroup()),
	}, nil
}

// GetCustodianGroup retrieves a custodian group by ID.
func (t *Transport) GetCustodianGroup(ctx context.Context, groupID string) (*transport.GetCustodianGroupResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GetCustodianGroup(ctx, &pb.GetCustodianGroupRequest{
		GroupId: groupID,
	})
	if err != nil {
		return nil, err
	}

	return &transport.GetCustodianGroupResponse{
		Group: pbCustodianGroupToTransport(resp.GetGroup()),
	}, nil
}

// ListCustodianGroups lists all custodian groups.
func (t *Transport) ListCustodianGroups(ctx context.Context) (*transport.ListCustodianGroupsResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.ListCustodianGroups(ctx, &pb.ListCustodianGroupsRequest{})
	if err != nil {
		return nil, err
	}

	groups := make([]transport.CustodianGroupInfo, len(resp.GetGroups()))
	for i, g := range resp.GetGroups() {
		groups[i] = pbCustodianGroupToTransport(g)
	}

	return &transport.ListCustodianGroupsResponse{
		Groups: groups,
	}, nil
}

// DeleteCustodianGroup deletes a custodian group.
func (t *Transport) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	if t.client == nil {
		return ErrNotConnected
	}

	_, err := t.client.DeleteCustodianGroup(ctx, &pb.DeleteCustodianGroupRequest{
		GroupId: groupID,
	})
	return err
}

// AddCustodianMember adds a member to a custodian group.
func (t *Transport) AddCustodianMember(ctx context.Context, req *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.AddCustodianMemberRequest{
		GroupId: req.GroupID,
		UserId:  req.UserID,
		Name:    req.Username,
		Email:   "",
		Role:    req.Method,
	}

	resp, err := t.client.AddCustodianMember(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	member := resp.GetMember()
	return &transport.AddCustodianMemberResponse{
		Member: transport.CustodianMemberInfo{
			UserID:   member.GetUserId(),
			Username: member.GetName(),
			Method:   member.GetRole(),
		},
	}, nil
}

// RemoveCustodianMember removes a member from a custodian group.
func (t *Transport) RemoveCustodianMember(ctx context.Context, req *transport.RemoveCustodianMemberRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}

	_, err := t.client.RemoveCustodianMember(ctx, &pb.RemoveCustodianMemberRequest{
		GroupId: req.GroupID,
		UserId:  req.UserID,
	})
	return err
}

// DistributeShares distributes Shamir shares to custodian group members.
func (t *Transport) DistributeShares(ctx context.Context, req *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.DistributeShares(ctx, &pb.DistributeSharesRequest{
		GroupId: req.GroupID,
	})
	if err != nil {
		return nil, err
	}

	return &transport.DistributeSharesResponse{
		Distributed: int(resp.GetDistributed()),
	}, nil
}

// Share Operations

// SubmitShare submits a received Shamir share back to the server.
func (t *Transport) SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.SubmitShareRequest{
		GroupId:    req.GroupID,
		ShareData:  base64.StdEncoding.EncodeToString(req.ShareData),
		ServerUrl:  req.ServerURL,
		GroupName:  req.GroupName,
		ShareIndex: int32(req.ShareIndex),
		Purpose:    req.Purpose,
		TenantId:   req.TenantID,
	}

	resp, err := t.client.SubmitShare(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.SubmitShareResponse{
		Accepted: resp.GetId() != "" || resp.GetMessage() != "",
	}, nil
}

// ListShares lists shares available for the authenticated user.
func (t *Transport) ListShares(ctx context.Context) (*transport.ListSharesResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.ListShares(ctx, &pb.ListSharesRequest{})
	if err != nil {
		return nil, err
	}

	shares := make([]transport.ShareInfo, len(resp.GetShares()))
	for i, s := range resp.GetShares() {
		shares[i] = pbShareInfoToTransport(s)
	}

	return &transport.ListSharesResponse{
		Shares: shares,
	}, nil
}

// GetShare returns a single stored share. Share material is never included
// in the response — the server returns metadata only.
func (t *Transport) GetShare(ctx context.Context, serverURL, groupID string, shareIndex int) (*transport.ShareInfo, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GetShare(ctx, &pb.GetShareRequest{
		ServerUrl:  serverURL,
		GroupId:    groupID,
		ShareIndex: int32(shareIndex), // #nosec G115 - share index fits in int32
	})
	if err != nil {
		return nil, err
	}

	info := pbShareInfoToTransport(resp)
	return &info, nil
}

// DeleteShare removes a single stored share.
func (t *Transport) DeleteShare(ctx context.Context, serverURL, groupID string, shareIndex int) error {
	if t.client == nil {
		return ErrNotConnected
	}

	_, err := t.client.DeleteShare(ctx, &pb.DeleteShareRequest{
		ServerUrl:  serverURL,
		GroupId:    groupID,
		ShareIndex: int32(shareIndex), // #nosec G115 - share index fits in int32
	})
	return err
}

// parseTimestamp parses an RFC3339 timestamp received from the server. An
// empty value yields the zero time silently: the field was never set. A
// non-empty value that fails to parse also yields the zero time -- the
// call still returns the rest of the entity, which is otherwise complete
// -- but it is logged, since it usually means the peer and this binary
// have drifted on the wire encoding.
func parseTimestamp(field, value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		slog.Debug("unix transport: failed to parse timestamp", "field", field, "value", value, "error", err)
		return time.Time{}
	}
	return t
}

// pbShareInfoToTransport converts a proto ShareInfo to its transport
// representation. An unparseable timestamp yields the zero time rather than
// failing the call — the metadata is still useful without it.
func pbShareInfoToTransport(s *pb.ShareInfo) transport.ShareInfo {
	receivedAt := parseTimestamp("submitted_at", s.GetSubmittedAt())
	return transport.ShareInfo{
		ServerURL:  s.GetServerUrl(),
		GroupID:    s.GetGroupId(),
		GroupName:  s.GetGroupName(),
		ShareIndex: int(s.GetShareIndex()),
		Purpose:    s.GetPurpose(),
		ReceivedAt: receivedAt,
		TenantID:   s.GetTenantId(),
	}
}

// GetShareCollectionStatus returns the collection status for a group.
func (t *Transport) GetShareCollectionStatus(ctx context.Context, groupID string) (*transport.ShareCollectionStatus, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GetShareCollectionStatus(ctx, &pb.GetShareCollectionStatusRequest{
		GroupId: groupID,
	})
	if err != nil {
		return nil, err
	}

	return &transport.ShareCollectionStatus{
		GroupID:   resp.GetGroupId(),
		Threshold: int(resp.GetRequired()),
		Collected: int(resp.GetCollected()),
		Ready:     resp.GetComplete(),
	}, nil
}

// Audit Operations

// QueryAudit returns one page of audit events from the tamper-evident audit
// chain owned by the embedded qrdb node.
func (t *Transport) QueryAudit(ctx context.Context, filter *transport.AuditFilter) (*transport.AuditPage, error) {
	if filter == nil {
		return nil, transport.ErrInvalidRequest
	}
	if t.client == nil {
		return nil, ErrNotConnected
	}

	req := &pb.QueryAuditRequest{
		Actor:    filter.Actor,
		Resource: filter.Resource,
		Action:   filter.Action,
		Outcome:  filter.Outcome,
		TenantId: filter.TenantID,
		Limit:    int32(filter.Limit), // #nosec G115 - page limit fits in int32
		Cursor:   filter.Cursor,
	}
	if !filter.From.IsZero() {
		req.From = timestamppb.New(filter.From)
	}
	if !filter.To.IsZero() {
		req.To = timestamppb.New(filter.To)
	}

	resp, err := t.client.QueryAudit(ctx, req)
	if err != nil {
		return nil, err
	}

	events := make([]transport.AuditEvent, len(resp.GetEvents()))
	for i, e := range resp.GetEvents() {
		events[i] = pbAuditEventToTransport(e)
	}

	return &transport.AuditPage{
		Events: events,
		Next:   resp.GetNext(),
		Total:  int(resp.GetTotal()),
	}, nil
}

// pbAuditEventToTransport converts a proto AuditEvent to its transport
// representation. A nil Attributes Struct converts to a nil map rather than
// panicking.
func pbAuditEventToTransport(e *pb.AuditEvent) transport.AuditEvent {
	var attrs map[string]any
	if a := e.GetAttributes(); a != nil {
		attrs = a.AsMap()
	}
	var ts time.Time
	if pts := e.GetTimestamp(); pts != nil {
		ts = pts.AsTime()
	}
	return transport.AuditEvent{
		Timestamp:  ts,
		Actor:      e.GetActor(),
		TenantID:   e.GetTenantId(),
		Role:       e.GetRole(),
		Resource:   e.GetResource(),
		Action:     e.GetAction(),
		Outcome:    e.GetOutcome(),
		Attributes: attrs,
		ClientIP:   e.GetClientIp(),
		RequestID:  e.GetRequestId(),
		PrevHash:   e.GetPrevHash(),
	}
}

// Tenant Operations

// CreateTenant creates a new tenant.
func (t *Transport) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	pbReq := &pb.CreateTenantRequest{
		Id:          req.ID,
		Name:        req.Name,
		Description: "",
	}

	resp, err := t.client.CreateTenant(ctx, pbReq)
	if err != nil {
		return nil, err
	}

	return &transport.CreateTenantResponse{
		Tenant: pbTenantInfoToTransport(resp.GetTenant()),
	}, nil
}

// GetTenant retrieves a tenant by ID.
func (t *Transport) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.GetTenant(ctx, &pb.GetTenantRequest{
		TenantId: tenantID,
	})
	if err != nil {
		return nil, err
	}

	return &transport.GetTenantResponse{
		Tenant: pbTenantInfoToTransport(resp.GetTenant()),
	}, nil
}

// ListTenants lists all tenants.
func (t *Transport) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.ListTenants(ctx, &pb.ListTenantsRequest{})
	if err != nil {
		return nil, err
	}

	tenants := make([]transport.TenantInfo, len(resp.GetTenants()))
	for i, ti := range resp.GetTenants() {
		tenants[i] = pbTenantInfoToTransport(ti)
	}

	return &transport.ListTenantsResponse{
		Tenants: tenants,
	}, nil
}

// DeleteTenant deletes a tenant.
func (t *Transport) DeleteTenant(ctx context.Context, tenantID string) error {
	if t.client == nil {
		return ErrNotConnected
	}

	_, err := t.client.DeleteTenant(ctx, &pb.DeleteTenantRequest{
		TenantId: tenantID,
	})
	return err
}

// TenantBarrierInit initializes a per-tenant barrier.
func (t *Transport) TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}

	_, err := t.client.TenantBarrierInit(ctx, &pb.TenantBarrierInitRequest{
		TenantId:  req.TenantID,
		Shares:    int32(req.Shares),
		Threshold: int32(req.Threshold),
	})
	return err
}

// TenantBarrierUnseal unseals a per-tenant barrier.
func (t *Transport) TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error {
	if t.client == nil {
		return ErrNotConnected
	}

	var shareValues []string
	if len(req.Share) > 0 {
		shareValues = append(shareValues, base64.StdEncoding.EncodeToString(req.Share))
	}
	if len(req.Key) > 0 {
		shareValues = append(shareValues, base64.StdEncoding.EncodeToString(req.Key))
	}

	_, err := t.client.TenantBarrierUnseal(ctx, &pb.TenantBarrierUnsealRequest{
		TenantId:    req.TenantID,
		ShareValues: shareValues,
	})
	return err
}

// TenantBarrierStatus reports the status of a per-tenant barrier.
func (t *Transport) TenantBarrierStatus(ctx context.Context, tenantID string) (*transport.TenantBarrierStatusResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.TenantBarrierStatus(ctx, &pb.TenantBarrierStatusRequest{TenantId: tenantID})
	if err != nil {
		return nil, err
	}
	return &transport.TenantBarrierStatusResponse{
		TenantID:        resp.GetTenantId(),
		Sealed:          resp.GetSealed(),
		Initialized:     resp.GetInitialized(),
		Strategy:        resp.GetStrategy(),
		HardwareBacked:  resp.GetHardwareBacked(),
		ShamirThreshold: int(resp.GetShamirThreshold()),
		ShamirTotal:     int(resp.GetShamirTotal()),
	}, nil
}

// UpdateTenantEntitlements updates a tenant's feature entitlements.
func (t *Transport) UpdateTenantEntitlements(ctx context.Context, req *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.UpdateTenantEntitlements(ctx, &pb.UpdateTenantEntitlementsRequest{
		TenantId:     req.TenantID,
		Entitlements: tenantEntitlementsToPB(req.Entitlements),
	})
	if err != nil {
		return nil, err
	}
	return &transport.UpdateTenantEntitlementsResponse{Tenant: pbTenantInfoToTransport(resp.GetTenant())}, nil
}

// UpdateTenantQuotas updates a tenant's resource quotas.
func (t *Transport) UpdateTenantQuotas(ctx context.Context, req *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.UpdateTenantQuotas(ctx, &pb.UpdateTenantQuotasRequest{
		TenantId: req.TenantID,
		Quotas:   tenantQuotasToPB(req.Quotas),
	})
	if err != nil {
		return nil, err
	}
	return &transport.UpdateTenantQuotasResponse{Tenant: pbTenantInfoToTransport(resp.GetTenant())}, nil
}

// Init Ceremony Operations

// doRawRequest performs an HTTP request over the Unix domain socket and returns
// the raw response body. It is used for REST endpoints that have no gRPC equivalent,
// such as init ceremony and credential management operations.
func (t *Transport) doRawRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	if t.httpClient == nil {
		return nil, ErrNotConnected
	}

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to marshal request body", Err: err}
		}
		reqBody = bytes.NewReader(data)
	}

	// Use a dummy host; the actual connection is routed through the unix socket dialer.
	reqURL := "http://localhost" + path

	req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create request", Err: err}
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if t.config.JWTToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.config.JWTToken)
	}

	for k, v := range t.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "request failed", Err: err}
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Debug("unix transport: failed to close HTTP response body", "error", cerr)
		}
	}()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read response body", Err: err}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &errs.Message{Msg: fmt.Sprintf("server returned status %d: %s", resp.StatusCode, string(respData))}
	}

	return respData, nil
}

// GetInitStatus returns the current init ceremony state.
func (t *Transport) GetInitStatus(ctx context.Context) (*transport.InitStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodGet, "/api/v1/init/status", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.InitStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ClaimCertBegin begins the certificate claim process for an officer.
func (t *Transport) ClaimCertBegin(ctx context.Context, req *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/init/claim-cert/begin", req)
	if err != nil {
		return nil, err
	}

	var resp transport.ClaimCertBeginResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ClaimCertComplete completes the certificate claim by verifying the officer's
// signature over the challenge nonce.
func (t *Transport) ClaimCertComplete(ctx context.Context, req *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/init/claim-cert/complete", req)
	if err != nil {
		return nil, err
	}

	var resp transport.ClaimCertCompleteResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ClaimShare retrieves the Shamir share for the named officer.
func (t *Transport) ClaimShareBegin(ctx context.Context, req *transport.ClaimShareBeginRequest) (*transport.ClaimShareBeginResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/init/claim-share/begin", req)
	if err != nil {
		return nil, err
	}

	var resp transport.ClaimShareBeginResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ClaimShareComplete completes the Shamir share claim handshake for the named
// officer.
func (t *Transport) ClaimShareComplete(ctx context.Context, req *transport.ClaimShareCompleteRequest) (*transport.ClaimShareCompleteResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/init/claim-share/complete", req)
	if err != nil {
		return nil, err
	}

	var resp transport.ClaimShareCompleteResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// SignCSRInit signs a CSR during initialization with SO authorization.
func (t *Transport) SignCSRInit(ctx context.Context, req *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/init/sign-csr", req)
	if err != nil {
		return nil, err
	}

	var resp transport.SignCSRInitResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// Credential Management Operations

// SubmitCredential submits a credential for manual mode.
func (t *Transport) SubmitCredential(ctx context.Context, req *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/credentials/submit", req)
	if err != nil {
		return nil, err
	}

	var resp transport.CredentialSubmitResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetCredentialStrategy returns the configured credential strategy.
func (t *Transport) GetCredentialStrategy(ctx context.Context) (*transport.CredentialStrategyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodGet, "/api/v1/credentials/strategy", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.CredentialStrategyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ==================== User Operations ====================
//
// xkms presents its own user model; the backing store is the embedded qrdb
// node, reached over the Unix (gRPC) transport.

// protoToUserInfo projects a protobuf UserInfo onto its transport form.
func protoToUserInfo(u *pb.UserInfo) transport.UserInfo {
	if u == nil {
		return transport.UserInfo{}
	}
	return transport.UserInfo{
		ID:       u.GetId(),
		Username: u.GetUsername(),
		// The canonical login key travels BOTH ways. The server-side projection
		// was updated without this one, so gRPC and unix clients read an empty
		// Email for a user that has one — the key this PR makes required was
		// unreadable over exactly the transports that send it as a typed field
		// (Codex, go-xkms #190).
		Email:       u.GetEmail(),
		DisplayName: u.GetDisplayName(),
		Role:        u.GetRole(),
		Enabled:     u.GetEnabled(),
	}
}

// protoToInviteInfo projects a protobuf InviteInfo onto its transport form.
// A nil message (no invitation minted -- a certificate-only/bootstrap
// create) stays nil, rather than a zero-valued struct that would look like
// an empty token.
func protoToInviteInfo(i *pb.InviteInfo) *transport.InviteInfo {
	if i == nil {
		return nil
	}
	return &transport.InviteInfo{
		Token:     i.GetToken(),
		URL:       i.GetUrl(),
		ExpiresAt: i.GetExpiresAt().AsTime(),
	}
}

// CreateUser creates a new xkms user.
func (t *Transport) CreateUser(ctx context.Context, req *transport.CreateUserRequest) (*transport.GetUserResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.CreateUser(ctx, &pb.CreateUserRequest{
		Username:             req.Username,
		Email:                req.Email,
		WithoutEmailLoginKey: req.WithoutEmailLoginKey,
		DisplayName:          req.DisplayName,
		Role:                 req.Role,
		TenantId:             req.TenantID,
		InviteTtlSeconds:     req.InviteTTLSeconds,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "create user failed", Err: err}
	}
	return &transport.GetUserResponse{User: protoToUserInfo(resp.GetUser()), Invite: protoToInviteInfo(resp.GetInvite())}, nil
}

// ListUsers lists xkms users.
func (t *Transport) ListUsers(ctx context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.ListUsers(ctx, &pb.ListUsersRequest{})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "list users failed", Err: err}
	}
	users := make([]transport.UserInfo, len(resp.GetUsers()))
	for i, u := range resp.GetUsers() {
		users[i] = protoToUserInfo(u)
	}
	return &transport.ListUsersResponse{Users: users}, nil
}

// GetUser resolves an xkms user by username.
func (t *Transport) GetUser(ctx context.Context, username string) (*transport.GetUserResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.GetUser(ctx, &pb.GetUserRequest{Username: username})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "get user failed", Err: err}
	}
	return &transport.GetUserResponse{User: protoToUserInfo(resp.GetUser())}, nil
}

// DeleteUser removes an xkms user by username.
func (t *Transport) DeleteUser(ctx context.Context, username string) error {
	if t.client == nil {
		return ErrNotConnected
	}
	if _, err := t.client.DeleteUser(ctx, &pb.DeleteUserRequest{Username: username}); err != nil {
		return &errs.Wrapped{Msg: "delete user failed", Err: err}
	}
	return nil
}

// EnableUser enables an xkms user by username.
func (t *Transport) EnableUser(ctx context.Context, username string) error {
	if t.client == nil {
		return ErrNotConnected
	}
	if _, err := t.client.EnableUser(ctx, &pb.EnableUserRequest{Username: username}); err != nil {
		return &errs.Wrapped{Msg: "enable user failed", Err: err}
	}
	return nil
}

// DisableUser disables an xkms user by username.
func (t *Transport) DisableUser(ctx context.Context, username string) error {
	if t.client == nil {
		return ErrNotConnected
	}
	if _, err := t.client.DisableUser(ctx, &pb.DisableUserRequest{Username: username}); err != nil {
		return &errs.Wrapped{Msg: "disable user failed", Err: err}
	}
	return nil
}

// BindUserCert binds an mTLS certificate SPKI thumbprint to an xkms user.
func (t *Transport) BindUserCert(ctx context.Context, username, thumbprint string, notAfterUnix int64) error {
	if t.client == nil {
		return ErrNotConnected
	}
	if _, err := t.client.BindUserCert(ctx, &pb.BindUserCertRequest{
		Username:     username,
		Thumbprint:   thumbprint,
		NotAfterUnix: notAfterUnix,
	}); err != nil {
		return &errs.Wrapped{Msg: "bind user cert failed", Err: err}
	}
	return nil
}

// ListUserCredentials lists the credentials registered to an xkms user.
func (t *Transport) ListUserCredentials(ctx context.Context, username string) (*transport.ListUserCredentialsResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.ListUserCredentials(ctx, &pb.ListUserCredentialsRequest{Username: username})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "list user credentials failed", Err: err}
	}
	creds := make([]transport.CredentialInfo, len(resp.GetCredentials()))
	for i, c := range resp.GetCredentials() {
		creds[i] = transport.CredentialInfo{ID: c.GetId(), DisplayName: c.GetName()}
	}
	return &transport.ListUserCredentialsResponse{Credentials: creds}, nil
}

// Compile-time assertion that Transport implements the transport.Client interface.
var _ transport.Client = (*Transport)(nil)

// Helper functions for converting between SDK types and protobuf types

// pbCustodianGroupToTransport converts a protobuf CustodianGroup to the transport type.
func pbCustodianGroupToTransport(g *pb.CustodianGroup) transport.CustodianGroupInfo {
	if g == nil {
		return transport.CustodianGroupInfo{}
	}

	members := make([]transport.CustodianMemberInfo, len(g.GetMembers()))
	for i, m := range g.GetMembers() {
		members[i] = transport.CustodianMemberInfo{
			UserID:   m.GetUserId(),
			Username: m.GetName(),
			Method:   m.GetRole(),
		}
	}

	createdAt := parseTimestamp("created_at", g.GetCreatedAt())
	updatedAt := parseTimestamp("updated_at", g.GetUpdatedAt())

	return transport.CustodianGroupInfo{
		ID:        g.GetId(),
		Name:      g.GetName(),
		Purpose:   g.GetDescription(),
		Threshold: int(g.GetThreshold()),
		Members:   members,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}
}

// pbTenantInfoToTransport converts a protobuf TenantInfo to the transport type.
func pbTenantInfoToTransport(ti *pb.TenantInfo) transport.TenantInfo {
	if ti == nil {
		return transport.TenantInfo{}
	}

	createdAt := parseTimestamp("created_at", ti.GetCreatedAt())
	updatedAt := parseTimestamp("updated_at", ti.GetUpdatedAt())

	out := transport.TenantInfo{
		ID:            ti.GetId(),
		Name:          ti.GetName(),
		IsolationType: transport.TenantIsolationType(ti.GetIsolationType()),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}
	out.Quotas = pbQuotasToTransport(ti.GetQuotas())
	out.Entitlements = pbEntitlementsToTransport(ti.GetEntitlements())
	return out
}

// Algorithms reports the algorithms the server supports.
func (t *Transport) Algorithms(ctx context.Context) (*transport.AlgorithmsResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}

	resp, err := t.client.Algorithms(ctx, &pb.AlgorithmsRequest{})
	if err != nil {
		return nil, err
	}

	return &transport.AlgorithmsResponse{
		Signing:          pbAlgorithmInfosToTransport(resp.GetSigning()),
		KeyEncapsulation: pbAlgorithmInfosToTransport(resp.GetKeyEncapsulation()),
	}, nil
}

// pbAlgorithmInfosToTransport converts proto algorithm entries to their
// transport representation.
func pbAlgorithmInfosToTransport(in []*pb.AlgorithmInfo) []transport.AlgorithmInfo {
	out := make([]transport.AlgorithmInfo, len(in))
	for i, a := range in {
		sizes := make([]int, len(a.GetKeySizes()))
		for j, s := range a.GetKeySizes() {
			sizes[j] = int(s)
		}
		out[i] = transport.AlgorithmInfo{
			Algorithm:   a.GetAlgorithm(),
			Curves:      a.GetCurves(),
			KeySizes:    sizes,
			Backends:    a.GetBackends(),
			PostQuantum: a.GetPostQuantum(),
		}
	}
	return out
}
