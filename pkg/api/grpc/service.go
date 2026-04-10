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

package grpc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/authz"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// grpcPageRequest converts the proto limit/offset fields to a PageRequest.
// When limit is 0, the request is treated as unpaginated (return all).
// When limit > 0 and offset >= 0, it computes the 1-based page number.
func grpcPageRequest(limit, offset int) transport.PageRequest {
	if limit <= 0 {
		return transport.PageRequest{Page: 0}
	}
	page := 1
	if offset > 0 && limit > 0 {
		page = (offset / limit) + 1
	}
	return transport.PageRequest{
		Page:     page,
		PageSize: limit,
	}
}

// getBackendDescription returns a human-readable description for a backend type
func getBackendDescription(bt types.BackendType) string {
	descriptions := map[types.BackendType]string{
		types.BackendTypeSoftware:  "Software-based key storage",
		types.BackendTypePKCS11:    "Hardware Security Module (PKCS#11)",
		types.BackendTypeTPM2:      "Trusted Platform Module 2.0",
		types.BackendTypeAWSKMS:    "AWS Key Management Service",
		types.BackendTypeGCPKMS:    "Google Cloud Key Management Service",
		types.BackendTypeAzureKV:   "Azure Key Vault",
		types.BackendTypeVault:     "HashiCorp Vault",
		types.BackendTypeSymmetric: "Symmetric key storage",
	}

	if desc, ok := descriptions[bt]; ok {
		return desc
	}

	return string(bt)
}

// Typed errors for authorization operations.
var (
	// ErrAuthorizationFailed is returned when the authorizer encounters
	// an internal error while evaluating the request.
	ErrAuthorizationFailed = errors.New("grpc: authorization error")

	// ErrAccessDenied is returned when the authorizer denies access to the
	// requested resource.
	ErrAccessDenied = errors.New("grpc: access denied")
)

// Service implements the KeystoreService gRPC interface
type Service struct {
	pb.UnimplementedKeystoreServiceServer
	authorizer  authz.Authorizer
	auditLogger audit.Logger
}

// NewService creates a new gRPC service.
// The service uses the global xkms service for backend management.
// If authorizer or auditLogger are nil, no-op implementations are used.
func NewService(authorizer authz.Authorizer, auditLogger audit.Logger) *Service {
	if authorizer == nil {
		authorizer = &authz.NoOpAuthorizer{}
	}
	if auditLogger == nil {
		auditLogger = &audit.NoOpLogger{}
	}
	return &Service{
		authorizer:  authorizer,
		auditLogger: auditLogger,
	}
}

// authorize performs an authorization check for the given resource, action,
// and resource ID. It extracts the caller's identity from the context, builds
// an authorization request, calls the authorizer, and logs the audit event.
// Returns nil if the action is allowed, or a gRPC status error on deny/error.
func (s *Service) authorize(ctx context.Context, resource, action, resourceID string) error {
	identity := auth.GetIdentity(ctx)

	subject := ""
	role := ""
	if identity != nil {
		subject = identity.Subject
		role = extractRoleFromIdentity(identity)
	}

	authzReq := &authz.AuthorizationRequest{
		Subject:  subject,
		Role:     role,
		Resource: resource,
		Action:   action,
		Context:  map[string]string{"resource_id": resourceID},
	}

	decision, err := s.authorizer.Authorize(ctx, authzReq)

	outcome := audit.OutcomeAllow
	if err != nil || (decision != nil && !decision.Allowed) {
		outcome = audit.OutcomeDeny
	}

	auditEvent := &audit.Event{
		Timestamp:  time.Now(),
		Subject:    subject,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Outcome:    outcome,
		Details:    map[string]string{"transport": "grpc"},
	}
	if role != "" {
		auditEvent.Details["role"] = role
	}
	// Best-effort audit logging; do not disrupt the request pipeline.
	_ = s.auditLogger.Log(ctx, auditEvent)

	if err != nil {
		return status.Error(codes.Internal, ErrAuthorizationFailed.Error())
	}

	if decision != nil && !decision.Allowed {
		reason := ErrAccessDenied.Error()
		if decision.Reason != "" {
			reason = decision.Reason
		}
		return status.Error(codes.PermissionDenied, reason)
	}

	return nil
}

// extractRoleFromIdentity extracts the first role from an identity's claims.
// It handles roles stored as []string, []interface{}, or string.
func extractRoleFromIdentity(identity *auth.Identity) string {
	if identity == nil || identity.Claims == nil {
		return ""
	}

	roles, ok := identity.Claims["roles"]
	if !ok {
		return ""
	}

	switch r := roles.(type) {
	case []string:
		if len(r) > 0 {
			return r[0]
		}
	case []interface{}:
		if len(r) > 0 {
			if s, ok := r[0].(string); ok {
				return s
			}
		}
	case string:
		return r
	}

	return ""
}

// Health returns the health status of the service
func (s *Service) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{
		Status:  "healthy",
		Version: xkms.Version(),
	}, nil
}

// ListBackends returns all available backend providers
func (s *Service) ListBackends(ctx context.Context, req *pb.ListBackendsRequest) (*pb.ListBackendsResponse, error) {
	if err := s.authorize(ctx, "backends", "read", ""); err != nil {
		return nil, err
	}

	backendNames := xkms.Backends()

	backends := make([]*pb.BackendInfo, 0, len(backendNames))
	for _, name := range backendNames {
		ks, err := xkms.GetBackend(name)
		if err != nil {
			continue // Skip backends that can't be retrieved
		}

		backend := ks.KeyProvider()
		caps := backend.Capabilities()

		backends = append(backends, &pb.BackendInfo{
			Name:               name,
			Type:               string(backend.Type()),
			Description:        getBackendDescription(backend.Type()),
			HardwareBacked:     caps.HardwareBacked,
			SupportsSigning:    caps.Signing,
			SupportsDecryption: caps.Decryption,
			SupportsRotation:   caps.KeyRotation,
		})
	}

	return &pb.ListBackendsResponse{
		Backends: backends,
		Count:    int32(len(backends)), // #nosec G115 - Backend count fits in int32
	}, nil
}

// GetBackendInfo returns detailed information about a specific backend
func (s *Service) GetBackendInfo(ctx context.Context, req *pb.GetBackendInfoRequest) (*pb.GetBackendInfoResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "backend name is required")
	}

	if err := s.authorize(ctx, "backends", "read", req.Name); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Name)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	backend := ks.KeyProvider()
	caps := backend.Capabilities()

	return &pb.GetBackendInfoResponse{
		Backend: &pb.BackendInfo{
			Name:               req.Name,
			Type:               string(backend.Type()),
			Description:        getBackendDescription(backend.Type()),
			HardwareBacked:     caps.HardwareBacked,
			SupportsSigning:    caps.Signing,
			SupportsDecryption: caps.Decryption,
			SupportsRotation:   caps.KeyRotation,
		},
	}, nil
}

// GenerateKey generates a new cryptographic key
func (s *Service) GenerateKey(ctx context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	// Validate request
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if req.KeyType == "" {
		return nil, status.Error(codes.InvalidArgument, "key_type is required")
	}

	if err := s.authorize(ctx, "keys", "write", req.KeyId); err != nil {
		return nil, err
	}

	// Get keystore
	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Parse key type
	keyType := types.ParseKeyType(req.KeyType)
	// Default to KeyTypeSigning if the parsed key type is invalid
	// (e.g., when req.KeyType is an algorithm name like "rsa", "ecdsa", "ed25519")
	if keyType == 0 {
		keyType = types.KeyTypeSigning
	}

	// Build key attributes
	attrs := &types.KeyAttributes{
		CN:         req.KeyId,
		KeyType:    keyType,
		StoreType:  types.StoreType(req.Backend),
		Hash:       parseHashAlgorithm(req.Hash),
		Partition:  types.Partition(req.Partition),
		Exportable: req.Exportable,
	}

	// Set algorithm-specific attributes
	var privKey crypto.PrivateKey
	// Use Algorithm field if provided, otherwise fall back to KeyType for backward compatibility
	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = req.KeyType
	}
	switch {
	case types.AlgorithmRSA.Equals(algorithm):
		keySize := int(req.KeySize)
		if keySize == 0 {
			keySize = types.RSAKeySize2048 // Default
		}
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: keySize,
		}
		privKey, err = ks.GenerateRSA(attrs)

	case types.AlgorithmECDSA.Equals(algorithm):
		curve := req.Curve
		if curve == "" {
			curve = string(types.CurveP256) // Default
		}
		attrs.KeyAlgorithm = x509.ECDSA
		parsedCurve, curveErr := types.ParseCurve(curve)
		if curveErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid curve: %v", curveErr)
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: parsedCurve,
		}
		privKey, err = ks.GenerateECDSA(attrs)

	case types.AlgorithmEd25519.Equals(algorithm):
		attrs.KeyAlgorithm = x509.Ed25519
		privKey, err = ks.GenerateEd25519(attrs)

	case types.AlgorithmSymmetric.Equals(algorithm):
		// Handle symmetric key generation
		symBackend, ok := ks.KeyProvider().(types.SymmetricKeyProvider)
		if !ok {
			return nil, status.Error(codes.Unimplemented, "backend does not support symmetric key generation")
		}

		// Determine key size and algorithm
		keySize := int(req.KeySize)
		symAlgorithm := req.Algorithm
		if symAlgorithm == "" || symAlgorithm == "symmetric" {
			// Default based on key size or use AES-256-GCM
			switch keySize {
			case 128:
				symAlgorithm = "aes128-gcm"
			case 192:
				symAlgorithm = "aes192-gcm"
			case 256, 0:
				symAlgorithm = "aes256-gcm"
			default:
				return nil, status.Errorf(codes.InvalidArgument, "invalid key size for symmetric key: %d", keySize)
			}
		}

		attrs.SymmetricAlgorithm = types.SymmetricAlgorithm(symAlgorithm)
		attrs.KeyType = types.KeyTypeSecret // Symmetric keys use KeyTypeSecret

		_, err = symBackend.GenerateSymmetricKey(attrs)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to generate symmetric key: %v", err)
		}

		// Symmetric keys have no public key
		return &pb.GenerateKeyResponse{
			KeyId:     req.KeyId,
			Backend:   req.Backend,
			KeyType:   req.KeyType,
			CreatedAt: timestamppb.Now(),
		}, nil

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported algorithm: %s", algorithm)
	}

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate key: %v", err)
	}

	// Extract public key PEM
	publicKeyPem, err := extractPublicKeyPEM(privKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to extract public key: %v", err)
	}

	return &pb.GenerateKeyResponse{
		KeyId:        req.KeyId,
		Backend:      req.Backend,
		KeyType:      req.KeyType,
		PublicKeyPem: publicKeyPem,
		CreatedAt:    timestamppb.Now(),
	}, nil
}

// ListKeys lists all keys in the specified backend
func (s *Service) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	if err := s.authorize(ctx, "keys", "read", ""); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	attrs, err := ks.ListKeys()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list keys: %v", err)
	}

	// Apply pagination using the shared helper. The proto uses limit/offset
	// fields which map to a page-based request for consistency across protocols.
	pr := grpcPageRequest(int(req.Limit), int(req.Offset))
	paginatedAttrs, _ := transport.ApplyPagination(attrs, pr)

	// Convert to protobuf format
	keys := make([]*pb.KeyInfo, len(paginatedAttrs))
	for i, attr := range paginatedAttrs {
		keys[i] = &pb.KeyInfo{
			KeyId:     attr.CN,
			Backend:   req.Backend,
			KeyType:   string(attr.KeyType),
			Algorithm: getAlgorithmString(attr),
			Partition: string(attr.Partition),
			CreatedAt: timestamppb.Now(), // Note: actual creation time not tracked in KeyAttributes
		}

		// Add algorithm-specific info
		if attr.RSAAttributes != nil {
			keys[i].KeySize = int32(attr.RSAAttributes.KeySize) // #nosec G115 - RSA key size fits in int32
		}
		if attr.ECCAttributes != nil {
			keys[i].Curve = types.CurveName(attr.ECCAttributes.Curve)
		}
	}

	return &pb.ListKeysResponse{
		Keys:  keys,
		Total: int32(len(attrs)), // #nosec G115 - Key count fits in int32
	}, nil
}

// GetKey retrieves information about a specific key
func (s *Service) GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	if err := s.authorize(ctx, "keys", "read", req.KeyId); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// List all keys and find the matching one
	attrs, err := ks.ListKeys()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list keys: %v", err)
	}

	for _, attr := range attrs {
		if attr.CN == req.KeyId {
			keyInfo := &pb.KeyInfo{
				KeyId:     attr.CN,
				Backend:   req.Backend,
				KeyType:   string(attr.KeyType),
				Algorithm: getAlgorithmString(attr),
				Partition: string(attr.Partition),
				CreatedAt: timestamppb.Now(),
			}

			if attr.RSAAttributes != nil {
				keyInfo.KeySize = int32(attr.RSAAttributes.KeySize) // #nosec G115 - RSA key size fits in int32
			}
			if attr.ECCAttributes != nil {
				keyInfo.Curve = types.CurveName(attr.ECCAttributes.Curve)
			}

			// Extract public key PEM for asymmetric signing keys
			var publicKeyPem string
			if attr.KeyType == types.KeyTypeSigning {
				signer, err := ks.Signer(attr)
				if err == nil {
					pubKey := signer.Public()
					pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
					if err == nil {
						pemBlock := &pem.Block{
							Type:  "PUBLIC KEY",
							Bytes: pubKeyBytes,
						}
						publicKeyPem = string(pem.EncodeToMemory(pemBlock))
					}
				}
			}

			return &pb.GetKeyResponse{
				Key:          keyInfo,
				PublicKeyPem: publicKeyPem,
			}, nil
		}
	}

	return nil, status.Errorf(codes.NotFound, "key not found: %s", req.KeyId)
}

// Sign signs data with the specified key
func (s *Service) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	if err := s.authorize(ctx, "keys", "use", req.KeyId); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Get signer
	signer, err := ks.Signer(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get signer: %v", err)
	}

	// Ed25519 uses pure signing (no prehashing) - pass raw message with Hash(0)
	// Ed25519 per RFC 8032 allows signing empty messages (the algorithm handles its own hashing)
	if attrs.KeyAlgorithm == x509.Ed25519 {
		signature, err := signer.Sign(nil, req.Data, crypto.Hash(0))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to sign: %v", err)
		}
		return &pb.SignResponse{
			Signature: signature,
		}, nil
	}

	// For non-Ed25519 algorithms, data is required for hashing
	if len(req.Data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data is required")
	}

	// Determine hash algorithm
	hashAlg := parseHashAlgorithm(req.Hash)
	cryptoHash := hashAlg

	// Hash the data
	hasher := cryptoHash.New()
	hasher.Write(req.Data)
	digest := hasher.Sum(nil)

	// Sign
	signature, err := signer.Sign(nil, digest, cryptoHash)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign: %v", err)
	}

	return &pb.SignResponse{
		Signature: signature,
	}, nil
}

// Verify verifies a signature with the specified key
func (s *Service) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.Signature) == 0 {
		return nil, status.Error(codes.InvalidArgument, "signature is required")
	}

	if err := s.authorize(ctx, "keys", "use", req.KeyId); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Get the key
	privKey, err := ks.GetKey(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get key: %v", err)
	}

	// Extract public key
	var pubKey crypto.PublicKey
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	case crypto.Signer:
		// Handle OpaqueKey and other Signer implementations
		pubKey = k.Public()
	default:
		return nil, status.Error(codes.Internal, "unsupported key type")
	}

	// Ed25519 uses pure verification (no prehashing) - allows empty messages per RFC 8032
	if _, isEd25519 := pubKey.(ed25519.PublicKey); isEd25519 {
		valid := ed25519.Verify(pubKey.(ed25519.PublicKey), req.Data, req.Signature)
		message := "signature is valid"
		if !valid {
			message = "signature is invalid"
		}
		return &pb.VerifyResponse{
			Valid:   valid,
			Message: message,
		}, nil
	}

	// For non-Ed25519 algorithms, data is required for hashing
	if len(req.Data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data is required")
	}

	// Determine hash algorithm
	hashAlg := parseHashAlgorithm(req.Hash)
	cryptoHash := hashAlg

	// Hash the data
	hasher := cryptoHash.New()
	hasher.Write(req.Data)
	digest := hasher.Sum(nil)

	// Verify signature based on public key type
	valid := false
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, cryptoHash, digest, req.Signature)
		valid = (err == nil)
	case *ecdsa.PublicKey:
		valid = ecdsa.VerifyASN1(pub, digest, req.Signature)
	}

	message := "signature is valid"
	if !valid {
		message = "signature is invalid"
	}

	return &pb.VerifyResponse{
		Valid:   valid,
		Message: message,
	}, nil
}

// DeleteKey deletes a key from the backend
func (s *Service) DeleteKey(ctx context.Context, req *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	if err := s.authorize(ctx, "keys", "delete", req.KeyId); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Delete the key
	err = ks.DeleteKey(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete key: %v", err)
	}

	return &pb.DeleteKeyResponse{
		Success: true,
		Message: fmt.Sprintf("key %s deleted successfully", req.KeyId),
	}, nil
}

// RotateKey rotates an existing key
func (s *Service) RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	if err := s.authorize(ctx, "keys", "write", req.KeyId); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Rotate the key
	newKey, err := ks.RotateKey(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to rotate key: %v", err)
	}

	// Extract public key PEM
	publicKeyPem, err := extractPublicKeyPEM(newKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to extract public key: %v", err)
	}

	return &pb.RotateKeyResponse{
		KeyId:        req.KeyId,
		Backend:      req.Backend,
		KeyType:      string(attrs.KeyType),
		PublicKeyPem: publicKeyPem,
		RotatedAt:    timestamppb.Now(),
	}, nil
}

// Encrypt encrypts data with the specified key (symmetric encryption)
func (s *Service) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.Plaintext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "plaintext is required")
	}

	if err := s.authorize(ctx, "keys", "use", req.KeyId); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Get the backend to check if it supports symmetric encryption
	backendImpl := ks.KeyProvider()
	symmetricBackend, ok := backendImpl.(types.SymmetricKeyProvider)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "backend %s does not support symmetric encryption", req.Backend)
	}

	// Get symmetric encrypter
	encrypter, err := symmetricBackend.SymmetricEncrypter(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get symmetric encrypter: %v", err)
	}

	// Build encrypt options
	opts := &types.EncryptOptions{
		AdditionalData: req.AdditionalData,
	}

	// Encrypt the data
	encryptedData, err := encrypter.Encrypt(req.Plaintext, opts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to encrypt: %v", err)
	}

	return &pb.EncryptResponse{
		Ciphertext: encryptedData.Ciphertext,
		Nonce:      encryptedData.Nonce,
		Tag:        encryptedData.Tag,
	}, nil
}

// Decrypt decrypts data with the specified key
func (s *Service) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.Ciphertext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ciphertext is required")
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	var plaintext []byte

	// Check if this is a symmetric key based on key attributes
	if attrs.IsSymmetric() {
		// Symmetric decryption path
		symBackend, ok := ks.KeyProvider().(types.SymmetricKeyProvider)
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "backend does not support symmetric decryption")
		}

		if err := s.authorize(ctx, "keys", "use", req.KeyId); err != nil {
			return nil, err
		}

		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to get symmetric encrypter: %v", err)
		}

		encryptedData := &types.EncryptedData{
			Ciphertext: req.Ciphertext,
			Nonce:      req.Nonce,
			Tag:        req.Tag,
		}

		decryptOpts := &types.DecryptOptions{
			AdditionalData: req.AdditionalData,
		}

		plaintext, err = encrypter.Decrypt(encryptedData, decryptOpts)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to decrypt: %v", err)
		}
	} else {
		// Asymmetric decryption path
		decrypter, err := ks.Decrypter(attrs)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to get decrypter: %v", err)
		}

		plaintext, err = decrypter.Decrypt(nil, req.Ciphertext, nil)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to decrypt: %v", err)
		}
	}

	return &pb.DecryptResponse{
		Plaintext: plaintext,
	}, nil
}

// SaveCert stores a certificate
func (s *Service) SaveCert(ctx context.Context, req *pb.SaveCertRequest) (*pb.SaveCertResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.CertPem == "" {
		return nil, status.Error(codes.InvalidArgument, "cert_pem is required")
	}

	// Parse PEM to certificate
	cert, err := parseCertFromPEM(req.CertPem)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid certificate PEM: %v", err)
	}

	if err := s.authorize(ctx, "certs", "write", req.KeyId); err != nil {
		return nil, err
	}

	// Get any backend's keystore for cert operations (they all share the same cert storage)
	backends := xkms.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := xkms.GetBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Save the certificate
	err = ks.SaveCert(req.KeyId, cert)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save certificate: %v", err)
	}

	return &pb.SaveCertResponse{
		Success: true,
		Message: fmt.Sprintf("certificate for %s saved successfully", req.KeyId),
	}, nil
}

// GetCert retrieves a certificate
func (s *Service) GetCert(ctx context.Context, req *pb.GetCertRequest) (*pb.GetCertResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	if err := s.authorize(ctx, "certs", "read", req.KeyId); err != nil {
		return nil, err
	}

	// Get any backend's keystore for cert operations
	backends := xkms.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := xkms.GetBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Get the certificate
	cert, err := ks.GetCert(req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "certificate not found: %v", err)
	}

	// Convert to PEM
	certPem := encodeCertToPEM(cert)

	return &pb.GetCertResponse{
		CertPem: certPem,
	}, nil
}

// DeleteCert removes a certificate
func (s *Service) DeleteCert(ctx context.Context, req *pb.DeleteCertRequest) (*pb.DeleteCertResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	if err := s.authorize(ctx, "certs", "delete", req.KeyId); err != nil {
		return nil, err
	}

	// Get any backend's keystore for cert operations
	backends := xkms.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := xkms.GetBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Delete the certificate
	err = ks.DeleteCert(req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete certificate: %v", err)
	}

	return &pb.DeleteCertResponse{
		Success: true,
		Message: fmt.Sprintf("certificate for %s deleted successfully", req.KeyId),
	}, nil
}

// ListCerts lists all certificates
func (s *Service) ListCerts(ctx context.Context, req *pb.ListCertsRequest) (*pb.ListCertsResponse, error) {
	if err := s.authorize(ctx, "certs", "read", ""); err != nil {
		return nil, err
	}

	// Get any backend's keystore for cert operations
	backends := xkms.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := xkms.GetBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// List certificates
	keyIDs, err := ks.ListCerts()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list certificates: %v", err)
	}

	return &pb.ListCertsResponse{
		KeyIds: keyIDs,
		Total:  int32(len(keyIDs)), // #nosec G115 - Certificate count fits in int32
	}, nil
}

// CertExists checks if a certificate exists
func (s *Service) CertExists(ctx context.Context, req *pb.CertExistsRequest) (*pb.CertExistsResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	if err := s.authorize(ctx, "certs", "read", req.KeyId); err != nil {
		return nil, err
	}

	// Get any backend's keystore for cert operations
	backends := xkms.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := xkms.GetBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Check if certificate exists
	exists, err := ks.CertExists(req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check certificate existence: %v", err)
	}

	return &pb.CertExistsResponse{
		Exists: exists,
	}, nil
}

// SaveCertChain stores a certificate chain
func (s *Service) SaveCertChain(ctx context.Context, req *pb.SaveCertChainRequest) (*pb.SaveCertChainResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if len(req.CertChainPem) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cert_chain_pem is required")
	}

	// Parse PEM chain to certificates
	chain := make([]*x509.Certificate, len(req.CertChainPem))
	for i, certPem := range req.CertChainPem {
		cert, err := parseCertFromPEM(certPem)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid certificate PEM at index %d: %v", i, err)
		}

		if err := s.authorize(ctx, "certs", "write", req.KeyId); err != nil {
			return nil, err
		}
		chain[i] = cert
	}

	// Get any backend's keystore for cert operations
	backends := xkms.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := xkms.GetBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Save the certificate chain
	err = ks.SaveCertChain(req.KeyId, chain)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save certificate chain: %v", err)
	}

	return &pb.SaveCertChainResponse{
		Success: true,
		Message: fmt.Sprintf("certificate chain for %s saved successfully", req.KeyId),
	}, nil
}

// GetCertChain retrieves a certificate chain
func (s *Service) GetCertChain(ctx context.Context, req *pb.GetCertChainRequest) (*pb.GetCertChainResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	if err := s.authorize(ctx, "certs", "read", req.KeyId); err != nil {
		return nil, err
	}

	// Get any backend's keystore for cert operations
	backends := xkms.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := xkms.GetBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Get the certificate chain
	chain, err := ks.GetCertChain(req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "certificate chain not found: %v", err)
	}

	// Convert to PEM
	chainPem := make([]string, len(chain))
	for i, cert := range chain {
		chainPem[i] = encodeCertToPEM(cert)
	}

	return &pb.GetCertChainResponse{
		CertChainPem: chainPem,
	}, nil
}

// GetTLSCertificate returns a TLS certificate with private key
func (s *Service) GetTLSCertificate(ctx context.Context, req *pb.GetTLSCertificateRequest) (*pb.GetTLSCertificateResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	if err := s.authorize(ctx, "certs", "read", req.KeyId); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Get the TLS certificate
	tlsCert, err := ks.GetTLSCertificate(req.KeyId, attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get TLS certificate: %v", err)
	}

	// Convert leaf certificate to PEM
	if len(tlsCert.Certificate) == 0 {
		return nil, status.Error(codes.Internal, "TLS certificate has no data")
	}

	leafCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse leaf certificate: %v", err)
	}
	certPem := encodeCertToPEM(leafCert)

	// Convert certificate chain to PEM (excluding leaf)
	chainPem := make([]string, 0, len(tlsCert.Certificate)-1)
	for i := 1; i < len(tlsCert.Certificate); i++ {
		cert, err := x509.ParseCertificate(tlsCert.Certificate[i])
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to parse certificate at index %d: %v", i, err)
		}
		chainPem = append(chainPem, encodeCertToPEM(cert))
	}

	// Convert private key to PEM
	privKeyPem, err := encodePrivateKeyToPEM(tlsCert.PrivateKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to encode private key: %v", err)
	}

	return &pb.GetTLSCertificateResponse{
		CertPem:       certPem,
		CertChainPem:  chainPem,
		PrivateKeyPem: privKeyPem,
	}, nil
}

// GetImportParameters retrieves parameters needed to import a key
func (s *Service) GetImportParameters(ctx context.Context, req *pb.GetImportParametersRequest) (*pb.GetImportParametersResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if req.WrappingAlgorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "wrapping_algorithm is required")
	}
	if req.KeyType == "" {
		return nil, status.Error(codes.InvalidArgument, "key_type is required")
	}

	if err := s.authorize(ctx, "keys", "read", req.KeyId); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Check if backend supports import/export
	backendImpl := ks.KeyProvider()
	importExportBackend, ok := backendImpl.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "backend %s does not support import/export operations", req.Backend)
	}

	// Parse key type and build attributes
	keyType := types.ParseKeyType(req.KeyType)
	attrs := &types.KeyAttributes{
		CN:        req.KeyId,
		KeyType:   keyType,
		StoreType: types.StoreType(req.Backend),
		Hash:      parseHashAlgorithm(req.Hash),
		Partition: types.Partition(req.Partition),
	}

	// Set algorithm-specific attributes based on key_type field (expected to be algorithm name)
	switch {
	case types.AlgorithmRSA.Equals(req.KeyType):
		keySize := int(req.KeySize)
		if keySize == 0 {
			keySize = types.RSAKeySize2048 // Default
		}
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: keySize,
		}
	case types.AlgorithmECDSA.Equals(req.KeyType):
		curve := req.Curve
		if curve == "" {
			curve = string(types.CurveP256) // Default
		}
		attrs.KeyAlgorithm = x509.ECDSA
		parsedCurve, curveErr := types.ParseCurve(curve)
		if curveErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid curve: %v", curveErr)
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: parsedCurve,
		}
	case types.AlgorithmEd25519.Equals(req.KeyType):
		attrs.KeyAlgorithm = x509.Ed25519
	case types.AlgorithmSymmetric.Equals(req.KeyType):
		// For symmetric keys, set algorithm based on key size
		switch req.KeySize {
		case 128:
			attrs.SymmetricAlgorithm = types.SymmetricAES128GCM
		case 192:
			attrs.SymmetricAlgorithm = types.SymmetricAES192GCM
		case 256:
			attrs.SymmetricAlgorithm = types.SymmetricAES256GCM
		default:
			return nil, status.Errorf(codes.InvalidArgument, "invalid key size for AES keys: %d (must be 128, 192, or 256)", req.KeySize)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported key type: %s", req.KeyType)
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.WrappingAlgorithm)

	// Get import parameters from backend
	params, err := importExportBackend.GetImportParameters(attrs, wrappingAlg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get import parameters: %v", err)
	}

	// Marshal public key to DER format
	pubKeyDER, err := x509.MarshalPKIXPublicKey(params.WrappingPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal public key: %v", err)
	}

	response := &pb.GetImportParametersResponse{
		WrappingPublicKey: pubKeyDER,
		ImportToken:       params.ImportToken,
		Algorithm:         string(params.Algorithm),
		KeySpec:           params.KeySpec,
	}

	if params.ExpiresAt != nil {
		response.ExpiresAt = timestamppb.New(*params.ExpiresAt)
	}

	return response, nil
}

// WrapKey wraps key material for secure transport
func (s *Service) WrapKey(ctx context.Context, req *pb.WrapKeyRequest) (*pb.WrapKeyResponse, error) {
	if len(req.KeyMaterial) == 0 {
		return nil, status.Error(codes.InvalidArgument, "key_material is required")
	}
	if len(req.WrappingPublicKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "wrapping_public_key is required")
	}
	if req.Algorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "algorithm is required")
	}

	// Parse public key from DER
	pubKey, err := x509.ParsePKIXPublicKey(req.WrappingPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse wrapping public key: %v", err)
	}

	if err := s.authorize(ctx, "keys", "use", ""); err != nil {
		return nil, err
	}

	// Create import parameters
	params := &backend.ImportParameters{
		WrappingPublicKey: pubKey,
		ImportToken:       req.ImportToken,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
		KeySpec:           req.KeySpec,
	}

	// Get any backend to perform the wrapping operation
	// Wrapping is typically done client-side, so we can use any backend that implements the interface
	backends := xkms.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	var wrapped *backend.WrappedKeyMaterial
	for _, backendName := range backends {
		ks, err := xkms.GetBackend(backendName)
		if err != nil {
			continue
		}

		backendImpl := ks.KeyProvider()
		importExportBackend, ok := backendImpl.(backend.ImportExportBackend)
		if ok {
			wrapped, err = importExportBackend.WrapKey(req.KeyMaterial, params)
			if err == nil {
				break
			}
		}
	}

	if wrapped == nil {
		return nil, status.Error(codes.Internal, "failed to wrap key: no suitable backend found or wrapping failed")
	}

	return &pb.WrapKeyResponse{
		WrappedKey:  wrapped.WrappedKey,
		Algorithm:   string(wrapped.Algorithm),
		ImportToken: wrapped.ImportToken,
		Metadata:    wrapped.Metadata,
	}, nil
}

// UnwrapKey unwraps previously wrapped key material
func (s *Service) UnwrapKey(ctx context.Context, req *pb.UnwrapKeyRequest) (*pb.UnwrapKeyResponse, error) {
	if len(req.WrappedKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "wrapped_key is required")
	}
	if req.Algorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "algorithm is required")
	}
	if len(req.WrappingPublicKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "wrapping_public_key is required")
	}

	// Parse public key from DER
	pubKey, err := x509.ParsePKIXPublicKey(req.WrappingPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse wrapping public key: %v", err)
	}

	if err := s.authorize(ctx, "keys", "use", ""); err != nil {
		return nil, err
	}

	// Create wrapped key material
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  req.WrappedKey,
		Algorithm:   backend.WrappingAlgorithm(req.Algorithm),
		ImportToken: req.ImportToken,
		Metadata:    req.Metadata,
	}

	// Create import parameters
	params := &backend.ImportParameters{
		WrappingPublicKey: pubKey,
		ImportToken:       req.ImportToken,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
		KeySpec:           req.KeySpec,
	}

	// Get any backend to perform the unwrapping operation
	backends := xkms.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	var keyMaterial []byte
	for _, backendName := range backends {
		ks, err := xkms.GetBackend(backendName)
		if err != nil {
			continue
		}

		backendImpl := ks.KeyProvider()
		importExportBackend, ok := backendImpl.(backend.ImportExportBackend)
		if ok {
			keyMaterial, err = importExportBackend.UnwrapKey(wrapped, params)
			if err == nil {
				break
			}
		}
	}

	if keyMaterial == nil {
		return nil, status.Error(codes.Internal, "failed to unwrap key: no suitable backend found or unwrapping failed")
	}

	return &pb.UnwrapKeyResponse{
		KeyMaterial: keyMaterial,
	}, nil
}

// ImportKey imports externally generated key material into the backend
func (s *Service) ImportKey(ctx context.Context, req *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.WrappedKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "wrapped_key is required")
	}
	if req.Algorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "algorithm is required")
	}
	if req.KeyType == "" {
		return nil, status.Error(codes.InvalidArgument, "key_type is required")
	}

	if err := s.authorize(ctx, "keys", "write", req.KeyId); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Check if backend supports import/export
	backendImpl := ks.KeyProvider()
	importExportBackend, ok := backendImpl.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "backend %s does not support import/export operations", req.Backend)
	}

	// Build key attributes
	// Determine KeyType from algorithm - asymmetric keys (RSA, ECDSA, Ed25519) are signing keys,
	// symmetric keys (AES) are encryption keys
	attrs := &types.KeyAttributes{
		CN:        req.KeyId,
		StoreType: types.StoreType(req.Backend),
		Hash:      parseHashAlgorithm(req.Hash),
		Partition: types.Partition(req.Partition),
	}

	// Set algorithm-specific attributes and determine KeyType
	switch {
	case types.AlgorithmRSA.Equals(req.KeyType):
		keySize := int(req.KeySize)
		if keySize == 0 {
			keySize = types.RSAKeySize2048 // Default
		}
		attrs.KeyType = types.KeyTypeSigning // RSA is an asymmetric signing algorithm
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: keySize,
		}
	case types.AlgorithmECDSA.Equals(req.KeyType):
		curve := req.Curve
		if curve == "" {
			curve = string(types.CurveP256) // Default
		}
		attrs.KeyType = types.KeyTypeSigning // ECDSA is an asymmetric signing algorithm
		attrs.KeyAlgorithm = x509.ECDSA
		parsedCurve, curveErr := types.ParseCurve(curve)
		if curveErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid curve: %v", curveErr)
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: parsedCurve,
		}
	case types.AlgorithmEd25519.Equals(req.KeyType):
		attrs.KeyType = types.KeyTypeSigning // Ed25519 is an asymmetric signing algorithm
		attrs.KeyAlgorithm = x509.Ed25519
	case types.AlgorithmSymmetric.Equals(req.KeyType) || types.AlgorithmAES.Equals(req.KeyType):
		// For symmetric keys, set algorithm based on key size
		attrs.KeyType = types.KeyTypeEncryption // Symmetric keys are encryption keys
		switch req.KeySize {
		case 128:
			attrs.SymmetricAlgorithm = types.SymmetricAES128GCM
		case 192:
			attrs.SymmetricAlgorithm = types.SymmetricAES192GCM
		case 256:
			attrs.SymmetricAlgorithm = types.SymmetricAES256GCM
		default:
			return nil, status.Errorf(codes.InvalidArgument, "invalid key size for AES keys: %d (must be 128, 192, or 256)", req.KeySize)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported key type: %s", req.KeyType)
	}

	// Create wrapped key material
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  req.WrappedKey,
		Algorithm:   backend.WrappingAlgorithm(req.Algorithm),
		ImportToken: req.ImportToken,
		Metadata:    req.Metadata,
	}

	// Import the key
	err = importExportBackend.ImportKey(attrs, wrapped)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to import key: %v", err)
	}

	return &pb.ImportKeyResponse{
		Success: true,
		Message: fmt.Sprintf("key %s imported successfully into backend %s", req.KeyId, req.Backend),
		KeyId:   req.KeyId,
	}, nil
}

// ExportKey exports a key in wrapped form for secure transport
func (s *Service) ExportKey(ctx context.Context, req *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if req.WrappingAlgorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "wrapping_algorithm is required")
	}

	if err := s.authorize(ctx, "keys", "read", req.KeyId); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Check if backend supports import/export
	backendImpl := ks.KeyProvider()
	importExportBackend, ok := backendImpl.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "backend %s does not support import/export operations", req.Backend)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.WrappingAlgorithm)

	// Export the key
	wrapped, err := importExportBackend.ExportKey(attrs, wrappingAlg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to export key: %v", err)
	}

	return &pb.ExportKeyResponse{
		WrappedKey:  wrapped.WrappedKey,
		Algorithm:   string(wrapped.Algorithm),
		ImportToken: wrapped.ImportToken,
		Metadata:    wrapped.Metadata,
	}, nil
}

// ExportKeyMaterial exports raw symmetric key bytes for extractable keys.
//
// SECURITY WARNING: This method returns plaintext key material without any
// cryptographic protection. Use with extreme caution:
//   - ONLY works for symmetric keys (AES, ChaCha20, etc.)
//   - Key must have been created with exportable=true
//   - Asymmetric keys (RSA, ECDSA, Ed25519) cannot be exported via this method
//   - For secure key transport between backends, use ExportKey instead
func (s *Service) ExportKeyMaterial(ctx context.Context, req *pb.ExportKeyMaterialRequest) (*pb.ExportKeyMaterialResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	if err := s.authorize(ctx, "keys", "read", req.KeyId); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Check if backend supports import/export
	backendImpl := ks.KeyProvider()
	importExportBackend, ok := backendImpl.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "backend %s does not support import/export operations", req.Backend)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Export the raw key material
	keyMaterial, err := importExportBackend.ExportKeyMaterial(attrs)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "failed to export key material: %v", err)
	}

	// Determine key type and size from attributes
	keyType := string(attrs.SymmetricAlgorithm)
	keySize := int32(attrs.SymmetricAlgorithm.KeySize()) // Returns key size in bytes, convert to bits

	return &pb.ExportKeyMaterialResponse{
		KeyMaterial: keyMaterial,
		KeyType:     keyType,
		KeySize:     keySize * 8, // Convert bytes to bits
	}, nil
}

// WrapKeyByID wraps a target key using a wrapping key, both identified by key IDs.
// This enables PKCS#11 C_WrapKey functionality with server-side keys.
// The target key must be extractable (exportable=true for symmetric keys).
//
// The wrapping process:
//  1. Get the target key's backend and verify it supports import/export
//  2. Export the target key's raw material (symmetric keys only, must be exportable)
//  3. Get the wrapping key's backend and verify it supports import/export
//  4. Get import parameters from the wrapping key's backend
//  5. Wrap the target key material using the wrapping key
//  6. Return the wrapped key material
func (s *Service) WrapKeyByID(ctx context.Context, req *pb.WrapKeyByIDRequest) (*pb.WrapKeyByIDResponse, error) {
	// Validate required fields
	if req.WrappingKeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "wrapping_key_id is required")
	}
	if req.WrappingKeyBackend == "" {
		return nil, status.Error(codes.InvalidArgument, "wrapping_key_backend is required")
	}
	if req.TargetKeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "target_key_id is required")
	}
	if req.TargetKeyBackend == "" {
		return nil, status.Error(codes.InvalidArgument, "target_key_backend is required")
	}
	if req.Algorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "algorithm is required")
	}

	if err := s.authorize(ctx, "keys", "read", req.TargetKeyId); err != nil {
		return nil, err
	}

	// Get the target key's keystore
	targetKs, err := xkms.GetBackend(req.TargetKeyBackend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "target key backend not found: %v", err)
	}

	// Check if target backend supports import/export
	targetBackendImpl := targetKs.KeyProvider()
	targetImportExport, ok := targetBackendImpl.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "target backend %s does not support import/export operations", req.TargetKeyBackend)
	}

	// Find target key attributes
	targetAttrs, err := s.findKeyAttributes(targetKs, req.TargetKeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "target key not found: %v", err)
	}

	// Export the target key's raw material
	// This only works for symmetric keys with Exportable=true
	keyMaterial, err := targetImportExport.ExportKeyMaterial(targetAttrs)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "failed to export target key material: %v", err)
	}

	// Get the wrapping key's keystore
	wrappingKs, err := xkms.GetBackend(req.WrappingKeyBackend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "wrapping key backend not found: %v", err)
	}

	// Check if wrapping backend supports import/export
	wrappingBackendImpl := wrappingKs.KeyProvider()
	wrappingImportExport, ok := wrappingBackendImpl.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "wrapping key backend %s does not support import/export operations", req.WrappingKeyBackend)
	}

	// Find wrapping key attributes
	wrappingAttrs, err := s.findKeyAttributes(wrappingKs, req.WrappingKeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "wrapping key not found: %v", err)
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.Algorithm)

	// Get import parameters from the wrapping key's backend
	// This provides the wrapping public key that will be used
	params, err := wrappingImportExport.GetImportParameters(wrappingAttrs, wrappingAlg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get import parameters: %v", err)
	}

	// Wrap the target key material using the wrapping key
	wrapped, err := wrappingImportExport.WrapKey(keyMaterial, params)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to wrap key: %v", err)
	}

	return &pb.WrapKeyByIDResponse{
		WrappedKey: wrapped.WrappedKey,
		Algorithm:  string(wrapped.Algorithm),
	}, nil
}

// UnwrapKeyByID unwraps key material and imports it as a new key.
// This enables PKCS#11 C_UnwrapKey functionality with server-side keys.
//
// The unwrapping process:
//  1. Get the unwrapping key's backend and verify it supports import/export
//  2. Find the unwrapping key's attributes
//  3. Unwrap the key material using the unwrapping key
//  4. Create the target key attributes from the request template
//  5. Import the unwrapped key material as a new key
//  6. Return the new key's ID and backend
func (s *Service) UnwrapKeyByID(ctx context.Context, req *pb.UnwrapKeyByIDRequest) (*pb.UnwrapKeyByIDResponse, error) {
	// Validate required fields
	if len(req.WrappedKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "wrapped_key is required")
	}
	if req.UnwrappingKeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "unwrapping_key_id is required")
	}
	if req.UnwrappingKeyBackend == "" {
		return nil, status.Error(codes.InvalidArgument, "unwrapping_key_backend is required")
	}
	if req.Algorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "algorithm is required")
	}
	if req.TargetKeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "target_key_id is required")
	}
	if req.TargetKeyBackend == "" {
		return nil, status.Error(codes.InvalidArgument, "target_key_backend is required")
	}

	if err := s.authorize(ctx, "keys", "write", req.TargetKeyId); err != nil {
		return nil, err
	}

	// Get the unwrapping key's keystore
	unwrappingKs, err := xkms.GetBackend(req.UnwrappingKeyBackend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "unwrapping key backend not found: %v", err)
	}

	// Check if unwrapping backend supports import/export
	unwrappingBackendImpl := unwrappingKs.KeyProvider()
	unwrappingImportExport, ok := unwrappingBackendImpl.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "unwrapping key backend %s does not support import/export operations", req.UnwrappingKeyBackend)
	}

	// Find unwrapping key attributes
	unwrappingAttrs, err := s.findKeyAttributes(unwrappingKs, req.UnwrappingKeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "unwrapping key not found: %v", err)
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.Algorithm)

	// Get import parameters to match the wrapping operation
	params, err := unwrappingImportExport.GetImportParameters(unwrappingAttrs, wrappingAlg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get import parameters: %v", err)
	}

	// Create wrapped key material structure
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: req.WrappedKey,
		Algorithm:  wrappingAlg,
	}

	// Unwrap the key material
	keyMaterial, err := unwrappingImportExport.UnwrapKey(wrapped, params)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unwrap key: %v", err)
	}

	// Get the target key's backend for importing
	targetKs, err := xkms.GetBackend(req.TargetKeyBackend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "target key backend not found: %v", err)
	}

	// Check if target backend supports import/export
	targetBackendImpl := targetKs.KeyProvider()
	targetImportExport, ok := targetBackendImpl.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "target key backend %s does not support import/export operations", req.TargetKeyBackend)
	}

	// Build target key attributes from the request template
	targetAttrs := &types.KeyAttributes{
		CN:         req.TargetKeyId,
		StoreType:  types.StoreType(req.TargetKeyBackend),
		Partition:  types.Partition(req.TargetPartition),
		Exportable: req.TargetExportable,
	}

	// Set algorithm-specific attributes based on key type
	keyType := req.TargetKeyType
	if keyType == "" {
		// Default to symmetric if key size is provided
		if req.TargetKeySize > 0 {
			keyType = "symmetric"
		} else {
			return nil, status.Error(codes.InvalidArgument, "target_key_type is required")
		}
	}

	switch {
	case types.AlgorithmRSA.Equals(keyType):
		keySize := int(req.TargetKeySize)
		if keySize == 0 {
			keySize = types.RSAKeySize2048
		}
		targetAttrs.KeyType = types.KeyTypeSigning
		targetAttrs.KeyAlgorithm = x509.RSA
		targetAttrs.RSAAttributes = &types.RSAAttributes{
			KeySize: keySize,
		}
	case types.AlgorithmECDSA.Equals(keyType):
		curve := req.TargetCurve
		if curve == "" {
			curve = string(types.CurveP256)
		}
		targetAttrs.KeyType = types.KeyTypeSigning
		targetAttrs.KeyAlgorithm = x509.ECDSA
		parsedCurve, curveErr := types.ParseCurve(curve)
		if curveErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid curve: %v", curveErr)
		}
		targetAttrs.ECCAttributes = &types.ECCAttributes{
			Curve: parsedCurve,
		}
	case types.AlgorithmEd25519.Equals(keyType):
		targetAttrs.KeyType = types.KeyTypeSigning
		targetAttrs.KeyAlgorithm = x509.Ed25519
	case types.AlgorithmSymmetric.Equals(keyType) || types.AlgorithmAES.Equals(keyType):
		targetAttrs.KeyType = types.KeyTypeSecret
		switch req.TargetKeySize {
		case 128:
			targetAttrs.SymmetricAlgorithm = types.SymmetricAES128GCM
		case 192:
			targetAttrs.SymmetricAlgorithm = types.SymmetricAES192GCM
		case 256, 0:
			// Default to AES-256-GCM if no size specified
			targetAttrs.SymmetricAlgorithm = types.SymmetricAES256GCM
		default:
			return nil, status.Errorf(codes.InvalidArgument, "invalid key size for symmetric key: %d (must be 128, 192, or 256)", req.TargetKeySize)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported target key type: %s", keyType)
	}

	// Create wrapped key material for import (the key is already unwrapped, but we need
	// to pass it through the import mechanism)
	// For direct import of unwrapped material, we create a "plaintext" wrapped structure
	importWrapped := &backend.WrappedKeyMaterial{
		WrappedKey: keyMaterial,
		Algorithm:  backend.WrappingAlgorithm("PLAINTEXT"), // Special marker for unwrapped material
	}

	// Import the key into the target backend
	err = targetImportExport.ImportKey(targetAttrs, importWrapped)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to import unwrapped key: %v", err)
	}

	return &pb.UnwrapKeyByIDResponse{
		KeyId:   req.TargetKeyId,
		Backend: req.TargetKeyBackend,
		Success: true,
		Message: fmt.Sprintf("key %s successfully unwrapped and imported into backend %s", req.TargetKeyId, req.TargetKeyBackend),
	}, nil
}

// CopyKey copies a key from one backend to another using export/import
func (s *Service) CopyKey(ctx context.Context, req *pb.CopyKeyRequest) (*pb.CopyKeyResponse, error) {
	if req.SourceBackend == "" {
		return nil, status.Error(codes.InvalidArgument, "source_backend is required")
	}
	if req.SourceKeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "source_key_id is required")
	}
	if req.DestBackend == "" {
		return nil, status.Error(codes.InvalidArgument, "dest_backend is required")
	}
	if req.DestKeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "dest_key_id is required")
	}
	if req.WrappingAlgorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "wrapping_algorithm is required")
	}

	if err := s.authorize(ctx, "keys", "write", req.DestKeyId); err != nil {
		return nil, err
	}

	// Get source keystore
	sourceKs, err := xkms.GetBackend(req.SourceBackend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "source backend not found: %v", err)
	}

	// Get destination keystore
	destKs, err := xkms.GetBackend(req.DestBackend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "destination backend not found: %v", err)
	}

	// Verify source backend supports export
	sourceBackend := sourceKs.KeyProvider()
	sourceImportExport, ok := sourceBackend.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "source backend %s does not support export operations", req.SourceBackend)
	}

	// Verify destination backend supports import
	destBackend := destKs.KeyProvider()
	destImportExport, ok := destBackend.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "destination backend %s does not support import operations", req.DestBackend)
	}

	// Find source key attributes
	sourceAttrs, err := s.findKeyAttributes(sourceKs, req.SourceKeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "source key not found: %v", err)
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.WrappingAlgorithm)

	// Step 1: Export the key from source backend
	wrapped, err := sourceImportExport.ExportKey(sourceAttrs, wrappingAlg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to export key from source backend: %v", err)
	}

	// Step 2: Create destination key attributes (copy from source but with new ID)
	destAttrs := &types.KeyAttributes{
		CN:                 sourceAttrs.CN,
		KeyType:            sourceAttrs.KeyType,
		KeyAlgorithm:       sourceAttrs.KeyAlgorithm,
		Hash:               sourceAttrs.Hash,
		StoreType:          types.StoreType(req.DestBackend),
		Partition:          sourceAttrs.Partition,
		RSAAttributes:      sourceAttrs.RSAAttributes,
		ECCAttributes:      sourceAttrs.ECCAttributes,
		SymmetricAlgorithm: sourceAttrs.SymmetricAlgorithm,
	}
	// Update CN to destination key ID
	destAttrs.CN = req.DestKeyId

	// Step 3: Import the key into destination backend
	err = destImportExport.ImportKey(destAttrs, wrapped)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to import key into destination backend: %v", err)
	}

	return &pb.CopyKeyResponse{
		Success:   true,
		Message:   fmt.Sprintf("key %s copied from %s to %s as %s", req.SourceKeyId, req.SourceBackend, req.DestBackend, req.DestKeyId),
		DestKeyId: req.DestKeyId,
	}, nil
}

// EncryptAsym performs asymmetric encryption using RSA-OAEP
func (s *Service) EncryptAsym(ctx context.Context, req *pb.EncryptAsymRequest) (*pb.EncryptAsymResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.Plaintext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "plaintext is required")
	}

	if err := s.authorize(ctx, "keys", "use", req.KeyId); err != nil {
		return nil, err
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find the key
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Get the key to extract public key
	key, err := ks.GetKey(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get key: %v", err)
	}

	// Extract public key
	var publicKey crypto.PublicKey
	switch k := key.(type) {
	case crypto.Signer:
		publicKey = k.Public()
	default:
		return nil, status.Error(codes.InvalidArgument, "key does not support public key extraction")
	}

	// Determine hash algorithm for OAEP
	hashFunc := parseHashAlgorithmForOAEP(req.Hash)

	// Encrypt based on key type - only RSA supports asymmetric encryption
	rsaPub, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "asymmetric encryption only supported for RSA keys, got: %T", publicKey)
	}

	ciphertext, err := rsa.EncryptOAEP(
		hashFunc.New(),
		rand.Reader,
		rsaPub,
		req.Plaintext,
		nil, // no label
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to encrypt data: %v", err)
	}

	return &pb.EncryptAsymResponse{
		Ciphertext: ciphertext,
	}, nil
}

// parseHashAlgorithmForOAEP parses hash algorithm string for OAEP encryption
func parseHashAlgorithmForOAEP(hash string) crypto.Hash {
	hashAlg := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(hash, "SHA-"), "sha-"))
	switch hashAlg {
	case "256", "sha256", "":
		return crypto.SHA256
	case "384", "sha384":
		return crypto.SHA384
	case "512", "sha512":
		return crypto.SHA512
	case "1", "sha1":
		return crypto.SHA1
	default:
		return crypto.SHA256 // default to SHA256
	}
}

// Seal encrypts data using the backend's sealing mechanism
func (s *Service) Seal(ctx context.Context, req *pb.SealRequest) (*pb.SealResponse, error) {
	// Validate required parameters
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.Data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data is required")
	}

	if err := s.authorize(ctx, "seal", "use", ""); err != nil {
		return nil, err
	}

	// Build seal options
	opts := &types.SealOptions{
		AAD: req.Aad,
	}

	// If key ID is provided, look up the key to get its actual attributes
	if req.KeyId != "" {
		// Get the backend to look up the key
		ks, err := xkms.GetBackend(req.Backend)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
		}

		// Find the key by CN to get its full attributes
		keyAttrs, err := ks.ListKeys()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to list keys: %v", err)
		}

		var targetAttr *types.KeyAttributes
		for _, attr := range keyAttrs {
			if attr.CN == req.KeyId {
				targetAttr = attr
				break
			}
		}

		if targetAttr == nil {
			return nil, status.Errorf(codes.NotFound, "key not found: %s", req.KeyId)
		}

		opts.KeyAttributes = targetAttr
	}

	// Call xkms service
	sealed, err := xkms.SealWithBackend(ctx, req.Backend, req.Data, opts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to seal data: %v", err)
	}

	// Convert metadata from map[string][]byte to map[string]string (base64 encoded)
	metadata := make(map[string]string, len(sealed.Metadata))
	for k, v := range sealed.Metadata {
		metadata[k] = base64.StdEncoding.EncodeToString(v)
	}

	return &pb.SealResponse{
		Backend:    string(sealed.Backend),
		Ciphertext: sealed.Ciphertext,
		Nonce:      sealed.Nonce,
		Tag:        sealed.Tag,
		Metadata:   metadata,
	}, nil
}

// Unseal decrypts previously sealed data
func (s *Service) Unseal(ctx context.Context, req *pb.UnsealRequest) (*pb.UnsealResponse, error) {
	// Validate required parameters
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.Ciphertext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ciphertext is required")
	}

	if err := s.authorize(ctx, "seal", "use", ""); err != nil {
		return nil, err
	}

	// Get backend to determine backend type for sealed data
	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Construct SealedData from request
	sealed := &types.SealedData{
		Backend:    ks.KeyProvider().Type(),
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Tag:        req.Tag,
	}

	// Build unseal options
	opts := &types.UnsealOptions{
		AAD: req.Aad,
	}

	// If key ID is provided, look up the key to get its actual attributes
	if req.KeyId != "" {
		// Find the key by CN to get its full attributes
		keyAttrs, err := ks.ListKeys()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to list keys: %v", err)
		}

		var targetAttr *types.KeyAttributes
		for _, attr := range keyAttrs {
			if attr.CN == req.KeyId {
				targetAttr = attr
				break
			}
		}

		if targetAttr == nil {
			return nil, status.Errorf(codes.NotFound, "key not found: %s", req.KeyId)
		}

		opts.KeyAttributes = targetAttr
		sealed.KeyID = targetAttr.ID() // Use storage format to match what Seal stores
	}

	// Call xkms service
	plaintext, err := xkms.UnsealWithBackend(ctx, req.Backend, sealed, opts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unseal data: %v", err)
	}

	return &pb.UnsealResponse{
		Plaintext: plaintext,
	}, nil
}

// CanSeal checks if a backend supports sealing operations
func (s *Service) CanSeal(ctx context.Context, req *pb.CanSealRequest) (*pb.CanSealResponse, error) {
	if err := s.authorize(ctx, "seal", "read", ""); err != nil {
		return nil, err
	}

	var canSeal bool

	// If backend is specified, check that specific backend
	// Otherwise check the default backend
	if req.Backend != "" {
		canSeal = xkms.CanSeal(req.Backend)
	} else {
		canSeal = xkms.CanSeal()
	}

	return &pb.CanSealResponse{
		CanSeal: canSeal,
	}, nil
}

// AttestKey generates a key attestation statement proving hardware backing.
func (s *Service) AttestKey(ctx context.Context, req *pb.AttestKeyRequest) (*pb.AttestKeyResponse, error) {
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	if err := s.authorize(ctx, "keys", "read", req.KeyId); err != nil {
		return nil, err
	}

	// Get the backend
	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Type-assert to AttestingBackend
	ab, ok := ks.KeyProvider().(types.AttestingKeyProvider)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "backend %s does not support attestation", req.Backend)
	}

	// Find the key attributes by CN
	keyAttrs, err := ks.ListKeys()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list keys: %v", err)
	}

	var targetAttr *types.KeyAttributes
	for _, attr := range keyAttrs {
		if attr.CN == req.KeyId {
			targetAttr = attr
			break
		}
	}
	if targetAttr == nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %s", req.KeyId)
	}

	// Call AttestKey on the backend
	result, err := ab.AttestKey(targetAttr, req.Nonce)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "attestation failed: %v", err)
	}

	// Type-assert to *attestation.AttestationStatement
	stmt, ok := result.(*attestation.AttestationStatement)
	if !ok {
		return nil, status.Error(codes.Internal, "unexpected attestation result type")
	}

	// Convert certificate chain to DER-encoded [][]byte
	var certChain [][]byte
	for _, cert := range stmt.CertificateChain {
		certChain = append(certChain, cert.Raw)
	}

	return &pb.AttestKeyResponse{
		Format:             stmt.Format,
		CertificateChain:   certChain,
		AttestationData:    stmt.AttestationData,
		Signature:          stmt.Signature,
		SignatureAlgorithm: stmt.SignatureAlgorithm.String(),
		Nonce:              stmt.Nonce,
		Backend:            stmt.Backend,
	}, nil
}

// kdfAdapterFactory maps algorithm names to KDF adapter constructors
var kdfAdapterFactory = map[string]func() kdf.KDFAdapter{
	"hkdf":                      func() kdf.KDFAdapter { return kdf.NewHKDFAdapter() },
	"sp800-108-counter":         func() kdf.KDFAdapter { return kdf.NewSP800108CounterAdapter() },
	"sp800-108-feedback":        func() kdf.KDFAdapter { return kdf.NewSP800108FeedbackAdapter() },
	"sp800-108-double-pipeline": func() kdf.KDFAdapter { return kdf.NewSP800108DoublePipelineAdapter() },
}

// DeriveKey performs key derivation using the specified algorithm
func (s *Service) DeriveKey(ctx context.Context, req *pb.DeriveKeyRequest) (*pb.DeriveKeyResponse, error) {
	// Validate algorithm
	if req.Algorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "algorithm is required")
	}

	// Normalize algorithm name to lowercase for lookup
	algorithmKey := strings.ToLower(req.Algorithm)

	// Get adapter factory using map-based dispatch (O(1) lookup)
	factory, ok := kdfAdapterFactory[algorithmKey]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported KDF algorithm: %s", req.Algorithm)
	}

	if err := s.authorize(ctx, "keys", "use", req.KeyId); err != nil {
		return nil, err
	}

	// Create the adapter
	adapter := factory()

	// Validate key length
	keyLength := int(req.KeyLength)
	if keyLength <= 0 {
		keyLength = 32 // Default to 32 bytes
	}

	// Parse hash algorithm
	hashAlg := parseHashAlgorithm(req.Hash)

	// Build KDF parameters based on algorithm
	params := &kdf.KDFParams{
		KeyLength: keyLength,
		Hash:      hashAlg,
		Salt:      req.Salt,
		Info:      req.Info,
	}

	// Set algorithm-specific parameters
	switch algorithmKey {
	case "hkdf":
		params.Algorithm = kdf.AlgorithmHKDF
	case "sp800-108-counter":
		params.Algorithm = kdf.AlgorithmSP800108Counter
		params.Label = req.Label
		params.Context = req.Context
		// CounterLength defaults to 32 bits in the adapter
	case "sp800-108-feedback":
		params.Algorithm = kdf.AlgorithmSP800108Feedback
		params.Label = req.Label
		params.Context = req.Context
		// IV can be passed via Salt field for feedback mode
		if len(req.Salt) > 0 {
			params.IV = req.Salt
		}
	case "sp800-108-double-pipeline":
		params.Algorithm = kdf.AlgorithmSP800108DoublePipeline
		params.Label = req.Label
		params.Context = req.Context
	}

	// Determine input key material
	var ikm []byte
	if len(req.InputKeyMaterial) > 0 {
		ikm = req.InputKeyMaterial
	} else if req.KeyId != "" && req.Backend != "" {
		// If key_id is specified, derive from an existing key's material
		// This requires the key to be exportable or accessible
		return nil, status.Error(codes.Unimplemented, "key-based derivation (ECDH, etc.) is not yet supported - use input_key_material instead")
	} else {
		return nil, status.Error(codes.InvalidArgument, "either input_key_material or (backend + key_id) is required")
	}

	// Derive the key
	derivedKey, err := adapter.DeriveKey(ikm, params)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "key derivation failed: %v", err)
	}

	// Handle StoreResult option
	if req.StoreResult {
		// Storing derived keys requires creating a symmetric key in the backend
		// This is a more complex operation that requires backend support
		return nil, status.Error(codes.Unimplemented, "storing derived keys is not yet supported - set store_result to false")
	}

	return &pb.DeriveKeyResponse{
		DerivedKey: derivedKey,
		Algorithm:  req.Algorithm,
		KeyLength:  int32(len(derivedKey)), // #nosec G115 - key length fits in int32
	}, nil
}

// DeriveKeyECDH performs ECDH key agreement and derives a symmetric key.
// This operation combines ECDH shared secret computation with a KDF to produce
// a derived key suitable for symmetric encryption.
func (s *Service) DeriveKeyECDH(ctx context.Context, req *pb.DeriveKeyECDHRequest) (*pb.DeriveKeyECDHResponse, error) {
	// Validate required parameters
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.PeerPublicKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "peer_public_key is required")
	}

	if err := s.authorize(ctx, "keys", "use", req.KeyId); err != nil {
		return nil, err
	}

	// Get the backend
	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Check if backend supports key agreement
	backendImpl := ks.KeyProvider()
	keyAgreementBackend, ok := backendImpl.(types.KeyAgreementProvider)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "backend %s does not support ECDH key agreement", req.Backend)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Validate that the key is an ECDSA key
	if attrs.KeyAlgorithm != x509.ECDSA {
		return nil, status.Errorf(codes.InvalidArgument, "key must be an ECDSA key for ECDH, got: %s", attrs.KeyAlgorithm.String())
	}

	// Build KDF parameters
	kdfParams := &types.KDFParams{
		Algorithm: parseKDFAlgorithm(req.KdfAlgorithm),
		Hash:      parseKDFHash(req.KdfHash),
		Salt:      req.KdfSalt,
		Info:      req.KdfInfo,
		KeyLength: int(req.KeyLength),
	}

	// Set default key length if not specified
	if kdfParams.KeyLength <= 0 {
		kdfParams.KeyLength = 32 // Default to 32 bytes (256 bits) for AES-256
	}

	// Perform ECDH key derivation
	derivedKey, err := keyAgreementBackend.DeriveKeyECDH(ctx, attrs, req.PeerPublicKey, kdfParams)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ECDH key derivation failed: %v", err)
	}

	return &pb.DeriveKeyECDHResponse{
		DerivedKey: derivedKey,
	}, nil
}

// Helper functions

func (s *Service) findKeyAttributes(ks xkms.Backend, keyID string) (*types.KeyAttributes, error) {
	attrs, err := ks.ListKeys()
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		if attr.CN == keyID {
			return attr, nil
		}
	}

	return nil, fmt.Errorf("key %s not found", keyID)
}

// getAlgorithmString returns the algorithm name as a string, handling both
// symmetric and asymmetric key types.
func getAlgorithmString(attrs *types.KeyAttributes) string {
	if attrs.SymmetricAlgorithm != "" {
		return string(attrs.SymmetricAlgorithm)
	}
	if attrs.KeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		return attrs.KeyAlgorithm.String()
	}
	return ""
}

func parseHashAlgorithm(hash string) crypto.Hash {
	if hash == "" {
		return crypto.SHA256 // Default
	}
	h := types.ParseHash(hash)
	if h == 0 {
		return crypto.SHA256 // Default if unknown
	}
	return h
}

// parseKDFAlgorithm parses the KDF algorithm string to types.KDFAlgorithm
func parseKDFAlgorithm(alg string) types.KDFAlgorithm {
	if alg == "" {
		return types.KDFAlgorithmHKDF // Default
	}
	switch strings.ToUpper(alg) {
	case "HKDF":
		return types.KDFAlgorithmHKDF
	case "SP800-108-COUNTER":
		return types.KDFAlgorithmSP800108Counter
	case "SP800-108-FEEDBACK":
		return types.KDFAlgorithmSP800108Feedback
	case "SP800-56A":
		return types.KDFAlgorithmSP80056A
	case "X963":
		return types.KDFAlgorithmX963
	default:
		return types.KDFAlgorithmHKDF // Default to HKDF for unknown algorithms
	}
}

// parseKDFHash parses the hash algorithm string for KDF
func parseKDFHash(hash string) string {
	if hash == "" {
		return "SHA-256" // Default
	}
	// Normalize the hash algorithm string
	normalized := strings.ToUpper(strings.ReplaceAll(hash, "-", ""))
	switch normalized {
	case "SHA256":
		return "SHA-256"
	case "SHA384":
		return "SHA-384"
	case "SHA512":
		return "SHA-512"
	case "SHA3256":
		return "SHA3-256"
	case "SHA3384":
		return "SHA3-384"
	case "SHA3512":
		return "SHA3-512"
	default:
		return hash // Return as-is for validation by KDFParams.Validate()
	}
}

func extractPublicKeyPEM(privKey crypto.PrivateKey) (string, error) {
	var pubKey crypto.PublicKey

	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	case crypto.Signer:
		// Handle OpaqueKey and other Signer implementations
		pubKey = k.Public()
	default:
		return "", fmt.Errorf("unsupported key type")
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

func parseCertFromPEM(certPem string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPem))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM type: %s (expected CERTIFICATE)", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func encodeCertToPEM(cert *x509.Certificate) string {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(pemBlock))
}

func encodePrivateKeyToPEM(privKey crypto.PrivateKey) (string, error) {
	var pemType string
	var keyBytes []byte
	var err error

	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pemType = "RSA PRIVATE KEY"
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		pemType = "EC PRIVATE KEY"
		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return "", fmt.Errorf("failed to marshal ECDSA key: %v", err)
		}
	case ed25519.PrivateKey:
		pemType = "PRIVATE KEY"
		keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return "", fmt.Errorf("failed to marshal Ed25519 key: %v", err)
		}
	default:
		return "", fmt.Errorf("unsupported private key type: %T", privKey)
	}

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}
