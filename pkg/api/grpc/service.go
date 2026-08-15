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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
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
	// ErrAccessDenied is returned when the authorizer denies access to the
	// requested resource without supplying a specific reason.
	ErrAccessDenied = errors.New("grpc: access denied")
)

// Service implements the KeystoreService gRPC interface
type Service struct {
	pb.UnimplementedKeystoreServiceServer
	authorizer  *auth.Authorizer
	auditLogger audit.Logger
	xkmsService *xkms.XKMSService
	sshClient   sdkssh.Client

	// localTrust marks this Service as constructed for a local IPC listener
	// (the Unix domain socket) rather than a network listener. It exists to
	// resolve the ambiguity of a nil authorizer for privileged RPCs: only a
	// Service marked local-trusted may treat a nil authorizer as "allow"
	// rather than as a misconfigured network listener.
	localTrust bool
}

// ServiceOption configures optional Service behavior at construction time.
type ServiceOption func(*Service)

// WithLocalTrust marks the Service as serving a local, filesystem-trust-boundary
// listener (the Unix domain socket gRPC server) rather than a network listener.
// The Unix transport's trust boundary is the socket's file mode and directory
// permissions, not RBAC, so it constructs its Service with both a nil
// authorizer AND WithLocalTrust(). Without this marker a nil authorizer is
// ambiguous: it could mean "this deployment does not enable RBAC" (the
// long-standing allow-all behavior every other RPC relies on) or "this network
// server forgot to wire an authorizer" (a misconfiguration). Privileged RPCs
// resolve that ambiguity explicitly instead of defaulting to either
// interpretation: only a Service marked local-trusted is allowed to treat a
// nil authorizer as "allow".
func WithLocalTrust() ServiceOption {
	return func(s *Service) {
		s.localTrust = true
	}
}

// SetSSHClient wires the SSH SDK client used by the SSH RPC handlers. When
// nil (the default), the SSH RPCs return codes.Unavailable. The server
// composition constructs the client with a backend provider so remote SSH
// key generation honors the server's configured backends.
func (s *Service) SetSSHClient(client sdkssh.Client) {
	s.sshClient = client
}

// NewService creates a new gRPC service.
// xkmsService is the initialized XKMSService instance to delegate operations to.
// A nil xkmsService causes service-layer handlers to return codes.Unavailable.
// If authorizer or auditLogger are nil, no-op implementations are used.
// opts applies optional construction-time configuration; see WithLocalTrust.
func NewService(authorizer *auth.Authorizer, auditLogger audit.Logger, xkmsService *xkms.XKMSService, opts ...ServiceOption) *Service {
	if authorizer == nil {
		// A nil authorizer disables authorization (allow all), matching the
		// behavior of an Authorizer constructed with a nil RBAC client.
		authorizer = auth.NewAuthorizer(nil)
	}
	if auditLogger == nil {
		auditLogger = &audit.NoOpLogger{}
	}
	s := &Service{
		authorizer:  authorizer,
		auditLogger: auditLogger,
		xkmsService: xkmsService,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// callerTenantID returns the tenant the authenticated caller belongs to, or
// the empty string for a system-level or unauthenticated request.
//
// Every key operation must carry this through to the service layer: the service
// resolves a tenant-scoped view of the backend from it, and a key ID is only
// unique within a tenant. Omitting it runs the operation against the unscoped
// backend, where a lookup by common name can reach another tenant's key.
func callerTenantID(ctx context.Context) string {
	if identity := auth.GetIdentity(ctx); identity != nil {
		return identity.TenantID
	}
	return ""
}

// authorize performs an authorization check for the given resource, action,
// and resource ID. It extracts the caller's identity from the context,
// delegates the decision to the qrdb-backed Authorizer, and logs the audit
// event. Returns nil if the action is allowed, or a gRPC status error on
// deny (PermissionDenied) or missing identity (Unauthenticated).
func (s *Service) authorize(ctx context.Context, resource, action, resourceID string) error {
	identity := auth.GetIdentity(ctx)

	subject := ""
	role := ""
	if identity != nil {
		subject = identity.Subject
		role = extractRoleFromIdentity(identity)
	}

	err := s.authorizer.Authorize(ctx, identity, resource, action)

	outcome := audit.OutcomeAllow
	if err != nil {
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
		if errors.Is(err, auth.ErrUnauthenticated) {
			return status.Error(codes.Unauthenticated, err.Error())
		}
		reason := err.Error()
		if reason == "" {
			reason = ErrAccessDenied.Error()
		}
		return status.Error(codes.PermissionDenied, reason)
	}

	return nil
}

// extractRoleFromIdentity returns the first role on an identity, or "" if none.
// It is a thin wrapper over auth.FirstRole used so audit / authorization-request
// builders in this package can stay symmetric with the REST/QUIC analogues.
func extractRoleFromIdentity(identity *auth.Identity) string {
	return auth.FirstRole(identity)
}

// Health returns the health status of the service
func (s *Service) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{
		Status:  "healthy",
		Version: xkms.Version(),
	}, nil
}

// Algorithms reports the cryptographic algorithms this build supports and
// which backends provide each one. It mirrors the REST discovery endpoint,
// which is served without authentication: the answer is derived from
// compiled-in capability and reads no tenant or key state. Health is the
// existing precedent for an ungated RPC on this service.
func (s *Service) Algorithms(ctx context.Context, _ *pb.AlgorithmsRequest) (*pb.AlgorithmsResponse, error) {
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not configured")
	}

	resp, err := s.xkmsService.Algorithms(ctx)
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.AlgorithmsResponse{
		Signing:          algorithmInfosToProto(resp.Signing),
		KeyEncapsulation: algorithmInfosToProto(resp.KeyEncapsulation),
	}, nil
}

// algorithmInfosToProto converts discovery entries to their proto form.
func algorithmInfosToProto(in []types.AlgorithmInfo) []*pb.AlgorithmInfo {
	out := make([]*pb.AlgorithmInfo, len(in))
	for i := range in {
		sizes := make([]int32, len(in[i].KeySizes))
		for j, s := range in[i].KeySizes {
			sizes[j] = int32(s) // #nosec G115 - key sizes in bits fit in int32
		}
		out[i] = &pb.AlgorithmInfo{
			Algorithm:   in[i].Algorithm,
			Curves:      in[i].Curves,
			KeySizes:    sizes,
			Backends:    in[i].Backends,
			PostQuantum: in[i].PostQuantum,
		}
	}
	return out
}

// ListBackends returns all available backend providers.
func (s *Service) ListBackends(ctx context.Context, req *pb.ListBackendsRequest) (*pb.ListBackendsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceBackends, auth.ActionList, ""); err != nil {
		return nil, err
	}

	backendNames := s.backendNames()

	backends := make([]*pb.BackendInfo, 0, len(backendNames))
	for _, name := range backendNames {
		ks, err := s.lookupBackend(name)
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

	if err := s.authorize(ctx, auth.ResourceBackends, auth.ActionRead, req.Name); err != nil {
		return nil, err
	}

	ks, err := s.lookupBackend(req.Name)
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionCreate, req.KeyId); err != nil {
		return nil, err
	}

	// Get keystore
	ks, err := s.lookupBackend(req.Backend)
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

	hashAlg, hashErr := parseHashAlgorithm(req.Hash)
	if hashErr != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, hashErr)
	}

	// Build key attributes
	attrs := &types.KeyAttributes{
		CN:         req.KeyId,
		KeyType:    keyType,
		StoreType:  types.StoreType(req.Backend),
		Hash:       hashAlg,
		Partition:  types.Partition(req.Partition),
		Exportable: req.Exportable,
		Sensitive:  req.GetSensitive(),
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
		privKey, err = ks.GenerateRSA(ctx, attrs)

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
		privKey, err = ks.GenerateECDSA(ctx, attrs)

	case types.AlgorithmEd25519.Equals(algorithm):
		attrs.KeyAlgorithm = x509.Ed25519
		privKey, err = ks.GenerateEd25519(ctx, attrs)

	case symmetricAlgorithm(algorithm) != "":
		// Handle symmetric key generation
		symBackend, ok := ks.KeyProvider().(types.SymmetricKeyProvider)
		if !ok {
			return nil, status.Error(codes.Unimplemented, "backend does not support symmetric key generation")
		}

		symAlgorithm := symmetricAlgorithm(algorithm)

		// A bare "symmetric" or "secret" names no cipher, so the key size
		// selects one. A request that named its cipher outright keeps it: the
		// size is already implied by the name, and overriding it here would
		// generate a key the caller did not ask for.
		if types.AlgorithmSymmetric.Equals(algorithm) || types.KeyTypeStringSecret.Equals(algorithm) {
			switch int(req.KeySize) {
			case 128:
				symAlgorithm = types.SymmetricAES128GCM
			case 192:
				symAlgorithm = types.SymmetricAES192GCM
			case 256, 0:
				symAlgorithm = types.SymmetricAES256GCM
			default:
				return nil, status.Errorf(codes.InvalidArgument, "invalid key size for symmetric key: %d", req.KeySize)
			}
		}

		attrs.SymmetricAlgorithm = symAlgorithm
		attrs.KeyType = types.KeyTypeSecret // Symmetric keys use KeyTypeSecret

		_, err = symBackend.GenerateSymmetricKey(ctx, attrs)
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
		return nil, wrapWriteError(ctx, s.xkmsService, err, codes.Internal, "failed to generate key: %v", err)
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

// symmetricAlgorithm resolves an algorithm name to the symmetric cipher it
// selects, or "" when the name is not a symmetric one.
//
// It mirrors the service layer's own parsing (xkms's parseSymmetricAlgorithm,
// which is unexported): every spelling types.ParseAEADAlgorithm accepts, plus
// the two bare names that mean "a symmetric key, you pick the cipher". This
// transport used to match the literal "symmetric" and nothing else, so a
// request naming its cipher outright -- "aes-256-gcm", "chacha20-poly1305" --
// was refused as an unsupported algorithm even though the service accepts it.
func symmetricAlgorithm(algorithm string) types.SymmetricAlgorithm {
	if sym := types.ParseAEADAlgorithm(algorithm).ToSymmetricAlgorithm(); sym != "" {
		return sym
	}
	if types.AlgorithmSymmetric.Equals(algorithm) || types.KeyTypeStringSecret.Equals(algorithm) {
		return types.SymmetricAES256GCM
	}
	return ""
}

// ListKeys lists all keys in the specified backend
func (s *Service) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionList, ""); err != nil {
		return nil, err
	}

	ks, err := s.lookupBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	attrs, err := ks.ListKeys(ctx)
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
			KeyType:   attr.KeyType.String(),
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionGet, req.KeyId); err != nil {
		return nil, err
	}

	ks, err := s.lookupBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// List all keys and find the matching one
	attrs, err := ks.ListKeys(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list keys: %v", err)
	}

	for _, attr := range attrs {
		if attr.CN == req.KeyId {
			keyInfo := &pb.KeyInfo{
				KeyId:     attr.CN,
				Backend:   req.Backend,
				KeyType:   attr.KeyType.String(),
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
				signer, err := ks.Signer(ctx, attr)
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionSign, req.KeyId); err != nil {
		return nil, err
	}

	// The signing itself belongs to the service layer, which owns padding
	// selection (PKCS#1 v1.5 vs PSS), the "no hashing" contract for a
	// caller-supplied digest, and the per-algorithm rules for Ed25519 and
	// ECDSA. Reimplementing any of that here would let the transports drift
	// apart from each other and from the PKCS#11 module.
	resp, err := s.xkmsService.Sign(ctx, &transport.SignRequest{
		Backend:      req.Backend,
		KeyID:        req.KeyId,
		Data:         req.Data,
		Hash:         req.Hash,
		Padding:      req.Padding,
		SaltLength:   int(req.SaltLength),
		DataIsDigest: req.DataIsDigest,
		TenantID:     callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.SignResponse{Signature: resp.Signature}, nil
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionVerify, req.KeyId); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.Verify(ctx, &transport.VerifyRequest{
		Backend:      req.Backend,
		KeyID:        req.KeyId,
		Data:         req.Data,
		Signature:    req.Signature,
		Hash:         req.Hash,
		Padding:      req.Padding,
		SaltLength:   int(req.SaltLength),
		DataIsDigest: req.DataIsDigest,
		TenantID:     callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	// The message is synthesized here rather than forwarded: the verifier's
	// own error text ("crypto/rsa: verification error") tells a client nothing
	// actionable and leaks implementation detail.
	message := "signature is invalid"
	if resp.Valid {
		message = "signature is valid"
	}

	return &pb.VerifyResponse{Valid: resp.Valid, Message: message}, nil
}

// DeleteKey deletes a key from the backend
func (s *Service) DeleteKey(ctx context.Context, req *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDelete, req.KeyId); err != nil {
		return nil, err
	}

	ks, err := s.lookupBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ctx, ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Delete the key
	err = ks.DeleteKey(ctx, attrs)
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRotate, req.KeyId); err != nil {
		return nil, err
	}

	ks, err := s.lookupBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ctx, ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Rotate the key
	newKey, err := ks.RotateKey(ctx, attrs)
	if err != nil {
		return nil, wrapWriteError(ctx, s.xkmsService, err, codes.Internal, "failed to rotate key: %v", err)
	}

	// Extract public key PEM
	publicKeyPem, err := extractPublicKeyPEM(newKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to extract public key: %v", err)
	}

	return &pb.RotateKeyResponse{
		KeyId:        req.KeyId,
		Backend:      req.Backend,
		KeyType:      attrs.KeyType.String(),
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionEncrypt, req.KeyId); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.Encrypt(ctx, &transport.EncryptRequest{
		Backend:        req.Backend,
		KeyID:          req.KeyId,
		Plaintext:      req.Plaintext,
		AdditionalData: req.AdditionalData,
		Nonce:          req.Nonce,
		Mode:           req.Mode,
		IV:             req.Iv,
		TagSize:        int(req.TagSize),
		TenantID:       callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.EncryptResponse{
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Tag:        resp.Tag,
		Iv:         resp.IV,
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDecrypt, req.KeyId); err != nil {
		return nil, err
	}

	// The decryption belongs to the service layer, which owns the choice
	// between symmetric and asymmetric decryption and the RSA padding mode.
	// Reimplementing it here is how the transports drift apart from each other
	// and from the PKCS#11 module.
	resp, err := s.xkmsService.Decrypt(ctx, &transport.DecryptRequest{
		Backend:        req.Backend,
		KeyID:          req.KeyId,
		Ciphertext:     req.Ciphertext,
		Nonce:          req.Nonce,
		Tag:            req.Tag,
		AdditionalData: req.AdditionalData,
		Mode:           req.Mode,
		IV:             req.Iv,
		Padding:        req.Padding,
		Hash:           req.Hash,
		Label:          req.Label,
		TagSize:        int(req.TagSize),
		TenantID:       callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.DecryptResponse{Plaintext: resp.Plaintext}, nil
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

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionGenerate, req.KeyId); err != nil {
		return nil, err
	}

	// Get any backend's keystore for cert operations (they all share the same cert storage)
	backends := s.backendNames()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := s.lookupBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Save the certificate
	err = ks.SaveCert(ctx, req.KeyId, cert)
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

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionRead, req.KeyId); err != nil {
		return nil, err
	}

	// Get any backend's keystore for cert operations
	backends := s.backendNames()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := s.lookupBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Get the certificate
	cert, err := ks.GetCert(ctx, req.KeyId)
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

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionRevoke, req.KeyId); err != nil {
		return nil, err
	}

	// Get any backend's keystore for cert operations
	backends := s.backendNames()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := s.lookupBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Delete the certificate
	err = ks.DeleteCert(ctx, req.KeyId)
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
	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionList, ""); err != nil {
		return nil, err
	}

	// Get any backend's keystore for cert operations
	backends := s.backendNames()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := s.lookupBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// List certificates
	keyIDs, err := ks.ListCerts(ctx)
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

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionRead, req.KeyId); err != nil {
		return nil, err
	}

	// Get any backend's keystore for cert operations
	backends := s.backendNames()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := s.lookupBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Check if certificate exists
	exists, err := ks.CertExists(ctx, req.KeyId)
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

		if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionGenerate, req.KeyId); err != nil {
			return nil, err
		}
		chain[i] = cert
	}

	// Get any backend's keystore for cert operations
	backends := s.backendNames()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := s.lookupBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Save the certificate chain
	err = ks.SaveCertChain(ctx, req.KeyId, chain)
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

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionRead, req.KeyId); err != nil {
		return nil, err
	}

	// Get any backend's keystore for cert operations
	backends := s.backendNames()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := s.lookupBackend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Get the certificate chain
	chain, err := ks.GetCertChain(ctx, req.KeyId)
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

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionRead, req.KeyId); err != nil {
		return nil, err
	}

	ks, err := s.lookupBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ctx, ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Get the TLS certificate
	tlsCert, err := ks.GetTLSCertificate(ctx, req.KeyId, attrs)
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionImport, req.KeyId); err != nil {
		return nil, err
	}

	ks, err := s.lookupBackend(req.Backend)
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
	hashAlg, hashErr := parseHashAlgorithm(req.Hash)
	if hashErr != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, hashErr)
	}
	attrs := &types.KeyAttributes{
		CN:        req.KeyId,
		KeyType:   keyType,
		StoreType: types.StoreType(req.Backend),
		Hash:      hashAlg,
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
	params, err := importExportBackend.GetImportParameters(ctx, attrs, wrappingAlg)
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

// WrapKey wraps key material for secure transport.
//
// The request must name the backend whose wrapping semantics are used. This
// used to loop over every registered backend and keep the first that answered
// without an error, so the backend that actually performed the wrap was
// whichever one map iteration reached first -- two identical requests could be
// served by two different backends, and the response did not say which.
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
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	pubKey, err := x509.ParsePKIXPublicKey(req.WrappingPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse wrapping public key: %v", err)
	}

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionWrap, ""); err != nil {
		return nil, err
	}

	// The named backend, and only the named backend. The service layer's
	// WrapKey is deliberately not used here: it drops KeySpec and the response
	// Metadata, both of which the cloud-KMS import ceremonies read.
	importExportBackend, err := s.importExportBackend(req.Backend)
	if err != nil {
		return nil, err
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: pubKey,
		ImportToken:       req.ImportToken,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
		KeySpec:           req.KeySpec,
	}

	wrapped, err := importExportBackend.WrapKey(ctx, req.KeyMaterial, params)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to wrap key with backend %s: %v", req.Backend, err)
	}

	return &pb.WrapKeyResponse{
		WrappedKey:  wrapped.WrappedKey,
		Algorithm:   string(wrapped.Algorithm),
		ImportToken: wrapped.ImportToken,
		Metadata:    wrapped.Metadata,
	}, nil
}

// UnwrapKey unwraps previously wrapped key material.
//
// The request must name the backend that performs the unwrap, and it has to be
// the backend that produced the wrapped material. This used to try every
// registered backend in turn and return the first success, which had two
// consequences. The backend that answered was whichever one map iteration
// reached first, so the choice was not reproducible; and, worse, the loop made
// the RPC an unwrap oracle across backends -- a caller learned which backend
// held the unwrapping key from which attempt succeeded, and every backend in
// the process performed an unwrap attempt on caller-supplied ciphertext for
// free.
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
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	// Parse public key from DER
	pubKey, err := x509.ParsePKIXPublicKey(req.WrappingPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse wrapping public key: %v", err)
	}

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionUnwrap, ""); err != nil {
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

	// The named backend, and only the named backend. The service layer's
	// UnwrapKey is deliberately not used here: it drops KeySpec, Metadata and
	// the wrapping public key, all of which the import ceremonies read.
	importExportBackend, err := s.importExportBackend(req.Backend)
	if err != nil {
		return nil, err
	}

	keyMaterial, err := importExportBackend.UnwrapKey(ctx, wrapped, params)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unwrap key with backend %s: %v", req.Backend, err)
	}

	return &pb.UnwrapKeyResponse{
		KeyMaterial: keyMaterial,
	}, nil
}

// importExportBackend resolves a named backend to its import/export interface.
// An unknown backend is NotFound and a backend that cannot import or export is
// Unimplemented; neither is allowed to fall back to another backend.
func (s *Service) importExportBackend(name string) (backend.ImportExportBackend, error) {
	ks, err := s.lookupBackend(name)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %s", name)
	}
	importExportBackend, ok := ks.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "backend %s does not support import/export operations", name)
	}
	return importExportBackend, nil
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionImport, req.KeyId); err != nil {
		return nil, err
	}

	ks, err := s.lookupBackend(req.Backend)
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
	hashAlg, hashErr := parseHashAlgorithm(req.Hash)
	if hashErr != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, hashErr)
	}
	attrs := &types.KeyAttributes{
		CN:        req.KeyId,
		StoreType: types.StoreType(req.Backend),
		Hash:      hashAlg,
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
		// KeyTypeSecret, matching GenerateKey's symmetric branch above and
		// buildKeyAttributes in pkg/xkms. This said KeyTypeEncryption, which no
		// other path uses for symmetric material, and the mismatch was not
		// cosmetic: types.KeyAttributes.ID() encodes the key type, so an
		// imported key was stored under an identifier nothing else would
		// construct. ListKeys then reported it as an RSA key and every
		// subsequent operation failed -- C_Encrypt with "key not found:
		// software:encryption:<cn>:rsa", C_WrapKey with CKR_ATTRIBUTE_SENSITIVE
		// -- so a key that imported successfully could never be used again.
		//
		// Exportable is set for the reason buildImportKeyAttributes gives: the
		// request carries no field for it, PKCS#11 v3.2 §4.9 Table 30 makes a
		// secret key CKA_EXTRACTABLE by default, and a key the backend will not
		// release cannot be read back or wrapped. Leaving it false made every
		// imported symmetric key unexportable regardless of what the caller
		// intended.
		attrs.KeyType = types.KeyTypeSecret
		attrs.Exportable = true
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
	err = importExportBackend.ImportKey(ctx, attrs, wrapped)
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionExport, req.KeyId); err != nil {
		return nil, err
	}

	ks, err := s.lookupBackend(req.Backend)
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
	attrs, err := s.findKeyAttributes(ctx, ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.WrappingAlgorithm)

	// Export the key
	wrapped, err := importExportBackend.ExportKey(ctx, attrs, wrappingAlg)
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
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionExport, req.GetKeyId()); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{
		KeyID:    req.GetKeyId(),
		Backend:  req.GetBackend(),
		TenantID: callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.ExportKeyMaterialResponse{
		KeyMaterial: resp.KeyMaterial,
		KeyType:     resp.KeyType,
		KeySize:     int32(resp.KeySize), // #nosec G115 - symmetric key sizes fit in int32
	}, nil
}

// WrapKeyByID wraps a target key using a wrapping key, both identified by key IDs.
// This enables PKCS#11 C_WrapKey functionality with server-side keys.
// The target key must be extractable (exportable=true for symmetric keys).
//
// The wrapping process is implemented by the service layer:
//  1. Resolve the target key's backend and verify it supports import/export
//  2. Export the target key's raw material (symmetric keys only, must be exportable)
//  3. Resolve the wrapping key's backend and verify it supports import/export
//  4. Get import parameters from the wrapping key's backend
//  5. Wrap the target key material using the wrapping key
func (s *Service) WrapKeyByID(ctx context.Context, req *pb.WrapKeyByIDRequest) (*pb.WrapKeyByIDResponse, error) {
	// A request that carries its target as inline material names no target key
	// id, so the wrapping key -- the only server-side key the call uses -- is
	// what authorization is checked against. Passing the empty target id would
	// name no resource at all.
	authSubject := req.GetTargetKeyId()
	if authSubject == "" {
		authSubject = req.GetWrappingKeyId()
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionWrap, authSubject); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
		WrappingKeyID:      req.GetWrappingKeyId(),
		WrappingKeyBackend: req.GetWrappingKeyBackend(),
		TargetKeyID:        req.GetTargetKeyId(),
		TargetKeyBackend:   req.GetTargetKeyBackend(),
		TargetKeyMaterial:  req.GetTargetKeyMaterial(),
		Algorithm:          req.GetAlgorithm(),
		IV:                 req.GetIv(),
		AAD:                req.GetAad(),
		TagBits:            int(req.GetTagBits()),
		OAEPLabel:          req.GetOaepLabel(),
		TenantID:           callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.WrapKeyByIDResponse{
		WrappedKey: resp.WrappedKey,
		Algorithm:  resp.Algorithm,
	}, nil
}

// UnwrapKeyByID unwraps key material and imports it as a new key.
// This enables PKCS#11 C_UnwrapKey functionality with server-side keys.
//
// The unwrapping process is implemented by the service layer:
//  1. Resolve the unwrapping key's backend and verify import/export support
//  2. Find the unwrapping key's attributes
//  3. Unwrap the key material using the unwrapping key
//  4. Build the target key attributes from the request template
//  5. Import the unwrapped key material as a new key
func (s *Service) UnwrapKeyByID(ctx context.Context, req *pb.UnwrapKeyByIDRequest) (*pb.UnwrapKeyByIDResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionUnwrap, req.GetTargetKeyId()); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{
		WrappedKey:           req.GetWrappedKey(),
		UnwrappingKeyID:      req.GetUnwrappingKeyId(),
		UnwrappingKeyBackend: req.GetUnwrappingKeyBackend(),
		Algorithm:            req.GetAlgorithm(),
		IV:                   req.GetIv(),
		AAD:                  req.GetAad(),
		TagBits:              int(req.GetTagBits()),
		OAEPLabel:            req.GetOaepLabel(),
		TargetKeyID:          req.GetTargetKeyId(),
		TargetKeyBackend:     req.GetTargetKeyBackend(),
		TargetKeyType:        req.GetTargetKeyType(),
		TargetKeySize:        int(req.GetTargetKeySize()),
		TargetCurve:          req.GetTargetCurve(),
		TargetPartition:      req.GetTargetPartition(),
		TargetExportable:     req.GetTargetExportable(),
		TenantID:             callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.UnwrapKeyByIDResponse{
		KeyId:   resp.KeyID,
		Backend: resp.Backend,
		Success: resp.Success,
		Message: resp.Message,
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionCreate, req.DestKeyId); err != nil {
		return nil, err
	}

	// Get source keystore
	sourceKs, err := s.lookupBackend(req.SourceBackend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "source backend not found: %v", err)
	}

	// Get destination keystore
	destKs, err := s.lookupBackend(req.DestBackend)
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
	sourceAttrs, err := s.findKeyAttributes(ctx, sourceKs, req.SourceKeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "source key not found: %v", err)
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.WrappingAlgorithm)

	// Step 1: Export the key from source backend
	wrapped, err := sourceImportExport.ExportKey(ctx, sourceAttrs, wrappingAlg)
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
	err = destImportExport.ImportKey(ctx, destAttrs, wrapped)
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionEncrypt, req.KeyId); err != nil {
		return nil, err
	}

	// Validate the backend and the key locally so a misspelled backend and a
	// missing key keep this transport's NotFound, then let the service layer
	// own the OAEP construction itself: the digest selection, its weak-hash
	// refusal, its refusal of hash "NONE", and the RSA key-type check.
	//
	// The digest used to be resolved here and handed straight to hashFunc.New().
	// xkms.ResolveOAEPHash answers crypto.Hash(0) for the name "NONE" -- a
	// legal, non-error answer meaning "no digest" -- and crypto.Hash(0).New()
	// panics, so a request naming that hash crashed the serving goroutine
	// rather than being refused. The service has always rejected it.
	ks, err := s.lookupBackend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	if _, err := s.findKeyAttributes(ctx, ks, req.KeyId); err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	resp, err := s.xkmsService.EncryptAsym(ctx, &transport.EncryptAsymRequest{
		Backend:   req.Backend,
		KeyID:     req.KeyId,
		Plaintext: req.Plaintext,
		Hash:      req.Hash,
		Label:     req.Label,
		TenantID:  callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.EncryptAsymResponse{
		Ciphertext: resp.Ciphertext,
	}, nil
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionEncrypt, ""); err != nil {
		return nil, err
	}

	// Build seal options
	opts := &types.SealOptions{
		AAD: req.Aad,
	}

	// If key ID is provided, look up the key to get its actual attributes
	if req.KeyId != "" {
		// Get the backend to look up the key
		ks, err := s.lookupBackend(req.Backend)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
		}

		// Find the key by CN to get its full attributes
		keyAttrs, err := ks.ListKeys(ctx)
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
	sealed, err := s.sealWithBackend(ctx, req.Backend, req.Data, opts)
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

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDecrypt, ""); err != nil {
		return nil, err
	}

	// Get backend to determine backend type for sealed data
	ks, err := s.lookupBackend(req.Backend)
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
		keyAttrs, err := ks.ListKeys(ctx)
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
	plaintext, err := s.unsealWithBackend(ctx, req.Backend, sealed, opts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unseal data: %v", err)
	}

	return &pb.UnsealResponse{
		Plaintext: plaintext,
	}, nil
}

// CanSeal checks if a backend supports sealing operations
func (s *Service) CanSeal(ctx context.Context, req *pb.CanSealRequest) (*pb.CanSealResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionGet, ""); err != nil {
		return nil, err
	}

	var canSeal bool

	// If backend is specified, check that specific backend
	// Otherwise check the default backend
	if req.Backend != "" {
		canSeal = s.canSeal(req.Backend)
	} else {
		canSeal = s.canSeal()
	}

	return &pb.CanSealResponse{
		CanSeal: canSeal,
	}, nil
}

// AttestKey generates a key attestation statement proving hardware backing.
func (s *Service) AttestKey(ctx context.Context, req *pb.AttestKeyRequest) (*pb.AttestKeyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionGet, req.GetKeyId()); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.AttestKey(ctx, &transport.AttestKeyRequest{
		Backend:  req.GetBackend(),
		KeyID:    req.GetKeyId(),
		Nonce:    req.GetNonce(),
		TenantID: callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.AttestKeyResponse{
		Format:             resp.Format,
		CertificateChain:   resp.CertificateChain,
		AttestationData:    resp.AttestationData,
		Signature:          resp.Signature,
		SignatureAlgorithm: resp.SignatureAlgorithm,
		Nonce:              resp.Nonce,
		Backend:            resp.Backend,
	}, nil
}

// DeriveKey performs key derivation using the specified algorithm.
//
// It is a transport adapter and nothing more: it validates the shape of the
// protobuf request, authorizes, and delegates every cryptographic decision to
// XKMSService.DeriveKey. It used to carry its own KDF adapter table, its own
// parameter assembly and its own salt-as-IV convention, calling pkg/crypto/kdf
// directly — a second implementation of the same primitive, which had already
// drifted from the service layer's: a salt supplied with SP 800-108 Feedback
// Mode became K(0) here and was dropped there, so the same request derived two
// different keys depending on which transport carried it. Both answers looked
// like successful derivations.
func (s *Service) DeriveKey(ctx context.Context, req *pb.DeriveKeyRequest) (*pb.DeriveKeyResponse, error) {
	if req.GetAlgorithm() == "" {
		return nil, status.Error(codes.InvalidArgument, "algorithm is required")
	}

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDerive, req.GetKeyId()); err != nil {
		return nil, err
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.DeriveKey(ctx, &transport.DeriveKeyRequest{
		Backend:          req.GetBackend(),
		KeyID:            req.GetKeyId(),
		Algorithm:        req.GetAlgorithm(),
		InputKeyMaterial: req.GetInputKeyMaterial(),
		Salt:             req.GetSalt(),
		Info:             req.GetInfo(),
		PeerPublicKey:    req.GetPeerPublicKey(),
		KeyLength:        int(req.GetKeyLength()),
		Hash:             req.GetHash(),
		Iterations:       int(req.GetIterations()),
		PRF:              req.GetPrf(),
		Label:            req.GetLabel(),
		Context:          req.GetContext(),
		Counter:          req.GetCounter(),
		UseCofactor:      req.GetUseCofactor(),
		StoreResult:      req.GetStoreResult(),
		DerivedKeyID:     req.GetDerivedKeyId(),
		DerivedKeyType:   req.GetDerivedKeyType(),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.DeriveKeyResponse{
		DerivedKey: resp.DerivedKey,
		KeyId:      resp.KeyID,
		Algorithm:  resp.Algorithm,
		KeyLength:  int32(resp.KeyLength), // #nosec G115 - key length fits in int32
	}, nil
}

// DeriveKeyECDH performs ECDH key agreement and derives a symmetric key.
// This operation combines ECDH shared secret computation with a KDF to produce
// a derived key suitable for symmetric encryption.
func (s *Service) DeriveKeyECDH(ctx context.Context, req *pb.DeriveKeyECDHRequest) (*pb.DeriveKeyECDHResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDerive, req.GetKeyId()); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{
		KeyID:         req.GetKeyId(),
		Backend:       req.GetBackend(),
		PeerPublicKey: req.GetPeerPublicKey(),
		KDFAlgorithm:  req.GetKdfAlgorithm(),
		KDFHash:       req.GetKdfHash(),
		KDFSalt:       req.GetKdfSalt(),
		KDFInfo:       req.GetKdfInfo(),
		KDFLabel:      req.GetKdfLabel(),
		KeyLength:     int(req.GetKeyLength()),
		TenantID:      callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.DeriveKeyECDHResponse{
		DerivedKey: resp.DerivedKey,
	}, nil
}

// Helper functions

func (s *Service) findKeyAttributes(ctx context.Context, ks xkms.Backend, keyID string) (*types.KeyAttributes, error) {
	attrs, err := ks.ListKeys(ctx)
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		if attr.CN == keyID {
			return attr, nil
		}
	}

	return nil, &errs.Message{Msg: fmt.Sprintf("key %s not found", keyID)}
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

// parseHashAlgorithm resolves a caller-supplied hash algorithm name for this
// transport. It delegates to xkms.ResolveHash so the wire and the service layer
// share one hash vocabulary, one default, and one refusal.
//
// It used to answer any name it could not resolve with SHA-256 and report
// success, so a caller that named a misspelled hash — or, once the weak-hash
// policy landed, MD5 or SHA-1 — received a SHA-256 signature over a digest it
// never chose, with nothing in the response to say so.
func parseHashAlgorithm(hash string) (crypto.Hash, error) {
	h, err := xkms.ResolveHash(hash)
	if err != nil {
		return 0, err
	}

	// xkms.ResolveHash maps the "NONE" sentinel to crypto.Hash(0), meaning
	// "the caller supplied a pre-built digest; do not hash". The handlers in
	// this file always hash their input, and crypto.Hash(0).New() panics, so
	// the sentinel must be rejected here rather than reaching a hasher.
	if h == 0 {
		return 0, xkms.ErrInvalidHashFunction
	}

	return h, nil
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
		return "", &errs.Message{Msg: "unsupported key type"}
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
		return nil, &errs.Message{Msg: "failed to decode PEM block"}
	}
	if block.Type != "CERTIFICATE" {
		return nil, &errs.Message{Msg: fmt.Sprintf("invalid PEM type: %s (expected CERTIFICATE)", block.Type)}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &errs.Message{Msg: fmt.Sprintf("failed to parse certificate: %v", err)}
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
			return "", &errs.Message{Msg: fmt.Sprintf("failed to marshal ECDSA key: %v", err)}
		}
	case ed25519.PrivateKey:
		pemType = "PRIVATE KEY"
		keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return "", &errs.Message{Msg: fmt.Sprintf("failed to marshal Ed25519 key: %v", err)}
		}
	default:
		return "", &errs.Message{Msg: fmt.Sprintf("unsupported private key type: %T", privKey)}
	}

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}

// lookupBackend retrieves a backend by name, delegating to s.xkmsService when
// available. Returns xkms.ErrNotInitialized when the service is not set.
func (s *Service) lookupBackend(name string) (xkms.Backend, error) {
	if s.xkmsService == nil {
		return nil, xkms.ErrNotInitialized
	}
	return s.xkmsService.LookupBackend(name)
}

// backendNames returns the list of all configured backend names. Returns nil
// when the service is not set.
func (s *Service) backendNames() []string {
	if s.xkmsService == nil {
		return nil
	}
	return s.xkmsService.BackendNames()
}

// sealWithBackend delegates to s.xkmsService.SealWithBackend.
// Returns xkms.ErrNotInitialized when the service is not set.
func (s *Service) sealWithBackend(ctx context.Context, backendName string, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if s.xkmsService == nil {
		return nil, xkms.ErrNotInitialized
	}
	return s.xkmsService.SealWithBackend(ctx, backendName, data, opts)
}

// unsealWithBackend delegates to s.xkmsService.UnsealWithBackend.
// Returns xkms.ErrNotInitialized when the service is not set.
func (s *Service) unsealWithBackend(ctx context.Context, backendName string, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if s.xkmsService == nil {
		return nil, xkms.ErrNotInitialized
	}
	return s.xkmsService.UnsealWithBackend(ctx, backendName, sealed, opts)
}

// canSeal returns whether the named backend (or default when no name is given)
// supports sealing. Returns false when the service is not set.
func (s *Service) canSeal(backendName ...string) bool {
	if s.xkmsService == nil {
		return false
	}
	return s.xkmsService.CanSealDirect(backendName...)
}
