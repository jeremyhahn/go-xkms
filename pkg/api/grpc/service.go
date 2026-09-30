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
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
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
	// ErrAccessDenied is the fixed, generic message authorize returns to the
	// client on a permission denial. The specific reason (a missing grant, a
	// tenant-scope rejection, or an RBAC backend detail) is not the caller's
	// to see; authorize records it in the audit event's Details["reason"]
	// instead, matching pkg/api/rest/rbac_middleware.go's RBACMiddleware
	// (go-xkms#1103).
	ErrAccessDenied = errors.New("grpc: access denied")

	// ErrAuthenticationRequired is the fixed, generic message authorize
	// returns to the client when it is invoked without an identity on the
	// context, matching pkg/api/rest/rbac_middleware.go's "Authentication
	// required" wording (go-xkms#1103).
	ErrAuthenticationRequired = errors.New("grpc: authentication required")
)

// Service implements the KeystoreService gRPC interface
type Service struct {
	pb.UnimplementedKeystoreServiceServer
	authorizer  *auth.Authorizer
	auditLogger audit.Logger
	xkmsService *xkms.XKMSService
	sshClient   sdkssh.Client

	// ca is the CA servicer wired via SetCA, delegated to by the CA RPC
	// handlers in service_ca.go and service_ca_tcg.go. Nil (the default)
	// causes those RPCs to return codes.Unavailable.
	ca any

	// caBundler is the CA bundle source wired via SetCABundler, consulted by
	// GetCABundle before it falls back to ca's own GetCABundle method. Nil
	// (the default) causes GetCABundle to rely on ca alone.
	caBundler CABundler

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
// event, recording the denial reason (if any) in the event's Details rather
// than the client-facing error. Returns nil if the action is allowed, or a
// gRPC status error carrying a fixed, generic message on deny
// (PermissionDenied) or missing identity (Unauthenticated) -- go-xkms#1103.
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
	if err != nil {
		// The denial reason stays in the audit trail, never the client
		// response: it can carry RBAC/backend detail (barrier state,
		// user-store failures, why a certificate was rejected) that is not
		// the caller's to see (go-xkms#1103).
		auditEvent.Details["reason"] = err.Error()
	}
	// authorize is a SeveritySecurity action (docs/audit-log/engineering.md):
	// a failed audit write fails the request rather than let an
	// authorization decision proceed unaudited.
	if auditErr := audit.HandleWriteFailure(nil, auditEvent.Action, s.auditLogger.Log(ctx, auditEvent)); auditErr != nil {
		return status.Error(codes.Internal, auditErr.Error())
	}

	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			return status.Error(codes.Unauthenticated, ErrAuthenticationRequired.Error())
		}
		return status.Error(codes.PermissionDenied, ErrAccessDenied.Error())
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
// GenerateKey generates a new key.
//
// Generation belongs to the service layer, which owns backend resolution,
// the algorithm and key-purpose vocabularies, the symmetric/asymmetric
// split, curve and RSA-size validation (including the 2048-bit floor,
// go-xkms#1204), and the exportability contract
// (pkg/xkms/servicer_key.go's buildKeyAttributes). This handler used to
// reimplement all of that so it could drift from REST, MCP and the embedded
// transport's own copies (go-xkms#1214).
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
	if req.Algorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "algorithm is required")
	}

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionCreate, req.KeyId); err != nil {
		return nil, err
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID:      req.KeyId,
		Backend:    req.Backend,
		KeyType:    req.KeyType,
		KeySize:    int(req.KeySize),
		Curve:      req.Curve,
		Hash:       req.Hash,
		Algorithm:  req.Algorithm,
		Exportable: req.Exportable,
		Sensitive:  req.GetSensitive(),
		TPMPolicy:  req.GetTpmPolicy(),
		Partition:  req.Partition,
		TenantID:   callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.GenerateKeyResponse{
		KeyId:        req.KeyId,
		Backend:      req.Backend,
		KeyType:      req.KeyType,
		PublicKeyPem: resp.PublicKeyPEM,
		CreatedAt:    timestamppb.Now(),
	}, nil
}

// ListKeys lists the keys in the specified backend.
//
// The listing belongs to the service layer, which confines it to the caller's
// tenant: a tenant sees only its own keys, and Total counts only those. This
// RPC used to list the unscoped backend itself, so any tenant could enumerate
// every other tenant's keys (go-xkms#1218).
func (s *Service) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionList, ""); err != nil {
		return nil, err
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	// The proto's limit/offset fields map to a page-based request for
	// consistency across protocols.
	listed, err := s.xkmsService.ListKeys(ctx, req.Backend,
		transport.WithPageRequest(grpcPageRequest(int(req.Limit), int(req.Offset))))
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	keys := make([]*pb.KeyInfo, 0, len(listed.Keys))
	for _, key := range listed.Keys {
		keys = append(keys, keyInfoToProto(key))
	}

	return &pb.ListKeysResponse{
		Keys:  keys,
		Total: int32(listed.Total), // #nosec G115 - Key count fits in int32
	}, nil
}

// GetKey retrieves information about a specific key.
//
// The lookup belongs to the service layer, which confines it to the caller's
// tenant. Another tenant's key is NotFound with exactly the message a key no
// tenant holds produces, so the answer does not reveal that it exists. This
// RPC used to scan the unscoped backend, and returned any tenant's key to any
// caller that named it (go-xkms#1218).
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.GetKey(ctx, req.Backend, req.KeyId)
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.GetKeyResponse{
		Key:          keyInfoToProto(resp.KeyInfo),
		PublicKeyPem: resp.PublicKeyPEM,
	}, nil
}

// keyInfoToProto renders the service layer's KeyInfo as this transport's
// wire shape. Key attributes carry no creation time, so CreatedAt reports the
// time of the response, as it always has.
func keyInfoToProto(key transport.KeyInfo) *pb.KeyInfo {
	return &pb.KeyInfo{
		KeyId:      key.KeyID,
		Backend:    key.Backend,
		KeyType:    key.KeyType,
		Algorithm:  key.Algorithm,
		KeySize:    int32(key.KeySize), // #nosec G115 - RSA key size fits in int32
		Curve:      key.Curve,
		Partition:  key.Partition,
		CreatedAt:  timestamppb.Now(),
		KeyVersion: key.KeyVersion,
	}
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
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

	return &pb.SignResponse{Signature: resp.Signature, KeyVersion: resp.KeyVersion}, nil
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
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
		KeyVersion:   req.GetKeyVersion(),
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

	return &pb.VerifyResponse{Valid: resp.Valid, Message: message, KeyVersion: resp.KeyVersion}, nil
}

// DeleteKey deletes a key from the backend.
//
// Deletion belongs to the service layer, which resolves the key within the
// caller's tenant; another tenant's key is NotFound, indistinguishable from a
// key no tenant holds (go-xkms#1218).
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	if err := s.xkmsService.DeleteKey(ctx, req.Backend, req.KeyId); err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.DeleteKeyResponse{
		Success: true,
		Message: fmt.Sprintf("key %s deleted successfully", req.KeyId),
	}, nil
}

// RotateKey rotates an existing key.
//
// Rotation belongs to the service layer, which resolves the key within the
// caller's tenant; another tenant's key is NotFound, indistinguishable from a
// key no tenant holds (go-xkms#1218).
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.RotateKey(ctx, &transport.RotateKeyRequest{
		Backend:  req.Backend,
		KeyID:    req.KeyId,
		TenantID: callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.RotateKeyResponse{
		KeyId:        resp.KeyID,
		Backend:      req.Backend,
		KeyType:      resp.KeyType,
		PublicKeyPem: resp.PublicKeyPEM,
		RotatedAt:    timestamppb.Now(),
		KeyVersion:   resp.KeyVersion,
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
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
		Ciphertext:   resp.Ciphertext,
		Nonce:        resp.Nonce,
		Tag:          resp.Tag,
		Iv:           resp.IV,
		GcmNonceMode: resp.GCMNonceMode,
		KeyVersion:   resp.KeyVersion,
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
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
		GCMNonceMode:   req.GcmNonceMode,
		Mode:           req.Mode,
		IV:             req.Iv,
		Padding:        req.Padding,
		Hash:           req.Hash,
		Label:          req.Label,
		TagSize:        int(req.TagSize),
		KeyVersion:     req.GetKeyVersion(),
		TenantID:       callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.DecryptResponse{Plaintext: resp.Plaintext, KeyVersion: resp.KeyVersion}, nil
}

// The certificate RPCs below are thin adapters over the XKMSService
// certificate methods, which confine every read, write, listing and delete to
// the caller's tenant namespace on the default backend. A certificate another
// tenant holds, or one the platform holds, answers exactly as one nobody
// stored, and a key ID that names another namespace ("tenant-b/web") is
// refused as malformed. These RPCs used to call whichever backend the name
// map yielded first, unscoped, so any tenant could read, overwrite, list or
// delete every tenant's certificates and the platform's (go-xkms#1228).

// SaveCert stores a certificate
func (s *Service) SaveCert(ctx context.Context, req *pb.SaveCertRequest) (*pb.SaveCertResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.CertPem == "" {
		return nil, status.Error(codes.InvalidArgument, "cert_pem is required")
	}

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionGenerate, req.KeyId); err != nil {
		return nil, err
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	if err := s.xkmsService.SaveCertificate(ctx, &transport.SaveCertificateRequest{
		KeyID:          req.KeyId,
		CertificatePEM: req.CertPem,
		TenantID:       callerTenantID(ctx),
	}); err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.GetCertificate(ctx, "", req.KeyId)
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.GetCertResponse{
		CertPem: resp.CertificatePEM,
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	if err := s.xkmsService.DeleteCertificate(ctx, "", req.KeyId); err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	listed, err := s.xkmsService.ListCertificates(ctx, "")
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	keyIDs := make([]string, 0, len(listed.Certificates))
	for _, cert := range listed.Certificates {
		keyIDs = append(keyIDs, cert.KeyID)
	}

	return &pb.ListCertsResponse{
		KeyIds: keyIDs,
		Total:  int32(listed.Total), // #nosec G115 - Certificate count fits in int32
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	exists, err := s.xkmsService.CertificateExists(ctx, "", req.KeyId)
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
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

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionGenerate, req.KeyId); err != nil {
		return nil, err
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	if err := s.xkmsService.SaveCertificateChain(ctx, &transport.SaveCertificateChainRequest{
		KeyID:    req.KeyId,
		ChainPEM: req.CertChainPem,
		TenantID: callerTenantID(ctx),
	}); err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.GetCertificateChain(ctx, "", req.KeyId)
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.GetCertChainResponse{
		CertChainPem: resp.ChainPEM,
	}, nil
}

// GetTLSCertificate returns a TLS certificate and its chain, read from the
// caller's certificate namespace in the named backend. The private key never
// travels on this response (go-xkms#627).
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.GetTLSCertificate(ctx, req.Backend, req.KeyId)
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.GetTLSCertificateResponse{
		CertPem:      resp.CertificatePEM,
		CertChainPem: resp.ChainPEM,
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

	// A named backend that does not exist is reported as NotFound before the
	// ceremony is attempted, matching every other capability-gated RPC on
	// this service.
	if _, err := s.lookupBackend(req.Backend); err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// The ceremony belongs to the service layer, which owns the key-template
	// vocabulary, the RSA floor (go-xkms#1204) and the import-capability
	// assertion (backend.ImportBackend, never the full ImportExportBackend
	// union -- a backend that genuinely cannot export, AWS KMS by hardware
	// design, must still be reachable here). This RPC used to rebuild all of
	// that by hand, which is how it drifted from the gRPC ImportKey's own
	// copy of the same switch (go-xkms#1214, go-xkms#1216).
	resp, err := s.xkmsService.GetImportParameters(ctx, &transport.GetImportParametersRequest{
		Backend:   req.Backend,
		KeyID:     req.KeyId,
		Algorithm: req.WrappingAlgorithm,
		KeyType:   req.KeyType,
		KeySize:   int(req.KeySize),
		Curve:     req.Curve,
		TenantID:  callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	response := &pb.GetImportParametersResponse{
		WrappingPublicKey: resp.WrappingPublicKey,
		ImportToken:       resp.ImportToken,
		Algorithm:         resp.Algorithm,
		KeySpec:           resp.KeySpec,
	}

	if resp.ExpiresAt != "" {
		expiresAt, parseErr := time.Parse("2006-01-02T15:04:05Z", resp.ExpiresAt)
		if parseErr == nil {
			response.ExpiresAt = timestamppb.New(expiresAt)
		}
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
//
// WrapKey belongs to the service layer, which resolves the named backend's
// import capability (backend.ImportBackend, never the full
// ImportExportBackend union) the same way ImportKey does, and carries KeySpec
// and Metadata through both directions -- the "service drops fields" reason
// this RPC used to bypass it no longer holds (go-xkms#1216).
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

	// Parsed only to validate the DER the caller sent; the service takes the
	// DER bytes directly.
	if _, err := x509.ParsePKIXPublicKey(req.WrappingPublicKey); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse wrapping public key: %v", err)
	}

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionWrap, ""); err != nil {
		return nil, err
	}

	// The named backend, and only the named backend: a lookup failure is
	// reported before the wrap is attempted, matching every other
	// capability-gated RPC on this service.
	if _, err := s.lookupBackend(req.Backend); err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %s", req.Backend)
	}

	resp, err := s.xkmsService.WrapKey(ctx, &transport.WrapKeyRequest{
		Backend:           req.Backend,
		KeyMaterial:       req.KeyMaterial,
		Algorithm:         req.Algorithm,
		WrappingPublicKey: req.WrappingPublicKey,
		ImportToken:       req.ImportToken,
		KeySpec:           req.KeySpec,
		TenantID:          callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.WrapKeyResponse{
		WrappedKey:  resp.WrappedKeyMaterial,
		Algorithm:   resp.Algorithm,
		ImportToken: resp.ImportToken,
		Metadata:    resp.Metadata,
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
//
// UnwrapKey belongs to the service layer for the same reason WrapKey does;
// see its doc comment.
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

	// Parsed only to validate the DER the caller sent; the service takes the
	// DER bytes directly.
	if _, err := x509.ParsePKIXPublicKey(req.WrappingPublicKey); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse wrapping public key: %v", err)
	}

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionUnwrap, ""); err != nil {
		return nil, err
	}

	// The named backend, and only the named backend; see WrapKey.
	if _, err := s.lookupBackend(req.Backend); err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %s", req.Backend)
	}

	resp, err := s.xkmsService.UnwrapKey(ctx, &transport.UnwrapKeyRequest{
		Backend:            req.Backend,
		WrappedKeyMaterial: req.WrappedKey,
		Algorithm:          req.Algorithm,
		ImportToken:        req.ImportToken,
		WrappingPublicKey:  req.WrappingPublicKey,
		KeySpec:            req.KeySpec,
		Metadata:           req.Metadata,
		TenantID:           callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.UnwrapKeyResponse{
		KeyMaterial: resp.KeyMaterial,
	}, nil
}

// ImportKey imports externally generated key material into the backend.
//
// Import belongs to the service layer, which owns backend resolution, the
// key-template vocabulary, the RSA floor (go-xkms#1204), the exportability
// write-once default, and the import-capability assertion
// (backend.ImportBackend, never the full ImportExportBackend union, so a
// backend that genuinely cannot export -- AWS KMS by hardware design -- is
// never blocked from importing because of that unrelated limitation). This
// RPC used to rebuild all of that by hand, which is how its symmetric-size
// validation drifted from the service's own (go-xkms#1214, go-xkms#1216).
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

	// A named backend that does not exist is reported as NotFound before the
	// import is attempted, matching every other capability-gated RPC on this
	// service.
	if _, err := s.lookupBackend(req.Backend); err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	resp, err := s.xkmsService.ImportKey(ctx, &transport.ImportKeyRequest{
		Backend:            req.Backend,
		KeyID:              req.KeyId,
		KeyType:            req.KeyType,
		KeySize:            int(req.KeySize),
		Curve:              req.Curve,
		Hash:               req.Hash,
		WrappedKeyMaterial: req.WrappedKey,
		Algorithm:          req.Algorithm,
		ImportToken:        req.ImportToken,
		Partition:          req.Partition,
		Metadata:           req.Metadata,
		Exportable:         req.Exportable,
		Sensitive:          req.GetSensitive(),
		TenantID:           callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.ImportKeyResponse{
		Success: resp.Success,
		Message: fmt.Sprintf("key %s imported successfully into backend %s", req.KeyId, req.Backend),
		KeyId:   resp.KeyID,
	}, nil
}

// ExportKey exports a key in wrapped form for secure transport.
//
// Export belongs to the service layer, which resolves the key within the
// caller's tenant; another tenant's key is NotFound, indistinguishable from a
// key no tenant holds (go-xkms#1218).
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.ExportKey(ctx, &transport.ExportKeyRequest{
		Backend:   req.Backend,
		KeyID:     req.KeyId,
		Algorithm: req.WrappingAlgorithm,
		TenantID:  callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.ExportKeyResponse{
		WrappedKey:  resp.WrappedKeyMaterial,
		Algorithm:   resp.Algorithm,
		ImportToken: resp.ImportToken,
		Metadata:    resp.Metadata,
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
		WrappedKey:         resp.WrappedKey,
		Algorithm:          resp.Algorithm,
		WrappingKeyVersion: resp.WrappingKeyVersion,
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
		UnwrappingKeyVersion: req.GetUnwrappingKeyVersion(),
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

// CopyKey copies a key from one backend to another using export/import.
//
// The copy belongs to the service layer, which resolves the source key within
// the caller's tenant, imports the copy into the caller's tenant in the
// destination backend, and wraps the material for the destination's own
// import parameters; the copy takes its attributes from the source key. This
// RPC used to import the copy through the UNSCOPED destination backend, so a
// tenant's copy landed with no tenant at all, and wrapped the material under
// a token only the source backend could open, so a copy between two backend
// instances always failed (go-xkms#1218).
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	resp, err := s.xkmsService.CopyKey(ctx, &transport.CopyKeyRequest{
		SourceBackend: req.SourceBackend,
		SourceKeyID:   req.SourceKeyId,
		DestBackend:   req.DestBackend,
		DestKeyID:     req.DestKeyId,
		Algorithm:     req.WrappingAlgorithm,
		TenantID:      callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.CopyKeyResponse{
		Success:   true,
		Message:   fmt.Sprintf("key %s copied from %s to %s as %s", req.SourceKeyId, req.SourceBackend, req.DestBackend, resp.KeyID),
		DestKeyId: resp.KeyID,
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

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
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
	ks, err := s.lookupTenantBackend(ctx, req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	if _, err := xkms.FindKeyAttributes(ctx, ks, req.KeyId); err != nil {
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
		KeyVersion: resp.KeyVersion,
	}, nil
}

// Seal encrypts data using the backend's sealing mechanism.
//
// The seal belongs to the service layer, which resolves the sealing key --
// the named one, or the caller's default sealing key when none is named --
// within the caller's tenant. Another tenant's key is NotFound with exactly
// the message a key no tenant holds produces. This RPC used to resolve the
// key over the unscoped backend and sealed under any tenant's key of that
// name (go-xkms#1228).
func (s *Service) Seal(ctx context.Context, req *pb.SealRequest) (*pb.SealResponse, error) {
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.Data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data is required")
	}

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionEncrypt, ""); err != nil {
		return nil, err
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	sealed, err := s.xkmsService.Seal(ctx, pbconv.SealRequestFromProto(req, callerTenantID(ctx)))
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}
	return pbconv.SealResponseToProto(sealed), nil
}

// Unseal decrypts previously sealed data.
//
// As with Seal, the key is resolved within the caller's tenant by the
// service, so a blob sealed under another tenant's key -- named, or that
// tenant's default sealing key -- does not unseal here. This RPC used to
// resolve the key over the unscoped backend, so a tenant that held another
// tenant's blob and knew its key's name recovered the plaintext
// (go-xkms#1228).
func (s *Service) Unseal(ctx context.Context, req *pb.UnsealRequest) (*pb.UnsealResponse, error) {
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.Ciphertext) == 0 && (len(req.TpmPublic) == 0 || len(req.TpmPrivate) == 0) {
		return nil, status.Error(codes.InvalidArgument, "ciphertext is required (or tpm_public and tpm_private for a TPM2 sealed object)")
	}

	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDecrypt, ""); err != nil {
		return nil, err
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}

	unsealReq, err := pbconv.UnsealRequestFromProto(req, callerTenantID(ctx))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	resp, err := s.xkmsService.Unseal(ctx, unsealReq)
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.UnsealResponse{
		Plaintext: resp.Plaintext,
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
		KeyVersion:       req.GetKeyVersion(),
		TenantID:         callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.DeriveKeyResponse{
		DerivedKey: resp.DerivedKey,
		KeyId:      resp.KeyID,
		Algorithm:  resp.Algorithm,
		KeyLength:  int32(resp.KeyLength), // #nosec G115 - key length fits in int32
		KeyVersion: resp.KeyVersion,
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
		KeyVersion:    req.GetKeyVersion(),
		TenantID:      callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.DeriveKeyECDHResponse{
		DerivedKey: resp.DerivedKey,
		KeyVersion: resp.KeyVersion,
	}, nil
}

// Helper functions

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

// lookupBackend retrieves a backend by name, delegating to s.xkmsService when
// available. Returns xkms.ErrNotInitialized when the service is not set.
func (s *Service) lookupBackend(name string) (xkms.Backend, error) {
	if s.xkmsService == nil {
		return nil, xkms.ErrNotInitialized
	}
	return s.xkmsService.LookupBackend(name)
}

// lookupTenantBackend returns the named backend viewed through the tenant of
// the authenticated caller. It is what every path that resolves a key by
// COMMON NAME must use, because a common name is unique only within a tenant:
// xkms.FindKeyAttributes scans whatever backend it is handed, so handing it
// an unscoped one lets the scan match another tenant's key.
//
// That was not hypothetical. Before go-xkms#221 the key-by-CN paths on this
// transport called lookupBackend, and a caller holding no key of that name at
// all resolved -- and then deleted, rotated, exported or decrypted with -- the
// first key any tenant happened to have stored under it.
//
// It delegates to XKMSService.LookupTenantBackend, the same helper the MCP
// transport uses, so all three transports agree on what a tenant is rather
// than each deciding for itself. The system tenant and unauthenticated
// system-level calls resolve to the unscoped backend, which is
// tenantScopes' rule and not a special case invented here.
func (s *Service) lookupTenantBackend(ctx context.Context, name string) (xkms.Backend, error) {
	if s.xkmsService == nil {
		return nil, xkms.ErrNotInitialized
	}
	return s.xkmsService.LookupTenantBackend(name, callerTenantID(ctx))
}

// backendNames returns the list of all configured backend names. Returns nil
// when the service is not set.
func (s *Service) backendNames() []string {
	if s.xkmsService == nil {
		return nil
	}
	return s.xkmsService.BackendNames()
}

// canSeal returns whether the named backend (or default when no name is given)
// supports sealing. Returns false when the service is not set.
func (s *Service) canSeal(backendName ...string) bool {
	if s.xkmsService == nil {
		return false
	}
	return s.xkmsService.CanSealDirect(backendName...)
}
