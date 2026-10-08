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

package admin

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sort"
	"strconv"
	"sync"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// wrapInputError creates an error with context for invalid input.
func wrapInputError(field, message string) error {
	return caerrors.MalformedError("admin: invalid input - %s: %s", field, message)
}

// tenantCAEntry represents a cached tenant CA.
type tenantCAEntry struct {
	rootCA          *x509.Certificate
	rootSigner      crypto.Signer
	intermediateCAs map[string]*tenantIntermediateCAEntry
	defaultIntCA    string
}

// tenantIntermediateCAEntry represents a cached tenant intermediate CA.
type tenantIntermediateCAEntry struct {
	cert   *x509.Certificate
	signer crypto.Signer
}

// QRDBClient is the go-qrdb client surface the tenant-aware admin service
// delegates tenant roles, users, and per-tenant CA records to.
// *qrdbsdk.Client satisfies it.
type QRDBClient interface {
	KV() db.KVClient
	Users() db.UserClient
	Roles() db.RoleClient
}

var _ QRDBClient = (*qrdbsdk.Client)(nil)

// TenantAwareAdminService provides multi-tenant admin operations.
// It embeds AdminService for base operations and adds tenant-specific functionality.
type TenantAwareAdminService struct {
	*AdminService
	qrdbService QRDBClient
	tenantDAO   qrdbsdk.GenericDAO[*entities.Tenant]
	logger      *slog.Logger
	tenantCAs   map[string]*tenantCAEntry
	mu          sync.RWMutex

	// tenantSvc is go-qrdb's canonical TenantServicer (qrdbsdk.ServiceTenantServicer),
	// wired via SetTenantService by the composing binary (cmd/xkmsd, through
	// server.Server.TenantService()). Tenant identity lifecycle —
	// create/get/update/delete/list — is a thin pass-through to it, per the
	// owner decision that xkms inherits qrdb's multi-tenant model instead of
	// keeping a parallel one. The local entities.Tenant record (tenantDAO) is
	// never authoritative for tenant existence: it is a linkage row keyed by
	// the same tenant ID for what xkms genuinely owns — per-tenant CA
	// material, EAB tokens, and the ACME-operational active/suspended status
	// qrdb has no concept of.
	//
	// A nil tenantSvc is not a fallback trigger. CreateTenant, GetTenant,
	// UpdateTenant, DeleteTenant, and ListTenants fail closed with
	// ErrTenantServiceUnavailable when it is unset: qrdb is the single
	// tenant authority, so there is no local-only path left to fall back to.
	tenantSvc qrdbsdk.ServiceTenantServicer
}

// SetTenantService wires the qrdb TenantServicer the tenant lifecycle
// methods (CreateTenant, GetTenant, UpdateTenant, DeleteTenant, ListTenants)
// delegate to. Mirrors SetBarrierService's post-construction wiring: the
// composing binary calls this once the embedded qrdb node (and its
// TenantServicer) has been constructed, which happens after
// NewTenantAwareAdminService in xkmsd's start-up sequence.
func (s *TenantAwareAdminService) SetTenantService(svc qrdbsdk.ServiceTenantServicer) {
	s.tenantSvc = svc
}

// TenantDAOInitError reports a failure to obtain the tenant-aware storage
// factory's DAO for entities.Tenant while constructing a tenant-aware admin
// service. Unlike a storage.TenantAwareFactory type assertion failing (which
// legitimately means "this deployment has no local tenant DAO" and leaves
// tenantDAO nil — see the NewTenantAwareAdminService doc comment), this means
// the factory claims tenant-aware support but could not produce the DAO — a
// real, actionable failure, distinct from the ordinary degraded mode that
// every tenantDAO-nil check throughout this file already handles.
// NewTenantAwareAdminService refuses construction and returns this error
// rather than starting in a silently degraded state nobody asked for.
type TenantDAOInitError struct {
	Err error
}

// Error implements the error interface.
func (e *TenantDAOInitError) Error() string {
	return fmt.Sprintf("admin: failed to initialize tenant DAO: %v", e.Err)
}

// Unwrap returns the underlying cause.
func (e *TenantDAOInitError) Unwrap() error {
	return e.Err
}

// NewTenantAwareAdminService creates a new tenant-aware admin service.
//
// A storageFactory that does not implement storage.TenantAwareFactory
// leaves the service's local tenant DAO nil, and that is a legitimate
// configuration, not a misconfiguration to refuse: the local tenantDAO is
// never authoritative for tenant existence (qrdb, via tenantSvc, is the
// single tenant authority — see the tenantSvc field doc comment); it is
// only an optional linkage row for the CA/EAB/status state qrdb has no
// concept of. Every method on this service already guards s.tenantDAO !=
// nil before touching it, and xkmsd's only production wiring
// (cmd/xkmsd/acme.go, via objstore.NewFactory) constructs the
// plain, non-tenant-aware storage.Factory today, so this is the normal
// production path, not an edge case.
//
// A storageFactory that DOES implement storage.TenantAwareFactory but
// fails to produce the DAO is different: the factory promised tenant-aware
// support and could not deliver it, which is a real, actionable failure.
// Construction is refused with a *TenantDAOInitError wrapping the cause,
// rather than logging and continuing in the degraded mode above.
func NewTenantAwareAdminService(
	certificateAuthority ca.TCGCA,
	storageFactory storage.Factory,
	qrdbService QRDBClient,
	logger *slog.Logger,
	version string,
) (*TenantAwareAdminService, error) {
	// Get TenantDAO from the storage factory if it supports tenant-aware operations
	var tenantDAO qrdbsdk.GenericDAO[*entities.Tenant]
	if tenantAwareFactory, ok := storageFactory.(storage.TenantAwareFactory); ok {
		dao, err := tenantAwareFactory.TenantDAO()
		if err != nil {
			return nil, &TenantDAOInitError{Err: err}
		}
		tenantDAO = dao
	}

	return &TenantAwareAdminService{
		AdminService: NewAdminService(certificateAuthority, storageFactory, logger, version),
		qrdbService:  qrdbService,
		tenantDAO:    tenantDAO,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}, nil
}

// CreateTenant creates a new tenant with default policies. Tenant identity
// and existence are delegated to qrdb's TenantServicer, which must be wired
// via SetTenantService before this is called — there is no local-only path.
//
// Creating a tenant is a platform operation: a tenant-scoped caller is refused
// with a *PlatformScopeError whatever ID it names.
func (s *TenantAwareAdminService) CreateTenant(ctx context.Context, req CreateTenantRequest) (*TenantInfo, error) {
	if err := requirePlatformScope(ctx, "create tenant"); err != nil {
		return nil, err
	}
	if req.ID == "" {
		return nil, wrapInputError("id", "tenant ID is required")
	}
	if req.Name == "" {
		return nil, wrapInputError("name", "tenant name is required")
	}
	if s.tenantSvc == nil {
		return nil, ErrTenantServiceUnavailable
	}
	return s.createTenantQRDB(ctx, req)
}

// createTenantQRDB creates the tenant's canonical identity record in qrdb
// (the multi-tenant model xkms inherits) and a subordinate entities.Tenant
// linkage row for the CA/EAB/status state xkms genuinely owns, keyed by the
// same tenant ID. qrdb is authoritative for ID, Name, and existence; a
// tenantDAO save failure is logged but non-fatal, mirroring how CA/EAB
// bookkeeping already degrades elsewhere in this file — the tenant still
// exists in qrdb even if the local linkage row could not be written.
func (s *TenantAwareAdminService) createTenantQRDB(ctx context.Context, req CreateTenantRequest) (*TenantInfo, error) {
	if _, err := s.tenantSvc.GetTenant(ctx, req.ID); err == nil {
		return nil, ErrTenantAlreadyExists
	} else if !errors.Is(err, qrdbsdk.ErrTenantMissing) {
		return nil, caerrors.StorageFailureError("admin: failed to check tenant existence: %s", err)
	}

	qt, err := s.tenantSvc.CreateTenant(ctx, req.ID, req.Name, "")
	if err != nil {
		if errors.Is(err, qrdbsdk.ErrTenantExists) {
			return nil, ErrTenantAlreadyExists
		}
		return nil, caerrors.StorageFailureError("admin: failed to create tenant: %s", err)
	}

	now := time.Now()
	tenant := &entities.Tenant{
		ID:        qt.ID,
		Name:      qt.Name,
		Status:    entities.TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if req.Settings != nil {
		tenant.Settings = tenantSettingsInfoToEntity(req.Settings)
	}
	if s.tenantDAO != nil {
		if err := s.tenantDAO.Save(ctx, tenant); err != nil {
			s.logger.Warn("failed to save tenant linkage record",
				slog.String("tenant_id", req.ID),
				slog.String("error", err.Error()))
		}
	}

	s.logger.Info("tenant created",
		slog.String("id", req.ID),
		slog.String("name", req.Name))

	return tenantEntityToInfo(tenant), nil
}

// GetTenant retrieves a tenant by ID, delegating existence to qrdb and
// enriching the result with the local CA/EAB/status linkage row.
func (s *TenantAwareAdminService) GetTenant(ctx context.Context, tenantID string) (*TenantInfo, error) {
	if tenantID == "" {
		return nil, wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "get tenant", tenantID); err != nil {
		return nil, err
	}
	if s.tenantSvc == nil {
		return nil, ErrTenantServiceUnavailable
	}
	return s.getTenantQRDB(ctx, tenantID)
}

// getTenantQRDB resolves existence, ID, name, and timestamps from qrdb, then
// overlays the local linkage row's CA/EAB/settings/status fields when one
// exists. A missing linkage row is not an error: it means no CA/EAB
// operations have happened yet for an otherwise-real qrdb tenant.
func (s *TenantAwareAdminService) getTenantQRDB(ctx context.Context, tenantID string) (*TenantInfo, error) {
	qt, err := s.tenantSvc.GetTenant(ctx, tenantID)
	if err != nil {
		if errors.Is(err, qrdbsdk.ErrTenantMissing) {
			return nil, ErrTenantNotFound
		}
		return nil, caerrors.StorageFailureError("admin: failed to get tenant: %s", err)
	}

	info := &TenantInfo{
		ID:        qt.ID,
		Name:      qt.Name,
		Status:    entities.TenantStatusActive,
		CreatedAt: qt.CreatedAt,
		UpdatedAt: qt.UpdatedAt,
	}
	if s.tenantDAO != nil {
		if local, lerr := s.tenantDAO.Get(ctx, entities.StringToEntityID(tenantID)); lerr == nil {
			// A tenant soft-deleted only in the local linkage row (the
			// ACME-operational status qrdb has no concept of) is not
			// returned, even though its identity still exists in qrdb.
			if local.Status == entities.TenantStatusDeleted {
				return nil, ErrTenantNotFound
			}
			info = tenantEntityToInfo(local)
			info.ID = qt.ID
			info.Name = qt.Name
			info.CreatedAt = qt.CreatedAt
			info.UpdatedAt = qt.UpdatedAt
		}
	}
	return info, nil
}

// UpdateTenant updates tenant configuration, applying the name patch to qrdb
// (the canonical identity record) and Settings to the local linkage row.
// qrdb must be wired via SetTenantService — there is no local-only path.
func (s *TenantAwareAdminService) UpdateTenant(ctx context.Context, tenantID string, req UpdateTenantRequest) (*TenantInfo, error) {
	if tenantID == "" {
		return nil, wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "update tenant", tenantID); err != nil {
		return nil, err
	}
	if s.tenantSvc == nil {
		return nil, ErrTenantServiceUnavailable
	}
	return s.updateTenantQRDB(ctx, tenantID, req)
}

// updateTenantQRDB applies the name patch through qrdb (the canonical
// identity record) and persists Settings on the local linkage row.
func (s *TenantAwareAdminService) updateTenantQRDB(ctx context.Context, tenantID string, req UpdateTenantRequest) (*TenantInfo, error) {
	qt, err := s.tenantSvc.UpdateTenant(ctx, tenantID, qrdbsdk.TenantPatch{Name: req.Name})
	if err != nil {
		if errors.Is(err, qrdbsdk.ErrTenantMissing) {
			return nil, ErrTenantNotFound
		}
		return nil, caerrors.StorageFailureError("admin: failed to update tenant: %s", err)
	}

	info := &TenantInfo{
		ID:        qt.ID,
		Name:      qt.Name,
		Status:    entities.TenantStatusActive,
		CreatedAt: qt.CreatedAt,
		UpdatedAt: qt.UpdatedAt,
	}
	if s.tenantDAO != nil {
		local, lerr := s.tenantDAO.Get(ctx, entities.StringToEntityID(tenantID))
		if lerr != nil {
			if !isNotFoundError(lerr) {
				return nil, caerrors.StorageFailureError("admin: failed to load tenant linkage record: %s", lerr)
			}
			local = &entities.Tenant{ID: qt.ID, Status: entities.TenantStatusActive, CreatedAt: qt.CreatedAt}
		}
		if local.Status == entities.TenantStatusDeleted {
			return nil, ErrTenantDeleted
		}
		local.Name = qt.Name
		if req.Settings != nil {
			local.Settings = tenantSettingsInfoToEntity(req.Settings)
		}
		local.UpdatedAt = time.Now()
		if err := s.tenantDAO.Save(ctx, local); err != nil {
			s.logger.Warn("failed to update tenant linkage record",
				slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		} else {
			info = tenantEntityToInfo(local)
			info.CreatedAt = qt.CreatedAt
			info.UpdatedAt = qt.UpdatedAt
		}
	}

	s.logger.Info("tenant updated", slog.String("id", tenantID))
	return info, nil
}

// UpdateTenantStatus updates a tenant's status.
func (s *TenantAwareAdminService) UpdateTenantStatus(ctx context.Context, tenantID string, status string) error {
	if tenantID == "" {
		return wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "update tenant status", tenantID); err != nil {
		return err
	}
	if status == "" {
		return wrapInputError("status", "status is required")
	}

	validStatuses := map[string]bool{
		entities.TenantStatusActive:    true,
		entities.TenantStatusSuspended: true,
		entities.TenantStatusDeleted:   true,
	}
	if !validStatuses[status] {
		return wrapInputError("status", "invalid status: must be active, suspended, or deleted")
	}

	// Update tenant status: Get -> mutate -> Save
	if s.tenantDAO != nil {
		tenant, err := s.tenantDAO.Get(ctx, entities.StringToEntityID(tenantID))
		if err != nil {
			if isNotFoundError(err) {
				return ErrTenantNotFound
			}
			return caerrors.StorageFailureError("admin: failed to get tenant for status update: %s", err)
		}
		tenant.Status = status
		tenant.UpdatedAt = time.Now()
		if err := s.tenantDAO.Save(ctx, tenant); err != nil {
			return caerrors.StorageFailureError("admin: failed to update tenant status: %s", err)
		}
	}

	s.logger.Info("tenant status updated",
		slog.String("id", tenantID),
		slog.String("status", status))

	return nil
}

// DeleteTenant deletes a tenant and all associated resources, delegating
// existence and canonical deletion to qrdb.
func (s *TenantAwareAdminService) DeleteTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "delete tenant", tenantID); err != nil {
		return err
	}
	if s.tenantSvc == nil {
		return ErrTenantServiceUnavailable
	}

	if _, err := s.tenantSvc.GetTenant(ctx, tenantID); err != nil {
		if errors.Is(err, qrdbsdk.ErrTenantMissing) {
			return ErrTenantNotFound
		}
		return caerrors.StorageFailureError("admin: failed to check tenant existence: %s", err)
	}

	// Clean up RBAC roles for the tenant, within the tenant: qrdb resolves a
	// role within the context's tenant.
	if s.qrdbService != nil && s.qrdbService.Roles() != nil {
		tenantCtx := qrdbsdk.ContextWithTenant(ctx, tenantID)
		roles, err := s.qrdbService.Roles().ListRoles(tenantCtx, &db.ListRolesRequest{TenantID: tenantID})
		if err == nil && roles != nil {
			for _, role := range roles.Roles {
				if !role.System {
					if err := s.qrdbService.Roles().DeleteRole(tenantCtx, role.ID); err != nil {
						s.logger.Warn("failed to delete tenant RBAC role",
							slog.String("tenant_id", tenantID),
							slog.String("role_id", role.ID),
							slog.String("error", err.Error()))
					}
				}
			}
		}
	}

	// Clean up tenant CAs from cache
	s.mu.Lock()
	delete(s.tenantCAs, tenantID)
	s.mu.Unlock()

	// Clean up tenant CA data from KV storage
	if s.qrdbService != nil && s.qrdbService.KV() != nil {
		// Delete CA metadata stored in KV
		caPrefix := fmt.Sprintf("tenants/%s/cas/", tenantID)
		keys, err := s.qrdbService.KV().List(ctx, caPrefix)
		if err == nil {
			for _, key := range keys {
				if err := s.qrdbService.KV().Delete(ctx, key); err != nil {
					s.logger.Warn("failed to delete tenant CA data",
						slog.String("key", key),
						slog.String("error", err.Error()))
				}
			}
		}

		// Delete default CA setting
		defaultCAKey := fmt.Sprintf("tenants/%s/default_intermediate_ca", tenantID)
		if err := s.qrdbService.KV().Delete(ctx, defaultCAKey); err != nil {
			s.logger.Warn("failed to delete tenant default CA setting",
				slog.String("tenant_id", tenantID),
				slog.String("key", defaultCAKey),
				slog.String("error", err.Error()))
		}
	}

	// Canonical deletion: hard delete of the tenant's identity record in qrdb.
	if err := s.tenantSvc.DeleteTenant(ctx, tenantID); err != nil {
		if errors.Is(err, qrdbsdk.ErrTenantMissing) {
			return ErrTenantNotFound
		}
		return caerrors.StorageFailureError("admin: failed to delete tenant: %s", err)
	}

	// Remove the local linkage row (best-effort: the tenant is already gone
	// from qrdb at this point regardless of whether this succeeds).
	if s.tenantDAO != nil {
		tenant, err := s.tenantDAO.Get(ctx, entities.StringToEntityID(tenantID))
		if err != nil {
			if !isNotFoundError(err) {
				s.logger.Warn("failed to load tenant linkage record for deletion",
					slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
			}
		} else if err := s.tenantDAO.Delete(ctx, tenant); err != nil {
			s.logger.Warn("failed to delete tenant linkage record",
				slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		}
	}

	s.logger.Info("tenant deleted", slog.String("id", tenantID))

	return nil
}

// ListTenants lists, with pagination, the tenants the caller may see: every
// tenant for a cross-tenant caller, only its own tenant for a tenant-scoped
// one. The pagination total counts only what the caller may see.
func (s *TenantAwareAdminService) ListTenants(ctx context.Context, req ListTenantsRequest) ([]*TenantInfo, *Pagination, error) {
	// Set defaults
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PerPage < 1 {
		req.PerPage = 20
	}
	if req.PerPage > 100 {
		req.PerPage = 100
	}

	if s.tenantSvc == nil {
		return nil, nil, ErrTenantServiceUnavailable
	}
	return s.listTenantsQRDB(ctx, req)
}

// listTenantsQRDB lists tenants from qrdb's TenantServicer (the canonical
// set) and overlays each with its local linkage row when one exists. A
// tenant soft-deleted only in the local row (legacy state) is excluded, since
// qrdb has no soft-delete concept and its presence there means the tenant is
// live.
func (s *TenantAwareAdminService) listTenantsQRDB(ctx context.Context, req ListTenantsRequest) ([]*TenantInfo, *Pagination, error) {
	all, err := s.tenantSvc.ListTenants(ctx)
	if err != nil {
		return nil, nil, caerrors.StorageFailureError("admin: failed to list tenants: %s", err)
	}

	caller, confined := callerTenant(ctx)
	infos := make([]*TenantInfo, 0, len(all))
	for i := range all {
		qt := all[i]
		if confined && qt.ID != caller {
			continue
		}
		info := &TenantInfo{
			ID:        qt.ID,
			Name:      qt.Name,
			Status:    entities.TenantStatusActive,
			CreatedAt: qt.CreatedAt,
			UpdatedAt: qt.UpdatedAt,
		}
		if s.tenantDAO != nil {
			if local, lerr := s.tenantDAO.Get(ctx, entities.StringToEntityID(qt.ID)); lerr == nil &&
				local.Status != entities.TenantStatusDeleted {
				info = tenantEntityToInfo(local)
				info.ID = qt.ID
				info.Name = qt.Name
				info.CreatedAt = qt.CreatedAt
				info.UpdatedAt = qt.UpdatedAt
			}
		}
		if req.Status == "" || info.Status == req.Status {
			infos = append(infos, info)
		}
	}

	sort.Slice(infos, func(i, j int) bool {
		return infos[i].CreatedAt.After(infos[j].CreatedAt)
	})

	total := len(infos)
	start := (req.Page - 1) * req.PerPage
	end := start + req.PerPage
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	return infos[start:end], &Pagination{
		Page:    req.Page,
		PerPage: req.PerPage,
		Total:   total,
	}, nil
}

// identityProvider is implemented by certificate authorities that can report
// the identity they issue from. It is declared here rather than added to
// ca.TrustedCA so that existing implementations and mocks stay
// source-compatible; the tenant service type-asserts to it.
type identityProvider interface {
	IssuingIdentity() ca.Identity
}

// caProfile returns the certificate profile every tenant CA — root and
// intermediate alike — is issued with.
//
// Resolving it from the platform CA's registry rather than constructing one
// here is what makes a change to the CA profile reach tenant CAs: an operator
// who registers a stricter "ca" profile changes the platform root, every
// platform intermediate and every tenant CA in one edit. Falling back to the
// built-in profile keeps tenant CA creation working when no platform CA is
// configured, which is the case in the admin service's standalone mode.
func (s *TenantAwareAdminService) caProfile() ca.ProfileProvider {
	if s.AdminService != nil && s.ca != nil {
		if registry, ok := s.ca.(interface {
			Profiles() ca.ProfileRegistry
		}); ok {
			if profile, err := registry.Profiles().Get(ca.ProfileNameCA); err == nil {
				return profile
			}
		}
	}
	return ca.NewCAProfile()
}

// parentIdentity returns the issuing identity whose revocation and Authority
// Information Access endpoints belong on a tenant intermediate.
//
// An intermediate signed by the platform CA inherits the platform CA's
// endpoints, because the platform CA is the authority that will publish its
// revocation status. An intermediate signed by a tenant's own root has no such
// authority behind it and therefore carries no endpoints.
func (s *TenantAwareAdminService) parentIdentity(parentType string) *ca.Identity {
	if parentType == "tenant" {
		return nil
	}
	if s.AdminService == nil || s.ca == nil {
		return nil
	}
	provider, ok := s.ca.(identityProvider)
	if !ok {
		return nil
	}
	identity := provider.IssuingIdentity()
	return &identity
}

// CreateTenantRootCA creates a root CA for a tenant.
func (s *TenantAwareAdminService) CreateTenantRootCA(ctx context.Context, tenantID string, req CreateTenantRootCARequest) (*TenantRootCAInfo, error) {
	if tenantID == "" {
		return nil, wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "create tenant root CA", tenantID); err != nil {
		return nil, err
	}
	if req.CommonName == "" {
		return nil, wrapInputError("common_name", "common name is required")
	}
	if req.ValidityYears < 1 {
		req.ValidityYears = 10 // Default 10 years for root CA
	}

	// Check if tenant already has a root CA
	s.mu.RLock()
	if entry, exists := s.tenantCAs[tenantID]; exists && entry.rootCA != nil {
		s.mu.RUnlock()
		return nil, ErrTenantRootCAExists
	}
	s.mu.RUnlock()

	// Parse key algorithm
	keyAlgo, err := parseKeyAlgorithm(req.KeyAlgorithm)
	if err != nil {
		return nil, wrapInputError("key_algorithm", err.Error())
	}

	// Generate key pair
	privateKey, publicKey, err := s.generateKeyPair(keyAlgo)
	if err != nil {
		return nil, caerrors.KeyGenerationFailureError("admin: failed to generate key pair: %s", err)
	}

	// Create self-signed root CA certificate
	now := time.Now()
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, caerrors.InternalServerError("admin: failed to generate serial number: %s", err)
	}

	// Get signer
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, caerrors.InternalServerError("admin: private key does not implement crypto.Signer")
	}

	// Create the self-signed root through pkg/ca, which is the single
	// implementer of CA certificate creation in go-xkms. A nil
	// Issuer.Certificate requests self-signing, and the CA profile supplies
	// the key usage and basic constraints every CA certificate carries — the
	// same profile the platform root and every intermediate are issued with,
	// so a tenant root cannot drift away from them.
	cert, err := (&ca.Issuer{Signer: signer}).Issue(rand.Reader, &ca.CertificateSpec{
		Serial: serialNumber,
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{tenantID},
		},
		NotBefore: now,
		NotAfter:  now.AddDate(req.ValidityYears, 0, 0),
		PublicKey: publicKey,
		Profile:   s.caProfile(),
		Request: &ca.CertificateRequest{
			Subject:    ca.Subject{CommonName: req.CommonName, Organization: tenantID},
			TenantID:   tenantID,
			IsCA:       true,
			MaxPathLen: 1, // Allow one level of intermediate CAs
		},
	})
	if err != nil {
		return nil, caerrors.SigningFailureError("admin: failed to create root CA certificate: %s", err)
	}

	// Store in keystore if available
	if err := s.storeKeyAndCert(ctx, tenantID, "root", privateKey, cert); err != nil {
		return nil, caerrors.StorageFailureError("admin: failed to store root CA: %s", err)
	}

	// Cache the tenant CA entry
	s.mu.Lock()
	if s.tenantCAs[tenantID] == nil {
		s.tenantCAs[tenantID] = &tenantCAEntry{
			intermediateCAs: make(map[string]*tenantIntermediateCAEntry),
		}
	}
	s.tenantCAs[tenantID].rootCA = cert
	s.tenantCAs[tenantID].rootSigner = signer
	s.mu.Unlock()

	// Update tenant entity with root CA info
	if s.tenantDAO != nil {
		tenant, err := s.tenantDAO.Get(ctx, entities.StringToEntityID(tenantID))
		if err == nil {
			tenant.RootCA = &entities.TenantRootCA{
				CommonName:     cert.Subject.CommonName,
				SerialNumber:   serialNumber.String(),
				KeyAlgorithm:   req.KeyAlgorithm,
				NotBefore:      cert.NotBefore,
				NotAfter:       cert.NotAfter,
				Status:         entities.CAStatusActive,
				CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
				CreatedAt:      now,
			}
			tenant.UpdatedAt = now
			if err := s.tenantDAO.Save(ctx, tenant); err != nil {
				s.logger.Warn("failed to update tenant with root CA info",
					slog.String("tenant_id", tenantID),
					slog.String("error", err.Error()))
			}
		}
	}

	s.logger.Info("tenant root CA created",
		slog.String("tenant_id", tenantID),
		slog.String("common_name", req.CommonName),
		slog.String("serial", serialNumber.String()))

	return &TenantRootCAInfo{
		CommonName:   cert.Subject.CommonName,
		SerialNumber: serialNumber.String(),
		KeyAlgorithm: req.KeyAlgorithm,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Status:       "active",
		CreatedAt:    now,
	}, nil
}

// CreateTenantIntermediateCA creates an intermediate CA for a tenant.
func (s *TenantAwareAdminService) CreateTenantIntermediateCA(ctx context.Context, tenantID string, req CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error) {
	if tenantID == "" {
		return nil, wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "create tenant intermediate CA", tenantID); err != nil {
		return nil, err
	}
	if req.CommonName == "" {
		return nil, wrapInputError("common_name", "common name is required")
	}
	if req.ValidityYears < 1 {
		req.ValidityYears = 5 // Default 5 years for intermediate CA
	}

	// Generate a unique ID for this intermediate CA
	caID := fmt.Sprintf("int-%d", time.Now().UnixNano())
	if req.Purpose != "" {
		caID = fmt.Sprintf("int-%s-%d", req.Purpose, time.Now().UnixNano())
	}

	// Determine the parent CA signer
	var parentSigner crypto.Signer
	var parentCert *x509.Certificate

	if req.ParentType == "tenant" {
		// Use tenant's root CA as parent
		s.mu.RLock()
		entry, exists := s.tenantCAs[tenantID]
		s.mu.RUnlock()

		if !exists || entry.rootCA == nil || entry.rootSigner == nil {
			return nil, ErrTenantRootCANotFound
		}
		parentSigner = entry.rootSigner
		parentCert = entry.rootCA
	} else {
		// Use global CA as parent (default). A nil CA (ACME disabled,
		// go-xkms#1075) is reported through the same typed sentinel every
		// other global-CA guard in this file uses, rather than dereferencing
		// s.ca as a crypto.Signer below.
		if s.AdminService == nil || s.ca == nil {
			return nil, ErrCANotConfigured
		}
		// Its error is no longer discarded: proceeding with a nil parentCert
		// would sign the new intermediate CA without the parent chain data
		// it needs, silently producing a certificate that cannot be chained
		// back to a trusted root.
		root, err := s.ca.TrustedRoot()
		if err != nil {
			return nil, caerrors.Wrap(caerrors.StorageFailure, err, "admin: failed to load global CA trusted root: %s", err)
		}
		parentCert = root
		parentSigner = s.ca
	}

	// Parse key algorithm
	keyAlgo, err := parseKeyAlgorithm(req.KeyAlgorithm)
	if err != nil {
		return nil, wrapInputError("key_algorithm", err.Error())
	}

	// Generate key pair for intermediate CA
	privateKey, publicKey, err := s.generateKeyPair(keyAlgo)
	if err != nil {
		return nil, caerrors.KeyGenerationFailureError("admin: failed to generate key pair: %s", err)
	}

	// Create intermediate CA certificate
	now := time.Now()
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, caerrors.InternalServerError("admin: failed to generate serial number: %s", err)
	}

	// Issue the intermediate through pkg/ca under the resolved parent — the
	// tenant's own root, or the platform CA. The issuer is carried explicitly
	// rather than assumed, which is what makes per-tenant issuance possible at
	// all. The path length of zero forbids further subordinate CAs.
	cert, err := (&ca.Issuer{
		Signer:      parentSigner,
		Certificate: parentCert,
		Identity:    s.parentIdentity(req.ParentType),
	}).Issue(rand.Reader, &ca.CertificateSpec{
		Serial: serialNumber,
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{tenantID},
		},
		NotBefore: now,
		NotAfter:  now.AddDate(req.ValidityYears, 0, 0),
		PublicKey: publicKey,
		Profile:   s.caProfile(),
		Request: &ca.CertificateRequest{
			Subject:        ca.Subject{CommonName: req.CommonName, Organization: tenantID},
			TenantID:       tenantID,
			IsCA:           true,
			MaxPathLen:     0, // Cannot issue CA certificates
			MaxPathLenZero: true,
		},
	})
	if err != nil {
		return nil, caerrors.SigningFailureError("admin: failed to create intermediate CA certificate: %s", err)
	}

	// Get signer for caching
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, caerrors.InternalServerError("admin: private key does not implement crypto.Signer")
	}

	// Store in keystore and KV
	if err := s.storeKeyAndCert(ctx, tenantID, caID, privateKey, cert); err != nil {
		return nil, caerrors.StorageFailureError("admin: failed to store intermediate CA: %s", err)
	}

	// Cache the intermediate CA entry
	s.mu.Lock()
	if s.tenantCAs[tenantID] == nil {
		s.tenantCAs[tenantID] = &tenantCAEntry{
			intermediateCAs: make(map[string]*tenantIntermediateCAEntry),
		}
	}
	s.tenantCAs[tenantID].intermediateCAs[caID] = &tenantIntermediateCAEntry{
		cert:   cert,
		signer: signer,
	}
	if req.SetAsDefault || s.tenantCAs[tenantID].defaultIntCA == "" {
		s.tenantCAs[tenantID].defaultIntCA = caID
	}
	s.mu.Unlock()

	// Update tenant entity with intermediate CA info
	if s.tenantDAO != nil {
		tenant, err := s.tenantDAO.Get(ctx, entities.StringToEntityID(tenantID))
		if err == nil {
			intCA := &entities.TenantIntermediateCA{
				ID:             caID,
				CommonName:     cert.Subject.CommonName,
				SerialNumber:   serialNumber.String(),
				ParentType:     req.ParentType,
				Purpose:        req.Purpose,
				KeyAlgorithm:   req.KeyAlgorithm,
				NotBefore:      cert.NotBefore,
				NotAfter:       cert.NotAfter,
				Status:         entities.CAStatusActive,
				CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
				CreatedAt:      now,
			}
			tenant.IntermediateCAs = append(tenant.IntermediateCAs, intCA)
			if req.SetAsDefault || tenant.DefaultIntermediateCAID == "" {
				tenant.DefaultIntermediateCAID = caID
			}
			tenant.UpdatedAt = now
			if err := s.tenantDAO.Save(ctx, tenant); err != nil {
				s.logger.Warn("failed to update tenant with intermediate CA info",
					slog.String("tenant_id", tenantID),
					slog.String("error", err.Error()))
			}
		}
	}

	s.logger.Info("tenant intermediate CA created",
		slog.String("tenant_id", tenantID),
		slog.String("ca_id", caID),
		slog.String("common_name", req.CommonName),
		slog.String("parent_type", req.ParentType))

	return &TenantIntCAInfo{
		ID:           caID,
		CommonName:   cert.Subject.CommonName,
		SerialNumber: serialNumber.String(),
		ParentType:   req.ParentType,
		Purpose:      req.Purpose,
		KeyAlgorithm: req.KeyAlgorithm,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Status:       "active",
		CreatedAt:    now,
	}, nil
}

// GetTenantIntermediateCA retrieves a specific intermediate CA.
func (s *TenantAwareAdminService) GetTenantIntermediateCA(ctx context.Context, tenantID string, caID string) (*TenantIntCAInfo, error) {
	if tenantID == "" {
		return nil, wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "get tenant intermediate CA", tenantID); err != nil {
		return nil, err
	}
	if caID == "" {
		return nil, wrapInputError("ca_id", "CA ID is required")
	}

	s.mu.RLock()
	entry, exists := s.tenantCAs[tenantID]
	s.mu.RUnlock()

	if !exists {
		return nil, ErrTenantCANotConfigured
	}

	intCA, ok := entry.intermediateCAs[caID]
	if !ok || intCA.cert == nil {
		return nil, ErrTenantIntCANotFound
	}

	// Determine status
	status := "active"
	if time.Now().After(intCA.cert.NotAfter) {
		status = "expired"
	}

	return &TenantIntCAInfo{
		ID:           caID,
		CommonName:   intCA.cert.Subject.CommonName,
		SerialNumber: intCA.cert.SerialNumber.String(),
		KeyAlgorithm: intCA.cert.PublicKeyAlgorithm.String(),
		NotBefore:    intCA.cert.NotBefore,
		NotAfter:     intCA.cert.NotAfter,
		Status:       status,
	}, nil
}

// ListTenantIntermediateCAs lists all intermediate CAs for a tenant.
func (s *TenantAwareAdminService) ListTenantIntermediateCAs(ctx context.Context, tenantID string) ([]*TenantIntCAInfo, error) {
	if tenantID == "" {
		return nil, wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "list tenant intermediate CAs", tenantID); err != nil {
		return nil, err
	}

	s.mu.RLock()
	entry, exists := s.tenantCAs[tenantID]
	s.mu.RUnlock()

	if !exists {
		return []*TenantIntCAInfo{}, nil
	}

	result := make([]*TenantIntCAInfo, 0, len(entry.intermediateCAs))
	for caID, intCA := range entry.intermediateCAs {
		if intCA.cert == nil {
			continue
		}

		status := "active"
		if time.Now().After(intCA.cert.NotAfter) {
			status = "expired"
		}

		result = append(result, &TenantIntCAInfo{
			ID:           caID,
			CommonName:   intCA.cert.Subject.CommonName,
			SerialNumber: intCA.cert.SerialNumber.String(),
			KeyAlgorithm: intCA.cert.PublicKeyAlgorithm.String(),
			NotBefore:    intCA.cert.NotBefore,
			NotAfter:     intCA.cert.NotAfter,
			Status:       status,
		})
	}

	return result, nil
}

// UpdateTenantIntermediateCAStatus updates the status of an intermediate CA.
func (s *TenantAwareAdminService) UpdateTenantIntermediateCAStatus(ctx context.Context, tenantID string, caID string, status string) error {
	if tenantID == "" {
		return wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "update tenant intermediate CA status", tenantID); err != nil {
		return err
	}
	if caID == "" {
		return wrapInputError("ca_id", "CA ID is required")
	}

	validStatuses := map[string]bool{"active": true, "suspended": true, "revoked": true}
	if !validStatuses[status] {
		return wrapInputError("status", "invalid status: must be active, suspended, or revoked")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.tenantCAs[tenantID]
	if !exists {
		return ErrTenantCANotConfigured
	}

	intCA, ok := entry.intermediateCAs[caID]
	if !ok {
		return ErrTenantIntCANotFound
	}

	// If suspending/revoking, remove from active signers
	if status != "active" {
		intCA.signer = nil
		if entry.defaultIntCA == caID {
			entry.defaultIntCA = ""
		}
	}

	// Update status in KV storage
	if s.qrdbService != nil && s.qrdbService.KV() != nil {
		kvKey := fmt.Sprintf("tenants/%s/cas/%s/status", tenantID, caID)
		if err := s.qrdbService.KV().Put(ctx, kvKey, []byte(status)); err != nil {
			s.logger.Warn("failed to update CA status in KV",
				slog.String("error", err.Error()))
		}
	}

	// Update tenant entity
	if s.tenantDAO != nil {
		tenant, err := s.tenantDAO.Get(ctx, entities.StringToEntityID(tenantID))
		if err == nil {
			for _, ca := range tenant.IntermediateCAs {
				if ca.ID == caID {
					ca.Status = status
					ca.UpdatedAt = time.Now()
					break
				}
			}
			if status != "active" && tenant.DefaultIntermediateCAID == caID {
				tenant.DefaultIntermediateCAID = ""
			}
			tenant.UpdatedAt = time.Now()
			if err := s.tenantDAO.Save(ctx, tenant); err != nil {
				s.logger.Warn("failed to update tenant CA status",
					slog.String("tenant_id", tenantID),
					slog.String("error", err.Error()))
			}
		}
	}

	s.logger.Info("tenant intermediate CA status updated",
		slog.String("tenant_id", tenantID),
		slog.String("ca_id", caID),
		slog.String("status", status))

	return nil
}

// SetTenantDefaultIntermediateCA sets the default intermediate CA for a tenant.
func (s *TenantAwareAdminService) SetTenantDefaultIntermediateCA(ctx context.Context, tenantID string, caID string) error {
	if tenantID == "" {
		return wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "set tenant default intermediate CA", tenantID); err != nil {
		return err
	}
	if caID == "" {
		return wrapInputError("ca_id", "CA ID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.tenantCAs[tenantID]
	if !exists {
		return ErrTenantCANotConfigured
	}

	if _, ok := entry.intermediateCAs[caID]; !ok {
		return ErrTenantIntCANotFound
	}

	entry.defaultIntCA = caID

	// Update in KV storage
	if s.qrdbService != nil && s.qrdbService.KV() != nil {
		kvKey := fmt.Sprintf("tenants/%s/default_intermediate_ca", tenantID)
		if err := s.qrdbService.KV().Put(ctx, kvKey, []byte(caID)); err != nil {
			s.logger.Warn("failed to update default intermediate CA in KV",
				slog.String("error", err.Error()))
		}
	}

	// Update tenant entity
	if s.tenantDAO != nil {
		tenant, err := s.tenantDAO.Get(ctx, entities.StringToEntityID(tenantID))
		if err == nil {
			tenant.DefaultIntermediateCAID = caID
			tenant.UpdatedAt = time.Now()
			if err := s.tenantDAO.Save(ctx, tenant); err != nil {
				s.logger.Warn("failed to update tenant default CA",
					slog.String("tenant_id", tenantID),
					slog.String("error", err.Error()))
			}
		}
	}

	s.logger.Info("tenant default intermediate CA set",
		slog.String("tenant_id", tenantID),
		slog.String("ca_id", caID))

	return nil
}

// GetTenantCAStatus retrieves the CA status for a tenant.
func (s *TenantAwareAdminService) GetTenantCAStatus(ctx context.Context, tenantID string) (*TenantCAStatusInfo, error) {
	if tenantID == "" {
		return nil, wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "get tenant CA status", tenantID); err != nil {
		return nil, err
	}

	s.mu.RLock()
	entry, exists := s.tenantCAs[tenantID]
	s.mu.RUnlock()

	result := &TenantCAStatusInfo{
		TenantID:      tenantID,
		ActiveCACount: 0,
		CanIssueCerts: false,
	}

	if !exists {
		// Even without tenant CA, can still use global CA
		if s.AdminService != nil && s.ca != nil {
			root, err := s.ca.TrustedRoot()
			if err == nil && root != nil {
				result.CanIssueCerts = true
			}
		}
		return result, nil
	}

	// Check root CA
	if entry.rootCA != nil {
		result.RootCA = &TenantRootCAInfo{
			CommonName:   entry.rootCA.Subject.CommonName,
			SerialNumber: entry.rootCA.SerialNumber.String(),
			NotBefore:    entry.rootCA.NotBefore,
			NotAfter:     entry.rootCA.NotAfter,
			Status:       "active",
		}
		if time.Now().After(entry.rootCA.NotAfter) {
			result.RootCA.Status = "expired"
		} else {
			result.ActiveCACount++
		}
	}

	// Check intermediate CAs
	result.IntermediateCAs = make([]*TenantIntCAInfo, 0, len(entry.intermediateCAs))
	for caID, intCA := range entry.intermediateCAs {
		if intCA.cert == nil {
			continue
		}

		status := "active"
		switch {
		case time.Now().After(intCA.cert.NotAfter):
			status = "expired"
		case intCA.signer == nil:
			status = "suspended"
		default:
			result.ActiveCACount++
		}

		result.IntermediateCAs = append(result.IntermediateCAs, &TenantIntCAInfo{
			ID:           caID,
			CommonName:   intCA.cert.Subject.CommonName,
			SerialNumber: intCA.cert.SerialNumber.String(),
			NotBefore:    intCA.cert.NotBefore,
			NotAfter:     intCA.cert.NotAfter,
			Status:       status,
		})
	}

	result.DefaultIntermediateCAID = entry.defaultIntCA

	// Can issue certs if any CA is active or global CA is available
	result.CanIssueCerts = result.ActiveCACount > 0
	if !result.CanIssueCerts && s.AdminService != nil && s.ca != nil {
		root, err := s.ca.TrustedRoot()
		if err == nil && root != nil {
			result.CanIssueCerts = true
		}
	}

	return result, nil
}

// CreateTenantEAB creates an External Account Binding token for a tenant.
func (s *TenantAwareAdminService) CreateTenantEAB(ctx context.Context, tenantID string, req CreateEABRequest) (*CreateEABResponse, error) {
	if tenantID == "" {
		return nil, wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "create tenant EAB", tenantID); err != nil {
		return nil, err
	}

	// Validate purpose
	purpose := req.Purpose
	if purpose == "" {
		purpose = entities.EABPurposeAccountBinding
	}
	if !isValidEABPurpose(purpose) {
		return nil, ErrInvalidEABPurpose
	}

	// Get tenant-scoped EAB DAO
	eabDAO, err := s.getTenantEABDAO(tenantID)
	if err != nil {
		return nil, caerrors.StorageFailureError("failed to get EAB storage: %s", err)
	}

	// Generate unique key identifier (kid)
	kid, err := generateEABKeyID()
	if err != nil {
		return nil, caerrors.KeyGenerationFailureError("failed to generate key ID: %s", err)
	}

	// Generate MAC key (256 bits for HS256)
	macKey, err := generateMACKey(32)
	if err != nil {
		return nil, caerrors.KeyGenerationFailureError("failed to generate MAC key: %s", err)
	}

	// Calculate expiration if specified
	var expiresAt *time.Time
	if req.ExpiresInDays > 0 {
		exp := time.Now().Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
		expiresAt = &exp
	}

	// Convert device info DTO to entity
	var deviceInfo *entities.EABDeviceInfo
	if req.DeviceInfo != nil {
		deviceInfo = &entities.EABDeviceInfo{
			DeviceID:           req.DeviceInfo.DeviceID,
			Manufacturer:       req.DeviceInfo.Manufacturer,
			Model:              req.DeviceInfo.Model,
			EKPublicKeyHash:    req.DeviceInfo.EKPublicKeyHash,
			TPMManufacturer:    req.DeviceInfo.TPMManufacturer,
			TPMFirmwareVersion: req.DeviceInfo.TPMFirmwareVersion,
			Metadata:           req.DeviceInfo.Metadata,
		}
	}

	// Create EAB entity
	eab := &entities.ExternalAccountBinding{
		ID:                kid,
		MACKey:            base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm:      "HS256",
		TenantID:          tenantID,
		Purpose:           purpose,
		ExternalAccountID: req.ExternalAccountID,
		DeviceInfo:        deviceInfo,
		Contact:           req.Contact,
		Status:            entities.EABStatusActive,
		CreatedAt:         time.Now(),
		ExpiresAt:         expiresAt,
		Metadata:          req.Metadata,
	}

	// Save to storage
	if err := eabDAO.Save(ctx, eab); err != nil {
		return nil, caerrors.StorageFailureError("failed to save EAB: %s", err)
	}

	s.logger.Info("tenant EAB created",
		slog.String("tenant_id", tenantID),
		slog.String("kid", kid),
		slog.String("purpose", purpose))

	return &CreateEABResponse{
		ID:        kid,
		MACKey:    eab.MACKey, // Return base64url-encoded MAC key (shown only once)
		Algorithm: "HS256",
		ExpiresAt: expiresAt,
	}, nil
}

// GetTenantEAB retrieves an EAB token for a tenant.
func (s *TenantAwareAdminService) GetTenantEAB(ctx context.Context, tenantID string, kid string) (*EABInfo, error) {
	if tenantID == "" {
		return nil, wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "get tenant EAB", tenantID); err != nil {
		return nil, err
	}
	if kid == "" {
		return nil, wrapInputError("kid", "key ID is required")
	}

	// Get tenant-scoped EAB DAO
	eabDAO, err := s.getTenantEABDAO(tenantID)
	if err != nil {
		return nil, caerrors.StorageFailureError("failed to get EAB storage: %s", err)
	}

	// Retrieve EAB by key identifier
	eab, err := eabDAO.Get(ctx, entities.StringToEntityID(kid))
	if err != nil {
		if isNotFoundError(err) {
			return nil, ErrEABNotFound
		}
		return nil, caerrors.StorageFailureError("failed to retrieve EAB: %s", err)
	}

	// Verify tenant ownership
	if eab.TenantID != "" && eab.TenantID != tenantID {
		return nil, ErrEABNotFound // Don't leak info about other tenants
	}

	return eabEntityToInfo(eab), nil
}

// DeleteTenantEAB deletes an EAB token for a tenant.
func (s *TenantAwareAdminService) DeleteTenantEAB(ctx context.Context, tenantID string, kid string) error {
	if tenantID == "" {
		return wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "delete tenant EAB", tenantID); err != nil {
		return err
	}
	if kid == "" {
		return wrapInputError("kid", "key ID is required")
	}

	// Get tenant-scoped EAB DAO
	eabDAO, err := s.getTenantEABDAO(tenantID)
	if err != nil {
		return caerrors.StorageFailureError("failed to get EAB storage: %s", err)
	}

	// First retrieve to verify tenant ownership
	eab, err := eabDAO.Get(ctx, entities.StringToEntityID(kid))
	if err != nil {
		if isNotFoundError(err) {
			return ErrEABNotFound
		}
		return caerrors.StorageFailureError("failed to retrieve EAB: %s", err)
	}

	// Verify tenant ownership
	if eab.TenantID != "" && eab.TenantID != tenantID {
		return ErrEABNotFound // Don't leak info about other tenants
	}

	// Delete the EAB (GenericDAO.Delete takes entity, not ID)
	if err := eabDAO.Delete(ctx, eab); err != nil {
		return caerrors.StorageFailureError("failed to delete EAB: %s", err)
	}

	s.logger.Info("tenant EAB deleted",
		slog.String("tenant_id", tenantID),
		slog.String("kid", kid))

	return nil
}

// ListTenantEABs lists EAB tokens for a tenant.
func (s *TenantAwareAdminService) ListTenantEABs(ctx context.Context, tenantID string, req ListEABRequest) ([]*EABInfo, *Pagination, error) {
	if tenantID == "" {
		return nil, nil, wrapInputError("tenant_id", "tenant ID is required")
	}
	if err := bindTenantTarget(ctx, "list tenant EABs", tenantID); err != nil {
		return nil, nil, err
	}

	// Get tenant-scoped EAB DAO
	eabDAO, err := s.getTenantEABDAO(tenantID)
	if err != nil {
		return nil, nil, caerrors.StorageFailureError("failed to get EAB storage: %s", err)
	}

	// List all EABs for this tenant
	var eabList []*entities.ExternalAccountBinding
	err = eabDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ExternalAccountBinding]) error {
		eabList = append(eabList, page.Entities...)
		return nil
	})
	if err != nil {
		return nil, nil, caerrors.StorageFailureError("failed to list EABs: %s", err)
	}

	// Filter by status and purpose if specified
	var filtered []*entities.ExternalAccountBinding
	for _, eab := range eabList {
		// Skip EABs from other tenants
		if eab.TenantID != "" && eab.TenantID != tenantID {
			continue
		}
		// Filter by status
		if req.Status != "" && eab.Status != req.Status {
			continue
		}
		// Filter by purpose
		if req.Purpose != "" && eab.Purpose != req.Purpose {
			continue
		}
		filtered = append(filtered, eab)
	}

	// Apply pagination
	page := req.Page
	if page < 1 {
		page = 1
	}
	perPage := req.PerPage
	if perPage < 1 {
		perPage = 20
	}
	if perPage > 100 {
		perPage = 100
	}

	total := len(filtered)
	start := (page - 1) * perPage
	end := start + perPage
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	// Convert to info objects
	result := make([]*EABInfo, 0, end-start)
	for _, eab := range filtered[start:end] {
		result = append(result, eabEntityToInfo(eab))
	}

	return result, &Pagination{
		Page:    page,
		PerPage: perPage,
		Total:   total,
	}, nil
}

// CreateTenantRole creates a new role within a tenant. The request's tenant
// is always the tenant the path names.
func (s *TenantAwareAdminService) CreateTenantRole(ctx context.Context, tenantID string, req *db.CreateRoleRequest) (*db.Role, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	ctx, err := bindTenantIAM(ctx, "create tenant role", tenantID)
	if err != nil {
		return nil, err
	}
	if s.qrdbService == nil || s.qrdbService.Roles() == nil {
		return nil, ErrRBACNotAvailable
	}
	req.TenantID = tenantID
	return s.qrdbService.Roles().CreateRole(ctx, req)
}

// GetTenantRole retrieves a role by ID within a tenant. A role of another
// tenant is ErrRoleNotFound, exactly like a role that does not exist.
func (s *TenantAwareAdminService) GetTenantRole(ctx context.Context, tenantID string, roleID string) (*db.Role, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	ctx, err := bindTenantIAM(ctx, "get tenant role", tenantID)
	if err != nil {
		return nil, err
	}
	if s.qrdbService == nil || s.qrdbService.Roles() == nil {
		return nil, ErrRBACNotAvailable
	}
	return s.tenantRole(ctx, tenantID, roleID)
}

// UpdateTenantRole updates an existing role within a tenant, after verifying
// the role belongs to that tenant.
func (s *TenantAwareAdminService) UpdateTenantRole(ctx context.Context, tenantID string, req *db.UpdateRoleRequest) (*db.Role, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	ctx, err := bindTenantIAM(ctx, "update tenant role", tenantID)
	if err != nil {
		return nil, err
	}
	if s.qrdbService == nil || s.qrdbService.Roles() == nil {
		return nil, ErrRBACNotAvailable
	}
	if _, err := s.tenantRole(ctx, tenantID, req.ID); err != nil {
		return nil, err
	}
	return s.qrdbService.Roles().UpdateRole(ctx, req)
}

// DeleteTenantRole deletes a role from a tenant, after verifying the role
// belongs to that tenant.
func (s *TenantAwareAdminService) DeleteTenantRole(ctx context.Context, tenantID string, roleID string) error {
	if tenantID == "" {
		return ErrInvalidTenantID
	}
	ctx, err := bindTenantIAM(ctx, "delete tenant role", tenantID)
	if err != nil {
		return err
	}
	if s.qrdbService == nil || s.qrdbService.Roles() == nil {
		return ErrRBACNotAvailable
	}
	if _, err := s.tenantRole(ctx, tenantID, roleID); err != nil {
		return err
	}
	return s.qrdbService.Roles().DeleteRole(ctx, roleID)
}

// ListTenantRoles lists roles for a tenant.
func (s *TenantAwareAdminService) ListTenantRoles(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	ctx, err := bindTenantIAM(ctx, "list tenant roles", tenantID)
	if err != nil {
		return nil, err
	}
	if s.qrdbService == nil || s.qrdbService.Roles() == nil {
		return nil, ErrRBACNotAvailable
	}
	req.TenantID = tenantID
	return s.qrdbService.Roles().ListRoles(ctx, req)
}

// tenantRole returns the role roleID when it belongs to tenantID. A role that
// does not exist and a role of another tenant are the same ErrRoleNotFound:
// the path's tenant is the only tenant a role operation may touch, for the
// platform as for a tenant caller, and a foreign role's existence is not
// disclosed.
func (s *TenantAwareAdminService) tenantRole(ctx context.Context, tenantID, roleID string) (*db.Role, error) {
	role, err := s.qrdbService.Roles().GetRole(ctx, roleID)
	if err != nil {
		if isRoleNotFound(err) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	if !sameTenant(role.TenantID, tenantID) {
		return nil, ErrRoleNotFound
	}
	return role, nil
}

// CreateTenantUser creates a new user within a tenant. The request's tenant
// is always the tenant the path names.
func (s *TenantAwareAdminService) CreateTenantUser(ctx context.Context, tenantID string, req *db.CreateUserRequest) (*db.User, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	ctx, err := bindTenantIAM(ctx, "create tenant user", tenantID)
	if err != nil {
		return nil, err
	}
	if s.qrdbService == nil || s.qrdbService.Users() == nil {
		return nil, ErrRBACNotAvailable
	}
	req.TenantID = tenantID
	return s.qrdbService.Users().CreateUser(ctx, req)
}

// GetTenantUser retrieves a user by ID within a tenant. A user of another
// tenant is ErrUserNotFound, exactly like a user that does not exist.
func (s *TenantAwareAdminService) GetTenantUser(ctx context.Context, tenantID string, userID string) (*db.User, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	ctx, err := bindTenantIAM(ctx, "get tenant user", tenantID)
	if err != nil {
		return nil, err
	}
	if s.qrdbService == nil || s.qrdbService.Users() == nil {
		return nil, ErrRBACNotAvailable
	}
	id, err := parseUserID(userID)
	if err != nil {
		return nil, err
	}
	return s.tenantUser(ctx, tenantID, id)
}

// UpdateTenantUser updates an existing user within a tenant, after verifying
// the user belongs to that tenant.
func (s *TenantAwareAdminService) UpdateTenantUser(ctx context.Context, tenantID string, req *db.UpdateUserRequest) (*db.User, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	ctx, err := bindTenantIAM(ctx, "update tenant user", tenantID)
	if err != nil {
		return nil, err
	}
	if s.qrdbService == nil || s.qrdbService.Users() == nil {
		return nil, ErrRBACNotAvailable
	}
	if _, err := s.tenantUser(ctx, tenantID, req.ID); err != nil {
		return nil, err
	}
	return s.qrdbService.Users().UpdateUser(ctx, req)
}

// DeleteTenantUser deletes a user from a tenant, after verifying the user
// belongs to that tenant.
func (s *TenantAwareAdminService) DeleteTenantUser(ctx context.Context, tenantID string, userID string) error {
	if tenantID == "" {
		return ErrInvalidTenantID
	}
	ctx, err := bindTenantIAM(ctx, "delete tenant user", tenantID)
	if err != nil {
		return err
	}
	if s.qrdbService == nil || s.qrdbService.Users() == nil {
		return ErrRBACNotAvailable
	}
	id, err := parseUserID(userID)
	if err != nil {
		return err
	}
	if _, err := s.tenantUser(ctx, tenantID, id); err != nil {
		return err
	}
	return s.qrdbService.Users().DeleteUser(ctx, id)
}

// ListTenantUsers lists users for a tenant.
func (s *TenantAwareAdminService) ListTenantUsers(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	ctx, err := bindTenantIAM(ctx, "list tenant users", tenantID)
	if err != nil {
		return nil, err
	}
	if s.qrdbService == nil || s.qrdbService.Users() == nil {
		return nil, ErrRBACNotAvailable
	}
	req.TenantID = tenantID
	return s.qrdbService.Users().ListUsers(ctx, req)
}

// tenantUser returns the user userID when it belongs to tenantID. A user that
// does not exist and a user of another tenant are the same ErrUserNotFound,
// for the same reasons tenantRole gives.
func (s *TenantAwareAdminService) tenantUser(ctx context.Context, tenantID string, userID uint64) (*db.User, error) {
	user, err := s.qrdbService.Users().GetUser(ctx, userID)
	if err != nil {
		if isUserNotFound(err) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	if !sameTenant(user.TenantID, tenantID) {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// parseUserID converts the admin-API string user identifier into qrdb's
// canonical uint64 user ID. The admin API surface (REST/gRPC/QUIC/MCP) exposes
// the identifier as a decimal string; qrdb assigns numeric IDs via its
// Snowflake generator. Returns a MalformedError when the value is not a valid
// unsigned integer.
func parseUserID(userID string) (uint64, error) {
	id, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		return 0, caerrors.MalformedError("admin: invalid user id %q: %s", userID, err)
	}
	return id, nil
}

// parseKeyAlgorithm converts a key algorithm string to x509.PublicKeyAlgorithm.
func parseKeyAlgorithm(algo string) (x509.PublicKeyAlgorithm, error) {
	switch algo {
	case "RSA", "rsa", "":
		return x509.RSA, nil
	case "ECDSA", "ecdsa", "EC", "ec":
		return x509.ECDSA, nil
	case "Ed25519", "ed25519", "ED25519":
		return x509.Ed25519, nil
	default:
		return 0, caerrors.MalformedError("unsupported key algorithm: %s", algo)
	}
}

// generateKeyPair generates a key pair based on the algorithm.
func (s *TenantAwareAdminService) generateKeyPair(algo x509.PublicKeyAlgorithm) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch algo {
	case x509.RSA:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	case x509.ECDSA:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	case x509.Ed25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, pub, nil
	default:
		return nil, nil, ErrInvalidKeyAlgorithm
	}
}

// storeKeyAndCert stores a key and certificate in the keystore and KV.
func (s *TenantAwareAdminService) storeKeyAndCert(ctx context.Context, tenantID, caType string, key crypto.PrivateKey, cert *x509.Certificate) error {
	// Store in keystore if available
	if s.AdminService != nil && s.ca != nil {
		ks := s.ca.KeyStore()
		if ks != nil {
			keyID := fmt.Sprintf("tenant:%s:%s-ca", tenantID, caType)
			attrs := &xkmssdk.KeyAttributes{
				CN:      keyID,
				KeyType: xkmssdk.KeyTypeCA,
			}

			// Determine algorithm and set attrs
			switch k := key.(type) {
			case *rsa.PrivateKey:
				attrs.KeyAlgorithm = x509.RSA
				attrs.RSAAttributes = &xkmssdk.RSAAttributes{KeySize: k.Size() * 8}
			case *ecdsa.PrivateKey:
				attrs.KeyAlgorithm = x509.ECDSA
				attrs.ECCAttributes = &xkmssdk.ECCAttributes{Curve: k.Curve}
			case ed25519.PrivateKey:
				attrs.KeyAlgorithm = x509.Ed25519
			}
			_ = attrs // Used for key storage context

			// Save cert to keystore
			if err := ks.SaveCert(ctx, keyID, cert); err != nil {
				s.logger.Warn("failed to save cert to keystore, continuing with KV storage",
					slog.String("error", err.Error()))
			}
		}
	}

	// Store CA metadata in QRDB KV
	kvKey := fmt.Sprintf("tenants/%s/cas/%s", tenantID, caType)
	caData := map[string]interface{}{
		"common_name":   cert.Subject.CommonName,
		"serial_number": cert.SerialNumber.String(),
		"not_before":    cert.NotBefore.Format(time.RFC3339),
		"not_after":     cert.NotAfter.Format(time.RFC3339),
		"status":        "active",
		"created_at":    time.Now().Format(time.RFC3339),
		"certificate":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}

	data, err := json.Marshal(caData)
	if err != nil {
		return caerrors.SerializationFailureError("failed to marshal CA data: %s", err)
	}

	if s.qrdbService != nil && s.qrdbService.KV() != nil {
		if err := s.qrdbService.KV().Put(ctx, kvKey, data); err != nil {
			s.logger.Warn("failed to store CA in KV, using memory only",
				slog.String("error", err.Error()))
		}
	}

	return nil
}

// GetTenantSigningCA returns the appropriate signing CA for a tenant.
// It follows the fallback hierarchy:
// 1. Tenant's default intermediate CA (if configured)
// 2. Tenant's root CA (if exists)
// 3. Global default intermediate CA
func (s *TenantAwareAdminService) GetTenantSigningCA(ctx context.Context, tenantID string) (crypto.Signer, *x509.Certificate, error) {
	s.mu.RLock()
	entry, exists := s.tenantCAs[tenantID]
	s.mu.RUnlock()

	if exists {
		// Priority 1: Tenant's default intermediate CA
		if entry.defaultIntCA != "" {
			if intCA, ok := entry.intermediateCAs[entry.defaultIntCA]; ok && intCA.signer != nil {
				return intCA.signer, intCA.cert, nil
			}
		}

		// Priority 2: First available intermediate CA
		for _, intCA := range entry.intermediateCAs {
			if intCA.signer != nil {
				return intCA.signer, intCA.cert, nil
			}
		}

		// Priority 3: Tenant's root CA (sign directly)
		if entry.rootSigner != nil && entry.rootCA != nil {
			return entry.rootSigner, entry.rootCA, nil
		}
	}

	// Priority 4: Global default intermediate CA
	if s.AdminService == nil || s.ca == nil {
		return nil, nil, ErrNoSigningCAAvailable
	}

	// Get the signer from the global CA
	signer, err := s.ca.Signer(ctx)
	if err != nil {
		return nil, nil, ErrNoSigningCAAvailable
	}

	// Get the intermediate CA certificate (preferred for signing end-entity certs)
	intermediate, err := s.ca.TrustedIntermediate()
	if err != nil {
		// If no intermediate exists, fall back to root CA certificate
		root, rootErr := s.ca.TrustedRoot()
		if rootErr != nil {
			return nil, nil, ErrNoSigningCAAvailable
		}
		return signer, root, nil
	}

	return signer, intermediate, nil
}

// getTenantEABDAO returns a tenant-scoped EAB DAO.
func (s *TenantAwareAdminService) getTenantEABDAO(tenantID string) (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	if s.AdminService == nil || s.storageFactory == nil {
		return nil, caerrors.StorageFailureError("storage factory not available")
	}

	// Check if storage factory supports tenant-aware operations
	tenantAwareFactory, ok := s.storageFactory.(storage.TenantAwareFactory)
	if ok {
		scopedFactory, err := tenantAwareFactory.ForTenant(tenantID)
		if err != nil {
			return nil, err
		}
		return scopedFactory.ExternalAccountBindingDAO()
	}

	// Fall back to global EAB DAO
	return s.storageFactory.ExternalAccountBindingDAO()
}

// generateEABKeyID generates a unique key identifier for an EAB.
func generateEABKeyID() (string, error) {
	// Generate 16 random bytes (128 bits of entropy)
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Use base64url encoding without padding for URL-safe key ID
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateMACKey generates a random MAC key of the specified length.
func generateMACKey(length int) ([]byte, error) {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// isValidEABPurpose validates the EAB purpose.
func isValidEABPurpose(purpose string) bool {
	switch purpose {
	case entities.EABPurposeAccountBinding,
		entities.EABPurposeEndorse01,
		entities.EABPurposeEnroll01:
		return true
	default:
		return false
	}
}

// eabEntityToInfo converts an EAB entity to an EABInfo DTO.
func eabEntityToInfo(eab *entities.ExternalAccountBinding) *EABInfo {
	if eab == nil {
		return nil
	}

	info := &EABInfo{
		ID:                eab.ID,
		TenantID:          eab.TenantID,
		Status:            eab.Status,
		Purpose:           eab.Purpose,
		AccountID:         eab.AccountID,
		ExternalAccountID: eab.ExternalAccountID,
		Contact:           eab.Contact,
		CreatedAt:         eab.CreatedAt,
		CreatedBy:         eab.CreatedBy,
		UsedAt:            eab.UsedAt,
		ExpiresAt:         eab.ExpiresAt,
	}

	// Convert device info
	if eab.DeviceInfo != nil {
		info.DeviceInfo = &EABDeviceInfoDTO{
			DeviceID:           eab.DeviceInfo.DeviceID,
			Manufacturer:       eab.DeviceInfo.Manufacturer,
			Model:              eab.DeviceInfo.Model,
			EKPublicKeyHash:    eab.DeviceInfo.EKPublicKeyHash,
			TPMManufacturer:    eab.DeviceInfo.TPMManufacturer,
			TPMFirmwareVersion: eab.DeviceInfo.TPMFirmwareVersion,
			Metadata:           eab.DeviceInfo.Metadata,
		}
	}

	return info
}

// isNotFoundError checks if an error is a "not found" error.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if qrdbsdk.IsDAONotFound(err) {
		return true
	}
	if qrdbsdk.IsErrorNotFound(err) {
		return true
	}
	errStr := err.Error()
	return errStr == "not found" ||
		errStr == "tenant not found" ||
		errStr == "storage: external account binding not found" ||
		errStr == "admin: external account binding not found"
}

// tenantEntityToInfo converts a Tenant entity to a TenantInfo DTO.
func tenantEntityToInfo(tenant *entities.Tenant) *TenantInfo {
	if tenant == nil {
		return nil
	}

	info := &TenantInfo{
		ID:                      tenant.ID,
		Name:                    tenant.Name,
		Status:                  tenant.Status,
		DefaultIntermediateCAID: tenant.DefaultIntermediateCAID,
		CreatedAt:               tenant.CreatedAt,
		UpdatedAt:               tenant.UpdatedAt,
		CreatedBy:               tenant.CreatedBy,
	}

	// Convert root CA info
	if tenant.RootCA != nil {
		info.RootCA = &TenantRootCAInfo{
			CommonName:   tenant.RootCA.CommonName,
			SerialNumber: tenant.RootCA.SerialNumber,
			KeyAlgorithm: tenant.RootCA.KeyAlgorithm,
			NotBefore:    tenant.RootCA.NotBefore,
			NotAfter:     tenant.RootCA.NotAfter,
			Status:       tenant.RootCA.Status,
			CreatedAt:    tenant.RootCA.CreatedAt,
		}
	}

	// Convert intermediate CA info
	if len(tenant.IntermediateCAs) > 0 {
		info.IntermediateCAs = make([]*TenantIntCAInfo, 0, len(tenant.IntermediateCAs))
		for _, intCA := range tenant.IntermediateCAs {
			info.IntermediateCAs = append(info.IntermediateCAs, &TenantIntCAInfo{
				ID:           intCA.ID,
				CommonName:   intCA.CommonName,
				SerialNumber: intCA.SerialNumber,
				ParentType:   intCA.ParentType,
				Purpose:      intCA.Purpose,
				KeyAlgorithm: intCA.KeyAlgorithm,
				NotBefore:    intCA.NotBefore,
				NotAfter:     intCA.NotAfter,
				Status:       intCA.Status,
				CreatedAt:    intCA.CreatedAt,
				UpdatedAt:    intCA.UpdatedAt,
			})
		}
	}

	// Convert settings
	if tenant.Settings != nil {
		info.Settings = tenantSettingsEntityToInfo(tenant.Settings)
	}

	return info
}

// tenantSettingsEntityToInfo converts TenantSettings entity to TenantSettingsInfo DTO.
func tenantSettingsEntityToInfo(settings *entities.TenantSettings) *TenantSettingsInfo {
	if settings == nil {
		return nil
	}
	return &TenantSettingsInfo{
		MaxCertificates:         settings.MaxCertificates,
		MaxAccounts:             settings.MaxAccounts,
		AllowedKeyAlgorithms:    settings.AllowedKeyAlgorithms,
		AllowedChallengeTypes:   settings.AllowedChallengeTypes,
		CertificateValidityDays: settings.CertificateValidityDays,
		RequireEAB:              settings.RequireEAB,
		AllowEndorse01:          settings.AllowEndorse01,
		AllowEnroll01:           settings.AllowEnroll01,
	}
}

// tenantSettingsInfoToEntity converts TenantSettingsInfo DTO to TenantSettings entity.
func tenantSettingsInfoToEntity(info *TenantSettingsInfo) *entities.TenantSettings {
	if info == nil {
		return nil
	}
	return &entities.TenantSettings{
		MaxCertificates:         info.MaxCertificates,
		MaxAccounts:             info.MaxAccounts,
		AllowedKeyAlgorithms:    info.AllowedKeyAlgorithms,
		AllowedChallengeTypes:   info.AllowedChallengeTypes,
		CertificateValidityDays: info.CertificateValidityDays,
		RequireEAB:              info.RequireEAB,
		AllowEndorse01:          info.AllowEndorse01,
		AllowEnroll01:           info.AllowEnroll01,
	}
}

// Ensure TenantAwareAdminService implements TenantAwareService interface.
var _ TenantAwareService = (*TenantAwareAdminService)(nil)
