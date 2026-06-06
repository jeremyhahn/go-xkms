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
	"github.com/jeremyhahn/go-xkms/pkg/acme/qrdb"
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

// TenantAwareAdminService provides multi-tenant admin operations.
// It embeds AdminService for base operations and adds tenant-specific functionality.
type TenantAwareAdminService struct {
	*AdminService
	qrdbService qrdb.Service
	tenantDAO   qrdbsdk.GenericDAO[*entities.Tenant]
	logger      *slog.Logger
	tenantCAs   map[string]*tenantCAEntry
	mu          sync.RWMutex
	barrierSvc  BarrierService
	setupSvc    SetupService
}

// NewTenantAwareAdminService creates a new tenant-aware admin service.
func NewTenantAwareAdminService(
	certificateAuthority ca.TCGCA,
	storageFactory storage.Factory,
	qrdbService qrdb.Service,
	logger *slog.Logger,
	version string,
) *TenantAwareAdminService {
	// Get TenantDAO from the storage factory if it supports tenant-aware operations
	var tenantDAO qrdbsdk.GenericDAO[*entities.Tenant]
	if tenantAwareFactory, ok := storageFactory.(storage.TenantAwareFactory); ok {
		tenantDAO, _ = tenantAwareFactory.TenantDAO()
	}

	return &TenantAwareAdminService{
		AdminService: NewAdminService(certificateAuthority, storageFactory, logger, version),
		qrdbService:  qrdbService,
		tenantDAO:    tenantDAO,
		logger:       logger,
		tenantCAs:    make(map[string]*tenantCAEntry),
	}
}

// BarrierSvc returns the barrier service for seal/unseal operations.
func (s *TenantAwareAdminService) BarrierSvc() BarrierService {
	return s.barrierSvc
}

// SetBarrierService sets the barrier service on the tenant-aware admin service.
func (s *TenantAwareAdminService) SetBarrierService(svc BarrierService) {
	s.barrierSvc = svc
}

// SetupSvc returns the setup service for first-run initialization.
func (s *TenantAwareAdminService) SetupSvc() SetupService {
	return s.setupSvc
}

// SetSetupService sets the setup service on the tenant-aware admin service.
func (s *TenantAwareAdminService) SetSetupService(svc SetupService) {
	s.setupSvc = svc
}

// CreateTenant creates a new tenant with default policies.
func (s *TenantAwareAdminService) CreateTenant(ctx context.Context, req CreateTenantRequest) (*TenantInfo, error) {
	if req.ID == "" {
		return nil, wrapInputError("id", "tenant ID is required")
	}
	if req.Name == "" {
		return nil, wrapInputError("name", "tenant name is required")
	}

	// Check if tenant already exists
	if s.tenantDAO != nil {
		_, err := s.tenantDAO.Get(ctx, entities.StringToEntityID(req.ID))
		if err != nil && !qrdbsdk.IsDAONotFound(err) {
			s.logger.Warn("failed to check tenant existence",
				slog.String("tenant_id", req.ID),
				slog.String("error", err.Error()))
		}
		if err == nil {
			return nil, ErrTenantAlreadyExists
		}
	}

	now := time.Now()

	// Create tenant entity
	tenant := &entities.Tenant{
		ID:        req.ID,
		Name:      req.Name,
		Status:    entities.TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Convert settings if provided
	if req.Settings != nil {
		tenant.Settings = tenantSettingsInfoToEntity(req.Settings)
	}

	// Store tenant entity in QRDB KV
	if s.tenantDAO != nil {
		if err := s.tenantDAO.Save(ctx, tenant); err != nil {
			return nil, caerrors.StorageFailureError("admin: failed to save tenant: %s", err)
		}
	}

	// Create default RBAC roles for the new tenant
	if s.qrdbService != nil && s.qrdbService.Roles() != nil {
		defaultRoles := []struct {
			name        string
			permissions []string
		}{
			{
				name: string(RoleAdmin),
				permissions: []string{
					string(PermCertificatesRead), string(PermCertificatesList), string(PermCertificatesCreate), string(PermCertificatesRevoke),
					string(PermAccountsRead), string(PermAccountsList), string(PermAccountsDisable),
					string(PermOrdersRead), string(PermOrdersList),
					string(PermTenantsRead), string(PermTenantsUpdate),
					string(PermTenantCARead), string(PermTenantCACreate), string(PermTenantCAUpdate),
					string(PermEABRead), string(PermEABList), string(PermEABCreate), string(PermEABDelete),
					string(PermRolesRead), string(PermRolesList), string(PermRolesCreate), string(PermRolesUpdate), string(PermRolesDelete),
					string(PermUsersRead), string(PermUsersList), string(PermUsersCreate), string(PermUsersUpdate), string(PermUsersDelete),
				},
			},
			{
				name: string(RoleOperator),
				permissions: []string{
					string(PermCertificatesRead), string(PermCertificatesList), string(PermCertificatesCreate),
					string(PermAccountsRead), string(PermAccountsList),
					string(PermOrdersRead), string(PermOrdersList),
					string(PermEABRead), string(PermEABList), string(PermEABCreate),
				},
			},
			{
				name: string(RoleViewer),
				permissions: []string{
					string(PermCertificatesRead), string(PermCertificatesList),
					string(PermAccountsRead), string(PermAccountsList),
					string(PermOrdersRead), string(PermOrdersList),
				},
			},
		}
		for _, dr := range defaultRoles {
			_, err := s.qrdbService.Roles().CreateRole(ctx, &db.CreateRoleRequest{
				Name:        dr.name,
				TenantID:    req.ID,
				Permissions: dr.permissions,
			})
			if err != nil {
				s.logger.Warn("failed to create default role",
					slog.String("tenant_id", req.ID),
					slog.String("role", dr.name),
					slog.String("error", err.Error()))
			}
		}
	}
	s.logger.Info("tenant created",
		slog.String("id", req.ID),
		slog.String("name", req.Name))

	return tenantEntityToInfo(tenant), nil
}

// GetTenant retrieves a tenant by ID.
func (s *TenantAwareAdminService) GetTenant(ctx context.Context, tenantID string) (*TenantInfo, error) {
	if tenantID == "" {
		return nil, wrapInputError("tenant_id", "tenant ID is required")
	}

	// Retrieve tenant from QRDB KV storage
	if s.tenantDAO != nil {
		tenant, err := s.tenantDAO.Get(ctx, entities.StringToEntityID(tenantID))
		if err != nil {
			if isNotFoundError(err) {
				return nil, ErrTenantNotFound
			}
			return nil, caerrors.StorageFailureError("admin: failed to get tenant: %s", err)
		}
		// Soft-deleted tenants should not be returned
		if tenant.Status == entities.TenantStatusDeleted {
			return nil, ErrTenantNotFound
		}
		return tenantEntityToInfo(tenant), nil
	}
	return nil, ErrTenantNotFound
}

// UpdateTenant updates tenant configuration.
func (s *TenantAwareAdminService) UpdateTenant(ctx context.Context, tenantID string, req UpdateTenantRequest) (*TenantInfo, error) {
	if tenantID == "" {
		return nil, wrapInputError("tenant_id", "tenant ID is required")
	}

	// Get existing tenant
	if s.tenantDAO == nil {
		return nil, caerrors.StorageFailureError("admin: tenant storage not available")
	}

	tenant, err := s.tenantDAO.Get(ctx, entities.StringToEntityID(tenantID))
	if err != nil {
		if isNotFoundError(err) {
			return nil, ErrTenantNotFound
		}
		return nil, caerrors.StorageFailureError("admin: failed to get tenant: %s", err)
	}

	// Check tenant status
	if tenant.Status == entities.TenantStatusDeleted {
		return nil, ErrTenantDeleted
	}

	// Update fields
	if req.Name != "" {
		tenant.Name = req.Name
	}
	if req.Settings != nil {
		tenant.Settings = tenantSettingsInfoToEntity(req.Settings)
	}
	tenant.UpdatedAt = time.Now()

	// Update tenant in QRDB KV storage
	if err := s.tenantDAO.Save(ctx, tenant); err != nil {
		return nil, caerrors.StorageFailureError("admin: failed to update tenant: %s", err)
	}

	s.logger.Info("tenant updated", slog.String("id", tenantID))

	return tenantEntityToInfo(tenant), nil
}

// UpdateTenantStatus updates a tenant's status.
func (s *TenantAwareAdminService) UpdateTenantStatus(ctx context.Context, tenantID string, status string) error {
	if tenantID == "" {
		return wrapInputError("tenant_id", "tenant ID is required")
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

// DeleteTenant deletes a tenant and all associated resources.
func (s *TenantAwareAdminService) DeleteTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return wrapInputError("tenant_id", "tenant ID is required")
	}

	// Verify tenant exists
	if s.tenantDAO != nil {
		_, err := s.tenantDAO.Get(ctx, entities.StringToEntityID(tenantID))
		if err != nil {
			if isNotFoundError(err) {
				return ErrTenantNotFound
			}
			return caerrors.StorageFailureError("admin: failed to check tenant existence: %s", err)
		}
	}

	// Clean up RBAC roles for the tenant
	if s.qrdbService != nil && s.qrdbService.Roles() != nil {
		roles, err := s.qrdbService.Roles().ListRoles(ctx, &db.ListRolesRequest{TenantID: tenantID})
		if err == nil && roles != nil {
			for _, role := range roles.Roles {
				if !role.System {
					_ = s.qrdbService.Roles().DeleteRole(ctx, role.ID)
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
		_ = s.qrdbService.KV().Delete(ctx, defaultCAKey)
	}

	// Soft delete tenant entity: Get -> Delete(entity)
	if s.tenantDAO != nil {
		tenant, err := s.tenantDAO.Get(ctx, entities.StringToEntityID(tenantID))
		if err != nil {
			if !isNotFoundError(err) {
				return caerrors.StorageFailureError("admin: failed to get tenant for deletion: %s", err)
			}
		} else {
			if err := s.tenantDAO.Delete(ctx, tenant); err != nil {
				return caerrors.StorageFailureError("admin: failed to delete tenant: %s", err)
			}
		}
	}

	s.logger.Info("tenant deleted", slog.String("id", tenantID))

	return nil
}

// ListTenants lists all tenants with pagination.
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

	// List tenants from QRDB KV storage
	if s.tenantDAO == nil {
		return []*TenantInfo{}, &Pagination{
			Page:    req.Page,
			PerPage: req.PerPage,
			Total:   0,
		}, nil
	}

	// Get all tenants then filter by status in-memory
	var tenants []*entities.Tenant
	err := s.tenantDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.Tenant]) error {
		for _, t := range page.Entities {
			if req.Status == "" || t.Status == req.Status {
				tenants = append(tenants, t)
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, caerrors.StorageFailureError("admin: failed to list tenants: %s", err)
	}

	// Sort by created time descending (newest first) for consistent pagination
	sort.Slice(tenants, func(i, j int) bool {
		return tenants[i].CreatedAt.After(tenants[j].CreatedAt)
	})

	// Apply pagination
	total := len(tenants)
	start := (req.Page - 1) * req.PerPage
	end := start + req.PerPage
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	// Convert to info objects
	result := make([]*TenantInfo, 0, end-start)
	for _, tenant := range tenants[start:end] {
		result = append(result, tenantEntityToInfo(tenant))
	}

	return result, &Pagination{
		Page:    req.Page,
		PerPage: req.PerPage,
		Total:   total,
	}, nil
}

// CreateTenantRootCA creates a root CA for a tenant.
func (s *TenantAwareAdminService) CreateTenantRootCA(ctx context.Context, tenantID string, req CreateTenantRootCARequest) (*TenantRootCAInfo, error) {
	if tenantID == "" {
		return nil, wrapInputError("tenant_id", "tenant ID is required")
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

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{tenantID},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(req.ValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1, // Allow one level of intermediate CAs
		MaxPathLenZero:        false,
	}

	// Get signer
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, caerrors.InternalServerError("admin: private key does not implement crypto.Signer")
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, signer)
	if err != nil {
		return nil, caerrors.SigningFailureError("admin: failed to create root CA certificate: %s", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, caerrors.InternalServerError("admin: failed to parse root CA certificate: %s", err)
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
		// Use global CA as parent (default)
		parentCert, _ = s.ca.TrustedRoot()
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

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{tenantID},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(req.ValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // Cannot issue CA certificates
		MaxPathLenZero:        true,
	}

	// Sign with parent CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, parentCert, publicKey, parentSigner)
	if err != nil {
		return nil, caerrors.SigningFailureError("admin: failed to create intermediate CA certificate: %s", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, caerrors.InternalServerError("admin: failed to parse intermediate CA certificate: %s", err)
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
		if time.Now().After(intCA.cert.NotAfter) {
			status = "expired"
		} else if intCA.signer == nil {
			status = "suspended"
		} else {
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

// CreateTenantRole creates a new role within a tenant.
func (s *TenantAwareAdminService) CreateTenantRole(ctx context.Context, tenantID string, req *db.CreateRoleRequest) (*db.Role, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	if s.qrdbService == nil || s.qrdbService.Roles() == nil {
		return nil, ErrRBACNotAvailable
	}
	req.TenantID = tenantID
	return s.qrdbService.Roles().CreateRole(ctx, req)
}

// GetTenantRole retrieves a role by ID within a tenant.
func (s *TenantAwareAdminService) GetTenantRole(ctx context.Context, tenantID string, roleID string) (*db.Role, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	if s.qrdbService == nil || s.qrdbService.Roles() == nil {
		return nil, ErrRBACNotAvailable
	}
	return s.qrdbService.Roles().GetRole(ctx, roleID)
}

// UpdateTenantRole updates an existing role within a tenant.
func (s *TenantAwareAdminService) UpdateTenantRole(ctx context.Context, tenantID string, req *db.UpdateRoleRequest) (*db.Role, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	if s.qrdbService == nil || s.qrdbService.Roles() == nil {
		return nil, ErrRBACNotAvailable
	}
	return s.qrdbService.Roles().UpdateRole(ctx, req)
}

// DeleteTenantRole deletes a role from a tenant.
func (s *TenantAwareAdminService) DeleteTenantRole(ctx context.Context, tenantID string, roleID string) error {
	if tenantID == "" {
		return ErrInvalidTenantID
	}
	if s.qrdbService == nil || s.qrdbService.Roles() == nil {
		return ErrRBACNotAvailable
	}
	return s.qrdbService.Roles().DeleteRole(ctx, roleID)
}

// ListTenantRoles lists roles for a tenant.
func (s *TenantAwareAdminService) ListTenantRoles(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	if s.qrdbService == nil || s.qrdbService.Roles() == nil {
		return nil, ErrRBACNotAvailable
	}
	req.TenantID = tenantID
	return s.qrdbService.Roles().ListRoles(ctx, req)
}

// CreateTenantUser creates a new user within a tenant.
func (s *TenantAwareAdminService) CreateTenantUser(ctx context.Context, tenantID string, req *db.CreateUserRequest) (*db.User, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	if s.qrdbService == nil || s.qrdbService.Users() == nil {
		return nil, ErrRBACNotAvailable
	}
	req.TenantID = tenantID
	return s.qrdbService.Users().CreateUser(ctx, req)
}

// GetTenantUser retrieves a user by ID within a tenant.
func (s *TenantAwareAdminService) GetTenantUser(ctx context.Context, tenantID string, userID string) (*db.User, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	if s.qrdbService == nil || s.qrdbService.Users() == nil {
		return nil, ErrRBACNotAvailable
	}
	id, err := parseUserID(userID)
	if err != nil {
		return nil, err
	}
	return s.qrdbService.Users().GetUser(ctx, id)
}

// UpdateTenantUser updates an existing user within a tenant.
func (s *TenantAwareAdminService) UpdateTenantUser(ctx context.Context, tenantID string, req *db.UpdateUserRequest) (*db.User, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	if s.qrdbService == nil || s.qrdbService.Users() == nil {
		return nil, ErrRBACNotAvailable
	}
	return s.qrdbService.Users().UpdateUser(ctx, req)
}

// DeleteTenantUser deletes a user from a tenant.
func (s *TenantAwareAdminService) DeleteTenantUser(ctx context.Context, tenantID string, userID string) error {
	if tenantID == "" {
		return ErrInvalidTenantID
	}
	if s.qrdbService == nil || s.qrdbService.Users() == nil {
		return ErrRBACNotAvailable
	}
	id, err := parseUserID(userID)
	if err != nil {
		return err
	}
	return s.qrdbService.Users().DeleteUser(ctx, id)
}

// ListTenantUsers lists users for a tenant.
func (s *TenantAwareAdminService) ListTenantUsers(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID
	}
	if s.qrdbService == nil || s.qrdbService.Users() == nil {
		return nil, ErrRBACNotAvailable
	}
	req.TenantID = tenantID
	return s.qrdbService.Users().ListUsers(ctx, req)
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
			if err := ks.SaveCert(keyID, cert); err != nil {
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
	signer, err := s.ca.Signer()
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
	if qrdb.IsNotFound(err) {
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
