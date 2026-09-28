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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// AdminService provides business logic for admin operations
type AdminService struct {
	ca             ca.TCGCA
	storageFactory storage.Factory
	logger         *slog.Logger
	version        string
	startTime      time.Time
}

// NewAdminService creates a new admin service instance
func NewAdminService(
	certificateAuthority ca.TCGCA,
	storageFactory storage.Factory,
	logger *slog.Logger,
	version string,
) *AdminService {
	return &AdminService{
		ca:             certificateAuthority,
		storageFactory: storageFactory,
		logger:         logger,
		version:        version,
		startTime:      time.Now(),
	}
}

// ListCertificates retrieves a paginated list of certificates
func (s *AdminService) ListCertificates(ctx context.Context, req ListCertificatesRequest) ([]*CertificateInfo, *Pagination, error) {
	if s.storageFactory == nil {
		return nil, nil, ErrStorageNotConfigured
	}

	// Set default pagination
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PerPage < 1 {
		req.PerPage = 20
	}
	if req.PerPage > 100 {
		req.PerPage = 100
	}

	certDAO, err := s.storageFactory.CertificateDAO()
	if err != nil {
		return nil, nil, caerrors.StorageFailureError("failed to get certificate DAO: %s", err)
	}

	// List all certificates
	var allCerts []*entities.ACMECertificate
	err = certDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMECertificate]) error {
		allCerts = append(allCerts, page.Entities...)
		return nil
	})
	if err != nil {
		return nil, nil, caerrors.StorageFailureError("failed to list certificates: %s", err)
	}

	// Filter certificates
	filteredCerts := make([]*entities.ACMECertificate, 0)
	for _, cert := range allCerts {
		// Filter by status
		if req.Status != "" && cert.Status != req.Status {
			continue
		}

		// Filter by subject (if PEM is available)
		if req.Subject != "" {
			x509Cert, err := parsePEMCertificate(cert.PEM)
			if err == nil && x509Cert.Subject.CommonName != req.Subject {
				continue
			}
		}

		// Filter by expiration days
		if req.ExpiresDays > 0 {
			daysUntilExpiry := int(time.Until(cert.ExpiresAt).Hours() / 24)
			if daysUntilExpiry > req.ExpiresDays {
				continue
			}
		}

		filteredCerts = append(filteredCerts, cert)
	}

	// Calculate pagination
	total := len(filteredCerts)
	start := (req.Page - 1) * req.PerPage
	end := start + req.PerPage

	if start >= total {
		return []*CertificateInfo{}, &Pagination{
			Page:    req.Page,
			PerPage: req.PerPage,
			Total:   total,
		}, nil
	}

	if end > total {
		end = total
	}

	// Convert to CertificateInfo
	result := make([]*CertificateInfo, 0, end-start)
	for _, cert := range filteredCerts[start:end] {
		certInfo, err := s.convertToCertificateInfo(cert)
		if err != nil {
			s.logger.Warn("failed to convert certificate", slog.String("serial", cert.Serial), slog.String("error", err.Error()))
			continue
		}
		result = append(result, certInfo)
	}

	pagination := &Pagination{
		Page:    req.Page,
		PerPage: req.PerPage,
		Total:   total,
	}

	return result, pagination, nil
}

// GetCertificate retrieves a certificate by serial number
func (s *AdminService) GetCertificate(ctx context.Context, serial string) (*CertificateInfo, error) {
	if s.storageFactory == nil {
		return nil, ErrStorageNotConfigured
	}

	certDAO, err := s.storageFactory.CertificateDAO()
	if err != nil {
		return nil, caerrors.StorageFailureError("failed to get certificate DAO: %s", err)
	}

	// List all certificates and find by serial
	var certs []*entities.ACMECertificate
	err = certDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMECertificate]) error {
		certs = append(certs, page.Entities...)
		return nil
	})
	if err != nil {
		return nil, caerrors.StorageFailureError("failed to list certificates: %s", err)
	}

	for _, cert := range certs {
		x509Cert, err := parsePEMCertificate(cert.PEM)
		if err != nil {
			continue
		}

		if x509Cert.SerialNumber.String() == serial {
			return s.convertToCertificateInfo(cert)
		}
	}

	return nil, ErrCertificateNotFound
}

// RevokeCertificate revokes a certificate by serial number
func (s *AdminService) RevokeCertificate(ctx context.Context, serial string, reason string) error {
	if s.storageFactory == nil {
		return ErrStorageNotConfigured
	}
	if s.ca == nil {
		return ErrCANotConfigured
	}

	certDAO, err := s.storageFactory.CertificateDAO()
	if err != nil {
		return caerrors.StorageFailureError("failed to get certificate DAO: %s", err)
	}

	// Find certificate by serial
	var certs []*entities.ACMECertificate
	err = certDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMECertificate]) error {
		certs = append(certs, page.Entities...)
		return nil
	})
	if err != nil {
		return caerrors.StorageFailureError("failed to list certificates: %s", err)
	}

	var targetCert *entities.ACMECertificate
	var x509Cert *x509.Certificate

	for _, cert := range certs {
		parsed, err := parsePEMCertificate(cert.PEM)
		if err != nil {
			continue
		}

		if parsed.SerialNumber.String() == serial {
			targetCert = cert
			x509Cert = parsed
			break
		}
	}

	if targetCert == nil {
		return ErrCertificateNotFound
	}

	// Revoke the certificate using CA
	if err := s.ca.RevokeCert(ctx, x509Cert, ca.RevokeOptions{}); err != nil {
		return caerrors.InternalServerError("failed to revoke certificate: %s", err)
	}

	// Update certificate status
	targetCert.Status = "revoked"
	if err := certDAO.Save(ctx, targetCert); err != nil {
		return caerrors.StorageFailureError("failed to update certificate status: %s", err)
	}

	s.logger.Info("certificate revoked",
		slog.String("serial", serial),
		slog.String("reason", reason))

	return nil
}

// ListExpiringCertificates retrieves certificates expiring within specified days
func (s *AdminService) ListExpiringCertificates(ctx context.Context, days int, page, perPage int) ([]*CertificateInfo, *Pagination, error) {
	req := ListCertificatesRequest{
		Page:        page,
		PerPage:     perPage,
		ExpiresDays: days,
	}
	return s.ListCertificates(ctx, req)
}

// ListAccounts retrieves a paginated list of ACME accounts
func (s *AdminService) ListAccounts(ctx context.Context, req ListAccountsRequest) ([]*AccountInfo, *Pagination, error) {
	if s.storageFactory == nil {
		return nil, nil, ErrStorageNotConfigured
	}

	// Set default pagination
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PerPage < 1 {
		req.PerPage = 20
	}
	if req.PerPage > 100 {
		req.PerPage = 100
	}

	accountDAO, err := s.storageFactory.AccountDAO()
	if err != nil {
		return nil, nil, caerrors.StorageFailureError("failed to get account DAO: %s", err)
	}

	// List all accounts
	var allAccounts []*entities.ACMEAccount
	err = accountDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEAccount]) error {
		allAccounts = append(allAccounts, page.Entities...)
		return nil
	})
	if err != nil {
		return nil, nil, caerrors.StorageFailureError("failed to list accounts: %s", err)
	}

	// Filter accounts
	filteredAccounts := make([]*entities.ACMEAccount, 0)
	for _, account := range allAccounts {
		if req.Status != "" && account.Status != req.Status {
			continue
		}
		filteredAccounts = append(filteredAccounts, account)
	}

	// Calculate pagination
	total := len(filteredAccounts)
	start := (req.Page - 1) * req.PerPage
	end := start + req.PerPage

	if start >= total {
		return []*AccountInfo{}, &Pagination{
			Page:    req.Page,
			PerPage: req.PerPage,
			Total:   total,
		}, nil
	}

	if end > total {
		end = total
	}

	// Convert to AccountInfo
	result := make([]*AccountInfo, 0, end-start)
	for _, account := range filteredAccounts[start:end] {
		accountInfo, err := s.convertToAccountInfo(ctx, account)
		if err != nil {
			s.logger.Warn("failed to convert account", slog.Uint64("id", account.ID), slog.String("error", err.Error()))
			continue
		}
		result = append(result, accountInfo)
	}

	pagination := &Pagination{
		Page:    req.Page,
		PerPage: req.PerPage,
		Total:   total,
	}

	return result, pagination, nil
}

// GetAccount retrieves an account by ID
func (s *AdminService) GetAccount(ctx context.Context, accountID uint64) (*AccountInfo, error) {
	if s.storageFactory == nil {
		return nil, ErrStorageNotConfigured
	}

	accountDAO, err := s.storageFactory.AccountDAO()
	if err != nil {
		return nil, caerrors.StorageFailureError("failed to get account DAO: %s", err)
	}

	account, err := accountDAO.Get(ctx, accountID)
	if err != nil {
		return nil, caerrors.StorageFailureError("failed to get account: %s", err)
	}

	return s.convertToAccountInfo(ctx, account)
}

// DisableAccount disables an ACME account
func (s *AdminService) DisableAccount(ctx context.Context, accountID uint64) error {
	if s.storageFactory == nil {
		return ErrStorageNotConfigured
	}

	accountDAO, err := s.storageFactory.AccountDAO()
	if err != nil {
		return caerrors.StorageFailureError("failed to get account DAO: %s", err)
	}

	account, err := accountDAO.Get(ctx, accountID)
	if err != nil {
		return caerrors.StorageFailureError("failed to get account: %s", err)
	}

	account.Status = "deactivated"
	if err := accountDAO.Save(ctx, account); err != nil {
		return caerrors.StorageFailureError("failed to update account: %s", err)
	}

	s.logger.Info("account disabled", slog.Uint64("id", accountID))
	return nil
}

// ListOrders retrieves a paginated list of orders
func (s *AdminService) ListOrders(ctx context.Context, req ListOrdersRequest) ([]*OrderInfo, *Pagination, error) {
	if s.storageFactory == nil {
		return nil, nil, ErrStorageNotConfigured
	}

	// Set default pagination
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PerPage < 1 {
		req.PerPage = 20
	}
	if req.PerPage > 100 {
		req.PerPage = 100
	}

	var allOrders []*entities.ACMEOrder

	if req.AccountID > 0 {
		// Get orders for specific account (DAO is already account-scoped)
		orderDAO, err := s.storageFactory.OrderDAO(req.AccountID)
		if err != nil {
			return nil, nil, caerrors.StorageFailureError("failed to get order DAO: %s", err)
		}

		err = orderDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEOrder]) error {
			allOrders = append(allOrders, page.Entities...)
			return nil
		})
		if err != nil {
			return nil, nil, caerrors.StorageFailureError("failed to list orders: %s", err)
		}
	} else {
		// Get all accounts and their orders
		accountDAO, err := s.storageFactory.AccountDAO()
		if err != nil {
			return nil, nil, caerrors.StorageFailureError("failed to get account DAO: %s", err)
		}

		var accounts []*entities.ACMEAccount
		err = accountDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEAccount]) error {
			accounts = append(accounts, page.Entities...)
			return nil
		})
		if err != nil {
			return nil, nil, caerrors.StorageFailureError("failed to list accounts: %s", err)
		}

		allOrders = make([]*entities.ACMEOrder, 0)
		for _, account := range accounts {
			orderDAO, err := s.storageFactory.OrderDAO(account.ID)
			if err != nil {
				continue
			}

			// Scan all orders for this account (the DAO is already account-scoped)
			err = orderDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEOrder]) error {
				allOrders = append(allOrders, page.Entities...)
				return nil
			})
			if err != nil {
				continue
			}
		}
	}

	// Filter orders
	filteredOrders := make([]*entities.ACMEOrder, 0)
	for _, order := range allOrders {
		if req.Status != "" && order.Status != req.Status {
			continue
		}
		filteredOrders = append(filteredOrders, order)
	}

	// Calculate pagination
	total := len(filteredOrders)
	start := (req.Page - 1) * req.PerPage
	end := start + req.PerPage

	if start >= total {
		return []*OrderInfo{}, &Pagination{
			Page:    req.Page,
			PerPage: req.PerPage,
			Total:   total,
		}, nil
	}

	if end > total {
		end = total
	}

	// Convert to OrderInfo
	result := make([]*OrderInfo, 0, end-start)
	for _, order := range filteredOrders[start:end] {
		result = append(result, convertToOrderInfo(order))
	}

	pagination := &Pagination{
		Page:    req.Page,
		PerPage: req.PerPage,
		Total:   total,
	}

	return result, pagination, nil
}

// GetOrder retrieves an order by ID
func (s *AdminService) GetOrder(ctx context.Context, orderID uint64, accountID uint64) (*OrderInfo, error) {
	if s.storageFactory == nil {
		return nil, ErrStorageNotConfigured
	}

	orderDAO, err := s.storageFactory.OrderDAO(accountID)
	if err != nil {
		return nil, caerrors.StorageFailureError("failed to get order DAO: %s", err)
	}

	order, err := orderDAO.Get(ctx, orderID)
	if err != nil {
		return nil, caerrors.StorageFailureError("failed to get order: %s", err)
	}

	return convertToOrderInfo(order), nil
}

// GetStatus retrieves CA status information
func (s *AdminService) GetStatus(ctx context.Context) (*CAStatus, error) {
	if s.ca == nil {
		return nil, ErrCANotConfigured
	}

	rootCert, err := s.ca.TrustedRoot()
	if err != nil {
		return nil, caerrors.InternalServerError("failed to get root CA: %s", err)
	}

	intermediateCert, err := s.ca.TrustedIntermediate()
	if err != nil && !errors.Is(err, ca.ErrIntermediateNotFound) {
		return nil, caerrors.InternalServerError("failed to get intermediate CA: %s", err)
	}

	status := &CAStatus{
		Identity:      s.ca.Identity(),
		Initialized:   s.ca.IsInitialized(),
		Version:       s.version,
		StartedAt:     s.startTime,
		KeyAlgorithm:  s.ca.DefaultKeyAlgorithm().String(),
		SignatureAlgo: s.ca.DefaultSignatureAlgorithm().String(),
		RootCA:        rootCert.Subject.CommonName,
	}

	if intermediateCert != nil {
		status.IntermediateCA = intermediateCert.Subject.CommonName
	}

	// Build multi-key information from the issuing identity's Keys configuration.
	// The issuing identity is the one actively signing certificates (intermediate if
	// configured, otherwise root).
	identity := s.ca.IssuingIdentity()
	if len(identity.Keys) > 0 {
		keys := make([]KeyInfo, 0, len(identity.Keys))
		for i, kc := range identity.Keys {
			keys = append(keys, KeyInfoFromKeyConfig(kc, i == 0))
		}
		status.Keys = keys
	}

	return status, nil
}

// GetStats retrieves CA statistics
func (s *AdminService) GetStats(ctx context.Context) (*CAStats, error) {
	if s.storageFactory == nil {
		return nil, ErrStorageNotConfigured
	}

	stats := &CAStats{}

	// Get certificate statistics
	certDAO, err := s.storageFactory.CertificateDAO()
	if err != nil {
		return nil, caerrors.StorageFailureError("failed to get certificate DAO: %s", err)
	}

	var certs []*entities.ACMECertificate
	err = certDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMECertificate]) error {
		certs = append(certs, page.Entities...)
		return nil
	})
	if err != nil {
		return nil, caerrors.StorageFailureError("failed to list certificates: %s", err)
	}

	stats.TotalCertificates = len(certs)
	now := time.Now()

	for _, cert := range certs {
		switch cert.Status {
		case "valid":
			if now.Before(cert.ExpiresAt) {
				stats.ValidCertificates++
			} else {
				stats.ExpiredCertificates++
			}
		case "revoked":
			stats.RevokedCertificates++
		}
	}

	// Get account statistics
	accountDAO, err := s.storageFactory.AccountDAO()
	if err != nil {
		return nil, caerrors.StorageFailureError("failed to get account DAO: %s", err)
	}

	var accounts []*entities.ACMEAccount
	err = accountDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEAccount]) error {
		accounts = append(accounts, page.Entities...)
		return nil
	})
	if err != nil {
		return nil, caerrors.StorageFailureError("failed to list accounts: %s", err)
	}

	stats.TotalAccounts = len(accounts)
	for _, account := range accounts {
		if account.Status == "valid" {
			stats.ActiveAccounts++
		}
	}

	// Get order statistics from all accounts
	for _, account := range accounts {
		orderDAO, err := s.storageFactory.OrderDAO(account.ID)
		if err != nil {
			continue
		}

		var orders []*entities.ACMEOrder
		if err := orderDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEOrder]) error {
			orders = append(orders, page.Entities...)
			return nil
		}); err != nil {
			return nil, caerrors.StorageFailureError("failed to list orders for account %d: %s", account.ID, err)
		}

		stats.TotalOrders += len(orders)
		for _, order := range orders {
			switch order.Status {
			case "pending", "processing":
				stats.PendingOrders++
			case "valid":
				stats.CompletedOrders++
			}
		}
	}

	return stats, nil
}

// Helper functions

func (s *AdminService) convertToCertificateInfo(cert *entities.ACMECertificate) (*CertificateInfo, error) {
	x509Cert, err := parsePEMCertificate(cert.PEM)
	if err != nil {
		return nil, err
	}

	return &CertificateInfo{
		SerialNumber: x509Cert.SerialNumber.String(),
		Subject:      x509Cert.Subject.String(),
		Issuer:       x509Cert.Issuer.String(),
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		Status:       cert.Status,
		IssuedAt:     cert.IssuedAt,
		CertURL:      cert.CertURL,
	}, nil
}

func (s *AdminService) convertToAccountInfo(ctx context.Context, account *entities.ACMEAccount) (*AccountInfo, error) {
	// Count orders for this account
	orderCount := 0
	if orderDAO, err := s.storageFactory.OrderDAO(account.ID); err == nil {
		count, err := orderDAO.Count(ctx)
		if err == nil {
			orderCount = count
		}
	}

	return &AccountInfo{
		ID:                   FlexUint64(account.ID),
		Status:               account.Status,
		Contact:              account.Contact,
		CreatedAt:            account.CreatedAt,
		TermsOfServiceAgreed: account.TermsOfServiceAgreed,
		OrdersURL:            account.Orders,
		OrderCount:           orderCount,
	}, nil
}

func convertToOrderInfo(order *entities.ACMEOrder) *OrderInfo {
	identifiers := make([]string, len(order.Identifiers))
	for i, id := range order.Identifiers {
		identifiers[i] = id.Value
	}

	return &OrderInfo{
		ID:          order.ID,
		AccountID:   order.AccountID,
		Status:      order.Status,
		Identifiers: identifiers,
		NotBefore:   order.NotBefore,
		NotAfter:    order.NotAfter,
		Expires:     order.Expires,
		Certificate: order.Certificate,
		CreatedAt:   time.Now(), // Note: ACMEOrder doesn't have CreatedAt, using current time
	}
}

func parsePEMCertificate(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, caerrors.MalformedError("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, caerrors.MalformedError("failed to parse certificate: %s", err)
	}

	return cert, nil
}
