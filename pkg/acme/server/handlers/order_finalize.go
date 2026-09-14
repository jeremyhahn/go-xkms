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

package handlers

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

type OrderFinalizeRequest struct {
	CSR string `json:"csr"`
}

// resolveTenantSigningCA determines which CA should sign certificates for the given account.
// For multi-tenant deployments, this looks up the tenant and uses GetSigningCA to determine
// the signing authority. For single-tenant deployments or when tenant lookup fails,
// falls back to the global CA.
//
// Parameters:
//   - ctx: the request context
//   - account: the ACME account requesting certificate issuance
//   - purpose: the intended purpose (e.g., "tpm-endorsement", "general")
//
// Returns the SigningCAInfo indicating which CA should sign, or nil to use global default.
func (s *RestService) resolveTenantSigningCA(ctx context.Context, account *entities.ACMEAccount, purpose string) *entities.SigningCAInfo {
	// If no tenant ID, use global CA
	if account.TenantID == "" {
		s.logger.Debug("Account has no tenant ID, using global CA",
			"account_id", account.ID)
		return nil
	}

	// Check if storage factory supports tenant-aware operations
	tenantAwareFactory, ok := s.storageFactory.(storage.TenantAwareFactory)
	if !ok {
		s.logger.Debug("Storage factory does not support TenantAwareFactory, using global CA",
			"account_id", account.ID,
			"tenant_id", account.TenantID)
		return nil
	}

	// Get TenantDAO
	tenantDAO, err := tenantAwareFactory.TenantDAO()
	if err != nil {
		s.logger.Warn("Failed to get TenantDAO, using global CA",
			"error", err,
			"account_id", account.ID,
			"tenant_id", account.TenantID)
		return nil
	}

	// Look up the tenant by string ID
	tenant, err := tenantDAO.Get(ctx, entities.StringToEntityID(account.TenantID))
	if err != nil {
		s.logger.Warn("Failed to get tenant, using global CA",
			"error", err,
			"account_id", account.ID,
			"tenant_id", account.TenantID)
		return nil
	}

	// Check if tenant is active
	if !tenant.IsActive() {
		s.logger.Warn("Tenant is not active, using global CA",
			"account_id", account.ID,
			"tenant_id", account.TenantID,
			"tenant_status", tenant.Status)
		return nil
	}

	// Get the signing CA for this tenant
	signingCA := tenant.GetSigningCA(purpose)

	s.logger.Info("Resolved tenant signing CA",
		"account_id", account.ID,
		"tenant_id", account.TenantID,
		"signing_ca_type", signingCA.Type,
		"purpose", purpose,
		"use_global_default", signingCA.UseGlobalDefault)

	return signingCA
}

// getTenantCASigner retrieves the appropriate signer for tenant CA operations.
// Returns a crypto.Signer from KMS if tenant-specific CA is configured, or nil
// to indicate the global CA should be used.
//
// Parameters:
//   - ctx: the request context
//   - signingCAInfo: the resolved signing CA info from resolveTenantSigningCA
//
// Returns crypto.Signer for tenant signing, or nil to use global CA.
func (s *RestService) getTenantCASigner(ctx context.Context, signingCAInfo *entities.SigningCAInfo) crypto.Signer {
	// If no signing CA info or using global default, use global CA
	if signingCAInfo == nil || signingCAInfo.UseGlobalDefault {
		return nil
	}

	// If KMS service is not configured, use global CA
	if s.kmsService == nil {
		s.logger.Debug("KMSService not configured, using global CA",
			"tenant_id", signingCAInfo.TenantID)
		return nil
	}

	// Determine the key purpose based on signing CA type
	var purpose kms.KeyPurpose
	switch signingCAInfo.Type {
	case entities.SigningCATypeIntermediate:
		purpose = kms.KeyPurposeTenantIntermediateCA
	case entities.SigningCATypeRoot:
		purpose = kms.KeyPurposeTenantRootCA
	default:
		s.logger.Warn("Unknown signing CA type, using global CA",
			"type", signingCAInfo.Type,
			"tenant_id", signingCAInfo.TenantID)
		return nil
	}

	// Get the signer from KMS
	signer, err := s.kmsService.GetSigningKey(ctx, signingCAInfo.TenantID, purpose)
	if err != nil {
		s.logger.Warn("Failed to get tenant CA signer from KMS, using global CA",
			"error", err,
			"tenant_id", signingCAInfo.TenantID,
			"purpose", purpose)
		return nil
	}

	s.logger.Info("Using tenant CA signer from KMS",
		"tenant_id", signingCAInfo.TenantID,
		"purpose", purpose,
		"signing_ca_type", signingCAInfo.Type)

	return signer
}

// resolveTenantComplianceConfig retrieves the effective compliance configuration
// for certificate issuance based on tenant settings and global configuration.
//
// Parameters:
//   - ctx: the request context
//   - account: the ACME account requesting certificate issuance
//
// Returns the effective ComplianceConfig, or nil if compliance is not configured.
func (s *RestService) resolveTenantComplianceConfig(ctx context.Context, account *entities.ACMEAccount) *ComplianceConfig {
	// Get global compliance config
	globalConfig := s.globalComplianceConfig

	// If no tenant ID, use global config
	if account.TenantID == "" {
		if globalConfig != nil {
			return &globalConfig.ComplianceConfig
		}
		return nil
	}

	// Check if storage factory supports tenant-aware operations
	tenantAwareFactory, ok := s.storageFactory.(storage.TenantAwareFactory)
	if !ok {
		if globalConfig != nil {
			return &globalConfig.ComplianceConfig
		}
		return nil
	}

	// Get TenantDAO
	tenantDAO, err := tenantAwareFactory.TenantDAO()
	if err != nil {
		s.logger.Warn("Failed to get TenantDAO for compliance config, using global config",
			"error", err,
			"account_id", account.ID,
			"tenant_id", account.TenantID)
		if globalConfig != nil {
			return &globalConfig.ComplianceConfig
		}
		return nil
	}

	// Look up the tenant by string ID
	tenant, err := tenantDAO.Get(ctx, entities.StringToEntityID(account.TenantID))
	if err != nil {
		s.logger.Warn("Failed to get tenant for compliance config, using global config",
			"error", err,
			"account_id", account.ID,
			"tenant_id", account.TenantID)
		if globalConfig != nil {
			return &globalConfig.ComplianceConfig
		}
		return nil
	}

	// Use ResolveComplianceConfig to determine effective config
	return entities.ResolveComplianceConfig(globalConfig, tenant.Settings)
}

func (s *RestService) OrderFinalizeHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("OrderFinalizeHandler", "method", r.Method, "url", r.URL)
	ctx := r.Context()

	account, payload, err := s.parseKID(ctx, r)
	if err != nil {
		writeError(w, common.MalformedError("Failed to parse account key", nil))
		return
	}

	orderDAO, err := s.storageFactory.OrderDAO(account.ID)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create order DAO"))
		return
	}

	vars := mux.Vars(r)
	strOrderID := vars["id"]
	orderID, err := strconv.ParseUint(strOrderID, 10, 64)
	if err != nil {
		writeError(w, common.MalformedError("Invalid order ID", nil))
		return
	}

	order, err := orderDAO.Get(ctx, orderID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			writeError(w, common.MalformedError("Order not found", nil))
		} else {
			s.logger.Error("Storage error retrieving order", "error", err)
			writeError(w, common.ServerInternal("Storage error"))
		}
		return
	}

	if order.AccountID != account.ID {
		writeError(w, common.Unauthorized("Unauthorized"))
		return
	}

	if order.Status != common.StatusReady {
		writeError(w, common.OrderNotReady("Order is not ready for finalization"))
		return
	}

	// Set the order status to processing
	order.Status = common.StatusProcessing
	if err := orderDAO.Save(ctx, order); err != nil {
		writeError(w, common.ServerInternal("Failed to update order status"))
		return
	}

	var finalizeRequest OrderFinalizeRequest

	// Decode the finalize request paylaod
	if err := json.Unmarshal(payload, &finalizeRequest); err != nil {
		writeError(w, common.MalformedError("Invalid request payload", nil))
		return
	}

	// Decode the CSR from the request payload
	csrDER, err := base64.RawURLEncoding.DecodeString(finalizeRequest.CSR)
	if err != nil {
		writeError(w, common.MalformedError("Invalid CSR encoding", nil))
		return
	}

	var serialNumber uint64
	var pem []byte

	// Parse the CSR as a standard x509 certificate request
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {

		// Failed, attempt to parse as TCG-CSR-IDEVID for enroll-01
		if len(order.Identifiers) > 0 {
			if order.Identifiers[0].Type == common.AuthzTypeIP ||
				order.Identifiers[0].Type == common.AuthzTypePermanentIdentifier {

				serialNumber, pem, err = s.finalizeTCGCSR(
					order.Identifiers[0].Value, csrDER, r, account, order)
				if err != nil {
					// finalizeTCGCSR returns *entities.Error or common errors
					if acmeErr, ok := err.(*entities.Error); ok {
						writeError(w, acmeErr)
					} else {
						writeError(w, common.MalformedError("Invalid CSR", nil))
					}
					return
				}

				// Send the final order response
				s.sendFinalizeResponse(ctx, orderDAO, order, serialNumber, pem, w)
				return
			}
		}

		// If we couldn't parse as TCG-CSR either, return the original error
		writeError(w, common.MalformedError("Invalid CSR", nil))
		return
	}

	// ... continue processing x509 certificate request

	// Encode the CSR to PEM
	csrPEM := encodeCSRToPEM(csrDER)

	// Check if this is an endorse-01 order (x509 CSR + permanent-identifier)
	// For endorse-01, the identifier is the IP address but the CSR contains the EK public key.
	// Skip strict identifier matching for endorse-01 since the validation was done during
	// the challenge phase (via EAB/server policy). The CSR public key will be certified.
	isEndorse01 := len(order.Identifiers) > 0 &&
		order.Identifiers[0].Type == common.AuthzTypePermanentIdentifier &&
		csr.PublicKey != nil

	// For non-endorse-01 orders (DNS type), ensure the CSR matches the order identifiers
	if !isEndorse01 {
		matches, err := matchesIdentifier(csr, order)
		if err != nil {
			writeError(w, err.(*entities.Error))
			return
		}
		if !matches {
			writeError(w, common.MalformedError("CSR does not match order identifiers", nil))
			return
		}
	}

	// Perform CAA validation for DNS identifiers before certificate issuance
	// per RFC 8555 Section 8.1 and RFC 8659
	if s.caaValidator != nil {
		for _, identifier := range order.Identifiers {
			// Only validate DNS identifiers - skip IP and permanent-identifier types
			if identifier.Type != common.AuthzTypeDNS {
				continue
			}

			// Check if this is a wildcard certificate request
			isWildcard := strings.HasPrefix(identifier.Value, "*.")
			domain := identifier.Value
			if isWildcard {
				// Remove the wildcard prefix for CAA validation
				domain = strings.TrimPrefix(domain, "*.")
			}

			// Perform CAA validation
			if err := s.caaValidator.Validate(ctx, domain, isWildcard); err != nil {
				s.logger.Error("CAA validation failed",
					"domain", domain,
					"wildcard", isWildcard,
					"error", err)

				// Check if this is a CAA validation failure
				var caaErr *server.ErrCAAValidationFailed
				if errors.As(err, &caaErr) {
					writeError(w, common.CAAError(err.Error()))
					return
				}

				// Other errors (DNS errors, etc.) - return as CAA error per RFC
				writeError(w, common.CAAError(fmt.Sprintf("CAA validation error: %v", err)))
				return
			}

			s.logger.Debug("CAA validation passed",
				"domain", domain,
				"wildcard", isWildcard)
		}
	}

	// Resolve tenant signing CA for multi-tenant deployments
	// This determines which CA should sign the certificate based on:
	// 1. Tenant's purpose-specific intermediate CA (e.g., tpm-endorsement)
	// 2. Tenant's default intermediate CA
	// 3. Tenant's root CA (if no intermediate)
	// 4. Global default CA (fallback)
	var signingCAInfo *entities.SigningCAInfo
	purpose := entities.CAPurposeGeneral
	if len(order.Identifiers) > 0 && order.Identifiers[0].Type == common.AuthzTypePermanentIdentifier {
		purpose = entities.CAPurposeTPMEndorsement
	}
	signingCAInfo = s.resolveTenantSigningCA(ctx, account, purpose)

	// Get the appropriate signer based on tenant CA configuration
	// If KMSService is configured and we have a tenant-specific CA, use that signer
	// Otherwise, fall back to the global CA
	tenantSigner := s.getTenantCASigner(ctx, signingCAInfo)

	// Get issuer certificate for tenant signing (if available)
	var issuerCert *x509.Certificate
	if tenantSigner != nil && signingCAInfo != nil {
		// Try to get the tenant's CA certificate from KMS
		if s.kmsService != nil {
			purpose := kms.KeyPurposeTenantIntermediateCA
			if signingCAInfo.Type == entities.SigningCATypeRoot {
				purpose = kms.KeyPurposeTenantRootCA
			}
			certDER, kmsErr := s.kmsService.GetCertificate(ctx, signingCAInfo.TenantID, purpose)
			if kmsErr == nil && len(certDER) > 0 {
				parsedCert, parseErr := x509.ParseCertificate(certDER)
				if parseErr == nil {
					issuerCert = parsedCert
					s.logger.Info("Using tenant CA certificate from KMS",
						"tenant_id", signingCAInfo.TenantID,
						"signing_ca_type", signingCAInfo.Type)
				} else {
					s.logger.Warn("Failed to parse tenant CA certificate from KMS",
						"error", parseErr,
						"tenant_id", signingCAInfo.TenantID)
				}
			}
		}

		// Fall back to global CA's issuer certificate if tenant cert not available
		if issuerCert == nil {
			issuerCert, err = s.ca.TrustedIntermediate()
			if err != nil || issuerCert == nil {
				// No intermediate, try root
				issuerCert, err = s.ca.TrustedRoot()
			}
			if err != nil || issuerCert == nil {
				s.logger.Warn("Failed to get issuer certificate, falling back to global CA",
					"error", err,
					"tenant_id", signingCAInfo.TenantID)
				tenantSigner = nil
			} else {
				s.logger.Info("Using tenant CA with global issuer certificate",
					"tenant_id", signingCAInfo.TenantID,
					"signing_ca_type", signingCAInfo.Type)
			}
		}
	}

	// Check if this is an endorse-01 order (x509 CSR + permanent-identifier with base64 public key)
	// endorse-01 is for issuing EK certificates to TPMs without manufacturer EK certs
	// device-attest-01 also uses permanent-identifier but with IP/hostname, not base64 public key
	var cert *x509.Certificate
	isEndorse01Order := false

	if len(order.Identifiers) > 0 &&
		order.Identifiers[0].Type == common.AuthzTypePermanentIdentifier {

		// Try to decode the permanent identifier as a base64url-encoded PKIX public key
		// This distinguishes endorse-01 (base64 public key) from device-attest-01 (IP/hostname)
		ekPubKeyBytes, err := base64.RawURLEncoding.DecodeString(order.Identifiers[0].Value)
		if err == nil {
			// Successfully decoded base64 - try to parse as PKIX public key
			ekPubKey, parseErr := x509.ParsePKIXPublicKey(ekPubKeyBytes)
			if parseErr == nil {
				// This is an endorse-01 order - issue EK certificate with TCG/TP extensions
				isEndorse01Order = true

				ekRequest := &ca.CertificateRequest{
					Subject: ca.Subject{
						CommonName: csr.Subject.CommonName,
					},
					PermanentID: order.Identifiers[0].Value,
				}

				// Copy organization info from CSR if available
				if len(csr.Subject.Organization) > 0 {
					ekRequest.Subject.Organization = csr.Subject.Organization[0]
				}
				if len(csr.Subject.OrganizationalUnit) > 0 {
					ekRequest.Subject.OrganizationalUnit = csr.Subject.OrganizationalUnit[0]
				}
				if len(csr.Subject.Country) > 0 {
					ekRequest.Subject.Country = csr.Subject.Country[0]
				}
				if len(csr.Subject.Locality) > 0 {
					ekRequest.Subject.Locality = csr.Subject.Locality[0]
				}
				if len(csr.Subject.Province) > 0 {
					ekRequest.Subject.Province = csr.Subject.Province[0]
				}

				// Add SANs from CSR
				if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 {
					ekRequest.SANS = &ca.SubjectAlternativeNames{
						DNS:   csr.DNSNames,
						Email: csr.EmailAddresses,
					}
					for _, ip := range csr.IPAddresses {
						ekRequest.SANS.IPs = append(ekRequest.SANS.IPs, ip.String())
					}
				}

				// Issue EK certificate using tenant CA if available
				if tenantSigner != nil && issuerCert != nil {
					ekRequest.Signer = tenantSigner
					ekRequest.IssuerCert = issuerCert
				}
				cert, err = s.ca.IssueEKCertificate(r.Context(), ekRequest, ekPubKey)
				if err != nil {
					s.logger.Error("Failed to issue EK certificate", "error", err)
					writeError(w, common.ServerInternal("Failed to issue EK certificate"))
					return
				}
			}
		}

		// If not endorse-01, log that we're treating this as device-attest-01 or standard cert
		if !isEndorse01Order {
			s.logger.Debug("Permanent identifier is not base64 public key, treating as device-attest-01",
				"identifier", order.Identifiers[0].Value)
		}
	}

	if !isEndorse01Order {
		// Execute pre-issuance hooks before certificate signing
		if s.params != nil && s.params.PreIssuanceHooks != nil && s.params.PreIssuanceHooks.Count() > 0 {
			// Resolve compliance configuration for this account
			complianceConfig := s.resolveTenantComplianceConfig(ctx, account)

			preHookCtx := &PreIssuanceHookContext{
				Context:          ctx,
				Order:            order,
				CSR:              csr,
				ClientIP:         r.RemoteAddr,
				IsTCGCSR:         false,
				ComplianceConfig: complianceConfig,
			}

			s.logger.Info("Executing pre-issuance hooks",
				"hook_count", s.params.PreIssuanceHooks.Count(),
				"is_tcg_csr", false,
				"client_ip", r.RemoteAddr,
				"compliance_enabled", complianceConfig != nil && complianceConfig.Enabled)

			if err := s.params.PreIssuanceHooks.Execute(preHookCtx); err != nil {
				s.logger.Warn("Pre-issuance hook failed, blocking certificate issuance",
					"error", err,
					"order_id", order.ID,
					"account_id", account.ID)
				writeError(w, common.Unauthorized(fmt.Sprintf("Pre-issuance check failed: %v", err)))
				return
			}
		}

		// Standard certificate or device-attest-01 - sign the CSR
		signOpts := &ca.SignOptions{}
		// Use tenant CA if available
		if tenantSigner != nil && issuerCert != nil {
			signOpts.Signer = tenantSigner
			signOpts.IssuerCert = issuerCert
		}

		// Execute pre-sign extension hooks and append returned extensions to signOpts.
		if s.preSignHooks != nil && s.preSignHooks.Count() > 0 {
			preSignCtx := &OrderPreSignHookContext{
				Context:  ctx,
				Order:    order,
				CSR:      csr,
				ClientIP: r.RemoteAddr,
				IsTCGCSR: false,
			}
			extraExts, hookErr := s.preSignHooks.Execute(preSignCtx)
			if hookErr != nil {
				s.logger.Warn("Pre-sign hook failed, aborting certificate issuance",
					"error", hookErr,
					"order_id", order.ID,
					"account_id", account.ID)
				writeError(w, common.ServerInternal(fmt.Sprintf("Pre-sign hook failed: %v", hookErr)))
				return
			}
			signOpts.ExtraExtensions = append(signOpts.ExtraExtensions, extraExts...)
		}

		cert, err = s.ca.SignCSR(r.Context(), csrPEM, signOpts)
		if err != nil {
			writeError(w, common.ServerInternal("Failed to sign CSR"))
			return
		}
	}

	// Use the lower 64 bits of the serial number for storage
	// X.509 serial numbers can be up to 20 bytes, but we store as uint64
	// If the serial number is too large, extract only the lower 64 bits
	if cert.SerialNumber == nil {
		writeError(w, common.ServerInternal("Certificate serial number is nil"))
		return
	}
	if cert.SerialNumber.IsUint64() {
		serialNumber = cert.SerialNumber.Uint64()
	} else {
		// Use modulo to get lower 64 bits without panicking
		var maxUint64 big.Int
		maxUint64.SetUint64(^uint64(0))
		maxUint64.Add(&maxUint64, big.NewInt(1))
		var temp big.Int
		temp.Mod(cert.SerialNumber, &maxUint64)
		serialNumber = temp.Uint64()
	}

	// Verify the certificate as a final sanity check before delivering to
	// the client. We pass nil for the signer since we don't have access
	// to the client's private key and we're just validating the chain.
	if _, err := s.ca.Verify(cert, nil); err != nil {
		writeError(w, common.ServerInternal("Failed to verify certificate"))
		return
	}

	// Encode the certificate to PEM, followed by the issuing chain so the
	// body matches the application/pem-certificate-chain media type it is
	// served under (RFC 8555 §7.4.2).
	pem = s.appendIssuingChain(encodeCertificatePEM(cert.Raw))

	// The CA has signed: the certificate exists in the world from here on, so
	// it is audited now rather than after delivery. A finalization hook or a
	// storage failure below may still abort the response, but it cannot unsign
	// the certificate, and an audit trail that omitted it would be wrong.
	s.recordAudit(audit.LogCertificateIssued(auditContext(r), s.auditLog,
		auditAccountID(account.ID),
		strconv.FormatUint(order.ID, 10),
		cert.Subject.CommonName,
		auditValidityDays(cert),
		cert.SerialNumber.String()))

	// Execute order finalization hooks if registered
	if s.params != nil && s.params.OrderFinalizeHooks != nil {
		hookCtx := &OrderFinalizeHookContext{
			Context:        ctx,
			Order:          order,
			Certificate:    cert,
			CertificatePEM: pem,
			CSR:            csr,
			ClientIP:       r.RemoteAddr,
			IsTCGCSR:       false,
		}

		s.logger.Info("Executing order finalization hooks",
			"hook_count", s.params.OrderFinalizeHooks.Count(),
			"is_tcg_csr", false,
			"client_ip", r.RemoteAddr)

		if err := s.params.OrderFinalizeHooks.Execute(hookCtx); err != nil {
			writeError(w, common.ServerInternal(fmt.Sprintf("Order finalization hook failed: %v", err)))
			return
		}
	} else {
		s.logger.Warn("No order finalization hooks registered",
			"params_nil", s.params == nil,
			"hooks_nil", s.params != nil && s.params.OrderFinalizeHooks == nil)
	}

	// Send the final order response
	s.sendFinalizeResponse(ctx, orderDAO, order, serialNumber, pem, w)
}

// sendFinalizeResponse sends the final order response to the client.
func (s *RestService) sendFinalizeResponse(
	ctx context.Context,
	orderDAO qrdbsdk.GenericDAO[*entities.ACMEOrder],
	order *entities.ACMEOrder,
	serialNumber uint64,
	pem []byte,
	w http.ResponseWriter) {

	certURL := fmt.Sprintf("%s/acme/cert/%d", s.baseRESTURI, serialNumber)

	certificate := &entities.ACMECertificate{
		ID:        serialNumber,
		CertURL:   certURL,
		PEM:       string(pem),
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
	}

	certDAO, err := s.storageFactory.CertificateDAO()
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create certificate DAO"))
		return
	}
	if err := certDAO.Save(ctx, certificate); err != nil {
		writeError(w, common.ServerInternal("Failed to save certificate"))
		return
	}

	order.Status = common.StatusValid
	order.Certificate = certURL
	if err := orderDAO.Save(ctx, order); err != nil {
		writeError(w, common.ServerInternal("Failed to update order"))
		return
	}

	s.orderResponse(w, order)
}

// Check if the identifiers in the CSR match the order identifiers
func matchesIdentifier(
	csr *x509.CertificateRequest,
	order *entities.ACMEOrder) (bool, error) {

	// Ensure the identifier matches
	matchesIdentifier := false
	for _, identifier := range order.Identifiers {

		switch identifier.Type {

		case common.AuthzTypePermanentIdentifier:
			permanentID, err := parseCertificateRequestPermanentIdentifier(csr)
			if err != nil {
				return false, common.MalformedError("Failed to parse permanent-identifier", nil)
			}
			if identifier.Value == permanentID {
				matchesIdentifier = true
				goto found
			}
		case common.AuthzTypeDNS:
			if identifier.Value == csr.Subject.CommonName {
				matchesIdentifier = true
				goto found
			}

		default:
			return false,
				common.UnsupportedIdentifier(fmt.Sprintf("Invalid identifier: %s", identifier.Type))
		}
	}

found:
	return matchesIdentifier, nil
}

// Finalize a TCG-CSR-IDEVID for a successful enroll-01 challenge verification
func (s *RestService) finalizeTCGCSR(
	ip string,
	csrDER []byte,
	r *http.Request,
	account *entities.ACMEAccount,
	order *entities.ACMEOrder,
) (uint64, []byte, error) {
	var pem []byte
	ctx := r.Context()

	// Unmarshal the TCG-CSR-IDEVID
	tcgCSR, err := xkmssdk.UnmarshalIDevIDCSR(csrDER)
	if err != nil {
		return 0, nil, common.MalformedError("Failed to parse TCG-CSR-IDEVID", nil)
	}

	// Get the CA's issuing certificate to populate the subject fields
	// Use TrustedIntermediate if available, otherwise TrustedRoot
	caCert, err := s.ca.TrustedIntermediate()
	if err != nil || caCert == nil {
		caCert, err = s.ca.TrustedRoot()
		if err != nil {
			return 0, nil, common.ServerInternal("Failed to get CA certificate")
		}
	}

	// Build the IDevID common name and internal CSR request object -

	// The TCG specifications regarding the TCG-CSR-IDEVID structure don't
	// provide the needed x509 PKIX subject for the client to send a proper
	// CSR. For now, this will only support "enterprise enrollments" where
	// it's assumed all devices are part of the same enterprise / domain as
	// this ACME server, but in the future, this will be extended to support
	// any domain via the TCG-CSR-IDEVID prodCAData field, where it will store
	// the necessary PKIX attributes. This, along with each platform having it's
	// own CA with cross-signing abilities, enables a decentralized, private
	// PKI Web of Trust between platforms.

	// Construct the common name for the certificate using the device
	// product model and serial number
	idevidCN := fmt.Sprintf("%s-%s",
		tcgCSR.CsrContents.ProdModel,
		tcgCSR.CsrContents.ProdSerial)

	// Build the IDevID certificate request using CA subject information
	organization := ""
	orgUnit := ""
	country := ""
	locality := ""
	province := ""
	if len(caCert.Subject.Organization) > 0 {
		organization = caCert.Subject.Organization[0]
	}
	if len(caCert.Subject.OrganizationalUnit) > 0 {
		orgUnit = caCert.Subject.OrganizationalUnit[0]
	}
	if len(caCert.Subject.Country) > 0 {
		country = caCert.Subject.Country[0]
	}
	if len(caCert.Subject.Locality) > 0 {
		locality = caCert.Subject.Locality[0]
	}
	if len(caCert.Subject.Province) > 0 {
		province = caCert.Subject.Province[0]
	}

	tcgCSRRequest := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:         idevidCN,
			Organization:       organization,
			OrganizationalUnit: orgUnit,
			Country:            country,
			Locality:           locality,
			Province:           province,
		},
	}

	// Execute pre-issuance hooks before TCG-CSR signing
	if s.params != nil && s.params.PreIssuanceHooks != nil && s.params.PreIssuanceHooks.Count() > 0 {
		// Resolve compliance configuration for this account
		complianceConfig := s.resolveTenantComplianceConfig(ctx, account)

		// Parse EK certificate for hook context (same as post-issuance hooks)
		ekcert, ekErr := x509.ParseCertificate(tcgCSR.CsrContents.EkCert)
		if ekErr != nil {
			return 0, nil, common.ServerInternal("Failed to parse EK certificate for pre-issuance hook")
		}

		// Build TCG enrollment data for hook context
		tcgData := &TCGEnrollmentData{
			ProductModel:         string(tcgCSR.CsrContents.ProdModel),
			ProductSerial:        string(tcgCSR.CsrContents.ProdSerial),
			PermanentIdentifier:  idevidCN,
			EKCertificate:        ekcert,
			AttestationPublicKey: tcgCSR.CsrContents.AttestPub,
			SigningPublicKey:     tcgCSR.CsrContents.SigningPub,
			EventLog:             tcgCSR.CsrContents.BootEvntLog,
			ProdCaData:           tcgCSR.CsrContents.ProdCaData,
		}

		preHookCtx := &PreIssuanceHookContext{
			Context:          ctx,
			Order:            order,
			ClientIP:         ip,
			IsTCGCSR:         true,
			TCGData:          tcgData,
			ComplianceConfig: complianceConfig,
		}

		s.logger.Info("Executing pre-issuance hooks for TCG-CSR",
			"hook_count", s.params.PreIssuanceHooks.Count(),
			"is_tcg_csr", true,
			"client_ip", ip,
			"product_model", string(tcgCSR.CsrContents.ProdModel),
			"product_serial", string(tcgCSR.CsrContents.ProdSerial),
			"compliance_enabled", complianceConfig != nil && complianceConfig.Enabled,
			"prodcadata_size", len(tcgCSR.CsrContents.ProdCaData),
			"eventlog_size", len(tcgCSR.CsrContents.BootEvntLog))

		if err := s.params.PreIssuanceHooks.Execute(preHookCtx); err != nil {
			s.logger.Warn("Pre-issuance hook failed for TCG-CSR, blocking certificate issuance",
				"error", err,
				"order_id", order.ID,
				"account_id", account.ID,
				"product_serial", string(tcgCSR.CsrContents.ProdSerial))
			return 0, nil, common.Unauthorized(fmt.Sprintf("Pre-issuance check failed: %v", err))
		}
	}

	// Execute pre-sign extension hooks and append returned extensions to the IDevID request.
	// The TCGCSRRequest.ExtraExtensions field is honored by SignTCGCSRIDevID for the IDevID cert.
	if s.preSignHooks != nil && s.preSignHooks.Count() > 0 {
		preSignCtx := &OrderPreSignHookContext{
			Context:  ctx,
			Order:    order,
			ClientIP: ip,
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:        string(tcgCSR.CsrContents.ProdModel),
				ProductSerial:       string(tcgCSR.CsrContents.ProdSerial),
				PermanentIdentifier: idevidCN,
			},
		}
		extraExts, hookErr := s.preSignHooks.Execute(preSignCtx)
		if hookErr != nil {
			return 0, nil, common.ServerInternal(fmt.Sprintf("Pre-sign hook failed: %v", hookErr))
		}
		tcgCSRRequest.ExtraExtensions = append(tcgCSRRequest.ExtraExtensions, extraExts...)
	}

	// Route issuance through the dedicated cluster intermediate when configured,
	// so Raft node transport certificates chain to a purpose-built intermediate
	// (root signs intermediates only) rather than the CA's default issuing
	// identity. resolveTCGSigner honors request.Signer+IssuerCert as the external
	// issuer. Fail closed: a configured but unresolvable cluster CA must not
	// silently fall back to the default issuer.
	clusterSigner, clusterIssuerCert, issuerErr := s.clusterIssuerOverride(ctx)
	if issuerErr != nil {
		s.logger.Error("Failed to resolve cluster CA issuer for enroll-01 issuance",
			"cluster_ca_cn", s.clusterCACN, "error", issuerErr.Error())
		return 0, nil, common.ServerInternal("Failed to resolve cluster CA issuer")
	}
	if clusterSigner != nil {
		tcgCSRRequest.Signer = clusterSigner
		tcgCSRRequest.IssuerCert = clusterIssuerCert
	}

	// Sign the TCG-CSR-IDEVID
	iakDER, idevidDER, err := s.ca.SignTCGCSRIDevID(ctx, tcgCSR, tcgCSRRequest)
	if err != nil {
		return 0, nil, common.ServerInternal("Failed to sign TCG-CSR-IDEVID")
	}

	idevidCert, err := x509.ParseCertificate(idevidDER)
	if err != nil {
		return 0, nil, common.ServerInternal("Failed to parse certificate")
	}

	// The IAK certificate's subject is the CA's business: SignTCGCSRIDevID
	// issues it under ca.IAKCommonName(model, serial), apart from the IDevID
	// record, and the DER returned here is handed to the finalize hooks and
	// the client unchanged.
	pem = encodeCertificatePEM(iakDER)

	// Encode the IDevID certificate to PEM
	idevidPEM := encodeCertificatePEM(idevidDER)

	// Append the IDevID certificate to the IAK certificate, then the issuing
	// chain: enroll-01 delivers two end-entity certificates, and RFC 8555
	// §7.4.2 puts the chain after them.
	pem = append(pem, idevidPEM...)
	pem = s.appendIssuingChain(pem)

	// Parse EK certificate for hook context
	ekcert, err := x509.ParseCertificate(tcgCSR.CsrContents.EkCert)
	if err != nil {
		return 0, nil, common.ServerInternal("Failed to parse EK certificate")
	}

	// enroll-01 binds a device identity to a TPM, so the trail records both the
	// enrollment decision and the IDevID certificate it produced.
	auditCtx := auditContext(r)
	s.recordAudit(audit.LogTPMEnrollment(auditCtx, s.auditLog,
		auditAccountID(account.ID), idevidCN,
		ekcert.Subject.CommonName, idevidCert.Subject.CommonName))
	s.recordAudit(audit.LogCertificateIssued(auditCtx, s.auditLog,
		auditAccountID(account.ID),
		strconv.FormatUint(order.ID, 10),
		idevidCert.Subject.CommonName,
		auditValidityDays(idevidCert),
		idevidCert.SerialNumber.String()))

	// Execute order finalization hooks if registered
	if s.params != nil && s.params.OrderFinalizeHooks != nil {
		hookCtx := &OrderFinalizeHookContext{
			Context:        r.Context(),
			Certificate:    idevidCert,
			CertificatePEM: pem,
			ClientIP:       ip,
			IsTCGCSR:       true,
			TCGData: &TCGEnrollmentData{
				ProductModel:         string(tcgCSR.CsrContents.ProdModel),
				ProductSerial:        string(tcgCSR.CsrContents.ProdSerial),
				PermanentIdentifier:  idevidCN,
				EKCertificate:        ekcert,
				IAKCertificateDER:    iakDER,
				IDevIDCertificateDER: idevidDER,
				AttestationPublicKey: tcgCSR.CsrContents.AttestPub,
				SigningPublicKey:     tcgCSR.CsrContents.SigningPub,
				EventLog:             tcgCSR.CsrContents.BootEvntLog,
				ProdCaData:           tcgCSR.CsrContents.ProdCaData,
			},
		}

		s.logger.Info("Executing TCG CSR order finalization hooks",
			"hook_count", s.params.OrderFinalizeHooks.Count(),
			"is_tcg_csr", true,
			"client_ip", ip,
			"product_model", string(tcgCSR.CsrContents.ProdModel),
			"product_serial", string(tcgCSR.CsrContents.ProdSerial),
			"prodcadata_size", len(tcgCSR.CsrContents.ProdCaData),
			"eventlog_size", len(tcgCSR.CsrContents.BootEvntLog))

		if err := s.params.OrderFinalizeHooks.Execute(hookCtx); err != nil {
			return 0, nil, common.ServerInternal(fmt.Sprintf("Order finalization hook failed: %v", err))
		}
	} else {
		s.logger.Warn("No order finalization hooks registered for TCG CSR")
	}

	// Device profile features for automated remote provisioning are implemented via
	// the OrderFinalizeHooks system. Applications can register hooks to:
	// - Enforce system state policies by verifying EventLog and PCR values
	// - Compare initial device state with expected pre-provisioning state
	// - Trigger automated provisioning workflows
	// - Capture device boot logs and attestation data for audit
	// - Register the device in an asset management system
	//
	// See OrderFinalizeHookRegistry and TCGEnrollmentData for available hook context.

	// Safely convert serial number to uint64
	var serialNumber uint64
	if idevidCert.SerialNumber == nil {
		return 0, nil, common.ServerInternal("Certificate serial number is nil")
	}
	if idevidCert.SerialNumber.IsUint64() {
		serialNumber = idevidCert.SerialNumber.Uint64()
	} else {
		// Use modulo to get lower 64 bits without panicking
		var maxUint64 big.Int
		maxUint64.SetUint64(^uint64(0))
		maxUint64.Add(&maxUint64, big.NewInt(1))
		var temp big.Int
		temp.Mod(idevidCert.SerialNumber, &maxUint64)
		serialNumber = temp.Uint64()
	}

	return serialNumber, pem, nil
}

// encodeCertificatePEM encodes DER-encoded certificate data to PEM format.
// appendIssuingChain appends the CA's issuing chain (intermediate, then root)
// after the end-entity certificate(s) already in pem.
//
// RFC 8555 §7.4.2 defines application/pem-certificate-chain as the end-entity
// certificate FOLLOWED BY THE CHAIN, and the certificate resource serves this
// body verbatim under that media type. Without the chain a client that is not
// already provisioned with this CA cannot build a path to a trust anchor, and
// an enrolled device cannot resolve the issuer of its own certificate at all
// (go-trusted-platform#653: every enroll-01 node compiled a caller-admission
// policy that admitted nobody, because CA.RootCertificate walks only the
// LOCAL store and the issuer is remote).
//
// A CA that cannot produce a bundle is not fatal to issuance: the certificate
// is already signed at this point, and withholding it would be worse than
// serving a leaf-only body. The omission is logged instead.
func (s *RestService) appendIssuingChain(pem []byte) []byte {
	bundle, err := s.ca.CABundle()
	if err != nil {
		s.logger.Warn("ACME: serving a certificate with no issuing chain; the CA bundle is unavailable",
			"error", err)
		return pem
	}
	if len(bundle) == 0 {
		s.logger.Warn("ACME: serving a certificate with no issuing chain; the CA bundle is empty")
		return pem
	}
	return append(pem, bundle...)
}

func encodeCertificatePEM(derBytes []byte) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block)
}

// encodeCSRToPEM encodes DER-encoded CSR data to PEM format.
func encodeCSRToPEM(derBytes []byte) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block)
}

// parseCertificateRequestPermanentIdentifier extracts the permanent identifier
// from a certificate request's Subject Alternative Name extension.
func parseCertificateRequestPermanentIdentifier(csr *x509.CertificateRequest) (string, error) {
	// Look for the permanent identifier in the SAN extension
	// This is a simplified implementation - you may need to expand based on your requirements
	for _, ext := range csr.Extensions {
		// OID 2.5.29.17 is SubjectAltName
		if ext.Id.Equal([]int{2, 5, 29, 17}) {
			// For now, we'll just return the subject CN as a fallback
			// A full implementation would parse the ASN.1 structure properly
			break
		}
	}

	// Fallback to subject common name
	if csr.Subject.CommonName != "" {
		return csr.Subject.CommonName, nil
	}

	return "", caerrors.MalformedError("no permanent identifier found in CSR")
}

// ErrClusterIssuerUnsupported is returned when cluster CA issuance is configured
// (ClusterCACN set) but the CA does not implement ca.IdentityIssuer, so a
// dedicated cluster intermediate cannot be resolved.
var ErrClusterIssuerUnsupported = errors.New("handlers: cluster CA issuance configured but CA does not support identity issuers")

// clusterIssuerOverride resolves the dedicated cluster intermediate that
// enroll-01 (TCG-CSR-IDEVID) issuance should chain to. It returns the external
// signer and issuer certificate to place on the CertificateRequest, or
// (nil, nil, nil) when no cluster CA CN is configured (default issuance). A
// configured CN that cannot be resolved returns an error so issuance fails
// closed rather than silently using the default issuer.
func (s *RestService) clusterIssuerOverride(ctx context.Context) (crypto.Signer, *x509.Certificate, error) {
	if s.clusterCACN == "" {
		return nil, nil, nil
	}
	issuer, ok := s.ca.(ca.IdentityIssuer)
	if !ok {
		return nil, nil, ErrClusterIssuerUnsupported
	}
	return issuer.IssuerForIdentity(ctx, s.clusterCACN)
}
