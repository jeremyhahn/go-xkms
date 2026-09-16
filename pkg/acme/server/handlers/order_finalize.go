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

// Tenant CA resolution errors. These are returned by resolveTenantSigningCA,
// getTenantCASigner, and tenantIssuerCertificate whenever a tenant-bound
// account's signing CA cannot be safely resolved. Per the fail-closed
// policy, none of these conditions may fall back to the global CA: a
// tenant-bound order whose CA cannot be resolved is rejected outright. The
// only legitimate way to sign a tenant-bound order with the global CA is an
// explicit SigningCAInfo.UseGlobalDefault, which entities.Tenant.GetSigningCA
// returns when the tenant has no root or intermediate CA configured at all.
var (
	// ErrTenantStorageUnsupported is returned when a tenant-bound account's
	// storage factory does not implement storage.TenantAwareFactory, so the
	// tenant's CA configuration cannot be looked up at all.
	ErrTenantStorageUnsupported = errors.New("handlers: tenant-bound issuance requires a tenant-aware storage factory")

	// ErrTenantDAOUnavailable is returned when the tenant-aware storage
	// factory cannot produce a TenantDAO.
	ErrTenantDAOUnavailable = errors.New("handlers: tenant DAO unavailable")

	// ErrTenantSignerUnavailable is returned when the tenant's CA signer
	// cannot be obtained from KMS, including when no KMSService is configured.
	ErrTenantSignerUnavailable = errors.New("handlers: tenant CA signer unavailable")

	// ErrTenantCATypeUnsupported is returned when a resolved SigningCAInfo
	// carries a CA type other than intermediate or root.
	ErrTenantCATypeUnsupported = errors.New("handlers: unsupported tenant signing CA type")

	// ErrTenantIssuerCertUnavailable is returned when the tenant's own
	// issuer certificate cannot be retrieved or parsed from KMS.
	ErrTenantIssuerCertUnavailable = errors.New("handlers: tenant CA issuer certificate unavailable")

	// ErrTenantSignerIssuerMismatch is returned when a tenant CA signer's
	// public key does not match the issuer certificate it would be paired
	// with, which would produce a certificate chain that never verifies.
	ErrTenantSignerIssuerMismatch = errors.New("handlers: tenant CA signer does not match issuer certificate")
)

// resolveTenantSigningCA determines which CA should sign certificates for the given account.
// For multi-tenant deployments, this looks up the tenant and uses GetSigningCA to determine
// the signing authority. For single-tenant deployments (account.TenantID == ""), it returns
// (nil, nil) to indicate the global CA should be used.
//
// Tenant-bound accounts fail closed: if the tenant cannot be resolved, or is
// suspended/inactive, this returns a non-nil error rather than silently
// falling back to the global CA. The global CA is only used for a
// tenant-bound account when GetSigningCA explicitly reports
// SigningCAInfo.UseGlobalDefault, which reflects the tenant's own
// configuration rather than a resolution failure.
//
// Parameters:
//   - ctx: the request context
//   - account: the ACME account requesting certificate issuance
//   - purpose: the intended purpose (e.g., "tpm-endorsement", "general")
//
// Returns the SigningCAInfo indicating which CA should sign, (nil, nil) to
// use the global default for a non-tenant account, or a non-nil error if a
// tenant-bound account's signing CA could not be resolved.
func (s *RestService) resolveTenantSigningCA(ctx context.Context, account *entities.ACMEAccount, purpose string) (*entities.SigningCAInfo, error) {
	// If no tenant ID, use global CA
	if account.TenantID == "" {
		s.logger.Debug("Account has no tenant ID, using global CA",
			"account_id", account.ID)
		return nil, nil
	}

	// Check if storage factory supports tenant-aware operations
	tenantAwareFactory, ok := s.storageFactory.(storage.TenantAwareFactory)
	if !ok {
		s.logger.Error("Storage factory does not support tenant-aware operations, refusing tenant-bound issuance",
			"account_id", account.ID,
			"tenant_id", account.TenantID)
		return nil, ErrTenantStorageUnsupported
	}

	// Get TenantDAO
	tenantDAO, err := tenantAwareFactory.TenantDAO()
	if err != nil {
		s.logger.Error("Failed to get TenantDAO, refusing tenant-bound issuance",
			"error", err,
			"account_id", account.ID,
			"tenant_id", account.TenantID)
		return nil, ErrTenantDAOUnavailable
	}

	// Look up the tenant by string ID
	tenant, err := tenantDAO.Get(ctx, entities.StringToEntityID(account.TenantID))
	if err != nil {
		s.logger.Error("Failed to get tenant, refusing tenant-bound issuance",
			"error", err,
			"account_id", account.ID,
			"tenant_id", account.TenantID)
		return nil, ErrTenantNotFound
	}

	// Check if tenant is active
	if !tenant.IsActive() {
		s.logger.Error("Tenant is not active, refusing tenant-bound issuance",
			"account_id", account.ID,
			"tenant_id", account.TenantID,
			"tenant_status", tenant.Status)
		return nil, ErrTenantInactive
	}

	// Get the signing CA for this tenant
	signingCA := tenant.GetSigningCA(purpose)

	s.logger.Info("Resolved tenant signing CA",
		"account_id", account.ID,
		"tenant_id", account.TenantID,
		"signing_ca_type", signingCA.Type,
		"purpose", purpose,
		"use_global_default", signingCA.UseGlobalDefault)

	return signingCA, nil
}

// getTenantCASigner retrieves the appropriate signer for tenant CA operations.
// Returns a crypto.Signer from KMS if tenant-specific CA is configured, or
// (nil, nil) when signingCAInfo is nil or explicitly configured to use the
// global default.
//
// A tenant-bound SigningCAInfo whose signer cannot be obtained from KMS -
// including when no KMSService is configured at all - fails closed with a
// non-nil error rather than falling back to the global CA.
//
// Parameters:
//   - ctx: the request context
//   - signingCAInfo: the resolved signing CA info from resolveTenantSigningCA
//
// Returns the crypto.Signer for tenant signing, (nil, nil) to use the global
// CA when explicitly configured, or a non-nil error if the tenant signer
// could not be resolved.
func (s *RestService) getTenantCASigner(ctx context.Context, signingCAInfo *entities.SigningCAInfo) (crypto.Signer, error) {
	// If no signing CA info or explicitly configured to use the global
	// default, use the global CA.
	if signingCAInfo == nil || signingCAInfo.UseGlobalDefault {
		return nil, nil
	}

	// A tenant-bound signing CA with no KMS service configured cannot be
	// resolved: fail closed rather than silently using the global CA.
	if s.kmsService == nil {
		s.logger.Error("KMSService not configured, refusing tenant-bound issuance",
			"tenant_id", signingCAInfo.TenantID)
		return nil, ErrTenantSignerUnavailable
	}

	// Determine the key purpose based on signing CA type
	var purpose kms.KeyPurpose
	switch signingCAInfo.Type {
	case entities.SigningCATypeIntermediate:
		purpose = kms.KeyPurposeTenantIntermediateCA
	case entities.SigningCATypeRoot:
		purpose = kms.KeyPurposeTenantRootCA
	default:
		s.logger.Error("Unsupported signing CA type, refusing tenant-bound issuance",
			"type", signingCAInfo.Type,
			"tenant_id", signingCAInfo.TenantID)
		return nil, ErrTenantCATypeUnsupported
	}

	// Get the signer from KMS
	signer, err := s.kmsService.GetSigningKey(ctx, signingCAInfo.TenantID, purpose)
	if err != nil {
		s.logger.Error("Failed to get tenant CA signer from KMS, refusing tenant-bound issuance",
			"error", err,
			"tenant_id", signingCAInfo.TenantID,
			"purpose", purpose)
		return nil, ErrTenantSignerUnavailable
	}

	s.logger.Info("Using tenant CA signer from KMS",
		"tenant_id", signingCAInfo.TenantID,
		"purpose", purpose,
		"signing_ca_type", signingCAInfo.Type)

	return signer, nil
}

// tenantIssuerCertificate retrieves and parses the tenant's own issuing
// certificate from KMS for the CA type described by signingCAInfo. It never
// falls back to the global CA's certificates: a tenant-specific signer must
// only ever be paired with that same tenant's issuer certificate, since
// x509.CreateCertificate signs with the supplied signer but stamps the
// issuer identity from the supplied certificate. Pairing a tenant key with
// a different CA's certificate produces a certificate whose signature does
// not verify against its stated issuer.
func (s *RestService) tenantIssuerCertificate(ctx context.Context, signingCAInfo *entities.SigningCAInfo) (*x509.Certificate, error) {
	if s.kmsService == nil {
		return nil, ErrTenantIssuerCertUnavailable
	}

	purpose := kms.KeyPurposeTenantIntermediateCA
	if signingCAInfo.Type == entities.SigningCATypeRoot {
		purpose = kms.KeyPurposeTenantRootCA
	}

	certDER, err := s.kmsService.GetCertificate(ctx, signingCAInfo.TenantID, purpose)
	if err != nil {
		s.logger.Error("Failed to get tenant CA certificate from KMS, refusing tenant-bound issuance",
			"error", err,
			"tenant_id", signingCAInfo.TenantID)
		return nil, ErrTenantIssuerCertUnavailable
	}
	if len(certDER) == 0 {
		s.logger.Error("Tenant CA certificate from KMS is empty, refusing tenant-bound issuance",
			"tenant_id", signingCAInfo.TenantID)
		return nil, ErrTenantIssuerCertUnavailable
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		s.logger.Error("Failed to parse tenant CA certificate from KMS, refusing tenant-bound issuance",
			"error", err,
			"tenant_id", signingCAInfo.TenantID)
		return nil, ErrTenantIssuerCertUnavailable
	}

	s.logger.Info("Using tenant CA certificate from KMS",
		"tenant_id", signingCAInfo.TenantID,
		"signing_ca_type", signingCAInfo.Type)

	return cert, nil
}

// signerMatchesIssuer reports whether signer's public key matches the
// issuer certificate's public key. x509.CreateCertificate signs the new
// certificate with signer but populates the issuer name and Authority Key
// Identifier from issuerCert; if the two keys do not correspond to the same
// private key, the resulting signature will never verify against
// issuerCert, so a mismatch here must never be allowed to reach signing.
func signerMatchesIssuer(signer crypto.Signer, issuerCert *x509.Certificate) bool {
	type publicKeyEqualer interface {
		Equal(x crypto.PublicKey) bool
	}
	pub, ok := signer.Public().(publicKeyEqualer)
	if !ok {
		return false
	}
	return pub.Equal(issuerCert.PublicKey)
}

// tenantSigningCAProblem converts a tenant CA resolution failure into the
// RFC 8555 problem document returned to the client. Every case here is a
// rejection, never a fallback to the global CA: a suspended or inactive
// tenant is the account's own fault (unauthorized), while every other cause
// is a server-side CA resolution failure the client cannot correct.
func tenantSigningCAProblem(err error) *entities.Error {
	if errors.Is(err, ErrTenantInactive) {
		return common.Unauthorized("Tenant is not active")
	}
	return common.ServerInternal("Failed to resolve tenant signing CA")
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

	// The order is not moved to "processing" until the payload, the CSR and
	// the identifiers it carries have all been validated: a malformed
	// submission must leave the order retryable in "ready", not stranded in
	// "processing" forever with no path back to a usable state.

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

	// Determine whether this is an endorse-01 order (x509 CSR + permanent-identifier
	// whose value is the EK public key being certified, not a name in the CSR). The
	// permanent identifier itself was already authorized when the endorse-01
	// challenge was validated (via EAB/server policy), so it is not re-checked
	// against the CSR here - only the CSR's DNS/IP SANs (and the blanket
	// email/URI rejection) are still enforced, via matchesEndorse01Identifier.
	isEndorse01 := len(order.Identifiers) > 0 &&
		order.Identifiers[0].Type == common.AuthzTypePermanentIdentifier
	if isEndorse01 {
		if _, ok := decodeEndorse01PublicKey(order.Identifiers[0].Value); !ok {
			isEndorse01 = false
		}
	}

	// Ensure the CSR's identity set corresponds exactly to the order's
	// authorized identifiers per RFC 8555 Section 7.4 before any certificate
	// work begins.
	var matches bool
	var matchErr error
	if isEndorse01 {
		matches, matchErr = matchesEndorse01Identifier(csr, order)
	} else {
		matches, matchErr = matchesIdentifier(csr, order)
	}
	if matchErr != nil {
		writeError(w, matchErr.(*entities.Error))
		return
	}
	if !matches {
		writeError(w, common.MalformedError("CSR does not match order identifiers", nil))
		return
	}

	// The CSR and its identifiers are now validated: only from this point can
	// the order meaningfully move to "processing". Any failure past this line
	// must drive the order to a terminal "invalid" state via failOrder rather
	// than leave it stranded.
	order.Status = common.StatusProcessing
	if err := orderDAO.Save(ctx, order); err != nil {
		writeError(w, common.ServerInternal("Failed to update order status"))
		return
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
					s.failOrder(ctx, orderDAO, order, w, common.CAAError(err.Error()))
					return
				}

				// Other errors (DNS errors, etc.) - return as CAA error per RFC
				s.failOrder(ctx, orderDAO, order, w, common.CAAError(fmt.Sprintf("CAA validation error: %v", err)))
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
	signingCAInfo, err = s.resolveTenantSigningCA(ctx, account, purpose)
	if err != nil {
		s.logger.Error("Failed to resolve tenant signing CA",
			"error", err, "account_id", account.ID, "tenant_id", account.TenantID)
		s.failOrder(ctx, orderDAO, order, w, tenantSigningCAProblem(err))
		return
	}

	// Get the appropriate signer based on tenant CA configuration. A nil
	// signer means the account is not tenant-bound, or the tenant is
	// explicitly configured (SigningCAInfo.UseGlobalDefault) to use the
	// global CA - never a fallback from an unresolved tenant CA.
	tenantSigner, err := s.getTenantCASigner(ctx, signingCAInfo)
	if err != nil {
		s.logger.Error("Failed to get tenant CA signer",
			"error", err, "tenant_id", account.TenantID)
		s.failOrder(ctx, orderDAO, order, w, tenantSigningCAProblem(err))
		return
	}

	// Resolve the tenant's own issuer certificate when a tenant-specific
	// signer is in play. The tenant key must never be paired with the
	// global CA's issuer certificate, so there is no fallback here: if the
	// tenant's certificate cannot be retrieved, or its key does not match
	// the tenant signer, issuance fails closed.
	var issuerCert *x509.Certificate
	if tenantSigner != nil {
		issuerCert, err = s.tenantIssuerCertificate(ctx, signingCAInfo)
		if err != nil {
			s.logger.Error("Failed to resolve tenant CA issuer certificate",
				"error", err, "tenant_id", signingCAInfo.TenantID)
			s.failOrder(ctx, orderDAO, order, w, tenantSigningCAProblem(err))
			return
		}

		if !signerMatchesIssuer(tenantSigner, issuerCert) {
			s.logger.Error("Tenant CA signer does not match issuer certificate",
				"error", ErrTenantSignerIssuerMismatch, "tenant_id", signingCAInfo.TenantID)
			s.failOrder(ctx, orderDAO, order, w, tenantSigningCAProblem(ErrTenantSignerIssuerMismatch))
			return
		}
	}

	// Check if this is an endorse-01 order (x509 CSR + permanent-identifier with base64 public key)
	// endorse-01 is for issuing EK certificates to TPMs without manufacturer EK certs
	// device-attest-01 also uses permanent-identifier but with IP/hostname, not base64 public key
	var cert *x509.Certificate
	isEndorse01Order := false

	if len(order.Identifiers) > 0 &&
		order.Identifiers[0].Type == common.AuthzTypePermanentIdentifier {

		// Distinguish endorse-01 (identifier is a base64url-encoded PKIX
		// public key) from device-attest-01 (identifier is an IP/hostname).
		if ekPubKey, ok := decodeEndorse01PublicKey(order.Identifiers[0].Value); ok {
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

			// Add SANs from CSR. matchesEndorse01Identifier has already
			// rejected email/URI SANs and any DNS/IP SAN not present in the
			// order's authorized identifiers, so every name copied here was
			// already authorized.
			if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 {
				ekRequest.SANS = &ca.SubjectAlternativeNames{
					DNS: csr.DNSNames,
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
				s.failOrder(ctx, orderDAO, order, w, common.ServerInternal("Failed to issue EK certificate"))
				return
			}
		} else {
			// Not endorse-01: treat this as device-attest-01 or a standard cert.
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
				s.failOrder(ctx, orderDAO, order, w,
					common.Unauthorized(fmt.Sprintf("Pre-issuance check failed: %v", err)))
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
				s.failOrder(ctx, orderDAO, order, w,
					common.ServerInternal(fmt.Sprintf("Pre-sign hook failed: %v", hookErr)))
				return
			}
			signOpts.ExtraExtensions = append(signOpts.ExtraExtensions, extraExts...)
		}

		cert, err = s.ca.SignCSR(r.Context(), csrPEM, signOpts)
		if err != nil {
			s.failOrder(ctx, orderDAO, order, w, common.ServerInternal("Failed to sign CSR"))
			return
		}
	}

	// Use the lower 64 bits of the serial number for storage
	// X.509 serial numbers can be up to 20 bytes, but we store as uint64
	// If the serial number is too large, extract only the lower 64 bits
	if cert.SerialNumber == nil {
		s.failOrder(ctx, orderDAO, order, w, common.ServerInternal("Certificate serial number is nil"))
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
		s.failOrder(ctx, orderDAO, order, w, common.ServerInternal("Failed to verify certificate"))
		return
	}

	// Encode the certificate to PEM
	pem = encodeCertificatePEM(cert.Raw)

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
			s.failOrder(ctx, orderDAO, order, w,
				common.ServerInternal(fmt.Sprintf("Order finalization hook failed: %v", err)))
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

// matchesIdentifier verifies that a CSR's complete identity set - its
// Subject Common Name together with every DNS and IP Subject Alternative
// Name - corresponds exactly to the order's authorized identifiers, per
// RFC 8555 Section 7.4. Both directions are checked: a name the CSR carries
// that the order did not authorize is rejected (this is what previously let
// unauthorized SAN issuance through, since only the CommonName was ever
// compared), and an authorized identifier the CSR omits is also rejected. A
// CSR with no CommonName is valid as long as its SANs alone cover the
// authorized set exactly.
//
// Email address and URI SANs are never permitted in an ACME CSR and are
// rejected outright, since the CA has no order-identifier type to authorize
// them against and RFC 8555 orders only ever carry "dns" or "ip"
// identifiers (aside from the permanent-identifier extension handled
// below).
//
// Orders authorizing a permanent-identifier (enroll-01, device-attest-01)
// are matched by comparing the permanent identifier embedded in the CSR
// against the order's identifier value, preserving the pre-existing
// permanent-identifier semantics unchanged. The endorse-01 flow, where the
// order's permanent identifier is the EK public key being certified rather
// than a name the CSR carries, uses matchesEndorse01Identifier instead.
func matchesIdentifier(
	csr *x509.CertificateRequest,
	order *entities.ACMEOrder) (bool, error) {

	if len(csr.EmailAddresses) > 0 {
		return false, common.MalformedError("CSR must not contain email address SANs", nil)
	}
	if len(csr.URIs) > 0 {
		return false, common.MalformedError("CSR must not contain URI SANs", nil)
	}

	for _, identifier := range order.Identifiers {
		if identifier.Type == common.AuthzTypePermanentIdentifier {
			permanentID, err := parseCertificateRequestPermanentIdentifier(csr)
			if err != nil {
				return false, common.MalformedError("Failed to parse permanent-identifier", nil)
			}
			return identifier.Value == permanentID, nil
		}
	}

	authorized := make(map[string]bool, len(order.Identifiers))
	for _, identifier := range order.Identifiers {
		switch identifier.Type {
		case common.AuthzTypeDNS, common.AuthzTypeIP:
			authorized[identifier.Value] = true
		default:
			return false,
				common.UnsupportedIdentifier(fmt.Sprintf("Invalid identifier: %s", identifier.Type))
		}
	}

	requested := make(map[string]bool, len(csr.DNSNames)+len(csr.IPAddresses)+1)
	if csr.Subject.CommonName != "" {
		requested[csr.Subject.CommonName] = true
	}
	for _, name := range csr.DNSNames {
		requested[name] = true
	}
	for _, ip := range csr.IPAddresses {
		requested[ip.String()] = true
	}

	if len(requested) == 0 || len(requested) != len(authorized) {
		return false, nil
	}
	for name := range requested {
		if !authorized[name] {
			return false, nil
		}
	}
	return true, nil
}

// matchesEndorse01Identifier validates a permanent-identifier order's CSR
// for the endorse-01 flow, where the order's identifier is the EK public
// key being certified rather than a name the CSR is expected to carry. The
// permanent-identifier comparison performed by matchesIdentifier is
// intentionally left out here - that identity was already authorized when
// the endorse-01 challenge was validated - but every other identity the CSR
// carries must still correspond exactly to the order's authorized DNS/IP
// identifiers, and email/URI SANs remain forbidden, exactly as in
// matchesIdentifier.
func matchesEndorse01Identifier(
	csr *x509.CertificateRequest,
	order *entities.ACMEOrder) (bool, error) {

	if len(csr.EmailAddresses) > 0 {
		return false, common.MalformedError("CSR must not contain email address SANs", nil)
	}
	if len(csr.URIs) > 0 {
		return false, common.MalformedError("CSR must not contain URI SANs", nil)
	}

	authorized := make(map[string]bool, len(order.Identifiers))
	for _, identifier := range order.Identifiers {
		switch identifier.Type {
		case common.AuthzTypeDNS, common.AuthzTypeIP:
			authorized[identifier.Value] = true
		case common.AuthzTypePermanentIdentifier:
			// The permanent identifier is the EK public key authorized during
			// the endorse-01 challenge, not a name the CSR carries. It is
			// intentionally excluded from the CSR name comparison below.
		default:
			return false,
				common.UnsupportedIdentifier(fmt.Sprintf("Invalid identifier: %s", identifier.Type))
		}
	}

	requested := make(map[string]bool, len(csr.DNSNames)+len(csr.IPAddresses))
	for _, name := range csr.DNSNames {
		requested[name] = true
	}
	for _, ip := range csr.IPAddresses {
		requested[ip.String()] = true
	}

	if len(requested) != len(authorized) {
		return false, nil
	}
	for name := range requested {
		if !authorized[name] {
			return false, nil
		}
	}
	return true, nil
}

// decodeEndorse01PublicKey attempts to decode a permanent-identifier order's
// identifier value as a base64url-encoded PKIX public key. This is what
// distinguishes an endorse-01 order - where the identifier IS the EK public
// key being certified - from a device-attest-01 order, where the identifier
// is an IP address or hostname. Returns the parsed key and true on success.
func decodeEndorse01PublicKey(identifierValue string) (crypto.PublicKey, bool) {
	ekPubKeyBytes, err := base64.RawURLEncoding.DecodeString(identifierValue)
	if err != nil {
		return nil, false
	}
	ekPubKey, err := x509.ParsePKIXPublicKey(ekPubKeyBytes)
	if err != nil {
		return nil, false
	}
	return ekPubKey, true
}

// failOrder transitions an order to the terminal "invalid" status with the
// given error and writes the error response. It must be used for every
// failure that occurs once the order has moved to "processing": per RFC
// 8555 Section 7.1.6, an order the CA cannot fulfill must reach a terminal
// state with its error field populated, never remain stranded in
// "processing" indefinitely.
func (s *RestService) failOrder(
	ctx context.Context,
	orderDAO qrdbsdk.GenericDAO[*entities.ACMEOrder],
	order *entities.ACMEOrder,
	w http.ResponseWriter,
	acmeErr *entities.Error) {

	order.Status = common.StatusInvalid
	order.Error = acmeErr
	if saveErr := orderDAO.Save(ctx, order); saveErr != nil {
		s.logger.Error("Failed to persist invalid order status",
			"error", saveErr, "order_id", order.ID)
	}
	writeError(w, acmeErr)
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

	// Append the IDevID certificate to the IAK certificate
	pem = append(pem, idevidPEM...)

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
