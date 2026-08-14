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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// Revocation statuses (for /revoke-cert)
const (
	RevocationReasonUnspecified          = 0 // Unspecified reason for revocation
	RevocationReasonKeyCompromise        = 1 // The key associated with the certificate has been compromised
	RevocationReasonCACertCompromise     = 2 // The issuing CA certificate has been compromised
	RevocationReasonAffiliationChanged   = 3 // The entity's affiliation with the domain has changed
	RevocationReasonSuperseded           = 4 // The certificate has been superseded by another certificate
	RevocationReasonCessationOfOperation = 5 // The entity has ceased its operations (e.g., the domain is no longer used)
	RevocationReasonCertificateHold      = 6 // The certificate is placed on hold (temporary revocation)
)

type RevokeCertRequest struct {
	Certificate string `json:"certificate"`
	Reason      int    `json:"reason,omitempty"`
}

func (s *RestService) RevokeCertHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("RevokeCertHandler", "method", r.Method, "url", r.URL)
	ctx := r.Context()

	// Parse and validate the requesting account
	account, payload, err := s.parseKID(ctx, r)
	if err != nil {
		writeError(w, common.MalformedError("Failed to parse account key", nil))
		return
	}

	// Verify account is valid and active
	if account.Status != common.StatusValid {
		writeError(w, common.Unauthorized("Account is not active"))
		return
	}

	var revokeRequest RevokeCertRequest
	if err := json.Unmarshal(payload, &revokeRequest); err != nil {
		writeError(w, common.MalformedError("Invalid request payload", nil))
		return
	}

	certDER, err := base64.RawURLEncoding.DecodeString(revokeRequest.Certificate)
	if err != nil {
		http.Error(w, "Invalid certificate encoding", http.StatusBadRequest)
		return
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		http.Error(w, "Invalid certificate format", http.StatusBadRequest)
		return
	}

	reason := revokeRequest.Reason
	if reason < 0 || reason > 10 {
		http.Error(w, "Invalid revocation reason", http.StatusBadRequest)
		return
	}

	certificateDAO, err := s.storageFactory.CertificateDAO()
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create certificate DAO"))
		return
	}
	entity, err := certificateDAO.Get(ctx, cert.SerialNumber.Uint64())
	if err != nil {
		writeError(w, common.MalformedError("Certificate not found", nil))
		return
	}

	// RFC 8555 Section 7.6: Authorization for revocation
	// An account can revoke a certificate if it has valid authorizations
	// for all identifiers in the certificate.
	// Extract DNS names from certificate (CN and SANs)
	dnsNames := cert.DNSNames
	if cert.Subject.CommonName != "" {
		// Check if CN is already in DNSNames
		found := false
		for _, name := range dnsNames {
			if name == cert.Subject.CommonName {
				found = true
				break
			}
		}
		if !found {
			dnsNames = append(dnsNames, cert.Subject.CommonName)
		}
	}

	// Verify the account has valid authorizations for all domains
	authzDAO, err := s.storageFactory.AuthorizationDAO(account.ID)
	if err != nil {
		writeError(w, common.ServerInternal("Failed to create authorization DAO"))
		return
	}

	// Get all authorizations for this account
	var authorizations []*entities.ACMEAuthorization
	err = authzDAO.ForEachPage(ctx, qrdbsdk.PageQuery{PageSize: 1000}, func(page qrdbsdk.PageResult[*entities.ACMEAuthorization]) error {
		authorizations = append(authorizations, page.Entities...)
		return nil
	})
	if err != nil {
		writeError(w, common.ServerInternal("Failed to retrieve authorizations"))
		return
	}

	// Build a map of valid authorizations by domain
	validAuthz := make(map[string]bool)
	for _, authz := range authorizations {
		if authz.Status == common.StatusValid && authz.Identifier.Type == "dns" {
			validAuthz[authz.Identifier.Value] = true
		}
	}

	// Check if account has authorization for all certificate domains
	for _, domain := range dnsNames {
		if !validAuthz[domain] {
			s.logger.Warn("Unauthorized revocation attempt",
				slog.Uint64("account_id", account.ID),
				slog.String("domain", domain),
				slog.String("serial", cert.SerialNumber.String()))

			// An account trying to revoke a certificate it never proved control
			// over is a security event, so it is recorded even though nothing
			// changed.
			s.recordAudit(s.auditLog.LogWithContext(auditContext(r),
				audit.EventAuthorizationFailed,
				auditAccountRef(account.ID),
				"certificate:"+cert.SerialNumber.String(),
				"revoke",
				audit.ResultFailure,
				map[string]interface{}{
					"serial_number":     cert.SerialNumber.String(),
					"domain":            domain,
					"unauthorized_kind": "no valid authorization for certificate domain",
				}))
			writeError(w, common.Unauthorized("Account not authorized for certificate domain: "+domain))
			return
		}
	}

	s.logger.Info("Authorization verified for certificate revocation",
		slog.Uint64("account_id", account.ID),
		slog.String("serial", cert.SerialNumber.String()))

	entity.Status = common.StatusRevoked

	if err := certificateDAO.Save(ctx, entity); err != nil {
		writeError(w, common.ServerInternal("Failed to update certificate status"))
		return
	}

	s.logger.Debug("Revoking certificate", slog.String("serial", cert.SerialNumber.String()))
	s.recordAudit(audit.LogCertificateRevoked(auditContext(r), s.auditLog,
		auditAccountID(account.ID), cert.SerialNumber.String(), reason))

	// Revoke the certificate
	// Note: The CA interface doesn't expose a Revoke method
	// The certificate status has already been updated in the database above
	// If the CA needs to publish a CRL, that should happen automatically via a background process

	w.WriteHeader(http.StatusOK)
}
