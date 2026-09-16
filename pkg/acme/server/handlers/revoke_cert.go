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
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
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

	// The submitted certificate only carries a serial number that was used
	// to look up the stored record above; its other fields (subject, SANs,
	// signature) are entirely attacker-controlled. A self-signed certificate
	// forged with a victim's serial number would otherwise sail through
	// authorization using names the attacker chose. Requiring byte-equality
	// with the certificate this server actually issued closes that gap, and
	// every authorization decision below uses the STORED certificate's
	// identities, never the submitted one's.
	storedCert, err := parseStoredCertificatePEM(entity.PEM)
	if err != nil {
		s.logger.Error("Failed to parse stored certificate record",
			slog.Uint64("account_id", account.ID),
			slog.String("serial", cert.SerialNumber.String()),
			slog.String("error", err.Error()))
		writeError(w, common.ServerInternal("Failed to parse stored certificate"))
		return
	}
	if !bytes.Equal(cert.Raw, storedCert.Raw) {
		s.logger.Warn("Revocation request certificate does not match stored record",
			slog.Uint64("account_id", account.ID),
			slog.String("serial", cert.SerialNumber.String()))

		s.recordAudit(s.auditLog.LogWithContext(auditContext(r),
			audit.EventAuthorizationFailed,
			auditAccountRef(account.ID),
			"certificate:"+cert.SerialNumber.String(),
			"revoke",
			audit.ResultFailure,
			map[string]interface{}{
				"serial_number":     cert.SerialNumber.String(),
				"unauthorized_kind": "submitted certificate does not match stored record",
			}))
		writeError(w, common.Unauthorized("Certificate does not match the certificate on record"))
		return
	}

	// RFC 8555 Section 7.6: Authorization for revocation
	// An account can revoke a certificate if it has valid authorizations
	// for all identifiers in the certificate. Extract DNS names from the
	// STORED certificate (CN and SANs) - never the submitted one.
	dnsNames := storedCert.DNSNames
	if storedCert.Subject.CommonName != "" {
		// Check if CN is already in DNSNames
		found := false
		for _, name := range dnsNames {
			if name == storedCert.Subject.CommonName {
				found = true
				break
			}
		}
		if !found {
			dnsNames = append(dnsNames, storedCert.Subject.CommonName)
		}
	}

	if len(dnsNames) == 0 {
		s.logger.Warn("Certificate has no identifiers to authorize revocation against",
			slog.Uint64("account_id", account.ID),
			slog.String("serial", cert.SerialNumber.String()))
		writeError(w, common.Unauthorized("Certificate has no identifiers to authorize revocation"))
		return
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

	// Revoke the certificate with the canonical CA revocation entry point
	// (mirroring pkg/acme/admin/service.go's RevokeCertificate) before
	// touching the ACME record, so the CA's revocation list and any CRL it
	// publishes actually reflect the revocation instead of only the ACME
	// bookkeeping. An already-revoked certificate is treated as success:
	// the desired end state - revoked - already holds.
	if err := s.ca.RevokeCert(ctx, storedCert, ca.RevokeOptions{Reason: reason}); err != nil {
		if !errors.Is(err, ca.ErrAlreadyRevoked) {
			s.logger.Error("Failed to revoke certificate with CA",
				slog.String("serial", cert.SerialNumber.String()),
				slog.String("error", err.Error()))
			writeError(w, common.ServerInternal("Failed to revoke certificate"))
			return
		}
	}

	entity.Status = common.StatusRevoked

	if err := certificateDAO.Save(ctx, entity); err != nil {
		writeError(w, common.ServerInternal("Failed to update certificate status"))
		return
	}

	s.logger.Debug("Revoked certificate", slog.String("serial", cert.SerialNumber.String()))
	s.recordAudit(audit.LogCertificateRevoked(auditContext(r), s.auditLog,
		auditAccountID(account.ID), cert.SerialNumber.String(), reason))

	w.WriteHeader(http.StatusOK)
}

// parseStoredCertificatePEM decodes the PEM-encoded certificate stored on an
// ACMECertificate record back into an *x509.Certificate, so revocation
// authorization and CA revocation can be performed against the certificate
// this server actually issued rather than one supplied by the caller.
func parseStoredCertificatePEM(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, caerrors.SerializationFailureError("no PEM block found in stored certificate record")
	}
	return x509.ParseCertificate(block.Bytes)
}
