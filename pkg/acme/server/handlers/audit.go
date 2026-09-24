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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
)

// AuditLogger returns the audit logger recording this service's decisions.
// It is never nil: a service configured without one records to a no-op logger,
// so call sites never have to test for absence.
func (s *RestService) AuditLogger() audit.AuditLogger {
	return s.auditLog
}

// SetAuditLogger replaces the audit logger. A nil logger restores the no-op
// logger rather than leaving the service unable to record.
func (s *RestService) SetAuditLogger(logger audit.AuditLogger) {
	if logger == nil {
		logger = audit.NewNoOpLogger()
	}
	s.auditLog = logger
	if s.params != nil {
		s.params.AuditLogger = logger
	}
}

// auditContext derives the context used for audit events recorded while
// handling r, stamping the correlation ID, client address, and user agent onto
// every event the handler emits.
func auditContext(r *http.Request) context.Context {
	return audit.RequestContext(r.Context(), r)
}

// recordAudit applies the go-xkms audit write-failure policy
// (docs/audit-log/engineering.md) to the error an audit.Log* helper
// returned for eventType. For a SeveritySecurity event type (certificate
// issuance/revocation, authentication failure, TPM enrollment, account key
// change, and any other event nobody has explicitly reviewed and
// classified informational), a write failure is returned as
// *audit.ErrAuditWriteFailed and the caller must fail the request rather
// than let a security-relevant ACME operation complete unaudited. For a
// SeverityInformational event type (account/order/authorization/challenge
// protocol progress), the failure is logged and counted, and recordAudit
// returns nil so the caller proceeds.
func (s *RestService) recordAudit(eventType audit.EventType, err error) error {
	return audit.HandleWriteFailure(s.logger, eventType, err)
}

// auditAccountID renders an ACME account ID for the audit.Log* helpers, which
// prefix it with "account:" themselves when they build the event.
func auditAccountID(accountID uint64) string {
	return strconv.FormatUint(accountID, 10)
}

// auditAccountRef renders an ACME account as it appears in an audit event's
// actor and resource fields. Events built directly, rather than through an
// audit.Log* helper, use this so every record names accounts identically.
func auditAccountRef(accountID uint64) string {
	return "account:" + auditAccountID(accountID)
}

// auditKeyFingerprint renders a public key as the stack's canonical SPKI
// thumbprint: base64url of the SHA-256 over the DER SubjectPublicKeyInfo, the
// same identifier certificate bindings use. It returns "unknown" for a key that
// cannot be marshalled, so an audit record is still written for the rollover
// rather than being dropped over a formatting problem.
func auditKeyFingerprint(key crypto.PublicKey) string {
	if key == nil {
		return "unknown"
	}

	spki, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "unknown"
	}

	sum := sha256.Sum256(spki)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// auditValidityDays reports the lifetime an issued certificate was granted,
// rounded down to whole days. It is recorded alongside every issuance so an
// auditor can spot a certificate that outlived the deployment's policy.
func auditValidityDays(cert *x509.Certificate) int {
	if cert == nil || cert.NotAfter.Before(cert.NotBefore) {
		return 0
	}
	return int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
}
