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

package webauthn

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
)

// CloneWarningAuditAction is the audit Event.Action recorded when a login
// completes with a credential whose signature counter did not advance
// (go-webauthn's CloneWarning, WebAuthn L2 §6.1.1). It classifies
// SeveritySecurity, so a failed audit write fails the login.
const CloneWarningAuditAction = "auth.webauthn.clone_warning"

// cloneWarningAuditResource is the audit Event.Resource for a clone warning.
const cloneWarningAuditResource = "webauthn_credential"

// reportCloneWarning logs at Warn and audits a login whose credential carries
// go-webauthn's CloneWarning: the authenticator presented a signature counter
// no greater than the stored one, which is how WebAuthn signals that the
// credential's private key may exist on more than one authenticator.
//
// It reports and nothing more. Whether a flagged credential may still log in
// is relying-party policy (WebAuthn L2 §6.1.1 leaves it to the RP), and the
// login proceeds unchanged. The warning is sticky on the stored credential,
// so every later login with it is reported too; first_detection marks the
// login that raised it.
//
// A nil audit logger records nothing beyond the log line. Otherwise the audit
// write-failure policy applies: the returned *audit.ErrAuditWriteFailed must
// fail the login rather than let it complete unaudited.
func (s *Service) reportCloneWarning(ctx context.Context, user User, stored *Credential, presentedCount uint32) error {
	credentialID := base64.RawURLEncoding.EncodeToString(stored.ID)
	firstDetection := !stored.Authenticator.CloneWarning

	s.logger.Warn("webauthn: credential signature counter did not advance; the authenticator may be cloned",
		"user", user.WebAuthnName(),
		"credential_id", credentialID,
		"stored_sign_count", stored.Authenticator.SignCount,
		"presented_sign_count", presentedCount,
		"first_detection", firstDetection,
	)

	if s.auditLogger == nil {
		return nil
	}
	event := &audit.Event{
		Timestamp:  time.Now().UTC(),
		Subject:    user.WebAuthnName(),
		Action:     CloneWarningAuditAction,
		Resource:   cloneWarningAuditResource,
		ResourceID: credentialID,
		Outcome:    audit.OutcomeAllow,
		Details: map[string]string{
			"stored_sign_count":    strconv.FormatUint(uint64(stored.Authenticator.SignCount), 10),
			"presented_sign_count": strconv.FormatUint(uint64(presentedCount), 10),
			"first_detection":      strconv.FormatBool(firstDetection),
			"rp_id":                s.config.RPID,
		},
	}
	return audit.HandleWriteFailure(s.logger, CloneWarningAuditAction, s.auditLogger.Log(ctx, event))
}
