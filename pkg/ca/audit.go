// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ca

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
)

// Audit action vocabulary for CA lifecycle events. These are xkms's generic
// pkg/audit.Event.Action values (the same vocabulary pkg/seal and
// pkg/api/grpc use), not pkg/acme/audit's ACME-specific EventType enum:
// pkg/ca is consumed by non-ACME callers (enterprise PKI, the init ceremony)
// as well as by pkg/acme, so it must not depend on the ACME package.
const (
	// auditActionCAInit is recorded once per certificate a CA constructs for
	// itself: the root in createRootCertificate, each intermediate in
	// createIntermediateCertificates, and the intermediate constructed by
	// initializeAsIntermediate (NewIntermediateCA).
	auditActionCAInit = "ca_init"

	// auditActionCACRLGenerate is recorded by generateAndPersistCRL.
	auditActionCACRLGenerate = "ca_crl_generate"

	// auditActionCACrossSign is recorded by ImportXSignedCertificate.
	auditActionCACrossSign = "ca_cross_sign"

	// auditResourceCA is the Event.Resource for CA lifecycle events.
	auditResourceCA = "ca"

	// auditResourceCRL is the Event.Resource for CRL generation events.
	auditResourceCRL = "crl"

	// auditResourceCrossSigned is the Event.Resource for cross-sign events.
	auditResourceCrossSigned = "cross-signed"
)

// emitAudit records a CA lifecycle event on the node audit sink. A failed
// write returns *qrdbsdk.AuditGateError: callers must propagate it and must
// not perform the state change (store a certificate, persist a CRL, persist a
// cross-signed certificate) the event describes
// (docs/audit-log/engineering.md).
//
// A nil ca.auditLogger disables CA audit logging entirely (opt-in wiring)
// and is not itself a failure.
func (ca *CA) emitAudit(ctx context.Context, action, resource, resourceID string) error {
	return audit.Emit(ctx, ca.auditLogger, &audit.Event{
		Timestamp:  time.Now(),
		Subject:    "system",
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Outcome:    audit.OutcomeAllow,
	})
}
