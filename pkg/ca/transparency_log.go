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
	"crypto/sha256"
	"crypto/x509"
	"math"
	"math/big"
	"strconv"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// TransparencyLog is the append side of the CA's transparency log: the
// entries issuance and revocation record. *tlog.Log satisfies it.
//
// pkg/ca/tlog does not import pkg/ca, so the interface names tlog's entry
// types directly and no import cycle forms.
type TransparencyLog interface {
	// AppendCertIssued appends a cert-issued entry and returns its index.
	AppendCertIssued(ctx context.Context, e tlog.CertIssued) (uint64, error)

	// AppendRevoked appends a revoked entry and returns its index.
	AppendRevoked(ctx context.Context, e tlog.Revoked) (uint64, error)
}

var _ TransparencyLog = (*tlog.Log)(nil)

// transparencyLogRef boxes a TransparencyLog so the CA can hold it in an
// atomic.Pointer.
type transparencyLogRef struct {
	log TransparencyLog
}

// SetTransparencyLog sets the log issuance and revocation append to; nil
// removes it. With no log, issuance and revocation record nothing.
//
// The log is set after construction, not through Params, because its
// signed tree heads are signed with this CA's key (tlog.HeadSignerProvider),
// so the CA exists before the log can be opened.
//
// Thread-safe: Yes (atomic store)
func (ca *CA) SetTransparencyLog(l TransparencyLog) {
	if l == nil {
		ca.transparencyLog.Store(nil)
		return
	}
	ca.transparencyLog.Store(&transparencyLogRef{log: l})
}

// currentTransparencyLog returns the configured log, or nil when none is.
func (ca *CA) currentTransparencyLog() TransparencyLog {
	ref := ca.transparencyLog.Load()
	if ref == nil {
		return nil
	}
	return ref.log
}

// appendCertIssued records a signed certificate in the transparency log. It
// runs after signing and before the certificate is stored or returned: an
// error fails the issuance (fail closed), so no certificate is released
// that the log does not hold. With no log configured it does nothing.
func (ca *CA) appendCertIssued(ctx context.Context, cert *x509.Certificate, profile ProfileProvider, tenant string) error {
	l := ca.currentTransparencyLog()
	if l == nil {
		return nil
	}
	// A certificate issued in the system scope (no tenant, e.g. a
	// subordinate CA) is logged under go-qrdb's system tenant: an entry
	// always names its tenant.
	if tenant == "" {
		tenant = qrdbsdk.SystemTenantID
	}
	entry := tlog.CertIssued{
		CertSHA256: sha256.Sum256(cert.Raw),
		Serial:     cert.SerialNumber,
		Profile:    profile.Name(),
		Tenant:     tenant,
	}
	if _, err := l.AppendCertIssued(ctx, entry); err != nil {
		return &errs.Joined{Lead: ErrTransparencyLogAppend, Detail: "cert-issued serial " + cert.SerialNumber.Text(10), Cause: err}
	}
	return nil
}

// appendRevoked records a revocation in the transparency log. It runs after
// the revocation is recorded, which it never undoes: an error reports that
// the revocation stands without its log entry. With no log configured it
// does nothing.
func (ca *CA) appendRevoked(ctx context.Context, serial *big.Int, reason int) error {
	l := ca.currentTransparencyLog()
	if l == nil {
		return nil
	}
	detail := "revoked serial " + serial.Text(10)
	if reason < 0 || reason > math.MaxUint8 {
		return &errs.Detail{Err: ErrTransparencyLogEntryMissing, Detail: detail + ": reason " + strconv.Itoa(reason) + " out of range"}
	}
	if _, err := l.AppendRevoked(ctx, tlog.Revoked{Serial: serial, Reason: uint8(reason)}); err != nil {
		return &errs.Joined{Lead: ErrTransparencyLogEntryMissing, Detail: detail, Cause: err}
	}
	return nil
}
