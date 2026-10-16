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

// Package ca provides cross-signing operations that allow a certificate
// issued by this CA to be counter-signed by an external issuer. Cross-signed
// certificates are persisted to the object store so the original issuer
// relationship can be rediscovered when constructing chains for validation.
//
// # Storage Layout
//
// Cross-signed certificates are stored in the object store under the
// "cross-signed/{issuer_cn}/{subject_cn}.pem" key pattern, with PEM-encoded
// CERTIFICATE bodies.
package ca

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// crossSignedStoreKey builds the canonical object-store key for a
// cross-signed certificate. Kept as a helper so the path conventions
// are declared once and reused by all cross-signing methods.
func crossSignedStoreKey(issuerCN, subjectCN string) string {
	return fmt.Sprintf("cross-signed/%s/%s.pem", issuerCN, subjectCN)
}

// ImportXSignedCertificate persists a certificate that has been cross-signed
// by an external issuer (identified by issuerCN). The certificate is stored
// in PEM form so the original DER can be recovered verbatim. Both issuerCN
// and cert must be non-nil/non-empty.
//
// Requires the object store to be configured; returns ErrObjectStoreRequired
// otherwise.
//
// Thread-safe: Yes
func (ca *CA) ImportXSignedCertificate(issuerCN string, cert *x509.Certificate) error {
	if issuerCN == "" {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "issuer common name required"}
	}
	if cert == nil {
		return ErrInvalidCertificate
	}
	if ca.objectStore == nil {
		return ErrObjectStoreRequired
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if pemData == nil {
		return &errs.Detail{Err: ErrStorageError, Detail: "failed to encode cross-signed certificate"}
	}

	// CA_CROSS_SIGN is SeveritySecurity (docs/audit-log/engineering.md): the
	// audit record is written before the cross-signed certificate is
	// persisted, so a failed write refuses the import rather than accept an
	// unaudited cross-sign relationship. ImportXSignedCertificate takes no
	// context; a CA lifecycle event has no caller-scoped deadline to inherit,
	// matching pkg/seal's emitAudit precedent for the same shape of call site.
	key := crossSignedStoreKey(issuerCN, cert.Subject.CommonName)
	if auditErr := ca.emitAudit(context.Background(), auditActionCACrossSign, auditResourceCrossSigned, key); auditErr != nil {
		return auditErr
	}

	return ca.putObject(key, pemData)
}

// XSignedRootCertificate walks the cross-signed certificate chain for the
// specified issuer starting from cert until it encounters a self-signed
// certificate, and returns that root. If cert is already self-signed it is
// returned directly.
//
// Thread-safe: Yes
func (ca *CA) XSignedRootCertificate(issuerCN string, cert *x509.Certificate) (*x509.Certificate, error) {
	if issuerCN == "" {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: "issuer common name required"}
	}
	if cert == nil {
		return nil, ErrInvalidCertificate
	}
	if ca.objectStore == nil {
		return nil, ErrObjectStoreRequired
	}

	if cert.Issuer.CommonName == cert.Subject.CommonName {
		return cert, nil
	}

	parent, err := ca.readCrossSignedCertificate(issuerCN, cert.Issuer.CommonName)
	if err != nil {
		return nil, err
	}
	return ca.XSignedRootCertificate(issuerCN, parent)
}

// XSignedIntermediateCertificates walks the cross-signed chain from the
// provided certificate upwards and returns every non-self-signed CA
// certificate encountered, in chain order (closest-to-leaf first). The
// returned slice is empty when no intermediate chain is available in the
// object store.
//
// Thread-safe: Yes
func (ca *CA) XSignedIntermediateCertificates(issuerCN string, cert *x509.Certificate) ([]*x509.Certificate, error) {
	if issuerCN == "" {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: "issuer common name required"}
	}
	if cert == nil {
		return nil, ErrInvalidCertificate
	}
	if ca.objectStore == nil {
		return nil, ErrObjectStoreRequired
	}

	intermediates := make([]*x509.Certificate, 0)
	current := cert

	for current.Issuer.CommonName != current.Subject.CommonName {
		parent, err := ca.readCrossSignedCertificate(issuerCN, current.Issuer.CommonName)
		if err != nil {
			// No more cross-signed entries available; terminate walk.
			break
		}
		if parent.IsCA && parent.Issuer.CommonName != parent.Subject.CommonName {
			intermediates = append(intermediates, parent)
		}
		current = parent
	}
	return intermediates, nil
}

// XSignedCertificate retrieves a specific cross-signed certificate that was
// issued by issuerCN for the subject identified by attrs.CN. Returns
// ErrCertificateNotFound when no matching entry exists.
//
// Thread-safe: Yes
func (ca *CA) XSignedCertificate(issuerCN string, attrs *types.KeyAttributes) (*x509.Certificate, error) {
	if issuerCN == "" {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: "issuer common name required"}
	}
	if attrs == nil || attrs.CN == "" {
		return nil, &errs.Detail{Err: ErrInvalidCertificate, Detail: "key attributes with CN required"}
	}
	if ca.objectStore == nil {
		return nil, ErrObjectStoreRequired
	}

	return ca.readCrossSignedCertificate(issuerCN, attrs.CN)
}

// CrossSignedPEM returns a PEM bundle containing every cross-signed
// certificate found for the subject identified by attrs.CN across all
// issuers present in the object store. Returns ErrCertificateNotFound when
// no entries match.
//
// Thread-safe: Yes
func (ca *CA) CrossSignedPEM(attrs *types.KeyAttributes) ([]byte, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, &errs.Detail{Err: ErrInvalidCertificate, Detail: "key attributes with CN required"}
	}
	if ca.objectStore == nil {
		return nil, ErrObjectStoreRequired
	}

	items, err := ca.listObjects("cross-signed/")
	if err != nil {
		return nil, err
	}

	// A store item that cannot be fetched is skipped by design (documented
	// on getXSignedCertificates below).
	var bundle strings.Builder
	suffix := fmt.Sprintf("/%s.pem", attrs.CN)
	for _, item := range items {
		if !strings.HasSuffix(item, suffix) {
			continue
		}
		data, err := ca.getObject(item)
		if err != nil {
			continue
		}
		_, _ = bundle.Write(data)
	}

	if bundle.Len() == 0 {
		return nil, &errs.Detail{Err: ErrCertificateNotFound, Detail: fmt.Sprintf("no cross-signed certificates for %s", attrs.CN)}
	}
	return []byte(bundle.String()), nil
}

// readCrossSignedCertificate is the shared helper that reads a single
// cross-signed entry from the object store and parses it into a
// *x509.Certificate.
func (ca *CA) readCrossSignedCertificate(issuerCN, subjectCN string) (*x509.Certificate, error) {
	data, err := ca.getObject(crossSignedStoreKey(issuerCN, subjectCN))
	if err != nil {
		return nil, &errs.Detail{Err: ErrCertificateNotFound, Detail: fmt.Sprintf("cross-signed certificate %s (issuer %s): %v", subjectCN, issuerCN, err)}
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &errs.Detail{Err: ErrInvalidPEM, Detail: fmt.Sprintf("invalid PEM for cross-signed certificate %s", subjectCN)}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidCertificate, Detail: fmt.Sprintf("failed to parse cross-signed certificate %s: %v", subjectCN, err)}
	}
	return cert, nil
}

// getXSignedCertificates lists every cross-signed certificate stored under
// any issuer for the given subject CN. This is the helper used by the
// cross-sign-aware trust pool variants to augment the chain.
//
// Implementations return an empty slice (not an error) if the object store
// is unavailable so the caller can continue with only the native chain.
func (ca *CA) getXSignedCertificates(cn string) []*x509.Certificate {
	if ca.objectStore == nil {
		return nil
	}

	items, err := ca.listObjects("cross-signed/")
	if err != nil {
		return nil
	}

	// Get/Parse failures on an individual item are skipped by design (see
	// the doc comment above).
	suffix := fmt.Sprintf("/%s.pem", cn)
	certs := make([]*x509.Certificate, 0)
	for _, item := range items {
		if !strings.HasSuffix(item, suffix) {
			continue
		}
		data, err := ca.getObject(item)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	return certs
}
