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

// Package ca provides the extended trust-chain operations that complement
// the native TrustedRootCertPool/TrustedIntermediateCertPool helpers with
// variants that honour cross-signed chains, AIA auto-import, and bundle
// parsing.
package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// TrustedRoot returns the root CA certificate that anchors this CA's
// hierarchy. Returns ErrNotInitialized if Init/Load has not been called,
// and ErrRootNotFound when the root has not been materialised yet.
//
// Thread-safe: Yes
func (ca *CA) TrustedRoot() (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	ca.mu.RLock()
	root := ca.rootCert
	ca.mu.RUnlock()

	if root == nil {
		return nil, ErrRootNotFound
	}
	return root, nil
}

// TrustedIntermediate returns the intermediate CA certificate, if any.
// Returns ErrIntermediateNotFound when the CA is configured as a pure root.
//
// Thread-safe: Yes
func (ca *CA) TrustedIntermediate() (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	ca.mu.RLock()
	intermediate := ca.intermediateCert
	ca.mu.RUnlock()

	if intermediate == nil {
		return nil, ErrIntermediateNotFound
	}
	return intermediate, nil
}

// TrustedRootCertPoolWithXSigner builds on TrustedRootCertPool by also
// appending any cross-signed root certificates that match the resolved root's
// CN when xsigner is non-nil. xsigner itself is not consulted for the pool
// contents; its non-nil value is used as the caller's opt-in to cross-sign
// augmentation so downstream TLS configurations can verify chains signed by
// both the native root and any foreign issuers that cross-signed it.
//
// Thread-safe: Yes
func (ca *CA) TrustedRootCertPoolWithXSigner(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	pool, err := ca.TrustedRootCertPool(cert)
	if err != nil {
		return nil, err
	}
	if xsigner == nil {
		return pool, nil
	}

	root, err := ca.RootCertificate(cert)
	if err != nil {
		// Fall back to the native root we already added to the pool.
		return pool, nil
	}

	// A non-nil error alongside a non-empty result means some entries were
	// read and parsed fine and only cleanup (closing a reader) failed;
	// those entries are still good and are used below, so gate on the
	// result, not the error. The error is worth knowing about, so it is
	// logged rather than dropped.
	xsigned, err := ca.getXSignedCertificates(root.Subject.CommonName)
	if err != nil {
		slog.Warn("ca: cross-signed root certificate lookup encountered an error", "cn", root.Subject.CommonName, "error", err)
	}
	if len(xsigned) == 0 {
		return pool, nil
	}

	for _, c := range xsigned {
		pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}))
	}
	return pool, nil
}

// TrustedIntermediateCertPoolWithXSigner is the cross-sign-aware counterpart
// to TrustedIntermediateCertPool. See TrustedRootCertPoolWithXSigner for the
// semantics of xsigner.
//
// Thread-safe: Yes
func (ca *CA) TrustedIntermediateCertPoolWithXSigner(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	pool, err := ca.TrustedIntermediateCertPool(cert)
	if err != nil {
		return nil, err
	}
	if xsigner == nil {
		return pool, nil
	}

	ca.mu.RLock()
	intermediate := ca.intermediateCert
	ca.mu.RUnlock()

	if intermediate == nil {
		return pool, nil
	}

	xsigned, err := ca.getXSignedCertificates(intermediate.Subject.CommonName)
	if err != nil {
		slog.Warn("ca: cross-signed intermediate certificate lookup encountered an error", "cn", intermediate.Subject.CommonName, "error", err)
	}
	if len(xsigned) == 0 {
		return pool, nil
	}

	for _, c := range xsigned {
		pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}))
	}
	return pool, nil
}

// ParseBundle parses a PEM-encoded certificate bundle into individual
// certificates. Empty input or input that contains no CERTIFICATE blocks
// returns ErrInvalidPEM so callers can cleanly distinguish missing bundles
// from genuinely unreadable ones.
//
// Thread-safe: Yes (pure function of its inputs)
func (ca *CA) ParseBundle(bundle []byte) ([]*x509.Certificate, error) {
	if len(bundle) == 0 {
		return nil, &errs.Detail{Err: ErrInvalidPEM, Detail: "empty bundle"}
	}

	certs := make([]*x509.Certificate, 0)
	remaining := bundle
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, &errs.Detail{Err: ErrInvalidCertificate, Detail: fmt.Sprintf("failed to parse certificate: %v", err)}
			}
			certs = append(certs, cert)
		}
		remaining = rest
		if len(rest) == 0 {
			break
		}
	}

	if len(certs) == 0 {
		return nil, &errs.Detail{Err: ErrInvalidPEM, Detail: "no certificates found"}
	}
	return certs, nil
}

// RootCertificate walks the issuer chain starting from childCert and returns
// the self-signed root certificate that anchors it. The walk consults both
// the certificate store (via ca.certStore) and the CA's own cached root and
// intermediate certificates. A maximum of 10 hops is permitted to prevent
// pathological chains.
//
// Thread-safe: Yes
func (ca *CA) RootCertificate(childCert *x509.Certificate) (*x509.Certificate, error) {
	if childCert == nil {
		return nil, ErrInvalidCertificate
	}

	if childCert.Issuer.CommonName == childCert.Subject.CommonName {
		if !childCert.IsCA {
			return nil, &errs.Detail{Err: ErrInvalidCertificateChain, Detail: "self-signed non-CA certificate"}
		}
		return childCert, nil
	}

	ca.mu.RLock()
	rootCert := ca.rootCert
	intermediateCert := ca.intermediateCert
	ca.mu.RUnlock()

	visited := make(map[string]bool)
	current := childCert
	for hop := 0; hop < 10; hop++ {
		if visited[current.Subject.CommonName] {
			return nil, &errs.Detail{Err: ErrInvalidCertificateChain, Detail: "circular chain detected"}
		}
		visited[current.Subject.CommonName] = true

		issuerCN := current.Issuer.CommonName

		// Try the certificate store first.
		var issuerCert *x509.Certificate
		if ca.certStore != nil {
			if c, err := ca.certStore.GetCertificate(issuerCN); err == nil {
				issuerCert = c
			}
		}

		if issuerCert == nil {
			switch {
			case intermediateCert != nil && intermediateCert.Subject.CommonName == issuerCN:
				issuerCert = intermediateCert
			case rootCert != nil && rootCert.Subject.CommonName == issuerCN:
				return rootCert, nil
			default:
				return nil, &errs.Detail{Err: ErrRootNotFound, Detail: fmt.Sprintf("issuer %s not found", issuerCN)}
			}
		}

		if issuerCert.Issuer.CommonName == issuerCert.Subject.CommonName {
			if !issuerCert.IsCA {
				return nil, &errs.Detail{Err: ErrInvalidCertificateChain, Detail: "self-signed non-CA certificate"}
			}
			return issuerCert, nil
		}

		current = issuerCert
	}
	return nil, &errs.Detail{Err: ErrInvalidCertificateChain, Detail: "chain too long"}
}

// ImportIssuingCAs walks the certificate's AuthorityInformationAccess
// (IssuingCertificateURL) extension upward, downloading each issuer and
// importing it into the certificate store. Certificates already in the store
// are not imported again, but the walk continues through them. The walk
// stops at a self-signed certificate.
//
// The URLs are chosen by whoever issued cert, so the walk is bounded:
//   - only http and https URLs resolving to public addresses are fetched
//     (ErrPKIFetchRefused), and each response is capped at
//     maxAIACertificateBytes (ErrPKIFetchTooLarge);
//   - a fetched certificate must have signed the certificate that named it
//     (ErrAIAIssuerSignatureInvalid), so an AIA URL cannot plant an
//     unrelated certificate in the store;
//   - a certificate seen earlier in the walk ends it (ErrAIALoop), and a
//     walk of more than maxAIADepth issuers is refused (ErrAIADepthExceeded).
//
// Returns nil when cert has no AIA extension (not an error).
//
// Thread-safe: Yes (stateless once initialised)
func (ca *CA) ImportIssuingCAs(ctx context.Context, cert *x509.Certificate) error {
	if cert == nil {
		return ErrInvalidCertificate
	}
	seen := map[[sha256.Size]byte]bool{sha256.Sum256(cert.Raw): true}
	return ca.importIssuingCAs(ctx, cert, seen, 0)
}

// importIssuingCAs imports the issuers named by child's AIA extension and
// recurses into each. depth is the number of issuers already fetched above
// the starting certificate; seen holds the fingerprints of every
// certificate visited so far.
func (ca *CA) importIssuingCAs(ctx context.Context, child *x509.Certificate, seen map[[sha256.Size]byte]bool, depth int) error {
	if len(child.IssuingCertificateURL) == 0 || isSelfSigned(child) {
		return nil
	}
	if depth >= maxAIADepth {
		return &errs.Detail{Err: ErrAIADepthExceeded, Detail: fmt.Sprintf("more than %d issuers above the starting certificate", maxAIADepth)}
	}

	for _, issuerURL := range child.IssuingCertificateURL {
		body, err := ca.fetchPKIObject(ctx, issuerURL, maxAIACertificateBytes)
		if err != nil {
			return err
		}
		issuerCert, err := parseAIACertificate(body)
		if err != nil {
			return &errs.Detail{Err: ErrInvalidCertificate, Detail: fmt.Sprintf("%s: %v", issuerURL, err)}
		}

		fingerprint := sha256.Sum256(issuerCert.Raw)
		if seen[fingerprint] {
			return &errs.Detail{Err: ErrAIALoop, Detail: fmt.Sprintf("%s returned %q, already visited", issuerURL, issuerCert.Subject.CommonName)}
		}
		seen[fingerprint] = true

		if err := child.CheckSignatureFrom(issuerCert); err != nil {
			return &errs.Detail{Err: ErrAIAIssuerSignatureInvalid, Detail: fmt.Sprintf("%s returned %q: %v", issuerURL, issuerCert.Subject.CommonName, err)}
		}

		if existing, err := ca.certStore.GetCertificate(issuerCert.Subject.CommonName); err != nil || existing == nil {
			if err := ca.ImportCertificate(ctx, issuerCert); err != nil {
				return err
			}
		}

		if err := ca.importIssuingCAs(ctx, issuerCert, seen, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// parseAIACertificate parses a certificate downloaded from an AIA URL.
// Both DER and PEM payloads are accepted because the TLS form used by AIA
// responses varies between deployments.
func parseAIACertificate(body []byte) (*x509.Certificate, error) {
	if cert, err := x509.ParseCertificate(body); err == nil {
		return cert, nil
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, &errs.Message{Msg: "payload is neither DER nor PEM"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// appendPEM is a small helper used by the cross-sign-aware pool builders.
//
//nolint:unused // retained for future pool construction helpers
func appendPEM(pool *x509.CertPool, cert *x509.Certificate) {
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// bufferBytes is a helper used by tests to materialise an io.Reader into a
// known byte slice in a single statement.
//
//nolint:unused // retained for consumers that reuse this helper
func bufferBytes(r io.Reader) ([]byte, error) {
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
