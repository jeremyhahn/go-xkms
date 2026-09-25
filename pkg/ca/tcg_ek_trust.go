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

// Package ca implements TCG "TPM 2.0 Keys for Device Identity and
// Attestation" v1.10r9 §6.1.2 step 5b and §6.2.2 step 4b: before the CA
// issues an IAK or IDevID credential it verifies the requesting device's
// endorsement key certificate against a configured pool of TPM-manufacturer
// trust anchors, and that the certificate carries the tcg-kp-EKCertificate
// extended key usage (2.23.133.8.1). TPM2_ActivateCredential (driven
// elsewhere in this package) proves the requester holds the EK private key;
// it says nothing about whether the EK belongs to a genuine TPM, which is
// what this file establishes.
package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
)

// TCGConfig holds the CA's TCG TPM 2.0 Keys for Device Identity and
// Attestation settings: the pool of TPM-manufacturer trust anchors the CA
// verifies an endorsement key certificate against before issuing an IAK or
// IDevID credential (TPM 2.0 Keys for Device Identity and Attestation
// v1.10r9 §6.1.2 step 5b, §6.2.2 step 4b).
//
// A nil TCGConfig, or one naming no anchors, is not "skip the check" --
// every EK verification refuses with ErrTCGEKCertUntrusted until at least
// one trust anchor is configured. A CA that never issues TCG credentials can
// leave this unset.
type TCGConfig struct {
	// TrustAnchors configures the TPM-manufacturer root (and, when a
	// manufacturer's chain has one, intermediate -- see the doc comment on
	// ekRootPool) certificates trusted to anchor an EK certificate chain.
	// Reuses pkg/attestation/truststore.Config, the same trust-anchor
	// configuration shape pkg/config.AttestationConfig uses for the "tpm2"
	// attestation format: both ultimately anchor a TPM manufacturer's chain,
	// even though this check runs at a different moment (credential
	// issuance) than attestation-quote verification does.
	TrustAnchors *truststore.Config `yaml:"trust-anchors,omitempty" json:"trust_anchors,omitempty" mapstructure:"trust-anchors"`
}

// ekRootPool loads the configured EK trust anchors as an x509.CertPool
// suitable for use as x509.VerifyOptions.Roots. stripTCGEKQuirks is applied
// to every loaded certificate before it is pooled, so a manufacturer root
// with the same critical-SAN encoding quirk as the leaf still chains.
//
// A manufacturer whose EK certificates chain through an intermediate can
// concatenate both certificates into one PEM file named in
// TrustAnchors.ExternalRootPaths: x509.CertPool draws no distinction between
// a self-signed and a non-self-signed entry, so an intermediate placed here
// anchors a chain exactly as a root does.
//
// Returns ErrTCGEKCertUntrusted when c is nil, TrustAnchors is nil, or the
// configured anchors resolve to zero certificates: an EK chain check with no
// configured anchors is a refusal, not a pass.
func (c *TCGConfig) ekRootPool() (*x509.CertPool, error) {
	if c == nil || c.TrustAnchors == nil {
		return nil, &errs.Detail{Err: ErrTCGEKCertUntrusted, Detail: "no ek trust anchors configured"}
	}

	ts, err := truststore.New(c.TrustAnchors)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTCGEKCertUntrusted, Cause: err}
	}
	if ts.Count() == 0 {
		return nil, &errs.Detail{Err: ErrTCGEKCertUntrusted, Detail: "no ek trust anchors configured"}
	}

	pool := x509.NewCertPool()
	for _, root := range ts.Roots() {
		stripTCGEKQuirks(root)
		pool.AddCert(root)
	}
	return pool, nil
}

// stripTCGEKQuirks removes the subjectAltName OID from cert's
// UnhandledCriticalExtensions when Go's x509 parser marked it unhandled
// solely because it found no dNSName, rfc822Name, iPAddress or
// uniformResourceIdentifier general name -- exactly the case for a critical
// SAN carrying only a TCG directoryName, the usual encoding a TPM
// manufacturer uses for an EK certificate whose subject is empty (TCG EK
// Credential Profile; RFC 5280 §4.2.1.6 requires SAN be critical when the
// subject is empty).
//
// This does not weaken Verify: cert.DNSNames / EmailAddresses / IPAddresses
// / URIs are unaffected (there was nothing of those types to extract), and
// this package never calls VerifyHostname on an EK certificate, so nothing
// that depended on SAN content was skipped by treating it as handled. Every
// other unhandled critical extension is left in place and still fails
// x509.Certificate.Verify with UnhandledCriticalExtension.
func stripTCGEKQuirks(cert *x509.Certificate) {
	if cert == nil || len(cert.UnhandledCriticalExtensions) == 0 {
		return
	}
	filtered := cert.UnhandledCriticalExtensions[:0]
	for _, oid := range cert.UnhandledCriticalExtensions {
		if oid.Equal(oidSubjectAltNameExt) {
			continue
		}
		filtered = append(filtered, oid)
	}
	cert.UnhandledCriticalExtensions = filtered
}

// hasTCGEKCertificateEKU reports whether cert carries the
// tcg-kp-EKCertificate extended key usage (2.23.133.8.1) -- the marker the
// TCG EK Credential Profile defines to identify a certificate as a genuine
// TPM endorsement key credential -- or the anyExtendedKeyUsage purpose that
// subsumes it.
//
// The OID belongs inside the certificate's standard ExtKeyUsage extension
// (RFC 5280 section 4.2.1.12), which is where a conformant manufacturer EK
// certificate and this CA's own EK issuance (IssueEKCertificate, via the
// tcg-ek profile's UnknownExtKeyUsage) both put it. The fallback to
// cert.Extensions recognises a standalone extension under the OID's own Id
// too, the non-standard encoding some manufacturer certificates use and
// ImportEndorsementKeyCertificate has always tolerated.
func hasTCGEKCertificateEKU(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, ku := range cert.ExtKeyUsage {
		if ku == x509.ExtKeyUsageAny {
			return true
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(OIDTCGKpEKCertificate) {
			return true
		}
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDTCGKpEKCertificate) {
			return true
		}
	}
	return false
}

// requireTCGEKCertificateEKU enforces that cert carries the
// tcg-kp-EKCertificate extended key usage. A chain to a trusted root is not,
// by itself, evidence that the leaf is an EK certificate rather than some
// other certificate the same root happened to issue.
func requireTCGEKCertificateEKU(cert *x509.Certificate) error {
	if hasTCGEKCertificateEKU(cert) {
		return nil
	}
	return &errs.Detail{
		Err:    ErrTCGEKCertUntrusted,
		Detail: "endorsement key certificate does not carry the tcg-kp-EKCertificate extended key usage",
	}
}

// parseEKCertificateChain parses the endorsement key certificate carried in
// a TCG-CSR-IDEVID's EkCert field, along with any additional certificates
// the device software concatenated after it in the same field.
//
// The field carries either a single DER-encoded certificate (no chain) or a
// PEM bundle. The first PEM block, or the sole DER certificate, is the
// leaf; any further PEM blocks are the intermediates the request supplied,
// per TPM 2.0 Keys for Device Identity and Attestation v1.10r9 §6.1.2 step
// 5b / §6.2.2 step 4b -- an EK certificate chain reached only via a network
// AIA fetch is not supported.
//
// Returns ErrTCGInvalidEKCert when raw is empty or the leaf cannot be
// parsed.
func parseEKCertificateChain(raw []byte) (leaf *x509.Certificate, intermediates []*x509.Certificate, err error) {
	block, rest := pem.Decode(raw)
	if block == nil {
		leaf, err = x509.ParseCertificate(raw)
		if err != nil {
			return nil, nil, &errs.Detail{Err: ErrTCGInvalidEKCert, Detail: fmt.Sprintf("der: %v", err)}
		}
		return leaf, nil, nil
	}

	leaf, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrTCGInvalidEKCert, Detail: fmt.Sprintf("pem: %v", err)}
	}

	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, &errs.Detail{Err: ErrTCGInvalidEKCert, Detail: fmt.Sprintf("pem intermediate: %v", err)}
		}
		intermediates = append(intermediates, cert)
	}

	return leaf, intermediates, nil
}

// verifyEKCertificateChain verifies an endorsement key certificate's chain
// and its tcg-kp-EKCertificate extended key usage against the CA's
// configured pool of TPM-manufacturer trust anchors, per TPM 2.0 Keys for
// Device Identity and Attestation v1.10r9 §6.1.2 step 5b / §6.2.2 step 4b.
// requestIntermediates carries any additional certificates the request
// supplied alongside the leaf (see parseEKCertificateChain); it may be nil.
//
// Chain building accepts ExtKeyUsageAny in x509.VerifyOptions so that Go's
// own extended-key-usage restriction (which defaults to requiring
// ExtKeyUsageServerAuth, and which cannot express an arbitrary OID such as
// tcg-kp-EKCertificate) does not reject a chain before
// requireTCGEKCertificateEKU gets to apply the check the TCG profile
// actually specifies.
//
// Returns ErrTCGEKCertUntrusted, with the underlying cause wrapped, when the
// CA has no EK trust anchors configured, the chain does not verify, or the
// leaf lacks the required extended key usage. There is no path that skips
// the check: a CA without configured anchors refuses every EK certificate.
func (ca *CA) verifyEKCertificateChain(leaf *x509.Certificate, requestIntermediates []*x509.Certificate) error {
	if leaf == nil {
		return &errs.Detail{Err: ErrTCGInvalidEKCert, Detail: "nil ek certificate"}
	}

	var tcgConfig *TCGConfig
	if ca.config != nil {
		tcgConfig = ca.config.TCGConfig
	}

	roots, err := tcgConfig.ekRootPool()
	if err != nil {
		return err
	}

	stripTCGEKQuirks(leaf)
	intermediates := x509.NewCertPool()
	for _, cert := range requestIntermediates {
		stripTCGEKQuirks(cert)
		intermediates.AddCert(cert)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return &errs.Joined{Lead: ErrTCGEKCertUntrusted, Cause: err}
	}

	return requireTCGEKCertificateEKU(leaf)
}
