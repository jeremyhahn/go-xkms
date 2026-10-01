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

package evidence

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"time"
)

// OIDTCGKpEKCertificate is tcg-kp-EKCertificate (2.23.133.8.1), the extended
// key usage the TCG EK Credential Profile defines to identify a certificate
// as a genuine TPM endorsement key credential.
var OIDTCGKpEKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 1}

// oidSubjectAltName is RFC 5280 id-ce-subjectAltName.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// EKCertificateOptions configures VerifyEKCertificate.
type EKCertificateOptions struct {
	// Roots are the TPM-manufacturer trust anchors. Required: a check with
	// no anchors is a refusal, never a pass.
	Roots *x509.CertPool
	// Now is the time the chain is evaluated at. Zero means time.Now().
	Now time.Time
}

// ParseEKCertificateChain parses an endorsement key certificate together with
// any intermediates delivered alongside it. raw is either a single DER
// certificate or a PEM bundle whose first CERTIFICATE block is the leaf and
// whose further CERTIFICATE blocks are intermediates (TPM 2.0 Keys for Device
// Identity and Attestation v1.10r9 §6.1.2 step 5b / §6.2.2 step 4b).
func ParseEKCertificateChain(raw []byte) (*x509.Certificate, []*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, nil, absent(CheckEKCertificate, "no endorsement key certificate")
	}
	block, rest := pem.Decode(raw)
	if block == nil {
		leaf, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, nil, &Error{Class: ClassForged, Check: CheckEKCertificate, Reason: "der: " + err.Error(), Cause: err}
		}
		return leaf, nil, nil
	}

	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, &Error{Class: ClassForged, Check: CheckEKCertificate, Reason: "pem: " + err.Error(), Cause: err}
	}

	var intermediates []*x509.Certificate
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
			return nil, nil, &Error{Class: ClassForged, Check: CheckEKCertificate, Reason: "pem intermediate: " + err.Error(), Cause: err}
		}
		intermediates = append(intermediates, cert)
	}
	return leaf, intermediates, nil
}

// VerifyEKCertificate verifies an endorsement key certificate's chain to
// opts.Roots and its tcg-kp-EKCertificate extended key usage. Chain building
// accepts any usage, so Go's default serverAuth restriction (which cannot
// express tcg-kp-EKCertificate) does not reject the chain before the TCG
// check runs. StripEKCertificateQuirks is applied to the leaf and every
// intermediate first.
func VerifyEKCertificate(leaf *x509.Certificate, intermediates []*x509.Certificate, opts EKCertificateOptions) error {
	if leaf == nil {
		return absent(CheckEKCertificate, "no endorsement key certificate")
	}
	if opts.Roots == nil {
		return absent(CheckEKCertificate, "no endorsement key trust anchors configured")
	}

	StripEKCertificateQuirks(leaf)
	pool := x509.NewCertPool()
	for _, cert := range intermediates {
		StripEKCertificateQuirks(cert)
		pool.AddCert(cert)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: pool,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return &Error{Class: ClassForged, Check: CheckEKCertificate, Reason: "endorsement key certificate does not chain to a trusted anchor: " + err.Error(), Cause: err}
	}

	if !HasEKCertificateEKU(leaf) {
		return forged(CheckEKCertificate, "endorsement key certificate does not carry the tcg-kp-EKCertificate extended key usage")
	}
	return nil
}

// HasEKCertificateEKU reports whether cert carries tcg-kp-EKCertificate, or
// the anyExtendedKeyUsage purpose that subsumes it. The OID belongs in the
// standard ExtKeyUsage extension (RFC 5280 §4.2.1.12); a standalone extension
// under the OID's own Id, the non-standard encoding some manufacturer
// certificates use, is recognised too.
func HasEKCertificateEKU(cert *x509.Certificate) bool {
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

// StripEKCertificateQuirks removes the subjectAltName OID from cert's
// UnhandledCriticalExtensions. Go marks a critical SAN as unhandled when it
// carries only name forms x509 does not extract -- exactly the critical SAN
// with only a TCG directoryName that TPM manufacturers use for an EK
// certificate whose subject is empty (RFC 5280 §4.2.1.6 requires SAN be
// critical then). This does not weaken verification: nothing of the
// extracted SAN types was present, and no hostname check is ever run on an
// EK certificate. Every other unhandled critical extension stays and still
// fails Verify.
func StripEKCertificateQuirks(cert *x509.Certificate) {
	if cert == nil || len(cert.UnhandledCriticalExtensions) == 0 {
		return
	}
	filtered := cert.UnhandledCriticalExtensions[:0]
	for _, oid := range cert.UnhandledCriticalExtensions {
		if oid.Equal(oidSubjectAltName) {
			continue
		}
		filtered = append(filtered, oid)
	}
	cert.UnhandledCriticalExtensions = filtered
}
