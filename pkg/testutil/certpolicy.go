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

package testutil

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// =============================================================================
// Certificate Policy Fingerprinting
// =============================================================================

// keyDerivedExtensions are the extension OIDs whose encoded value is derived
// from the (randomly generated) subject or issuer key and therefore differs
// between otherwise identical issuances. Their presence and criticality are
// still fingerprinted; only the value bytes are elided.
var keyDerivedExtensions = map[string]bool{
	"2.5.29.14": true, // subjectKeyIdentifier
	"2.5.29.35": true, // authorityKeyIdentifier
}

// CertificatePolicy is the complete, deterministic policy surface of an issued
// certificate: everything a certificate profile, a CA configuration or an
// issuance path can decide, and nothing that varies run to run.
//
// Deliberately excluded are the serial number, the absolute NotBefore/NotAfter
// instants, the public key, the signature, and the value bytes of the subject
// and authority key identifiers. Those are either random or derived from
// freshly generated key material, so including them would make the
// fingerprint useless for comparing two runs. The validity *duration* is
// included, because that is a policy decision.
//
// PolicyFingerprint over this structure is what lets a refactor of
// certificate issuance prove it did not silently change an extended key usage
// or a path length.
type CertificatePolicy struct {
	Version               int
	RawSubject            string
	SignatureAlgorithm    string
	PublicKeyAlgorithm    string
	KeyUsage              x509.KeyUsage
	ExtKeyUsage           []string
	UnknownExtKeyUsage    []string
	BasicConstraintsValid bool
	IsCA                  bool
	MaxPathLen            int
	MaxPathLenZero        bool
	Validity              time.Duration
	DNSNames              []string
	EmailAddresses        []string
	IPAddresses           []string
	URIs                  []string
	CRLDistributionPoints []string
	OCSPServer            []string
	IssuingCertificateURL []string
	Policies              []string
	PolicyIdentifiers     []string
	Extensions            []string
}

// CertificatePolicyOf extracts the policy surface of a parsed certificate.
//
// Returns a zero-value CertificatePolicy when cert is nil so callers in table
// tests do not have to nil-check before comparing.
func CertificatePolicyOf(cert *x509.Certificate) CertificatePolicy {
	if cert == nil {
		return CertificatePolicy{}
	}

	policy := CertificatePolicy{
		Version:               cert.Version,
		RawSubject:            hex.EncodeToString(cert.RawSubject),
		SignatureAlgorithm:    cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm:    cert.PublicKeyAlgorithm.String(),
		KeyUsage:              cert.KeyUsage,
		BasicConstraintsValid: cert.BasicConstraintsValid,
		IsCA:                  cert.IsCA,
		MaxPathLen:            cert.MaxPathLen,
		MaxPathLenZero:        cert.MaxPathLenZero,
		Validity:              cert.NotAfter.Sub(cert.NotBefore),
		DNSNames:              cloneSorted(cert.DNSNames),
		EmailAddresses:        cloneSorted(cert.EmailAddresses),
		CRLDistributionPoints: cloneSorted(cert.CRLDistributionPoints),
		OCSPServer:            cloneSorted(cert.OCSPServer),
		IssuingCertificateURL: cloneSorted(cert.IssuingCertificateURL),
	}

	for _, eku := range cert.ExtKeyUsage {
		policy.ExtKeyUsage = append(policy.ExtKeyUsage, fmt.Sprintf("%d", eku))
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		policy.UnknownExtKeyUsage = append(policy.UnknownExtKeyUsage, oid.String())
	}
	for _, ip := range cert.IPAddresses {
		policy.IPAddresses = append(policy.IPAddresses, ip.String())
	}
	for _, uri := range cert.URIs {
		if uri != nil {
			policy.URIs = append(policy.URIs, uri.String())
		}
	}
	for _, oid := range cert.Policies {
		policy.Policies = append(policy.Policies, oid.String())
	}
	for _, oid := range cert.PolicyIdentifiers {
		policy.PolicyIdentifiers = append(policy.PolicyIdentifiers, oid.String())
	}

	// Extensions are recorded in encoding order because that order is itself a
	// property of the issuance path: two paths that emit the same extensions in
	// a different order produce different certificates.
	for _, ext := range cert.Extensions {
		oid := ext.Id.String()
		value := hex.EncodeToString(ext.Value)
		if keyDerivedExtensions[oid] {
			value = "<key-derived>"
		}
		policy.Extensions = append(policy.Extensions,
			fmt.Sprintf("%s critical=%t value=%s", oid, ext.Critical, value))
	}

	sort.Strings(policy.IPAddresses)
	sort.Strings(policy.URIs)
	return policy
}

// PolicyFingerprint returns a stable SHA-256 fingerprint of a certificate's
// policy surface. Two certificates issued from the same inputs by the same
// policy produce the same fingerprint even though their keys, serials and
// timestamps differ.
func PolicyFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256([]byte(RenderCertificatePolicy(cert)))
	return hex.EncodeToString(sum[:])
}

// RenderCertificatePolicy renders a certificate's policy surface as stable,
// human-readable text. Test failures print this rather than a bare fingerprint
// mismatch so the offending field is visible without re-running with a
// debugger.
func RenderCertificatePolicy(cert *x509.Certificate) string {
	policy := CertificatePolicyOf(cert)
	var b strings.Builder
	fmt.Fprintf(&b, "version=%d\n", policy.Version)
	fmt.Fprintf(&b, "raw_subject=%s\n", policy.RawSubject)
	fmt.Fprintf(&b, "signature_algorithm=%s\n", policy.SignatureAlgorithm)
	fmt.Fprintf(&b, "public_key_algorithm=%s\n", policy.PublicKeyAlgorithm)
	fmt.Fprintf(&b, "key_usage=%d\n", policy.KeyUsage)
	fmt.Fprintf(&b, "ext_key_usage=%s\n", strings.Join(policy.ExtKeyUsage, ","))
	fmt.Fprintf(&b, "unknown_ext_key_usage=%s\n", strings.Join(policy.UnknownExtKeyUsage, ","))
	fmt.Fprintf(&b, "basic_constraints_valid=%t\n", policy.BasicConstraintsValid)
	fmt.Fprintf(&b, "is_ca=%t\n", policy.IsCA)
	fmt.Fprintf(&b, "max_path_len=%d\n", policy.MaxPathLen)
	fmt.Fprintf(&b, "max_path_len_zero=%t\n", policy.MaxPathLenZero)
	fmt.Fprintf(&b, "validity=%s\n", policy.Validity)
	fmt.Fprintf(&b, "dns=%s\n", strings.Join(policy.DNSNames, ","))
	fmt.Fprintf(&b, "email=%s\n", strings.Join(policy.EmailAddresses, ","))
	fmt.Fprintf(&b, "ip=%s\n", strings.Join(policy.IPAddresses, ","))
	fmt.Fprintf(&b, "uri=%s\n", strings.Join(policy.URIs, ","))
	fmt.Fprintf(&b, "crl=%s\n", strings.Join(policy.CRLDistributionPoints, ","))
	fmt.Fprintf(&b, "ocsp=%s\n", strings.Join(policy.OCSPServer, ","))
	fmt.Fprintf(&b, "aia=%s\n", strings.Join(policy.IssuingCertificateURL, ","))
	fmt.Fprintf(&b, "policies=%s\n", strings.Join(policy.Policies, ","))
	fmt.Fprintf(&b, "policy_identifiers=%s\n", strings.Join(policy.PolicyIdentifiers, ","))
	for _, ext := range policy.Extensions {
		fmt.Fprintf(&b, "ext=%s\n", ext)
	}
	return b.String()
}

// cloneSorted returns a sorted copy of s, or nil when s is empty. Sorting
// makes the fingerprint insensitive to the order in which a caller happened to
// append SANs or endpoint URLs, which is not a policy decision.
func cloneSorted(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}
