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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"time"
)

// OIDTCGVerifiedTPMRestricted is tcg-cap-verifiedTPMRestricted
// (2.23.133.11.1.3): the issuing CA verified that the attestation key is a
// Restricted signing key resident in a TPM. TCG "TPM 2.0 Keys for Device
// Identity and Attestation" v1 r12 §8.2 requires a relying party to check it
// before trusting a quote.
var OIDTCGVerifiedTPMRestricted = asn1.ObjectIdentifier{2, 23, 133, 11, 1, 3}

// OIDTCGVerifiedTPMRestrictedPolicy is the same policy in the x509.OID form
// Go populates Certificate.Policies with.
var OIDTCGVerifiedTPMRestrictedPolicy = mustOID(2, 23, 133, 11, 1, 3)

// mustOID builds an x509.OID from constant arcs. It panics only on arcs the
// x509 package rejects, which a constant never is.
func mustOID(arc ...uint64) x509.OID {
	oid, err := x509.OIDFromInts(arc)
	if err != nil {
		panic(err)
	}
	return oid
}

// AKCertificateOptions configures VerifyAKCertificate.
type AKCertificateOptions struct {
	// Roots are the trust anchors. Required: with no anchors nothing can be
	// chained and the check is an absence.
	Roots *x509.CertPool
	// Intermediates are additional intermediates the caller trusts to build
	// a chain with. Optional.
	Intermediates *x509.CertPool
	// Now is the time the chain is evaluated at. Zero means time.Now().
	Now time.Time
	// AllowUnrestricted waives the tcg-cap-verifiedTPMRestricted
	// requirement. It exists for anchors that never stamp the policy; a
	// verifier should leave it false.
	AllowUnrestricted bool
}

// ParseCertificatesPEM splits PEM evidence into the leaf and any
// intermediates that follow it. The first CERTIFICATE block is the leaf;
// other block types are skipped.
func ParseCertificatesPEM(pemBytes []byte) (*x509.Certificate, []*x509.Certificate, error) {
	var leaf *x509.Certificate
	var intermediates []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, &Error{Class: ClassForged, Check: CheckAKCertificate, Reason: "attestation key certificate does not parse: " + err.Error(), Cause: err}
		}
		if leaf == nil {
			leaf = cert
			continue
		}
		intermediates = append(intermediates, cert)
	}
	if leaf == nil {
		return nil, nil, forged(CheckAKCertificate, "attestation key certificate is not a PEM CERTIFICATE block")
	}
	return leaf, intermediates, nil
}

// VerifyAKCertificate chains the leaf to opts.Roots (using opts.Intermediates
// plus extra), requires tcg-cap-verifiedTPMRestricted unless waived, and
// returns the certified public key. An attestation key certificate carries
// no standard EKU that names attestation, so the chain is verified for any
// usage; what the key is FOR is established by the TCG policy.
func VerifyAKCertificate(leaf *x509.Certificate, extra []*x509.Certificate, opts AKCertificateOptions) (crypto.PublicKey, error) {
	if leaf == nil {
		return nil, absent(CheckAKCertificate, "no attestation key certificate in evidence")
	}
	if opts.Roots == nil {
		return nil, absent(CheckAKCertificate, "no trust anchors configured; attestation key certificate cannot be chained")
	}

	intermediates := opts.Intermediates
	if len(extra) > 0 {
		intermediates = x509.NewCertPool()
		if opts.Intermediates != nil {
			intermediates = opts.Intermediates.Clone()
		}
		for _, cert := range extra {
			intermediates.AddCert(cert)
		}
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, &Error{Class: ClassForged, Check: CheckAKCertificate, Reason: "attestation key certificate does not chain to a trusted anchor: " + err.Error(), Cause: err}
	}

	if !opts.AllowUnrestricted && !CarriesVerifiedTPMRestricted(leaf) {
		return nil, forged(CheckAKCertificate, "attestation key certificate does not carry tcg-cap-verifiedTPMRestricted (2.23.133.11.1.3), required by TCG DevID v1 r12 §8.2")
	}

	switch leaf.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return leaf.PublicKey, nil
	default:
		return nil, forged(CheckAKCertificate, "attestation key certificate carries an unsupported public key type")
	}
}

// CarriesVerifiedTPMRestricted reports whether the certificate's
// certificatePolicies extension includes tcg-cap-verifiedTPMRestricted. Both
// the x509.OID form and the legacy asn1.ObjectIdentifier form are consulted:
// Go populates Policies for every policy and PolicyIdentifiers for those
// whose arcs fit, and a certificate from an older issuer may carry only the
// latter.
func CarriesVerifiedTPMRestricted(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, p := range cert.Policies {
		if p.Equal(OIDTCGVerifiedTPMRestrictedPolicy) {
			return true
		}
	}
	for _, p := range cert.PolicyIdentifiers {
		if p.Equal(OIDTCGVerifiedTPMRestricted) {
			return true
		}
	}
	return false
}
