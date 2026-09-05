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

package peer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"time"
)

// oidTCGVerifiedTPMRestricted is tcg-cap-verifiedTPMRestricted
// (2.23.133.11.1.3): the issuing CA verified that the attestation key is a
// Restricted signing key resident in a TPM. TCG "TPM 2.0 Keys for Device
// Identity and Attestation" v1 r12 §8.2 requires a relying party to check it
// before trusting a quote. pkg/ca stamps the same value when it issues an
// IAK/LAK certificate; a test pins the two together so they cannot drift.
var oidTCGVerifiedTPMRestricted = asn1.ObjectIdentifier{2, 23, 133, 11, 1, 3}

// oidTCGVerifiedTPMRestrictedX509 is the same policy in the x509.OID form Go
// populates Certificate.Policies with.
var oidTCGVerifiedTPMRestrictedX509 = mustOID(2, 23, 133, 11, 1, 3)

func mustOID(arc ...uint64) x509.OID {
	oid, err := x509.OIDFromInts(arc)
	if err != nil {
		panic(err)
	}
	return oid
}

// parseAKCertificates splits the PEM evidence into the leaf and any
// intermediates that follow it. The first CERTIFICATE block is the leaf.
func parseAKCertificates(pemBytes []byte) (*x509.Certificate, []*x509.Certificate, *failure) {
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
			return nil, nil, wrong("attestation key certificate does not parse: " + err.Error())
		}
		if leaf == nil {
			leaf = cert
			continue
		}
		intermediates = append(intermediates, cert)
	}
	if leaf == nil {
		return nil, nil, wrong("attestation key certificate is not a PEM CERTIFICATE block")
	}
	return leaf, intermediates, nil
}

// verifyAKCertificate chains the leaf to the policy anchors, requires the
// Restricted policy unless the policy waives it, and returns the certified
// public key. The failure it returns is the check's outcome.
func verifyAKCertificate(leaf *x509.Certificate, extra []*x509.Certificate, policy *Policy, now time.Time) (crypto.PublicKey, *failure) {
	if policy.Anchors == nil {
		return nil, absent("no trust anchors configured; attestation key certificate cannot be chained")
	}

	intermediates := policy.Intermediates
	if len(extra) > 0 {
		intermediates = x509.NewCertPool()
		if policy.Intermediates != nil {
			intermediates = policy.Intermediates.Clone()
		}
		for _, cert := range extra {
			intermediates.AddCert(cert)
		}
	}

	// An attestation key certificate carries no standard EKU that names
	// attestation, so the chain is verified for any usage; what the key is
	// FOR is established by the TCG policy below, not by EKU.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         policy.Anchors,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, wrong("attestation key certificate does not chain to a trusted anchor: " + err.Error())
	}

	if !policy.AllowUnrestrictedAK && !carriesVerifiedTPMRestricted(leaf) {
		return nil, wrong("attestation key certificate does not carry tcg-cap-verifiedTPMRestricted (2.23.133.11.1.3), required by TCG DevID v1 r12 §8.2")
	}

	switch leaf.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return leaf.PublicKey, nil
	default:
		return nil, wrong("attestation key certificate carries an unsupported public key type")
	}
}

// carriesVerifiedTPMRestricted reports whether the certificate's
// certificatePolicies extension includes tcg-cap-verifiedTPMRestricted. Both
// the x509.OID form and the legacy asn1.ObjectIdentifier form are consulted:
// Go populates Policies for every policy and PolicyIdentifiers for those
// whose arcs fit, and a certificate produced by an older issuer may carry
// only the latter.
func carriesVerifiedTPMRestricted(cert *x509.Certificate) bool {
	for _, p := range cert.Policies {
		if p.Equal(oidTCGVerifiedTPMRestrictedX509) {
			return true
		}
	}
	for _, p := range cert.PolicyIdentifiers {
		if p.Equal(oidTCGVerifiedTPMRestricted) {
			return true
		}
	}
	return false
}
