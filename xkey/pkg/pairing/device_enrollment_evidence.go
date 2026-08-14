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

package pairing

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// decodeAttestationChain turns the wire form into certificates, leaf first.
func decodeAttestationChain(encoded []string) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(encoded))
	for i, entry := range encoded {
		der, err := base64.StdEncoding.DecodeString(entry)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate %d is not valid base64: %v",
				ErrEnrollmentChainUntrusted, i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate %d does not parse: %v",
				ErrEnrollmentChainUntrusted, i, err)
		}
		chain = append(chain, cert)
	}
	if len(chain) < 2 {
		// A lone certificate is self-signed: there is no path to a hardware
		// root, so nothing in it is attested by anything.
		return nil, fmt.Errorf("%w: a single certificate carries no attestation",
			ErrEnrollmentChainUntrusted)
	}
	return chain, nil
}

// csrMatchesAttestedKey confirms the CSR asks the CA to certify exactly the key
// the attestation leaf covers.
//
// Omitting this is the subtle way to build a CA that certifies anything: the
// chain verifies, the challenge is fresh, the boot state is good -- and the key
// being certified is one the caller generated in software, because the evidence
// was never tied to it. The evidence and the request must be about one key.
//
// The public keys are compared in their DER SubjectPublicKeyInfo form, which is
// canonical for a given key, rather than by parsed type.
func csrMatchesAttestedKey(csrDER []byte, leaf *x509.Certificate) error {
	if len(csrDER) == 0 {
		return fmt.Errorf("%w: the request carried no CSR", ErrEnrollmentKeyMismatch)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("%w: the CSR does not parse: %v", ErrEnrollmentKeyMismatch, err)
	}

	// A CSR is self-signed by the key it names; an invalid signature means the
	// requester does not hold the private half.
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("%w: the CSR signature does not verify: %v",
			ErrEnrollmentKeyMismatch, err)
	}

	if subtle.ConstantTimeCompare(
		csr.RawSubjectPublicKeyInfo,
		leaf.RawSubjectPublicKeyInfo,
	) != 1 {
		return ErrEnrollmentKeyMismatch
	}
	return nil
}

// bytesEqual compares in constant time, so a challenge check cannot be probed
// byte by byte through timing.
func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
