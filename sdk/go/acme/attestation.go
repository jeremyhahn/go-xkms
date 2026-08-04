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

package trustedca

import (
	"errors"
	"net"

	endorse01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/endorse-01"
	enroll01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/enroll-01"
)

// ErrACMEEnrollCAUnsupported is returned by the enroll-01 verifier when the
// configured CA does not implement the TCG-CSR-IDEVID verification surface
// (ACMEEnroll01CertificateAuthority) required for TPM attestation.
var ErrACMEEnrollCAUnsupported = errors.New("acme: configured CA does not support enroll-01 (TCG-CSR-IDEVID) verification")

// ACMEAttestationVerifiers returns the challenge-verifier entries for the TPM
// attestation challenges (enroll-01 and/or endorse-01), ready to merge into an
// ACME server's challenge map. This is the single, shared wiring used by every
// ACME server in the stack (xkmsd, quicbaas) so attestation is enabled
// identically everywhere.
//
//   - enroll-01 proves possession of a TPM-resident IDevID via TCG-CSR-IDEVID +
//     TPM2_MakeCredential/ActivateCredential. The verifier asserts the
//     server-supplied CA to ACMEEnroll01CertificateAuthority (the concrete
//     server TCGCA satisfies it) and returns ErrACMEEnrollCAUnsupported otherwise.
//   - endorse-01 issues an EK certificate for TPMs lacking a manufacturer EK
//     cert; server-side verification is a no-op (the CA is not consulted here),
//     and issuance is gated by External Account Binding in the challenge handler.
func ACMEAttestationVerifiers(enroll, endorse bool) map[string]ACMEChallengeVerifierFunc {
	m := make(map[string]ACMEChallengeVerifierFunc, 2)
	if enroll {
		m[ACMEChallengeTypeEnroll01] = func(
			resolver *net.Resolver,
			ca ACMECertificateAuthority,
			authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
			enrollCA, ok := ca.(ACMEEnroll01CertificateAuthority)
			if !ok {
				return ErrACMEEnrollCAUnsupported
			}
			return enroll01.Verify(resolver, enrollCA, authzValue, challengePort, challengeToken, expectedKeyAuth)
		}
	}
	if endorse {
		m[ACMEChallengeTypeEndorse01] = func(
			resolver *net.Resolver,
			_ ACMECertificateAuthority,
			authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
			return endorse01.Verify(resolver, nil, authzValue, challengePort, challengeToken, expectedKeyAuth)
		}
	}
	return m
}
