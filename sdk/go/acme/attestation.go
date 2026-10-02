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
	acmehandler "github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
)

// ErrACMEEnrollCAUnsupported is returned by the enroll-01 verifier when the
// configured CA does not implement the TCG-CSR-IDEVID verification surface
// (ACMEEnroll01TCGCSRVerifier) required for TPM attestation.
var ErrACMEEnrollCAUnsupported = errors.New("acme: configured CA does not support enroll-01 (TCG-CSR-IDEVID) verification")

// ACMEAttestationVerifiers returns the challenge-verifier entries for the TPM
// attestation challenges (enroll-01 and/or endorse-01).
//
// Deprecated: a ChallengeVerifierFunc cannot report the identity a device
// attested, so the ACME server refuses an attestation challenge (enroll-01,
// endorse-01, device-attest-01) served by one instead of running it without an
// identity check (go-xkms#828). Register ACMEAttestingVerifiers in
// ACMERestServiceParams.AttestingVerifiers. This function is kept so existing
// callers still compile.
func ACMEAttestationVerifiers(client *ACMEChallengeClient, enroll, endorse bool) map[string]ACMEChallengeVerifierFunc {
	m := make(map[string]ACMEChallengeVerifierFunc, 2)
	if enroll {
		m[ACMEChallengeTypeEnroll01] = func(
			_ *net.Resolver,
			ca ACMECertificateAuthority,
			authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
			_, err := verifyEnroll01(client, ca, authzValue, challengePort, challengeToken, expectedKeyAuth)
			return err
		}
	}
	if endorse {
		m[ACMEChallengeTypeEndorse01] = func(
			resolver *net.Resolver,
			_ ACMECertificateAuthority,
			authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
			return endorse01.Verify(resolver, authzValue, challengePort, challengeToken, expectedKeyAuth)
		}
	}
	return m
}

// ACMEAttestingVerifiers returns the attesting verifiers for the device
// attestation challenges (enroll-01, endorse-01 and/or device-attest-01),
// ready to register in ACMERestServiceParams.AttestingVerifiers. This is the
// single, shared wiring used by every ACME server in the stack (xkmsd,
// quicbaas) so attestation is enabled identically everywhere.
//
//   - enroll-01 proves possession of a TPM-resident IDevID via TCG-CSR-IDEVID +
//     TPM2_MakeCredential/ActivateCredential. The verifier asserts the
//     server-supplied CA to ACMEEnroll01TCGCSRVerifier (the concrete
//     server TCGCA satisfies it) and returns ErrACMEEnrollCAUnsupported otherwise.
//   - endorse-01 issues an EK certificate for TPMs lacking a manufacturer EK
//     cert; server-side verification is a no-op (the CA is not consulted here),
//     and issuance is gated by External Account Binding in the challenge handler.
//   - device-attest-01 verifies a TPM or DICE attestation object the client
//     POSTs to the challenge URL (draft-ietf-acme-device-attest: the server
//     never contacts the device) and reports the device identity the evidence
//     carries (the AIK permanentIdentifier, or the DICE Ueid) together with the
//     verified evidence finalization binds the certificate request's key to
//     (go-xkms#789, go-xkms#828). It is registered when deviceAttest is
//     non-nil; deviceAttest is the server's trust policy over the evidence
//     (ACMETrustAnchorVerifier is the configured-anchors implementation).
//
// What each verifier reports as the attested identity, derived from evidence
// and never from the order being checked:
//
//   - enroll-01: the order's identifier, because the dial that proved a genuine
//     TPM activated a credential reached the address that identifier names. The
//     TPM itself is named by the activated endorsement key, returned as the
//     record finalization binds the TCG-CSR-IDEVID to (go-xkms#1391).
//   - endorse-01: the EK the account's External Account Binding authorized
//     (ACMEAttestationChallenge.AuthorizedIdentity, set by ChallengeHandler
//     from the EAB). endorse-01 proves nothing about the device; the EAB is its
//     only control (go-xkms#1392).
//   - device-attest-01: the identity the evidence carries.
//
// ChallengeHandler enforces the comparison with the order's identifier for all
// three alike.
//
// client is the server's shared ACMEChallengeClient; the enroll-01 verifier
// contacts the device through it. The per-call resolver the challenge handler
// passes is not used by it: target resolution belongs to the client, whose
// dialer checks the resolved address.
func ACMEAttestingVerifiers(client *ACMEChallengeClient, enroll, endorse bool, deviceAttest ACMEDeviceAttest01Verifier) map[string]ACMEAttestingVerifier {
	m := make(map[string]ACMEAttestingVerifier, 3)
	if enroll {
		m[ACMEChallengeTypeEnroll01] = ACMEAttestingVerifierFunc(func(
			_ *net.Resolver,
			ca ACMECertificateAuthority,
			challenge ACMEAttestationChallenge,
		) (*ACMEAttestedIdentity, error) {
			activation, err := verifyEnroll01(client, ca, challenge.DialTarget, challenge.Port, challenge.Token, challenge.KeyAuthorization)
			if err != nil {
				return nil, err
			}
			record, err := activation.Record(challenge.IdentifierType, challenge.KeyAuthorization)
			if err != nil {
				return nil, err
			}
			// The identity the dial established is the order's identifier: a
			// genuine TPM answered, and activated a credential, at the
			// address the identifier names (DialTarget is the identifier, or
			// the client's own address under the dev-mode loopback
			// substitution). That binding is real, so ChallengeHandler keeps
			// its comparison. What names the TPM itself is the activated
			// endorsement key, which the record carries for finalization to
			// bind the TCG-CSR-IDEVID to (go-xkms#1391).
			return &ACMEAttestedIdentity{Identifier: challenge.IdentifierValue, Attestation: record}, nil
		})
	}
	if endorse {
		m[ACMEChallengeTypeEndorse01] = acmehandler.NewEndorseVerifier()
	}
	if deviceAttest != nil {
		m[ACMEChallengeTypeDeviceAttest01] = acmehandler.NewDeviceAttestVerifier(deviceAttest)
	}
	return m
}

// verifyEnroll01 asserts ca to ACMEEnroll01TCGCSRVerifier and runs the
// enroll-01 exchange against dialTarget, returning the endorsement key and
// activation key the credential was activated for.
func verifyEnroll01(client *ACMEChallengeClient, ca ACMECertificateAuthority, dialTarget, port, token, keyAuth string) (*enroll01.Activation, error) {
	enrollCA, ok := ca.(ACMEEnroll01TCGCSRVerifier)
	if !ok {
		return nil, ErrACMEEnrollCAUnsupported
	}
	return enroll01.VerifyActivation(client, enrollCA, dialTarget, port, token, keyAuth)
}
