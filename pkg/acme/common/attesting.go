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

package common

import (
	"net"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// AttestationChallenge is what ChallengeHandler hands an AttestingVerifier:
// the authorization being validated and the challenge exchange to run.
type AttestationChallenge struct {
	// IdentifierType is the authorization's identifier type. ChallengeHandler
	// has already refused "ip": attestation challenges never authorize it.
	IdentifierType string

	// IdentifierValue is the identifier being authorized, exactly as the
	// order declared it. It is never substituted for dev-mode loopback
	// dialing; that is DialTarget's job.
	IdentifierValue string

	// DialTarget is the host a verifier that contacts the device (enroll-01,
	// endorse-01) dials. It equals IdentifierValue except for the
	// loopback-identifier dev-mode substitution. Empty for a challenge the
	// server never dials (device-attest-01).
	DialTarget string

	// Port is the port to contact the device on. Empty for a challenge the
	// server never dials.
	Port string

	// AuthorizedIdentity is the identity an authority other than the device
	// authorized for this challenge, established by ChallengeHandler before the
	// verifier runs: for endorse-01, the EK the account's External Account
	// Binding is bound to (go-xkms#1392). A verifier whose challenge proves
	// nothing about the device itself reports it as the attested identity, so
	// the identity is derived from the authorization and not from the order
	// being checked. Empty for a challenge no outside authority authorizes
	// (enroll-01, device-attest-01), and a verifier that needs it refuses when
	// it is empty.
	AuthorizedIdentity string

	// Payload is the body of the client's authenticated POST to the challenge
	// URL, as the JWS carried it. A challenge answered by the client
	// (device-attest-01: {"attObj": ...}) is verified from it; a challenge the
	// server answers by contacting the device ignores it.
	Payload []byte

	// Token is the challenge token the server issued.
	Token string

	// KeyAuthorization is the key authorization the device must answer with.
	KeyAuthorization string
}

// AttestedIdentity is what an AttestingVerifier established about the device
// that answered the challenge (go-xkms#828).
type AttestedIdentity struct {
	// Identifier is the device identity the evidence itself carries (a TPM
	// AIK/IAK permanentIdentifier, a DICE Ueid). ChallengeHandler compares it
	// with the authorization's identifier value and refuses the challenge
	// with "unauthorized" on any difference; no verifier is trusted to have
	// made that comparison.
	Identifier string

	// Attestation is the verified evidence to persist on the challenge so
	// order finalization can bind the certificate request's key to it
	// (go-xkms#789). Nil for a challenge type with no finalize-time binding.
	Attestation *entities.DeviceAttestation
}

// AttestingVerifier verifies an attestation challenge (enroll-01, endorse-01,
// device-attest-01) and reports the identity the device attested.
//
// It sits beside ChallengeVerifierFunc, which cannot report an identity and
// is unchanged for http-01, dns-01 and tls-alpn-01 (go-xkms#828, owner ruling
// Option B). ChallengeHandler requires an AttestingVerifier for every
// attestation challenge type and refuses the challenge when none is
// registered: an attestation never authorizes an order without its identity
// being compared with the order's identifier.
type AttestingVerifier interface {
	// VerifyAttested runs the challenge and returns the attested identity, or
	// an error when the evidence does not verify. A nil identity with a nil
	// error breaks the contract and is refused.
	VerifyAttested(resolver *net.Resolver, ca CertificateAuthority, challenge AttestationChallenge) (*AttestedIdentity, error)
}

// AttestingVerifierFunc adapts a function to an AttestingVerifier, as
// http.HandlerFunc does for http.Handler.
type AttestingVerifierFunc func(resolver *net.Resolver, ca CertificateAuthority, challenge AttestationChallenge) (*AttestedIdentity, error)

// VerifyAttested calls f.
func (f AttestingVerifierFunc) VerifyAttested(resolver *net.Resolver, ca CertificateAuthority, challenge AttestationChallenge) (*AttestedIdentity, error) {
	return f(resolver, ca, challenge)
}
