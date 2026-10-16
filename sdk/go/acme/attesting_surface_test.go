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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	acmecommon "github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	acmehandler "github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
)

// The attesting-verifier SDK surface is the canonical pkg/acme types, not
// copies: each pair below must be assignable in both directions, or this file
// does not compile. A consumer that registers an ACMEAttestingVerifier in
// ACMERestServiceParams.AttestingVerifiers relies on exactly this.
var (
	_ acmecommon.AttestingVerifier     = ACMEAttestingVerifier(nil)
	_ ACMEAttestingVerifier            = acmecommon.AttestingVerifier(nil)
	_ acmecommon.AttestingVerifierFunc = ACMEAttestingVerifierFunc(nil)
	_ ACMEAttestingVerifierFunc        = acmecommon.AttestingVerifierFunc(nil)
	_ acmecommon.AttestationChallenge  = ACMEAttestationChallenge{}
	_ acmecommon.AttestedIdentity      = ACMEAttestedIdentity{}
	_ *entities.DeviceAttestation      = ACMEAttestedIdentity{}.Attestation
	_ *entities.DeviceAttestation      = (*ACMEDeviceAttestationEntity)(nil)
	_ ACMEAttestingVerifier            = ACMEAttestingVerifierFunc(nil)

	// The server parameter takes the SDK's own verifier map unchanged.
	_ map[string]ACMEAttestingVerifier = ACMERestServiceParams{}.AttestingVerifiers

	// The client surface: a TPM module reports its device identity and
	// returns the SDK's attested key, and the identity rule is the server's.
	_ interface{ DeviceIdentity() (string, error) } = ACMETPMModule(nil)
	_ interface {
		CreateAttestedKey(string, string) (*ACMEAttestedKey, error)
	} = ACMETPMModule(nil)
	_ func(deviceattest01.AttestationFormat, *x509.Certificate) (string, error) = ACMEDeviceIdentityFromCertificate
	_ *deviceattest01.AttestationObject                                         = (*ACMEDeviceAttestObject)(nil)
	_ ACMEDeviceAttestFormat                                                    = deviceattest01.FormatDICE
	_ error                                                                     = ACMEErrDeviceIdentityUnavailable
	_ error                                                                     = ACMEErrDeviceIdentityFailed

	// The error types are the handler's, so errors.As works across the SDK.
	_ *acmehandler.ErrAttestationIdentifierType = (*ACMEErrAttestationIdentifierType)(nil)
	_ *acmehandler.ErrAttestingVerifierRequired = (*ACMEErrAttestingVerifierRequired)(nil)
	_ *acmehandler.ErrAttestationNoIdentity     = (*ACMEErrAttestationNoIdentity)(nil)
	_ *acmehandler.ErrIdentityMismatch          = (*ACMEErrIdentityMismatch)(nil)
	_ *acmehandler.ErrDeviceAttestationNotFound = (*ACMEErrDeviceAttestationNotFound)(nil)
	_ *acmehandler.ErrOrderAuthorizationMissing = (*ACMEErrOrderAuthorizationMissing)(nil)

	// The device-attest-01 payload and trust-anchor surface is the canonical
	// pkg/acme types, and its error sentinels are real errors.
	_ deviceattest01.AttestationRequest   = ACMEDeviceAttestRequest{}
	_ deviceattest01.TrustAnchors         = ACMETrustAnchors{}
	_ deviceattest01.DICEPolicy           = ACMEDICEPolicy{}
	_ *deviceattest01.TrustAnchorVerifier = (*ACMETrustAnchorVerifier)(nil)
	_ deviceattest01.AttestationVerifier  = (*ACMETrustAnchorVerifier)(nil)
	_ ACMEDeviceAttest01Verifier          = (*ACMETrustAnchorVerifier)(nil)
	_ deviceattest01.AttestationStatement = ACMEDeviceAttestStatement{}
	_ error                               = ACMEErrNoTrustAnchors
	_ error                               = ACMEErrNoAttestationVerifier
	_ error                               = ACMEErrAttestationPayloadInvalid
)

// attestationChallengeFor is a challenge no network answers: the capability
// checks under test run before any I/O.
func attestationChallengeFor(identifierType string) ACMEAttestationChallenge {
	return ACMEAttestationChallenge{
		IdentifierType:   identifierType,
		IdentifierValue:  "device-1",
		DialTarget:       "device-1",
		Port:             "8443",
		Token:            "token",
		KeyAuthorization: "expected",
	}
}

// TestACMEAttestingVerifiers_RegistersEnabledTypesOnly proves each flag
// registers exactly its own challenge type and none registers nothing.
func TestACMEAttestingVerifiers_RegistersEnabledTypesOnly(t *testing.T) {
	client := NewACMEChallengeClient(ACMEChallengeClientConfig{Resolver: offlineResolver(t)})

	tests := []struct {
		name                         string
		enroll, endorse, deviceAttst bool
		want                         []string
	}{
		{name: "none", want: nil},
		{name: "enroll only", enroll: true, want: []string{ACMEChallengeTypeEnroll01}},
		{name: "endorse only", endorse: true, want: []string{ACMEChallengeTypeEndorse01}},
		{name: "device-attest only", deviceAttst: true, want: []string{ACMEChallengeTypeDeviceAttest01}},
		{
			name: "all", enroll: true, endorse: true, deviceAttst: true,
			want: []string{ACMEChallengeTypeEnroll01, ACMEChallengeTypeEndorse01, ACMEChallengeTypeDeviceAttest01},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var deviceAttest ACMEDeviceAttest01Verifier
			if tt.deviceAttst {
				deviceAttest = anchoredDeviceAttestVerifier(t)
			}
			got := ACMEAttestingVerifiers(client, tt.enroll, tt.endorse, deviceAttest)
			if len(got) != len(tt.want) {
				t.Fatalf("registered %d verifiers, want %d", len(got), len(tt.want))
			}
			for _, challengeType := range tt.want {
				if got[challengeType] == nil {
					t.Fatalf("%s verifier not registered", challengeType)
				}
			}
		})
	}
}

// TestACMEAttestingVerifiers_CapabilityChecks pins the CA capability
// assertion the enroll-01 verifier makes: a CA lacking the TCG surface is
// refused with the verifier's typed error before any evidence is fetched.
// device-attest-01 makes none: its trust policy is passed in, not asserted
// from the CA handle.
func TestACMEAttestingVerifiers_CapabilityChecks(t *testing.T) {
	client := NewACMEChallengeClient(ACMEChallengeClientConfig{Resolver: offlineResolver(t)})
	verifiers := ACMEAttestingVerifiers(client, true, true, anchoredDeviceAttestVerifier(t))

	t.Run("enroll-01 refuses a CA without the TCG surface", func(t *testing.T) {
		attested, err := verifiers[ACMEChallengeTypeEnroll01].VerifyAttested(
			offlineResolver(t), nonTCGCA{}, attestationChallengeFor(acmecommon.AuthzTypePermanentIdentifier))
		if !errors.Is(err, ErrACMEEnrollCAUnsupported) || attested != nil {
			t.Fatalf("got (%v, %v), want (nil, ErrACMEEnrollCAUnsupported)", attested, err)
		}
	})

	t.Run("enroll-01 clears the check with the production CA", func(t *testing.T) {
		_, err := verifiers[ACMEChallengeTypeEnroll01].VerifyAttested(
			offlineResolver(t), (*pkgca.CA)(nil), attestationChallengeFor(acmecommon.AuthzTypePermanentIdentifier))
		if errors.Is(err, ErrACMEEnrollCAUnsupported) {
			t.Fatal("the production CA was refused as unsupported")
		}
	})
}

// TestACMEAttestingVerifiers_EndorseReportsTheEABAuthorizedIdentity pins what
// endorse-01 attests (go-xkms#1392): the identity the account's External
// Account Binding authorized, never the order's own identifier. With no
// authorization to derive it from there is no identity, and the challenge is
// refused.
func TestACMEAttestingVerifiers_EndorseReportsTheEABAuthorizedIdentity(t *testing.T) {
	verifier := ACMEAttestingVerifiers(nil, false, true, nil)[ACMEChallengeTypeEndorse01]

	attested, err := verifier.VerifyAttested(nil, nil, ACMEAttestationChallenge{
		IdentifierType: acmecommon.AuthzTypePermanentIdentifier, IdentifierValue: "the-order-identifier",
		AuthorizedIdentity: "the-eab-bound-ek",
	})
	if err != nil {
		t.Fatalf("VerifyAttested: %v", err)
	}
	if attested.Identifier != "the-eab-bound-ek" || attested.Attestation != nil {
		t.Fatalf("attested = %+v, want the EAB-bound identity and no evidence", attested)
	}

	attested, err = verifier.VerifyAttested(nil, nil, attestationChallengeFor(acmecommon.AuthzTypePermanentIdentifier))
	if !errors.Is(err, ACMEErrEndorseNoAuthorizedIdentity) || attested != nil {
		t.Fatalf("got (%v, %v), want (nil, ACMEErrEndorseNoAuthorizedIdentity)", attested, err)
	}
}

// anchoredDeviceAttestVerifier is the production device-attest-01 trust policy
// over a throwaway TPM root.
func anchoredDeviceAttestVerifier(t *testing.T) ACMEDeviceAttest01Verifier {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TPM Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	verifier, err := ACMENewTrustAnchorVerifier(ACMETrustAnchors{TPMRoots: []*x509.Certificate{root}})
	if err != nil {
		t.Fatalf("ACMENewTrustAnchorVerifier: %v", err)
	}
	return verifier
}

// TestACMEAttestingVerifiers_DeviceAttestUsesTheInjectedPolicy proves the
// registered device-attest-01 verifier verifies the client's payload with the
// policy it was built with, and contacts nothing: it is handed no address.
func TestACMEAttestingVerifiers_DeviceAttestUsesTheInjectedPolicy(t *testing.T) {
	verifier := ACMEAttestingVerifiers(nil, false, false, anchoredDeviceAttestVerifier(t))[ACMEChallengeTypeDeviceAttest01]

	// An attestation whose chain is no certificate any configured root vouches for.
	payload, err := ACMEEncodeDeviceAttestRequest(&ACMEDeviceAttestObject{
		Format:       string(ACMEDeviceAttestFormatDICE),
		AttStatement: ACMEDeviceAttestStatement{X5c: []interface{}{[]byte("not a certificate")}},
	})
	if err != nil {
		t.Fatalf("ACMEEncodeDeviceAttestRequest: %v", err)
	}

	attested, err := verifier.VerifyAttested(nil, nil, ACMEAttestationChallenge{
		IdentifierType: acmecommon.AuthzTypePermanentIdentifier, IdentifierValue: "device-1",
		Token: "token", KeyAuthorization: "token.thumbprint", Payload: payload,
	})
	if err == nil || attested != nil {
		t.Fatalf("got (%v, %v), want a refusal of an attestation no configured root vouches for", attested, err)
	}
}

// TestACMEAttestingVerifiers_DeviceAttestWithoutAPolicyIsNotRegistered proves
// there is no way to register device-attest-01 without a trust policy.
func TestACMEAttestingVerifiers_DeviceAttestWithoutAPolicyIsNotRegistered(t *testing.T) {
	if got := ACMEAttestingVerifiers(nil, true, true, nil); got[ACMEChallengeTypeDeviceAttest01] != nil {
		t.Fatal("device-attest-01 was registered with no trust policy")
	}
}

// TestACMENewTrustAnchorVerifier_RefusesNoAnchors pins the SDK's error sentinel
// for a policy with nothing to anchor to.
func TestACMENewTrustAnchorVerifier_RefusesNoAnchors(t *testing.T) {
	if _, err := ACMENewTrustAnchorVerifier(ACMETrustAnchors{}); !errors.Is(err, ACMEErrNoTrustAnchors) {
		t.Fatalf("err = %v, want ACMEErrNoTrustAnchors", err)
	}
}

// TestACMEDeviceAttestPayloadRoundTrip pins the draft-ietf-acme-device-attest-10
// payload through the SDK surface a device tool uses.
func TestACMEDeviceAttestPayloadRoundTrip(t *testing.T) {
	object := &ACMEDeviceAttestObject{
		Format:       string(ACMEDeviceAttestFormatTPM),
		AttStatement: ACMEDeviceAttestStatement{Ver: "2.0", Alg: -7, X5c: []interface{}{[]byte{1, 2, 3}}},
	}
	payload, err := ACMEEncodeDeviceAttestRequest(object)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	parsed, err := ACMEParseDeviceAttestRequest(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Format != object.Format || parsed.AttStatement.Alg != -7 {
		t.Fatalf("round trip = %+v, want %+v", parsed, object)
	}
	if _, err := ACMEParseDeviceAttestRequest([]byte(`{}`)); !errors.Is(err, ACMEErrAttestationPayloadInvalid) {
		t.Fatalf("parse of an empty payload = %v, want ACMEErrAttestationPayloadInvalid", err)
	}
}
