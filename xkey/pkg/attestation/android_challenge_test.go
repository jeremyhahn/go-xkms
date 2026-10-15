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

package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
)

// androidKeyAttestationOID is the Android Key Attestation extension OID.
var androidKeyAttestationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// Android attestation security levels, as recorded in the extension.
const (
	androidSecurityLevelSoftware         = 0
	androidSecurityLevelTrustedEnv       = 1
	androidTestAttestationVersion        = 4
	androidTestKeymasterVersion          = 41
	androidTestSoftwareEnforcedEmptySeq  = 0x30
	androidTestSoftwareEnforcedEmptyLen  = 0x00
	androidTestUniqueIDPlaceholderLength = 0
)

// androidKeyDescriptionASN1 mirrors the on-wire KeyDescription SEQUENCE so a
// test can synthesize the certificate an Android device would produce.
//
//	KeyDescription ::= SEQUENCE {
//	    attestationVersion         INTEGER,
//	    attestationSecurityLevel   SecurityLevel,
//	    keymasterVersion           INTEGER,
//	    keymasterSecurityLevel     SecurityLevel,
//	    attestationChallenge       OCTET STRING,
//	    uniqueId                   OCTET STRING,
//	    softwareEnforced           AuthorizationList,
//	    teeEnforced                AuthorizationList,
//	}
type androidKeyDescriptionASN1 struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TeeEnforced              asn1.RawValue
}

// emptyAuthorizationList returns the DER of an empty AuthorizationList.
func emptyAuthorizationList() asn1.RawValue {
	return asn1.RawValue{
		FullBytes: []byte{androidTestSoftwareEnforcedEmptySeq, androidTestSoftwareEnforcedEmptyLen},
	}
}

// androidAttestationExtension builds the DER of an Android Key Attestation
// extension carrying the given challenge and attestation security level.
func androidAttestationExtension(t *testing.T, challenge []byte, securityLevel int) []byte {
	t.Helper()

	der, err := asn1.Marshal(androidKeyDescriptionASN1{
		AttestationVersion:       androidTestAttestationVersion,
		AttestationSecurityLevel: asn1.Enumerated(securityLevel),
		KeymasterVersion:         androidTestKeymasterVersion,
		KeymasterSecurityLevel:   asn1.Enumerated(securityLevel),
		AttestationChallenge:     challenge,
		UniqueID:                 make([]byte, androidTestUniqueIDPlaceholderLength),
		SoftwareEnforced:         emptyAuthorizationList(),
		TeeEnforced:              emptyAuthorizationList(),
	})
	if err != nil {
		t.Fatalf("failed to marshal Android key description: %v", err)
	}

	return der
}

// generateAttestedLeaf creates a leaf certificate signed by the given CA that
// carries an Android Key Attestation extension bound to challenge.
func generateAttestedLeaf(t *testing.T, signer *testCA, cn string, challenge []byte, securityLevel int) *x509.Certificate {
	t.Helper()
	return createAttestedCert(t, signer, cn, challenge, securityLevel, false)
}

// generateAttestedSelfSignedCA creates a self-signed CA certificate that also
// carries an Android Key Attestation extension. Android ships single-cert
// chains in some StrongBox configurations, and the verifier must bind those
// to the challenge as well.
func generateAttestedSelfSignedCA(t *testing.T, cn string, challenge []byte) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	self := &testCA{key: key}
	cert := createAttestedCertWithKey(t, self, key, cn, challenge, androidSecurityLevelTrustedEnv, true)
	self.cert = cert

	return self
}

// createAttestedCert issues a certificate signed by signer.
func createAttestedCert(t *testing.T, signer *testCA, cn string, challenge []byte, securityLevel int, isCA bool) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	return createAttestedCertWithKey(t, signer, key, cn, challenge, securityLevel, isCA)
}

// createAttestedCertWithKey issues a certificate for subjectKey. When the
// signer holds no certificate yet the certificate is self-signed, which is how
// generateAttestedSelfSignedCA bootstraps its anchor.
func createAttestedCertWithKey(
	t *testing.T,
	signer *testCA,
	subjectKey *ecdsa.PrivateKey,
	cn string,
	challenge []byte,
	securityLevel int,
	isCA bool,
) *x509.Certificate {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Test Organization"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		ExtraExtensions: []pkix.Extension{{
			Id:    androidKeyAttestationOID,
			Value: androidAttestationExtension(t, challenge, securityLevel),
		}},
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	parent := template
	if signer.cert != nil {
		parent = signer.cert
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &subjectKey.PublicKey, signer.key)
	if err != nil {
		t.Fatalf("failed to create attested certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse attested certificate: %v", err)
	}

	return cert
}

// newAndroidVerifier returns a verifier anchored on the given root for the
// Android hardware purpose.
func newAndroidVerifier(t *testing.T, root *x509.Certificate) *Verifier {
	t.Helper()

	store := newMockTrustStore()
	store.addCertForPurpose(root, truststore.PurposeAndroidHardware)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	return v
}

// --- Challenge binding ---

func TestVerifyAndroidAttestation_MatchingChallenge(t *testing.T) {
	challenge := []byte("challenge-generated-by-this-host")

	rootCA := generateTestCA(t, "Android Root CA")
	leaf := generateAttestedLeaf(t, rootCA, "Android Key", challenge, androidSecurityLevelTrustedEnv)
	v := newAndroidVerifier(t, rootCA.cert)

	result, err := v.VerifyAndroidAttestation([]*x509.Certificate{leaf, rootCA.cert}, challenge)
	if err != nil {
		t.Fatalf("VerifyAndroidAttestation() error: %v", err)
	}
	if !result.Verified {
		t.Fatalf("Verified = false, want true (message: %s)", result.Message)
	}
	if result.TrustLevel != TrustLevelHardware {
		t.Errorf("TrustLevel = %q, want %q", result.TrustLevel, TrustLevelHardware)
	}
}

func TestVerifyAndroidAttestation_MismatchedChallengeRejected(t *testing.T) {
	// The attestation was captured for a previous session's challenge; an
	// attacker replays it against a freshly generated one.
	capturedChallenge := []byte("challenge-from-an-earlier-session")
	freshChallenge := []byte("challenge-generated-by-this-host!")

	rootCA := generateTestCA(t, "Android Root CA")
	leaf := generateAttestedLeaf(t, rootCA, "Replayed Key", capturedChallenge, androidSecurityLevelTrustedEnv)
	v := newAndroidVerifier(t, rootCA.cert)

	result, err := v.VerifyAndroidAttestation([]*x509.Certificate{leaf, rootCA.cert}, freshChallenge)
	if !errors.Is(err, ErrChallengeVerification) {
		t.Fatalf("error = %v, want %v", err, ErrChallengeVerification)
	}
	if result == nil {
		t.Fatal("returned nil result on challenge mismatch")
	}
	if result.Verified {
		t.Error("Verified = true for a replayed attestation, want false")
	}
	if result.TrustLevel != TrustLevelUnknown {
		t.Errorf("TrustLevel = %q, want %q", result.TrustLevel, TrustLevelUnknown)
	}
}

func TestVerifyAndroidAttestation_ChallengePrefixNotAccepted(t *testing.T) {
	// A truncated challenge must not satisfy the comparison.
	challenge := []byte("challenge-generated-by-this-host")

	rootCA := generateTestCA(t, "Android Root CA")
	leaf := generateAttestedLeaf(t, rootCA, "Android Key", challenge, androidSecurityLevelTrustedEnv)
	v := newAndroidVerifier(t, rootCA.cert)

	result, err := v.VerifyAndroidAttestation([]*x509.Certificate{leaf, rootCA.cert}, challenge[:8])
	if !errors.Is(err, ErrChallengeVerification) {
		t.Fatalf("error = %v, want %v", err, ErrChallengeVerification)
	}
	if result.Verified {
		t.Error("Verified = true for a truncated challenge, want false")
	}
}

func TestVerifyAndroidAttestation_MissingExtensionRejected(t *testing.T) {
	// A certificate that chains to a genuine Android root but carries no key
	// attestation extension proves nothing about this challenge.
	challenge := []byte("challenge-generated-by-this-host")

	rootCA := generateTestCA(t, "Android Root CA")
	leaf := generateLeafCert(t, rootCA, "Unattested Key")
	v := newAndroidVerifier(t, rootCA.cert)

	result, err := v.VerifyAndroidAttestation([]*x509.Certificate{leaf, rootCA.cert}, challenge)
	if !errors.Is(err, ErrChallengeVerification) {
		t.Fatalf("error = %v, want %v", err, ErrChallengeVerification)
	}
	if result.Verified {
		t.Error("Verified = true without an attestation extension, want false")
	}
}

func TestVerifyAndroidAttestation_MissingNonceRejected(t *testing.T) {
	challenge := []byte("challenge-generated-by-this-host")

	rootCA := generateTestCA(t, "Android Root CA")
	leaf := generateAttestedLeaf(t, rootCA, "Android Key", challenge, androidSecurityLevelTrustedEnv)
	v := newAndroidVerifier(t, rootCA.cert)

	for _, nonce := range [][]byte{nil, {}} {
		result, err := v.VerifyAndroidAttestation([]*x509.Certificate{leaf, rootCA.cert}, nonce)
		if !errors.Is(err, ErrMissingNonce) {
			t.Fatalf("error = %v, want %v", err, ErrMissingNonce)
		}
		if result != nil {
			t.Error("result must be nil when the request is rejected outright")
		}
	}
}

func TestVerifyAndroidAttestation_CorruptExtensionRejected(t *testing.T) {
	challenge := []byte("challenge-generated-by-this-host")

	rootCA := generateTestCA(t, "Android Root CA")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Corrupt Attestation"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{{
			Id:    androidKeyAttestationOID,
			Value: []byte{0x30, 0x03, 0x02, 0x01, 0x04},
		}},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCA.cert, &key.PublicKey, rootCA.key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	v := newAndroidVerifier(t, rootCA.cert)

	result, err := v.VerifyAndroidAttestation([]*x509.Certificate{leaf, rootCA.cert}, challenge)
	if !errors.Is(err, ErrChallengeVerification) {
		t.Fatalf("error = %v, want %v", err, ErrChallengeVerification)
	}
	if result.Verified {
		t.Error("Verified = true for an unparseable extension, want false")
	}
}

func TestVerifyAndroidAttestation_SoftwareAttestationIsNotHardware(t *testing.T) {
	challenge := []byte("challenge-generated-by-this-host")

	rootCA := generateTestCA(t, "Android Root CA")
	leaf := generateAttestedLeaf(t, rootCA, "Software Key", challenge, androidSecurityLevelSoftware)
	v := newAndroidVerifier(t, rootCA.cert)

	result, err := v.VerifyAndroidAttestation([]*x509.Certificate{leaf, rootCA.cert}, challenge)
	if err != nil {
		t.Fatalf("VerifyAndroidAttestation() error: %v", err)
	}
	if !result.Verified {
		t.Fatalf("Verified = false, want true (message: %s)", result.Message)
	}
	if result.TrustLevel != TrustLevelSoftware {
		t.Errorf("TrustLevel = %q, want %q for a software attestation", result.TrustLevel, TrustLevelSoftware)
	}
}

func TestVerifyAndroidAttestation_ChallengeCheckedAfterChainFails(t *testing.T) {
	// An untrusted chain must be reported as a chain failure even when the
	// challenge would have matched.
	challenge := []byte("challenge-generated-by-this-host")

	trustedCA := generateTestCA(t, "Trusted Android CA")
	untrustedCA := generateTestCA(t, "Untrusted CA")
	leaf := generateAttestedLeaf(t, untrustedCA, "Android Key", challenge, androidSecurityLevelTrustedEnv)

	v := newAndroidVerifier(t, trustedCA.cert)

	result, err := v.VerifyAndroidAttestation([]*x509.Certificate{leaf}, challenge)
	if !errors.Is(err, ErrChainVerification) {
		t.Fatalf("error = %v, want %v", err, ErrChainVerification)
	}
	if result.Verified {
		t.Error("Verified = true for an untrusted chain, want false")
	}
}
