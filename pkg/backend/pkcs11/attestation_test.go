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

//go:build pkcs11

package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

// attestableKeyAttributes returns attributes that pass types.KeyAttributes
// validation, so tests reach the attestation logic rather than the input guard.
func attestableKeyAttributes(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:            cn,
		KeyType:       backend.KEY_TYPE_TLS,
		StoreType:     backend.STORE_PKCS11,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: rsaTestKeySize},
	}
}

// provisionRSADeviceKey generates an RSA device attestation key on the token
// under DeviceAttestationKeyLabel, the way a manufacturer or a provisioning
// ceremony would, and returns a signer for it.
func provisionRSADeviceKey(t *testing.T, b *Backend) crypto.Signer {
	t.Helper()

	label := []byte(DeviceAttestationKeyLabel)
	signer, err := generateRSAKeyPair(b.pool, label, label, rsaTestKeySize, false, "", "")
	require.NoError(t, err, "the token must accept a device attestation key")

	return signer
}

// provisionECDSADeviceKey generates an ECDSA P-256 device attestation key on
// the token under DeviceAttestationKeyLabel.
func provisionECDSADeviceKey(t *testing.T, b *Backend) crypto.Signer {
	t.Helper()

	label := []byte(DeviceAttestationKeyLabel)
	signer, err := generateECDSAKeyPair(b.pool, label, label, elliptic.P256(), false, "", "")
	require.NoError(t, err, "the token must accept an ECDSA device attestation key")

	return signer
}

// provisionEd25519DeviceKey generates an Ed25519 device attestation key on the
// token under DeviceAttestationKeyLabel. The templates match the ones
// GenerateEd25519 uses; only the label differs, because the device key is
// published under a fixed label rather than a per-key identifier.
func provisionEd25519DeviceKey(t *testing.T, b *Backend) crypto.Signer {
	t.Helper()

	label := []byte(DeviceAttestationKeyLabel)
	ed25519OID := []byte{0x06, 0x03, 0x2b, 0x65, 0x70}

	publicTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_EDWARDS),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, label),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed25519OID),
	}
	privateTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_EDWARDS),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, label),
	}

	var publicHandle, privateHandle pkcs11.ObjectHandle
	require.NoError(t, b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		var err error
		publicHandle, privateHandle, err = b.p11ctx.GenerateKeyPair(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_EC_EDWARDS_KEY_PAIR_GEN, nil)},
			publicTemplate,
			privateTemplate,
		)
		return err
	}), "the token must accept an Ed25519 device attestation key")

	return &pkcs11Ed25519Signer{
		pool:          b.pool,
		publicHandle:  publicHandle,
		privateHandle: privateHandle,
		label:         DeviceAttestationKeyLabel,
	}
}

// storeCertificateOnToken writes a DER certificate to the token as a
// CKO_CERTIFICATE object under the given CKA_ID / CKA_LABEL.
func storeCertificateOnToken(t *testing.T, b *Backend, der []byte, id []byte) {
	t.Helper()

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, id),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, cert.RawIssuer),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, der),
	}

	require.NoError(t, b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		_, err := b.p11ctx.CreateObject(session, template)
		return err
	}), "the token must accept a certificate object")
}

// issueDeviceCertificate issues a certificate for the device attestation key
// and stores it on the token under DeviceAttestationKeyLabel.
//
// When issuer is nil the certificate is self-signed by the device key itself,
// which models a token whose only identity evidence is its own assertion. When
// an issuer is supplied it models the real case: a certificate chaining to a
// manufacturer key that a verifier can anchor on.
func issueDeviceCertificate(t *testing.T, b *Backend, device crypto.Signer, issuer *x509.Certificate, issuerKey crypto.Signer) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "xkms test device attestation key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	parent := template
	signingKey := device
	if issuer != nil {
		parent = issuer
		signingKey = issuerKey
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, device.Public(), signingKey)
	require.NoError(t, err, "the device certificate must be issuable")

	storeCertificateOnToken(t, b, der, []byte(DeviceAttestationKeyLabel))

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// newTestCA returns a self-signed ECDSA CA certificate and its key, standing in
// for a manufacturer root. ECDSA keeps key generation fast enough for a unit
// test.
func newTestCA(t *testing.T, commonName string) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert, key
}

// verifyStatementSignature checks the statement's signature against the
// attesting public key using the standard library directly, deliberately
// bypassing every helper in this package. It is the oracle that makes a
// fabricated or constant signature impossible to pass off as real.
func verifyStatementSignature(t *testing.T, stmt *attestation.AttestationStatement, signed []byte) error {
	t.Helper()

	switch pub := stmt.AttestingKeyPublic.(type) {
	case *rsa.PublicKey:
		digest := sha256.Sum256(signed)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], stmt.Signature)
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(signed)
		if !ecdsa.VerifyASN1(pub, digest[:], stmt.Signature) {
			return errTestSignatureInvalid
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, signed, stmt.Signature) {
			return errTestSignatureInvalid
		}
		return nil
	default:
		t.Fatalf("unexpected attesting key type %T", stmt.AttestingKeyPublic)
		return nil
	}
}

// errTestSignatureInvalid reports a failed verification from the test oracle,
// which returns no detail of its own.
var errTestSignatureInvalid = errTestSignature("signature verification failed")

type errTestSignature string

func (e errTestSignature) Error() string { return string(e) }

// TestAttestKey_InvalidAttributes verifies that malformed key attributes are
// rejected before the backend touches the token, and that the validation cause
// is preserved for the caller.
func TestAttestKey_InvalidAttributes(t *testing.T) {
	b := newProvisionedBackend(t, "attest-invalid-attrs")

	for _, tc := range []struct {
		name  string
		attrs *types.KeyAttributes
		want  string
	}{
		{"nil attributes", nil, "pkcs11: invalid key attributes"},
		{"missing CN", &types.KeyAttributes{StoreType: backend.STORE_PKCS11, KeyType: backend.KEY_TYPE_TLS}, "common name (CN) is required"},
		{"missing store type", &types.KeyAttributes{CN: "x", KeyType: backend.KEY_TYPE_TLS}, "store type is required"},
		{"missing key type", &types.KeyAttributes{CN: "x", StoreType: backend.STORE_PKCS11}, "key type is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stmt, err := b.AttestKey(context.Background(), tc.attrs, []byte("nonce"))
			require.Nil(t, stmt)
			require.Error(t, err)
			require.Contains(t, err.Error(), "pkcs11: invalid key attributes")
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestAttestKey_NotInitialized verifies that attestation on a backend with no
// session pool reports the uninitialized state instead of dereferencing a nil
// pool.
func TestAttestKey_NotInitialized(t *testing.T) {
	b := &Backend{config: &Config{Library: "/usr/lib/softhsm/libsofthsm2.so"}}

	stmt, err := b.AttestKey(context.Background(), attestableKeyAttributes("uninitialized"), nil)
	require.Nil(t, stmt)
	require.ErrorIs(t, err, ErrHSMNotInitialized)
	require.EqualError(t, err, "pkcs11: HSM not initialized")
}

// TestAttestKey_UnsupportedDevice verifies the capability gate: a backend with
// no library path cannot identify the device, so attestation must be refused
// rather than fabricated.
func TestAttestKey_UnsupportedDevice(t *testing.T) {
	b := &Backend{
		config: &Config{Library: ""},
		pool:   &SessionPool{},
	}

	stmt, err := b.AttestKey(context.Background(), attestableKeyAttributes("no-library"), nil)
	require.Nil(t, stmt)
	require.ErrorIs(t, err, ErrAttestationUnsupported)
	require.EqualError(t, err, "pkcs11: HSM does not support key attestation")
}

// TestAttestKey_CancelledContext verifies that a cancelled caller gets no token
// work done on its behalf.
func TestAttestKey_CancelledContext(t *testing.T) {
	b := newProvisionedBackend(t, "attest-cancelled")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	stmt, err := b.AttestKey(ctx, attestableKeyAttributes("cancelled"), nil)
	require.Nil(t, stmt)
	require.ErrorIs(t, err, context.Canceled)
}

// TestAttestKey_DoesNotEmitUnsignedStatement is the safety guard of this file.
//
// An AttestationStatement with Format "pkcs11" is read by a relying party as
// cryptographic proof that a key lives in hardware. A statement whose signature
// was not produced by a key the device holds would be trivially forgeable while
// carrying that meaning, so it must never be returned.
//
// A stock SoftHSM2 token holds no device attestation key -- a software token
// has no manufacturer key and no hardware boundary to vouch for. The invariant
// asserted here is therefore: for a key that genuinely exists on such a token,
// AttestKey must fail with ErrNoDeviceAttestationKey rather than return a
// statement. If anyone reintroduces a fabricated or constant signature, this
// test fails and says why.
func TestAttestKey_DoesNotEmitUnsignedStatement(t *testing.T) {
	b := newProvisionedBackend(t, "attest-no-forgery")

	attrs := attestableKeyAttributes("attest-real-key")
	_, err := b.GenerateRSA(attrs)
	require.NoError(t, err, "the key under attestation must exist on the token")

	stmt, err := b.AttestKey(context.Background(), attrs, []byte("freshness-nonce"))
	require.Error(t, err, "a token with no device attestation key must not produce a statement")
	require.ErrorIs(t, err, ErrNoDeviceAttestationKey)
	require.Nil(t, stmt)

	// If a statement is ever returned here, it must carry a real signature.
	if typed, ok := stmt.(*attestation.AttestationStatement); ok && typed != nil {
		require.NotEqual(t, []byte("pkcs11-attestation-signature"), typed.Signature,
			"an attestation statement must never ship the placeholder signature")
	}
}

// TestAttestKey_RSADeviceKey proves the whole attestation contract end to end
// on a token provisioned with an RSA device key and a device certificate: the
// statement is signed by the device key over the encoded attestation data, the
// claims decode to the facts the token holds, and any change to those bytes
// invalidates the signature.
func TestAttestKey_RSADeviceKey(t *testing.T) {
	b := newProvisionedBackend(t, "attest-rsa-device")

	device := provisionRSADeviceKey(t, b)
	deviceCert := issueDeviceCertificate(t, b, device, nil, nil)

	attrs := attestableKeyAttributes("attested-rsa-key")
	attested, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	nonce := []byte("verifier-supplied-nonce")
	result, err := b.AttestKey(context.Background(), attrs, nonce)
	require.NoError(t, err)

	stmt, ok := result.(*attestation.AttestationStatement)
	require.True(t, ok, "AttestKey must return an *attestation.AttestationStatement")

	require.Equal(t, "pkcs11", stmt.Format)
	require.Equal(t, "pkcs11", stmt.Backend)
	require.Equal(t, x509.RSA, stmt.AttestingKeyAlgorithm)
	require.Equal(t, x509.SHA256WithRSA, stmt.SignatureAlgorithm)
	require.Equal(t, device.Public(), stmt.AttestingKeyPublic,
		"the attesting key must be the device key, never the key being attested")
	require.Equal(t, attested.Public(), stmt.AttestedKeyPublic)
	require.Equal(t, nonce, stmt.Nonce)
	require.NotEqual(t, []byte("pkcs11-attestation-signature"), stmt.Signature)

	require.Len(t, stmt.CertificateChain, 1)
	require.True(t, deviceCert.Equal(stmt.CertificateChain[0]))
	require.Equal(t, []byte("present"), stmt.ClaimData["device_certificate"])

	// Oracle: crypto/rsa, outside this package, over the exact bytes shipped as
	// attestation data.
	require.NoError(t, verifyStatementSignature(t, stmt, stmt.AttestationData),
		"the statement signature must verify against the device public key")

	// The in-repo verifier must reach the same conclusion, which is what a
	// relying party in this stack actually runs.
	require.NoError(t, attestation.NewVerifier(nil).VerifySignature(stmt, nil))

	// The signed bytes are the encoded attestation data, and they decode to the
	// facts the token holds.
	info, err := ParseAttestationInfo(stmt.AttestationData)
	require.NoError(t, err)
	require.Equal(t, attestationInfoVersion, info.Version)
	require.Equal(t, "pkcs11", info.Format)
	require.Equal(t, "attested-rsa-key.rsa", info.KeyID)
	require.Equal(t, nonce, info.Nonce)
	require.True(t, info.Properties.Local, "the token generated this key itself")
	require.True(t, info.Properties.Sensitive)
	require.True(t, info.Properties.NeverExtractable, "the key has never been allowed to leave the token")
	require.False(t, info.Properties.Extractable)
	require.NotEmpty(t, info.Device.Manufacturer)
	require.Equal(t, b.config.TokenLabel, info.Device.TokenLabel)
	require.WithinDuration(t, time.Now(), info.Timestamp, time.Minute)

	infoKey, err := info.AttestedPublicKey()
	require.NoError(t, err)
	require.Equal(t, attested.Public(), infoKey,
		"the signed body must bind the public key of the attested key")

	// Determinism: re-encoding the decoded body reproduces the signed bytes, so
	// a verifier can recompute exactly what was signed.
	reEncoded, err := asn1.Marshal(*info)
	require.NoError(t, err)
	require.Equal(t, stmt.AttestationData, reEncoded)

	// Negative: a single flipped byte in the signed data breaks verification.
	tampered := append([]byte(nil), stmt.AttestationData...)
	tampered[len(tampered)-1] ^= 0xFF
	require.Error(t, verifyStatementSignature(t, stmt, tampered),
		"a modified attestation body must not verify")

	// Negative: rewriting a security-critical claim breaks verification. This is
	// what makes a constant signature impossible to reintroduce -- a constant
	// would verify nothing, so it could not fail here.
	forged := *info
	forged.Properties.NeverExtractable = false
	forgedDER, err := asn1.Marshal(forged)
	require.NoError(t, err)
	require.NotEqual(t, stmt.AttestationData, forgedDER)
	require.Error(t, verifyStatementSignature(t, stmt, forgedDER),
		"a rewritten key property must not verify under the original signature")
}

// TestAttestKey_ECDSADeviceKey proves the ECDSA device key path produces a
// signature that crypto/ecdsa accepts, with the curve-matched digest.
func TestAttestKey_ECDSADeviceKey(t *testing.T) {
	b := newProvisionedBackend(t, "attest-ecdsa-device")

	device := provisionECDSADeviceKey(t, b)
	issueDeviceCertificate(t, b, device, nil, nil)

	attrs := attestableKeyAttributes("attested-key-ecdsa-device")
	_, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	result, err := b.AttestKey(context.Background(), attrs, []byte("ecdsa-nonce"))
	require.NoError(t, err)

	stmt := result.(*attestation.AttestationStatement)
	require.Equal(t, x509.ECDSA, stmt.AttestingKeyAlgorithm)
	require.Equal(t, x509.ECDSAWithSHA256, stmt.SignatureAlgorithm)
	require.Equal(t, device.Public(), stmt.AttestingKeyPublic)

	require.NoError(t, verifyStatementSignature(t, stmt, stmt.AttestationData))
	require.NoError(t, attestation.NewVerifier(nil).VerifySignature(stmt, nil))

	tampered := append([]byte(nil), stmt.AttestationData...)
	tampered[0] ^= 0x01
	require.Error(t, verifyStatementSignature(t, stmt, tampered))
}

// TestAttestKey_Ed25519DeviceKey proves the Ed25519 device key path signs the
// attestation body itself rather than a digest of it, which is what
// crypto/ed25519 verifies.
func TestAttestKey_Ed25519DeviceKey(t *testing.T) {
	b := newProvisionedBackend(t, "attest-ed25519-device")

	device := provisionEd25519DeviceKey(t, b)

	attrs := attestableKeyAttributes("attested-key-ed25519-device")
	_, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	result, err := b.AttestKey(context.Background(), attrs, nil)
	require.NoError(t, err)

	stmt := result.(*attestation.AttestationStatement)
	require.Equal(t, x509.Ed25519, stmt.AttestingKeyAlgorithm)
	require.Equal(t, x509.PureEd25519, stmt.SignatureAlgorithm)
	require.Equal(t, device.Public(), stmt.AttestingKeyPublic)

	require.NoError(t, verifyStatementSignature(t, stmt, stmt.AttestationData))

	tampered := append([]byte(nil), stmt.AttestationData...)
	tampered[1] ^= 0x08
	require.Error(t, verifyStatementSignature(t, stmt, tampered))
}

// TestAttestKey_WithoutDeviceCertificate proves the honest reporting of a token
// that can sign but cannot prove who it is: the statement is real and verifies,
// but it carries no chain and says so, and a verifier that requires an anchor
// rejects it.
func TestAttestKey_WithoutDeviceCertificate(t *testing.T) {
	b := newProvisionedBackend(t, "attest-no-device-cert")

	device := provisionRSADeviceKey(t, b)

	attrs := attestableKeyAttributes("attested-key-uncertified-device")
	_, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	result, err := b.AttestKey(context.Background(), attrs, []byte("nonce"))
	require.NoError(t, err)

	stmt := result.(*attestation.AttestationStatement)
	require.Empty(t, stmt.CertificateChain, "an uncertified device must not ship a chain")
	require.Equal(t, []byte("absent"), stmt.ClaimData["device_certificate"])
	require.Equal(t, device.Public(), stmt.AttestingKeyPublic)
	require.NoError(t, verifyStatementSignature(t, stmt, stmt.AttestationData))

	// Without a chain there is nothing to anchor, so a verifier holding trust
	// anchors must refuse the statement even though the signature is genuine.
	anchor, _ := newTestCA(t, "unrelated anchor")
	require.Error(t, attestation.NewVerifier([]*x509.Certificate{anchor}).VerifyChain(stmt, nil))
}

// TestAttestKey_ChainsToIssuerOnToken proves that when the device certificate
// was issued by a CA whose certificate is also on the token, the statement
// carries the chain a verifier needs to anchor it.
func TestAttestKey_ChainsToIssuerOnToken(t *testing.T) {
	b := newProvisionedBackend(t, "attest-device-chain")

	caCert, caKey := newTestCA(t, "xkms test device manufacturer")
	storeCertificateOnToken(t, b, caCert.Raw, []byte("device-manufacturer-ca"))

	device := provisionRSADeviceKey(t, b)
	deviceCert := issueDeviceCertificate(t, b, device, caCert, caKey)

	attrs := attestableKeyAttributes("attested-key-chained-device")
	_, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	result, err := b.AttestKey(context.Background(), attrs, []byte("nonce"))
	require.NoError(t, err)

	stmt := result.(*attestation.AttestationStatement)
	require.Len(t, stmt.CertificateChain, 2, "the chain must reach the issuer held on the token")
	require.True(t, deviceCert.Equal(stmt.CertificateChain[0]))
	require.True(t, caCert.Equal(stmt.CertificateChain[1]))

	require.NoError(t, verifyStatementSignature(t, stmt, stmt.AttestationData))
	require.NoError(t, attestation.NewVerifier([]*x509.Certificate{caCert}).VerifyChain(stmt, nil))
}

// TestAttestKey_KeyNotFound proves that a token able to attest still refuses to
// make claims about a key it does not hold.
func TestAttestKey_KeyNotFound(t *testing.T) {
	b := newProvisionedBackend(t, "attest-key-absent")

	device := provisionRSADeviceKey(t, b)
	issueDeviceCertificate(t, b, device, nil, nil)

	stmt, err := b.AttestKey(context.Background(), attestableKeyAttributes("never-generated"), nil)
	require.Nil(t, stmt)
	require.ErrorIs(t, err, ErrAttestedKeyNotFound)
}

// TestSupportsAttestation verifies the capability probe in both directions: an
// unidentified device (no library path) cannot attest, and an identified one
// passes the outer gate.
func TestSupportsAttestation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config *Config
		want   bool
	}{
		{"no config", nil, false},
		{"no library path", &Config{Library: ""}, false},
		{"identified device", &Config{Library: "/usr/lib/softhsm/libsofthsm2.so"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			supported, err := (&Backend{config: tc.config}).supportsAttestation()
			require.NoError(t, err)
			require.Equal(t, tc.want, supported)
		})
	}
}

// TestFindKeyObject_Success proves the lookup resolves a generated key to its
// token objects by CKA_ID, and that the handles it returns are the ones the
// token reports for that key.
func TestFindKeyObject_Success(t *testing.T) {
	b := newProvisionedBackend(t, "attest-find-key")

	attrs := attestableKeyAttributes("findable-key")
	_, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	objs, err := b.findKeyObject(attrs)
	require.NoError(t, err)
	require.Equal(t, []byte("findable-key.rsa"), objs.id)
	require.NotZero(t, objs.private)
	require.NotZero(t, objs.public)

	session := openIntrospectionSession(t, b)
	expected := findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, objs.id),
	})
	require.Equal(t, expected, objs.public)
}

// TestFindKeyObject_Errors pins the failure modes: bad input, a key the token
// does not hold, and a backend that has not logged in.
func TestFindKeyObject_Errors(t *testing.T) {
	b := newProvisionedBackend(t, "attest-find-key-errors")

	t.Run("nil attributes", func(t *testing.T) {
		objs, err := b.findKeyObject(nil)
		require.Nil(t, objs)
		require.ErrorIs(t, err, ErrInvalidKeyAttributes)
	})

	t.Run("key not on token", func(t *testing.T) {
		objs, err := b.findKeyObject(attestableKeyAttributes("absent-key"))
		require.Nil(t, objs)
		require.ErrorIs(t, err, ErrAttestedKeyNotFound)
		require.Contains(t, err.Error(), "absent-key")
	})

	t.Run("not initialized", func(t *testing.T) {
		uninitialized := &Backend{config: &Config{Library: "/usr/lib/softhsm/libsofthsm2.so"}}
		objs, err := uninitialized.findKeyObject(attestableKeyAttributes("anything"))
		require.Nil(t, objs)
		require.ErrorIs(t, err, ErrHSMNotInitialized)
	})
}

// TestGetPublicKeyFromObject_Success proves the public key is rebuilt from the
// token's own attribute values and matches what the signer reports, for both
// RSA (CKA_MODULUS / CKA_PUBLIC_EXPONENT) and EC (CKA_EC_PARAMS / CKA_EC_POINT).
func TestGetPublicKeyFromObject_Success(t *testing.T) {
	b := newProvisionedBackend(t, "attest-public-key")

	rsaAttrs := attestableKeyAttributes("public-rsa")
	rsaSigner, err := b.GenerateRSA(rsaAttrs)
	require.NoError(t, err)

	ecAttrs := attestableKeyAttributes("public-ec")
	ecAttrs.KeyAlgorithm = x509.ECDSA
	ecAttrs.RSAAttributes = nil
	ecSigner, err := b.GenerateECDSA(ecAttrs)
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		attrs  *types.KeyAttributes
		signer crypto.Signer
	}{
		{"rsa", rsaAttrs, rsaSigner},
		{"ecdsa", ecAttrs, ecSigner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, err := b.findKeyObject(tc.attrs)
			require.NoError(t, err)

			pub, err := b.getPublicKeyFromObject(objs)
			require.NoError(t, err)
			require.Equal(t, tc.signer.Public(), pub)
		})
	}
}

// TestGetPublicKeyFromObject_Errors pins the failure modes: no object, no
// public material on the token, and an uninitialized backend.
func TestGetPublicKeyFromObject_Errors(t *testing.T) {
	b := newProvisionedBackend(t, "attest-public-key-errors")

	t.Run("nil object", func(t *testing.T) {
		pub, err := b.getPublicKeyFromObject(nil)
		require.Nil(t, pub)
		require.ErrorIs(t, err, ErrInvalidKeyAttributes)
	})

	t.Run("no public material", func(t *testing.T) {
		pub, err := b.getPublicKeyFromObject(&tokenKeyObjects{id: []byte("orphan"), private: 1})
		require.Nil(t, pub)
		require.ErrorIs(t, err, ErrAttestedKeyPublicMissing)
	})

	t.Run("not initialized", func(t *testing.T) {
		uninitialized := &Backend{config: &Config{Library: "/usr/lib/softhsm/libsofthsm2.so"}}
		pub, err := uninitialized.getPublicKeyFromObject(&tokenKeyObjects{public: 1})
		require.Nil(t, pub)
		require.ErrorIs(t, err, ErrHSMNotInitialized)
	})
}

// TestGetPublicKeyFromObject_FromCertificate proves the PIV-style path: a token
// that publishes no public key object still yields the attested public key,
// recovered from the certificate stored under the same CKA_ID.
func TestGetPublicKeyFromObject_FromCertificate(t *testing.T) {
	b := newProvisionedBackend(t, "attest-public-from-cert")

	device := provisionRSADeviceKey(t, b)
	cert := issueDeviceCertificate(t, b, device, nil, nil)

	session := openIntrospectionSession(t, b)
	certHandle := findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(DeviceAttestationKeyLabel)),
	})

	pub, err := b.getPublicKeyFromObject(&tokenKeyObjects{
		id:          []byte(DeviceAttestationKeyLabel),
		private:     1,
		certificate: certHandle,
	})
	require.NoError(t, err)
	require.Equal(t, cert.PublicKey, pub)
	require.Equal(t, device.Public(), pub)
}

// TestGetDeviceIdentityCertificate_Success proves the device certificate and
// the chain built from the token's own certificate objects are returned, and
// that a chain link is only accepted when its signature actually verifies.
func TestGetDeviceIdentityCertificate_Success(t *testing.T) {
	b := newProvisionedBackend(t, "attest-device-cert")

	caCert, caKey := newTestCA(t, "xkms test device manufacturer")
	storeCertificateOnToken(t, b, caCert.Raw, []byte("manufacturer-ca"))

	// An unrelated CA with the same subject name as the real issuer must not be
	// accepted as a chain link, because it did not sign the device certificate.
	impostor, _ := newTestCA(t, "xkms test device manufacturer")
	storeCertificateOnToken(t, b, impostor.Raw, []byte("impostor-ca"))

	device := provisionRSADeviceKey(t, b)
	deviceCert := issueDeviceCertificate(t, b, device, caCert, caKey)

	cert, chain, err := b.getDeviceIdentityCertificate()
	require.NoError(t, err)
	require.True(t, deviceCert.Equal(cert))
	require.Len(t, chain, 2)
	require.True(t, deviceCert.Equal(chain[0]))
	require.True(t, caCert.Equal(chain[1]), "only the certificate that actually signed the device cert may be chained")
}

// TestGetDeviceIdentityCertificate_Errors pins the failure modes: a token with
// no device certificate, and a backend that has not logged in.
func TestGetDeviceIdentityCertificate_Errors(t *testing.T) {
	t.Run("no device certificate", func(t *testing.T) {
		b := newProvisionedBackend(t, "attest-device-cert-absent")

		cert, chain, err := b.getDeviceIdentityCertificate()
		require.Nil(t, cert)
		require.Nil(t, chain)
		require.ErrorIs(t, err, ErrDeviceCertificateNotFound)
	})

	t.Run("not initialized", func(t *testing.T) {
		b := &Backend{config: &Config{Library: "/usr/lib/softhsm/libsofthsm2.so"}}

		cert, chain, err := b.getDeviceIdentityCertificate()
		require.Nil(t, cert)
		require.Nil(t, chain)
		require.ErrorIs(t, err, ErrHSMNotInitialized)
	})
}

// TestDeviceAttestationKey_Success proves the device key is resolved from the
// token under the published label, with the algorithm identifiers a verifier
// needs, and that its signer really signs with the token key.
func TestDeviceAttestationKey_Success(t *testing.T) {
	b := newProvisionedBackend(t, "attest-device-key")

	device := provisionRSADeviceKey(t, b)

	resolved, err := b.deviceAttestationKey()
	require.NoError(t, err)
	require.Equal(t, device.Public(), resolved.publicKey)
	require.Equal(t, x509.RSA, resolved.keyAlgorithm)
	require.Equal(t, x509.SHA256WithRSA, resolved.signatureAlgorithm)
	require.Equal(t, crypto.SHA256, resolved.hash)

	message := []byte("proof that the resolved signer is the token key")
	digest := sha256.Sum256(message)
	signature, err := resolved.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(device.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], signature))
}

// TestDeviceAttestationKey_Errors pins the refusals: a token with no device key
// cannot attest, and neither can an uninitialized backend.
func TestDeviceAttestationKey_Errors(t *testing.T) {
	t.Run("no device key on token", func(t *testing.T) {
		b := newProvisionedBackend(t, "attest-device-key-absent")

		resolved, err := b.deviceAttestationKey()
		require.Nil(t, resolved)
		require.ErrorIs(t, err, ErrNoDeviceAttestationKey)
	})

	t.Run("not initialized", func(t *testing.T) {
		b := &Backend{config: &Config{Library: "/usr/lib/softhsm/libsofthsm2.so"}}

		resolved, err := b.deviceAttestationKey()
		require.Nil(t, resolved)
		require.ErrorIs(t, err, ErrHSMNotInitialized)
	})
}

// TestSignAttestationData_Success proves the signature is produced by the token
// key over the supplied bytes, verified outside this package.
func TestSignAttestationData_Success(t *testing.T) {
	b := newProvisionedBackend(t, "attest-sign")

	device := provisionRSADeviceKey(t, b)
	resolved, err := b.deviceAttestationKey()
	require.NoError(t, err)

	body := []byte("attestation body")
	signature, err := b.signAttestationData(resolved, body)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	digest := sha256.Sum256(body)
	require.NoError(t, rsa.VerifyPKCS1v15(device.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], signature))

	other := sha256.Sum256([]byte("different body"))
	require.Error(t, rsa.VerifyPKCS1v15(device.Public().(*rsa.PublicKey), crypto.SHA256, other[:], signature))
}

// TestSignAttestationData_Errors proves there is no path that returns bytes
// without a device key, and none that signs nothing.
func TestSignAttestationData_Errors(t *testing.T) {
	b := &Backend{config: &Config{Library: "/usr/lib/softhsm/libsofthsm2.so"}}

	t.Run("no device key", func(t *testing.T) {
		signature, err := b.signAttestationData(nil, []byte("body"))
		require.Nil(t, signature)
		require.ErrorIs(t, err, ErrNoDeviceAttestationKey)
	})

	t.Run("device key without signer", func(t *testing.T) {
		signature, err := b.signAttestationData(&deviceAttestationKey{}, []byte("body"))
		require.Nil(t, signature)
		require.ErrorIs(t, err, ErrNoDeviceAttestationKey)
	})

	t.Run("empty body", func(t *testing.T) {
		signature, err := b.signAttestationData(&deviceAttestationKey{signer: staticSigner{}}, nil)
		require.Nil(t, signature)
		require.ErrorIs(t, err, ErrMalformedAttestationInfo)
	})
}

// staticSigner is a crypto.Signer stand-in used only to reach the input guards
// of signAttestationData without a token.
type staticSigner struct{}

func (staticSigner) Public() crypto.PublicKey { return nil }

func (staticSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errTestSignature("staticSigner must never be asked to sign")
}

// TestEncodeAttestationData_Deterministic proves a verifier can recompute the
// signed bytes: the same facts always encode identically, and the encoding
// round-trips through the parser unchanged.
func TestEncodeAttestationData_Deterministic(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data := &attestationData{
		KeyID:     "example.rsa",
		KeyPublic: key.Public(),
		Device: DeviceInfo{
			Manufacturer: "SoftHSM project",
			Model:        "SoftHSM v2",
			Serial:       "0123456789abcdef",
			TokenLabel:   "test-token",
			Library:      "/usr/lib/softhsm/libsofthsm2.so",
		},
		Properties: KeyProperties{Local: true, Sensitive: true, AlwaysSensitive: true, NeverExtractable: true},
		Timestamp:  time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC),
		Nonce:      []byte("nonce"),
	}

	first, err := encodeAttestationData(data)
	require.NoError(t, err)
	second, err := encodeAttestationData(data)
	require.NoError(t, err)
	require.Equal(t, first, second, "the same facts must always produce the same signed bytes")

	// A sub-second difference must not change the encoding, or a verifier could
	// never recompute it from the parsed timestamp.
	shifted := *data
	shifted.Timestamp = data.Timestamp.Add(500 * time.Millisecond)
	shiftedDER, err := encodeAttestationData(&shifted)
	require.NoError(t, err)
	require.Equal(t, first, shiftedDER)

	info, err := ParseAttestationInfo(first)
	require.NoError(t, err)
	require.Equal(t, "example.rsa", info.KeyID)
	require.Equal(t, []byte("nonce"), info.Nonce)
	require.Equal(t, data.Device, info.Device)
	require.Equal(t, data.Properties, info.Properties)
	require.True(t, info.Timestamp.Equal(data.Timestamp))

	roundTripped, err := asn1.Marshal(*info)
	require.NoError(t, err)
	require.Equal(t, first, roundTripped)
}

// TestEncodeAttestationData_FieldBoundariesAreUnambiguous proves the encoding
// is structured rather than concatenated: moving a character from one field to
// the next produces different signed bytes. String concatenation would collide
// here, letting one signature stand for two different sets of claims.
func TestEncodeAttestationData_FieldBoundariesAreUnambiguous(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	timestamp := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)

	left, err := encodeAttestationData(&attestationData{
		KeyID: "ab", KeyPublic: key.Public(), Timestamp: timestamp, Nonce: []byte("c"),
	})
	require.NoError(t, err)

	right, err := encodeAttestationData(&attestationData{
		KeyID: "a", KeyPublic: key.Public(), Timestamp: timestamp, Nonce: []byte("bc"),
	})
	require.NoError(t, err)

	require.NotEqual(t, left, right, "field boundaries must be unambiguous in the signed bytes")
}

// TestEncodeAttestationData_Errors proves the encoder refuses input it cannot
// represent instead of emitting a placeholder.
func TestEncodeAttestationData_Errors(t *testing.T) {
	t.Run("nil data", func(t *testing.T) {
		der, err := encodeAttestationData(nil)
		require.Nil(t, der)
		require.ErrorIs(t, err, ErrMalformedAttestationInfo)
	})

	t.Run("missing public key", func(t *testing.T) {
		der, err := encodeAttestationData(&attestationData{KeyID: "x"})
		require.Nil(t, der)
		require.ErrorIs(t, err, ErrMalformedAttestationInfo)
	})

	t.Run("unmarshalable public key", func(t *testing.T) {
		der, err := encodeAttestationData(&attestationData{KeyID: "x", KeyPublic: "not a key"})
		require.Nil(t, der)
		require.Error(t, err)
		require.Contains(t, err.Error(), "marshal attested public key")
	})
}

// TestParseAttestationInfo_Errors proves a verifier cannot be fed a body that
// only looks well formed.
func TestParseAttestationInfo_Errors(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	valid, err := encodeAttestationData(&attestationData{
		KeyID:     "example.rsa",
		KeyPublic: key.Public(),
		Timestamp: time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC),
	})
	require.NoError(t, err)

	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)

	futureVersion, err := asn1.Marshal(AttestationInfo{
		Version:     attestationInfoVersion + 1,
		Format:      "pkcs11",
		KeyID:       "example.rsa",
		AttestedKey: asn1.RawValue{FullBytes: spki},
		Timestamp:   time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC),
		Nonce:       []byte{},
	})
	require.NoError(t, err)

	wrongFormat, err := asn1.Marshal(AttestationInfo{
		Version:     attestationInfoVersion,
		Format:      "tpm2",
		KeyID:       "example.rsa",
		AttestedKey: asn1.RawValue{FullBytes: spki},
		Timestamp:   time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC),
		Nonce:       []byte{},
	})
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		der  []byte
		want string
	}{
		{"empty", nil, "empty attestation data"},
		{"not DER", []byte("attestation-data-placeholder"), "parse attestation data"},
		{"trailing bytes", append(append([]byte(nil), valid...), 0x00), "trailing bytes"},
		{"unsupported version", futureVersion, "unsupported version"},
		{"foreign format", wrongFormat, "unexpected format"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := ParseAttestationInfo(tc.der)
			require.Nil(t, info)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestAttestationInfo_AttestedPublicKey proves the embedded SubjectPublicKeyInfo
// is the real key encoding, and that a corrupted one is reported rather than
// returned as a zero value.
func TestAttestationInfo_AttestedPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	der, err := encodeAttestationData(&attestationData{
		KeyID:     "p521.ecdsa",
		KeyPublic: key.Public(),
		Timestamp: time.Now(),
	})
	require.NoError(t, err)

	info, err := ParseAttestationInfo(der)
	require.NoError(t, err)

	pub, err := info.AttestedPublicKey()
	require.NoError(t, err)
	require.Equal(t, key.Public(), pub)

	corrupted := *info
	corrupted.AttestedKey = asn1.RawValue{FullBytes: []byte{0x30, 0x01, 0x00}}
	badKey, err := corrupted.AttestedPublicKey()
	require.Nil(t, badKey)
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse attested public key")
}

// TestKeyProperties_Success proves the attested properties are read from the
// token rather than assumed: a key generated by this package is local,
// sensitive and never extractable.
func TestKeyProperties_Success(t *testing.T) {
	b := newProvisionedBackend(t, "attest-key-properties")

	attrs := attestableKeyAttributes("properties-key")
	_, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	objs, err := b.findKeyObject(attrs)
	require.NoError(t, err)

	properties, err := b.keyProperties(objs.private)
	require.NoError(t, err)
	require.True(t, properties.Local)
	require.True(t, properties.Sensitive)
	require.True(t, properties.AlwaysSensitive)
	require.True(t, properties.NeverExtractable)
	require.False(t, properties.Extractable)
}

// TestKeyProperties_Errors pins the failure modes: an invalid handle and an
// uninitialized backend.
func TestKeyProperties_Errors(t *testing.T) {
	b := newProvisionedBackend(t, "attest-key-properties-errors")

	properties, err := b.keyProperties(0)
	require.Equal(t, KeyProperties{}, properties)
	require.ErrorIs(t, err, ErrAttestedKeyNotFound)

	uninitialized := &Backend{config: &Config{Library: "/usr/lib/softhsm/libsofthsm2.so"}}
	properties, err = uninitialized.keyProperties(1)
	require.Equal(t, KeyProperties{}, properties)
	require.ErrorIs(t, err, ErrHSMNotInitialized)
}

// TestTokenDeviceInfo verifies the device identity comes from C_GetTokenInfo,
// and that an uninitialized backend reports that rather than an empty identity.
func TestTokenDeviceInfo(t *testing.T) {
	b := newProvisionedBackend(t, "attest-token-info")

	info, err := b.tokenDeviceInfo()
	require.NoError(t, err)
	require.NotEmpty(t, info.Manufacturer)
	require.NotEmpty(t, info.Model)
	require.Equal(t, "attest-token-info", info.TokenLabel)
	require.Equal(t, b.config.Library, info.Library)
	require.Equal(t, info.Manufacturer, strings.TrimSpace(info.Manufacturer), "padding must be trimmed for a stable encoding")

	uninitialized := &Backend{config: &Config{Library: "/usr/lib/softhsm/libsofthsm2.so"}}
	empty, err := uninitialized.tokenDeviceInfo()
	require.Equal(t, DeviceInfo{}, empty)
	require.ErrorIs(t, err, ErrHSMNotInitialized)
}

// TestBuildDeviceChain proves chain construction stops where it should: at a
// self-signed certificate, at a missing issuer, and at a cycle among token
// certificate objects. A verifier is entitled to assume the chain terminates.
func TestBuildDeviceChain(t *testing.T) {
	root, rootKey := newTestCA(t, "root")
	intermediate, intermediateKey := newIntermediateCA(t, "intermediate", root, rootKey)
	leaf := newLeafCertificate(t, "leaf", intermediate, intermediateKey)
	unrelated, _ := newTestCA(t, "intermediate") // same subject, different key

	t.Run("self-signed leaf stops immediately", func(t *testing.T) {
		chain := buildDeviceChain(root, []*x509.Certificate{intermediate, leaf})
		require.Len(t, chain, 1)
		require.True(t, root.Equal(chain[0]))
	})

	t.Run("full chain to root", func(t *testing.T) {
		chain := buildDeviceChain(leaf, []*x509.Certificate{root, intermediate})
		require.Len(t, chain, 3)
		require.True(t, leaf.Equal(chain[0]))
		require.True(t, intermediate.Equal(chain[1]))
		require.True(t, root.Equal(chain[2]))
	})

	t.Run("issuer absent from token", func(t *testing.T) {
		chain := buildDeviceChain(leaf, []*x509.Certificate{root})
		require.Len(t, chain, 1)
	})

	t.Run("name collision without a valid signature is rejected", func(t *testing.T) {
		chain := buildDeviceChain(leaf, []*x509.Certificate{unrelated})
		require.Len(t, chain, 1, "a certificate that did not sign the leaf must not be chained")
	})
}

// newIntermediateCA issues a CA certificate under the given parent.
func newIntermediateCA(t *testing.T, commonName string, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert, key
}

// newLeafCertificate issues an end-entity certificate under the given parent.
func newLeafCertificate(t *testing.T, commonName string, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

// TestFindObjectByIDOrLabel_LabelFallback proves the CKA_LABEL fallback: a
// vendor-provisioned object that carries a label but no CKA_ID is still found,
// which is why the lookup does not stop at the CKA_ID search.
func TestFindObjectByIDOrLabel_LabelFallback(t *testing.T) {
	b := newProvisionedBackend(t, "attest-label-fallback")

	caCert, _ := newTestCA(t, "label only certificate")
	label := []byte("label-only-certificate")

	require.NoError(t, b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		_, err := b.p11ctx.CreateObject(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
			pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, caCert.RawSubject),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, caCert.Raw),
		})
		return err
	}))

	var found, missing pkcs11.ObjectHandle
	require.NoError(t, b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		var err error
		if found, err = b.findObjectByIDOrLabel(session, pkcs11.CKO_CERTIFICATE, label); err != nil {
			return err
		}
		missing, err = b.findObjectByIDOrLabel(session, pkcs11.CKO_CERTIFICATE, []byte("no-such-object"))
		return err
	}))

	require.NotZero(t, found, "an object carrying only CKA_LABEL must still be found")
	require.Zero(t, missing, "a search that matches nothing must report the invalid handle, not an error")

	cert, err := b.readCertificate(found)
	require.NoError(t, err)
	require.True(t, caCert.Equal(cert))
}

// TestObjectKeyType verifies CKA_KEY_TYPE is read from the token, and that an
// object which has no key type is reported rather than decoded as zero (zero is
// CKK_RSA, so a silent default here would misidentify keys).
func TestObjectKeyType(t *testing.T) {
	b := newProvisionedBackend(t, "attest-key-type")

	attrs := attestableKeyAttributes("key-type-probe")
	_, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	objs, err := b.findKeyObject(attrs)
	require.NoError(t, err)

	keyType, err := b.objectKeyType(objs.public)
	require.NoError(t, err)
	require.Equal(t, uint(pkcs11.CKK_RSA), keyType)

	caCert, _ := newTestCA(t, "not a key")
	storeCertificateOnToken(t, b, caCert.Raw, []byte("certificate-without-key-type"))

	session := openIntrospectionSession(t, b)
	certHandle := findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("certificate-without-key-type")),
	})

	keyType, err = b.objectKeyType(certHandle)
	require.Zero(t, keyType)
	require.Error(t, err)

	uninitialized := &Backend{config: &Config{Library: "/usr/lib/softhsm/libsofthsm2.so"}}
	keyType, err = uninitialized.objectKeyType(1)
	require.Zero(t, keyType)
	require.ErrorIs(t, err, ErrHSMNotInitialized)
}

// TestGetPublicKeyFromObject_UnsupportedKeyType proves an object whose key type
// has no public key encoding is refused rather than attested with a guess.
func TestGetPublicKeyFromObject_UnsupportedKeyType(t *testing.T) {
	b := newProvisionedBackend(t, "attest-unsupported-type")

	secretAttrs := attestableKeyAttributes("aes-secret")
	secretAttrs.KeyAlgorithm = x509.UnknownPublicKeyAlgorithm
	secretAttrs.RSAAttributes = nil

	handle, err := b.GenerateSecretKey(secretAttrs, 256)
	require.NoError(t, err)

	pub, err := b.getPublicKeyFromObject(&tokenKeyObjects{id: []byte("aes-secret"), private: handle, public: handle})
	require.Nil(t, pub)
	require.ErrorIs(t, err, ErrUnsupportedKeyAlgorithm)
}

// TestReadBoolAttribute verifies the attribute read used for the attested key
// properties: a value the token holds is returned, an attribute the token does
// not implement for that object class reads as false rather than failing the
// whole attestation, and an invalid handle is an error.
func TestReadBoolAttribute(t *testing.T) {
	b := newProvisionedBackend(t, "attest-bool-attribute")

	attrs := attestableKeyAttributes("bool-attribute-key")
	_, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	objs, err := b.findKeyObject(attrs)
	require.NoError(t, err)

	require.NoError(t, b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		sensitive, err := b.readBoolAttribute(session, objs.private, pkcs11.CKA_SENSITIVE)
		require.NoError(t, err)
		require.True(t, sensitive)

		// CKA_ALWAYS_SENSITIVE is not defined for public key objects; the token
		// says so and the read reports false rather than aborting attestation.
		absent, err := b.readBoolAttribute(session, objs.public, pkcs11.CKA_ALWAYS_SENSITIVE)
		require.NoError(t, err)
		require.False(t, absent)

		invalid, err := b.readBoolAttribute(session, pkcs11.ObjectHandle(0xFFFFFFFF), pkcs11.CKA_SENSITIVE)
		require.False(t, invalid)
		require.Error(t, err, "an unusable handle is not the same as an unimplemented attribute")
		return nil
	}))
}

// TestReadCertificate_Errors proves certificate reads fail loudly instead of
// returning an empty certificate a caller might chain.
func TestReadCertificate_Errors(t *testing.T) {
	b := newProvisionedBackend(t, "attest-read-cert-errors")

	cert, err := b.readCertificate(0)
	require.Nil(t, cert)
	require.ErrorIs(t, err, ErrDeviceCertificateNotFound)

	cert, err = b.readCertificate(pkcs11.ObjectHandle(0xFFFFFFFF))
	require.Nil(t, cert)
	require.Error(t, err)

	uninitialized := &Backend{config: &Config{Library: "/usr/lib/softhsm/libsofthsm2.so"}}
	cert, err = uninitialized.readCertificate(1)
	require.Nil(t, cert)
	require.ErrorIs(t, err, ErrHSMNotInitialized)
}

// TestTokenDeviceInfo_SlotError proves an unreadable token identity fails the
// attestation instead of being signed as an empty device description.
func TestTokenDeviceInfo_SlotError(t *testing.T) {
	b := newProvisionedBackend(t, "attest-token-info-error")

	missingSlot := 0x7FFF
	detached := &Backend{
		config: &Config{Library: b.config.Library, TokenLabel: b.config.TokenLabel, Slot: &missingSlot},
		p11ctx: b.p11ctx,
		pool:   b.pool,
	}

	info, err := detached.tokenDeviceInfo()
	require.Equal(t, DeviceInfo{}, info)
	require.Error(t, err)
	require.Contains(t, err.Error(), "C_GetTokenInfo")
}

// TestBoolClaim verifies the ClaimData rendering of the hardware-exclusivity
// claims, which a relying party reads as text.
func TestBoolClaim(t *testing.T) {
	require.Equal(t, "true", boolClaim(true))
	require.Equal(t, "false", boolClaim(false))
}

// TestDecodeCKULong verifies the CK_ULONG decoding used for CKA_KEY_TYPE, in
// both the value range that matters and the empty case.
func TestDecodeCKULong(t *testing.T) {
	require.Equal(t, uint(0), decodeCKULong(nil))
	require.Equal(t, uint(pkcs11.CKK_RSA), decodeCKULong([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}))
	require.Equal(t, uint(CKK_EC_EDWARDS), decodeCKULong([]byte{0x40, 0x00, 0x00, 0x00}))
	require.Equal(t, uint(0x01020304), decodeCKULong([]byte{0x04, 0x03, 0x02, 0x01}))
}
