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

package keybackend

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// testAAGUID is the authenticator identity used throughout these tests.
var testAAGUID = []byte{
	0x51, 0x50, 0xE2, 0x08, 0x1A, 0xB8, 0x51, 0x62,
	0xBC, 0x67, 0xF5, 0xE4, 0xF2, 0x4A, 0xDE, 0xFA,
}

// stubAttestationSource is a controllable AttestationKeySource.
type stubAttestationSource struct {
	signer      crypto.Signer
	chain       []*x509.Certificate
	generateErr error
	signerErr   error
	chainErr    error
}

func (s *stubAttestationSource) GenerateAttestationKey() (crypto.Signer, error) {
	if s.generateErr != nil {
		return nil, s.generateErr
	}
	return s.signer, nil
}

func (s *stubAttestationSource) AttestationSigner() (crypto.Signer, error) {
	if s.signerErr != nil {
		return nil, s.signerErr
	}
	return s.signer, nil
}

func (s *stubAttestationSource) AttestationCertificateChain() ([]*x509.Certificate, error) {
	if s.chainErr != nil {
		return nil, s.chainErr
	}
	return s.chain, nil
}

// attestationCertOptions selects which §8.2.1 requirement a generated
// certificate satisfies, so each rule can be exercised in isolation.
type attestationCertOptions struct {
	omitCountry      bool
	omitOrganization bool
	wrongOU          bool
	isCA             bool
	omitAAGUID       bool
	criticalAAGUID   bool
	aaguid           []byte
	malformedAAGUID  bool
}

// newTestAttestationCert issues an attestation certificate for publicKey.
func newTestAttestationCert(t *testing.T, publicKey crypto.PublicKey, opts attestationCertOptions) *x509.Certificate {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test attestation root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	subject := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"Automate The Things, LLC"},
		OrganizationalUnit: []string{AttestationCertificateOU},
		CommonName:         "xkey FIDO2 Attestation",
	}
	if opts.omitCountry {
		subject.Country = nil
	}
	if opts.omitOrganization {
		subject.Organization = nil
	}
	if opts.wrongOU {
		subject.OrganizationalUnit = []string{"Something Else"}
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  opts.isCA,
		BasicConstraintsValid: true,
	}
	if opts.isCA {
		template.KeyUsage = x509.KeyUsageCertSign
	}

	if !opts.omitAAGUID {
		aaguid := opts.aaguid
		if aaguid == nil {
			aaguid = testAAGUID
		}

		var value []byte
		if opts.malformedAAGUID {
			// A raw byte string rather than a DER OCTET STRING.
			value = []byte{0xDE, 0xAD}
		} else {
			value, err = MarshalAAGUIDExtensionValue(aaguid)
			require.NoError(t, err)
		}

		template.ExtraExtensions = []pkix.Extension{{
			Id:       OIDFIDOGenCEAAGUID,
			Critical: opts.criticalAAGUID,
			Value:    value,
		}}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, publicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

// newTestAuthData builds authenticator data carrying attested credential data
// with the given AAGUID, which is the shape MakeCredential produces.
func newTestAuthData(aaguid []byte) []byte {
	authData := make([]byte, 0, 53)
	authData = append(authData, make([]byte, 32)...)                     // RP ID hash
	authData = append(authData, authDataFlagAttestedCredentialData|0x01) // AT | UP
	authData = append(authData, 0x00, 0x00, 0x00, 0x01)                  // signature counter
	authData = append(authData, aaguid...)                               // AAGUID
	return authData
}

func TestValidateAttestationCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("accepts a conformant certificate", func(t *testing.T) {
		cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{})

		require.NoError(t, ValidateAttestationCertificate(cert, testAAGUID))
	})

	t.Run("accepts a certificate with no AAGUID extension", func(t *testing.T) {
		// §8.2.1 only requires the extension when the attestation root
		// certifies more than one authenticator model.
		cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{omitAAGUID: true})

		require.NoError(t, ValidateAttestationCertificate(cert, testAAGUID))
	})

	t.Run("rejects a nil certificate", func(t *testing.T) {
		require.ErrorIs(t, ValidateAttestationCertificate(nil, testAAGUID), ErrNoAttestationCertificate)
	})

	t.Run("rejects a subject with no country", func(t *testing.T) {
		cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{omitCountry: true})

		require.ErrorIs(t, ValidateAttestationCertificate(cert, testAAGUID), ErrAttestationCertInvalid)
	})

	t.Run("rejects a subject with no organization", func(t *testing.T) {
		cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{omitOrganization: true})

		require.ErrorIs(t, ValidateAttestationCertificate(cert, testAAGUID), ErrAttestationCertInvalid)
	})

	t.Run("rejects the wrong organizational unit", func(t *testing.T) {
		cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{wrongOU: true})

		require.ErrorIs(t, ValidateAttestationCertificate(cert, testAAGUID), ErrAttestationCertInvalid)
	})

	t.Run("rejects a CA certificate", func(t *testing.T) {
		cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{isCA: true})

		require.ErrorIs(t, ValidateAttestationCertificate(cert, testAAGUID), ErrAttestationCertInvalid)
	})

	t.Run("rejects a critical AAGUID extension", func(t *testing.T) {
		cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{criticalAAGUID: true})

		require.ErrorIs(t, ValidateAttestationCertificate(cert, testAAGUID), ErrAttestationCertInvalid)
	})

	t.Run("rejects a malformed AAGUID extension", func(t *testing.T) {
		cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{malformedAAGUID: true})

		require.ErrorIs(t, ValidateAttestationCertificate(cert, testAAGUID), ErrAttestationCertInvalid)
	})

	t.Run("rejects an AAGUID of the wrong length", func(t *testing.T) {
		shortAAGUID := []byte{0x01, 0x02, 0x03}
		value, marshalErr := asn1.Marshal(shortAAGUID)
		require.NoError(t, marshalErr)
		cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{omitAAGUID: true})
		cert.Extensions = append(cert.Extensions, pkix.Extension{Id: OIDFIDOGenCEAAGUID, Value: value})

		require.ErrorIs(t, ValidateAttestationCertificate(cert, testAAGUID), ErrAttestationCertInvalid)
	})

	t.Run("rejects an AAGUID that vouches for another model", func(t *testing.T) {
		other := make([]byte, aaguidSize)
		other[0] = 0xFF
		cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{aaguid: other})

		require.ErrorIs(t, ValidateAttestationCertificate(cert, testAAGUID), ErrAttestationAAGUIDMismatch)
	})

	t.Run("skips the AAGUID comparison when none is supplied", func(t *testing.T) {
		other := make([]byte, aaguidSize)
		other[0] = 0xFF
		cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{aaguid: other})

		require.NoError(t, ValidateAttestationCertificate(cert, nil))
	})
}

func TestMarshalAAGUIDExtensionValue(t *testing.T) {
	t.Run("encodes a 16-byte AAGUID as a DER OCTET STRING", func(t *testing.T) {
		value, err := MarshalAAGUIDExtensionValue(testAAGUID)

		require.NoError(t, err)
		require.Equal(t, byte(0x04), value[0], "must be an OCTET STRING")
		require.Equal(t, byte(aaguidSize), value[1])
		require.Equal(t, testAAGUID, value[2:])
	})

	t.Run("rejects an AAGUID of the wrong length", func(t *testing.T) {
		_, err := MarshalAAGUIDExtensionValue([]byte{0x01})

		require.ErrorIs(t, err, ErrAttestationCertInvalid)
	})
}

func TestPackedAttestationStatement(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{})
	authData := newTestAuthData(testAAGUID)
	clientDataHash := make([]byte, 32)

	t.Run("produces a verifiable statement", func(t *testing.T) {
		stmt, err := PackedAttestationStatement(key, []*x509.Certificate{cert}, authData, clientDataHash)

		require.NoError(t, err)
		require.Equal(t, AttestationFormatPacked, stmt.Format)
		require.Equal(t, COSEAlgES256, stmt.Algorithm)
		require.NotEmpty(t, stmt.Signature)
		require.Len(t, stmt.CertificateChain, 1)

		signed := append(append([]byte{}, authData...), clientDataHash...)
		digest := sha256.Sum256(signed)
		require.True(t, ecdsa.VerifyASN1(cert.PublicKey.(*ecdsa.PublicKey), digest[:], stmt.Signature))
	})

	t.Run("rejects a nil signer", func(t *testing.T) {
		_, err := PackedAttestationStatement(nil, []*x509.Certificate{cert}, authData, clientDataHash)

		require.ErrorIs(t, err, ErrNoAttestationKey)
	})

	t.Run("rejects an empty chain rather than self-attesting", func(t *testing.T) {
		_, err := PackedAttestationStatement(key, nil, authData, clientDataHash)

		require.ErrorIs(t, err, ErrNoAttestationCertificate)
	})

	t.Run("rejects a certificate issued for another key", func(t *testing.T) {
		strangerKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, keyErr)

		_, err := PackedAttestationStatement(strangerKey, []*x509.Certificate{cert}, authData, clientDataHash)

		require.ErrorIs(t, err, ErrAttestationKeyMismatch)
	})

	t.Run("rejects authenticator data with no attested credential data", func(t *testing.T) {
		bare := make([]byte, 37)

		_, err := PackedAttestationStatement(key, []*x509.Certificate{cert}, bare, clientDataHash)

		require.ErrorIs(t, err, ErrAttestationAuthDataInvalid)
	})

	t.Run("rejects authenticator data truncated before the AAGUID", func(t *testing.T) {
		truncated := newTestAuthData(testAAGUID)[:40]

		_, err := PackedAttestationStatement(key, []*x509.Certificate{cert}, truncated, clientDataHash)

		require.ErrorIs(t, err, ErrAttestationAuthDataInvalid)
	})

	t.Run("rejects a certificate vouching for another AAGUID", func(t *testing.T) {
		other := make([]byte, aaguidSize)
		other[0] = 0xFF

		_, err := PackedAttestationStatement(key, []*x509.Certificate{cert}, newTestAuthData(other), clientDataHash)

		require.ErrorIs(t, err, ErrAttestationAAGUIDMismatch)
	})

	t.Run("rejects an unsupported key algorithm", func(t *testing.T) {
		// An Ed25519 attestation key has no COSE ECDSA algorithm mapping, and a
		// statement whose alg cannot be stated is not a statement.
		_, edKey, keyErr := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, keyErr)
		edCert := newTestAttestationCert(t, edKey.Public(), attestationCertOptions{})

		_, err := PackedAttestationStatement(edKey, []*x509.Certificate{edCert}, authData, clientDataHash)

		require.ErrorIs(t, err, ErrUnsupportedAttestationKey)
	})
}

// refusingSigner is an attestation key whose device refuses to sign, as an
// HSM or token does when it is locked or removed mid-ceremony.
type refusingSigner struct {
	*ecdsa.PrivateKey
}

func (s refusingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errSignerRefused
}

var errSignerRefused = errors.New("signer refused")

// wrongKeySigner reports one public key but signs with another, so its
// signatures are well-formed ECDSA that the certified key does not verify.
type wrongKeySigner struct {
	*ecdsa.PrivateKey
	signsWith *ecdsa.PrivateKey
}

func (s wrongKeySigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signsWith.Sign(r, digest, opts)
}

func TestPackedAttestationStatement_RefusesBrokenInputs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{})
	authData := newTestAuthData(testAAGUID)
	clientDataHash := make([]byte, 32)

	t.Run("rejects a chain whose leaf is nil", func(t *testing.T) {
		_, err := PackedAttestationStatement(key, []*x509.Certificate{nil}, authData, clientDataHash)

		require.ErrorIs(t, err, ErrNoAttestationCertificate)
	})

	t.Run("rejects full-length authenticator data without the AT flag", func(t *testing.T) {
		noAT := newTestAuthData(testAAGUID)
		noAT[32] &^= authDataFlagAttestedCredentialData

		_, err := PackedAttestationStatement(key, []*x509.Certificate{cert}, noAT, clientDataHash)

		require.ErrorIs(t, err, ErrAttestationAuthDataInvalid)
	})

	t.Run("reports a signer that refuses as a signing failure", func(t *testing.T) {
		_, err := PackedAttestationStatement(refusingSigner{key}, []*x509.Certificate{cert}, authData, clientDataHash)

		require.ErrorIs(t, err, ErrSigningFailed)
		require.ErrorIs(t, err, errSignerRefused, "the device's own error must stay reachable")
	})

	t.Run("refuses a signature the leaf certificate does not verify", func(t *testing.T) {
		other, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, keyErr)

		_, err := PackedAttestationStatement(wrongKeySigner{PrivateKey: key, signsWith: other}, []*x509.Certificate{cert}, authData, clientDataHash)

		require.ErrorIs(t, err, ErrAttestationSignatureInvalid)
	})
}

func TestValidateAttestationCertificate_StructuralRequirements(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{})

	t.Run("rejects a certificate that is not X.509 v3", func(t *testing.T) {
		v1 := *cert
		v1.Version = 1

		err := ValidateAttestationCertificate(&v1, testAAGUID)

		require.ErrorIs(t, err, ErrAttestationCertInvalid)
	})

	t.Run("rejects trailing data after the AAGUID OCTET STRING", func(t *testing.T) {
		value, marshalErr := MarshalAAGUIDExtensionValue(testAAGUID)
		require.NoError(t, marshalErr)
		trailing := *cert
		trailing.Extensions = []pkix.Extension{{
			Id:    OIDFIDOGenCEAAGUID,
			Value: append(value, 0x00),
		}}

		err := ValidateAttestationCertificate(&trailing, testAAGUID)

		require.ErrorIs(t, err, ErrAttestationCertInvalid)
	})
}

func TestAttestingBackend(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := newTestAttestationCert(t, key.Public(), attestationCertOptions{})

	newBackend := func(source AttestationKeySource) *AttestingBackend {
		inner := newMockBackend("software", FIDO2KeyCapabilities{
			SupportedAlgorithms: []int{COSEAlgES256},
			SupportsExport:      true,
		})
		return NewAttestingBackend(inner, source)
	}

	t.Run("claims attestation support", func(t *testing.T) {
		backend := newBackend(&stubAttestationSource{signer: key, chain: []*x509.Certificate{cert}})

		caps := backend.Capabilities()

		require.True(t, caps.SupportsAttestation)
		require.True(t, caps.SupportsExport, "inner capabilities must be preserved")
	})

	t.Run("produces a packed statement", func(t *testing.T) {
		backend := newBackend(&stubAttestationSource{signer: key, chain: []*x509.Certificate{cert}})

		stmt, err := backend.GetAttestationStatement(AttestationFormatPacked, newTestAuthData(testAAGUID), make([]byte, 32))

		require.NoError(t, err)
		require.Equal(t, AttestationFormatPacked, stmt.Format)
	})

	t.Run("reports unsupported formats rather than improvising", func(t *testing.T) {
		backend := newBackend(&stubAttestationSource{signer: key, chain: []*x509.Certificate{cert}})

		_, err := backend.GetAttestationStatement("tpm", newTestAuthData(testAAGUID), make([]byte, 32))

		require.ErrorIs(t, err, ErrAttestationNotSupported)
	})

	t.Run("propagates an unprovisioned device", func(t *testing.T) {
		backend := newBackend(&stubAttestationSource{signerErr: ErrNoAttestationKey})

		_, err := backend.GetAttestationStatement(AttestationFormatPacked, newTestAuthData(testAAGUID), make([]byte, 32))

		require.ErrorIs(t, err, ErrNoAttestationKey)
	})

	t.Run("propagates a missing certificate chain", func(t *testing.T) {
		backend := newBackend(&stubAttestationSource{signer: key, chainErr: ErrNoAttestationCertificate})

		_, err := backend.GetAttestationStatement(AttestationFormatPacked, newTestAuthData(testAAGUID), make([]byte, 32))

		require.ErrorIs(t, err, ErrNoAttestationCertificate)
	})

	t.Run("generates an attestation key and returns its COSE public key", func(t *testing.T) {
		backend := newBackend(&stubAttestationSource{signer: key})

		handle, publicKeyCOSE, err := backend.GenerateAttestationKey()

		require.NoError(t, err)
		require.Equal(t, COSEAlgES256, handle.Algorithm())
		require.Nil(t, handle.CredentialID(), "the attestation key is not a credential")
		require.Equal(t, xkms.BackendType("software"), handle.BackendID())
		require.NotEmpty(t, publicKeyCOSE)
	})

	t.Run("propagates a key generation failure", func(t *testing.T) {
		sentinel := errors.New("hardware refused")
		backend := newBackend(&stubAttestationSource{generateErr: sentinel})

		_, _, err := backend.GenerateAttestationKey()

		require.ErrorIs(t, err, sentinel)
	})

	t.Run("rejects a generated key with no COSE algorithm mapping", func(t *testing.T) {
		_, edKey, keyErr := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, keyErr)
		backend := newBackend(&stubAttestationSource{signer: edKey})

		_, _, err := backend.GenerateAttestationKey()

		require.ErrorIs(t, err, ErrUnsupportedAttestationKey)
	})

	t.Run("returns the provisioned chain", func(t *testing.T) {
		backend := newBackend(&stubAttestationSource{signer: key, chain: []*x509.Certificate{cert}})

		chain, err := backend.AttestationCertificateChain()

		require.NoError(t, err)
		require.Len(t, chain, 1)
	})
}

func TestAttestationStatement_NilSource(t *testing.T) {
	_, err := AttestationStatement(nil, AttestationFormatPacked, newTestAuthData(testAAGUID), make([]byte, 32))

	require.ErrorIs(t, err, ErrNoAttestationKey)
}
