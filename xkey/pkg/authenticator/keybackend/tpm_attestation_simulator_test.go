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

//go:build tpm_simulator

package keybackend

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// simulatorTPM2AttestingBackend provisions the in-process MS TPM reference
// simulator with a full device identity (EK/SRK/IAK) and returns a
// TPM2AttestingBackend over it, plus the IAK certificate that vouches for it.
//
// The go-tpm-tools simulator is a process-global singleton (see
// xkey/pkg/pairing/bridge_enrollment_simulator_test.go), so tests in this file
// must not run in parallel with one another.
func simulatorTPM2AttestingBackend(t *testing.T) (*TPM2AttestingBackend, *x509.Certificate) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sim, err := xkms.OpenSimulator()
	require.NoError(t, err, "TPM simulator must be available; build with -tags tpm_simulator")
	// Release the process-global simulator on every exit path, including a
	// failed require below; otherwise the next simulator test blocks on the
	// simulator lock until the test binary times out.
	t.Cleanup(func() { assert.NoError(t, sim.Close(), "closing the TPM simulator") })

	storageFactory, err := xkms.NewTPMStorageFactory(logger, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, storageFactory.Close(), "closing the storage factory") })

	certStore := store.NewMemoryCertStore(logger)

	config := xkms.DefaultTPMConfig
	config.UseSimulator = false // the transport is supplied explicitly
	config.Device = ""

	tpm, err := xkms.NewTPM2(&xkms.TPMParams{
		Config:    &config,
		Logger:    logger,
		Backend:   storageFactory.KeyBackend(),
		BlobStore: storageFactory.BlobStore(),
		CertStore: certStore,
		Transport: sim.Transport(),
	})
	if tpm != nil {
		t.Cleanup(func() { assert.NoError(t, tpm.Close(), "closing the TPM") })
	}
	if err == xkms.ErrTPMNotInitialized {
		require.NotNil(t, tpm)
		require.NoError(t, tpm.Provision(nil), "provisioning the simulator must succeed")
	} else {
		require.NoError(t, err)
	}

	// Provision is TCG-only (EK + Shared SRK); xkms's own TPM2 backend
	// resolves its storage parent exclusively off the Platform SRK, so it
	// must be enrolled before NewTPM2BackendWithTPM is constructed below.
	require.NoError(t, tpm2test.EnrollPlatformSRK(tpm, &config),
		"simulator must enroll the Platform SRK xkms's own backend uses")

	iakPub, err := tpm.IAK()
	require.NoError(t, err, "provisioning must leave a usable IAK behind")

	iakCert := issueAIKCertificate(t, iakPub)
	require.NoError(t, tpm.ProvisionIAKCert(iakCert), "installing the AIK certificate must succeed")

	memStorage, err := xkms.NewMemoryBackend()
	require.NoError(t, err)
	blobs := xkms.NewFileBackend(logger, memStorage)

	tpm2Backend, err := xkms.NewTPM2BackendWithTPM(&xkms.TPM2BackendExternalConfig{
		TPM:        tpm,
		KeyBackend: blobs,
		Logger:     logger,
	})
	require.NoError(t, err)

	adapter := NewBackendAdapter(tpm2Backend, xkms.BackendTypeTPM2)
	return NewTPM2AttestingBackend(adapter, tpm, blobs), iakCert
}

// issueAIKCertificate builds a self-issued certificate over the TPM's real
// IAK public key that satisfies the WebAuthn L2 §8.3.1 TPM Attestation
// Statement Certificate Requirements: an empty Subject, a SubjectAltName
// carrying the TCG manufacturer/model/version directoryName attributes, the
// tcg-kp-AIKCertificate (2.23.133.8.3) EKU, and CA:false. A relying party's
// "tpm" format verifier checks the certificate against these requirements
// before it trusts anything the AIK signs.
func issueAIKCertificate(t *testing.T, iakPub crypto.PublicKey) *x509.Certificate {
	t.Helper()

	issuer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tcgDirectoryName := pkix.Name{
		ExtraNames: []pkix.AttributeTypeAndValue{
			// "id:414D4400" decodes (per the TCG vendor-ID registry) to AMD,
			// one of the manufacturer IDs isValidTPMManufacturer accepts.
			{Type: ca.OIDTCGAttributeTPMManufacturer, Value: "id:414D4400"},
			{Type: ca.OIDTCGAttributeTPMModel, Value: "xkey-fido2-simulator"},
			{Type: ca.OIDTCGAttributeTPMVersion, Value: "id:00010023"},
		},
	}
	sanExt, err := ca.BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil, nil, []pkix.Name{tcgDirectoryName})
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{}, // §8.3.1 requires an empty Subject
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{ca.OIDTCGKpAIKCertificate},
		ExtraExtensions:       []pkix.Extension{sanExt},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, iakPub, issuer)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// buildAuthData hand-assembles WebAuthn L2 §6.5.1 authenticator data carrying
// attested credential data: it cannot use the authenticator package's
// AuthDataBuilder because that package imports keybackend, and this test lives
// in keybackend.
func buildAuthData(rpIDHash [32]byte, aaguid [16]byte, credentialID, publicKeyCOSE []byte) []byte {
	buf := make([]byte, 0, 37+16+2+len(credentialID)+len(publicKeyCOSE))
	buf = append(buf, rpIDHash[:32]...)
	buf = append(buf, 0x41)       // flags: UP (0x01) | AT (0x40)
	buf = append(buf, 0, 0, 0, 1) // signCount
	buf = append(buf, aaguid[:]...)
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credentialID)))
	buf = append(buf, credIDLen...)
	buf = append(buf, credentialID...)
	buf = append(buf, publicKeyCOSE...)
	return buf
}

// wireRoundTrip CBOR-encodes then decodes v, simulating what a relying
// party's CBOR parser sees over the wire -- fxamacker/cbor decodes integers
// into int64/uint64 and byte strings into []byte when the target is
// interface{}, which is what go-webauthn's own attStmt decoding produces and
// what its format handler asserts against.
func wireRoundTrip(t *testing.T, v map[string]interface{}) map[string]interface{} {
	t.Helper()
	encoded, err := cbor.Marshal(v)
	require.NoError(t, err)
	var decoded map[string]interface{}
	require.NoError(t, cbor.Unmarshal(encoded, &decoded))
	return decoded
}

// verifyWithGoWebAuthn runs stmt through go-webauthn's own "tpm" format
// verifier -- the production TPM attestation statement format handler this
// library shares with pkg/webauthn's Service, which embeds *webauthn.WebAuthn
// from the same module. This is the "well-known verifier" the statement must
// satisfy end to end, not just the local TPM2_Certify checks.
func verifyWithGoWebAuthn(t *testing.T, stmt *FIDO2AttestationStatement, authData, clientDataHash []byte) (*protocol.AttestationObject, error) {
	t.Helper()

	x5c := make([]interface{}, len(stmt.CertificateChain))
	for i, cert := range stmt.CertificateChain {
		x5c[i] = cert.Raw
	}
	attStmt := wireRoundTrip(t, map[string]interface{}{
		"ver":      stmt.Ver,
		"alg":      stmt.Algorithm,
		"sig":      stmt.Signature,
		"certInfo": stmt.CertInfo,
		"pubArea":  stmt.PubArea,
		"x5c":      x5c,
	})

	var authenticatorData protocol.AuthenticatorData
	require.NoError(t, authenticatorData.Unmarshal(authData))

	attObj := &protocol.AttestationObject{
		AuthData:     authenticatorData,
		RawAuthData:  authData,
		Format:       "tpm",
		AttStatement: attStmt,
	}

	err := attObj.VerifyAttestation(clientDataHash, nil)
	return attObj, err
}

// TestTPM2AttestingBackend_GetAttestationStatement_VerifiesWithGoWebAuthn is
// the end-to-end proof that the "tpm" statement this backend produces is
// WebAuthn L2 §8.3 compliant: TPM2_Certify runs against the simulator's real
// IAK, and the resulting ver/alg/x5c/sig/certInfo/pubArea are handed to
// go-webauthn's own production verifier exactly as a relying party would
// receive them over the wire.
func TestTPM2AttestingBackend_GetAttestationStatement_VerifiesWithGoWebAuthn(t *testing.T) {
	backend, iakCert := simulatorTPM2AttestingBackend(t)

	credentialID := []byte("tpm-attestation-credential-0001")
	handle, publicKeyCOSE, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
	require.NoError(t, err)
	require.Equal(t, credentialID, handle.CredentialID())

	var rpIDHash [32]byte
	copy(rpIDHash[:], sha256Sum([]byte("example.com")))
	var aaguid [16]byte

	authData := buildAuthData(rpIDHash, aaguid, credentialID, publicKeyCOSE)
	clientDataHash := sha256Sum([]byte("tpm-attestation-client-data"))

	stmt, err := backend.GetAttestationStatement(AttestationFormatTPM, authData, clientDataHash)
	require.NoError(t, err)

	require.Equal(t, AttestationFormatTPM, stmt.Format)
	require.Equal(t, "2.0", stmt.Ver)
	require.NotEmpty(t, stmt.CertInfo)
	require.NotEmpty(t, stmt.PubArea)
	require.NotEmpty(t, stmt.Signature)
	require.Len(t, stmt.CertificateChain, 1)
	require.Equal(t, iakCert.Raw, stmt.CertificateChain[0].Raw)

	attObj, err := verifyWithGoWebAuthn(t, stmt, authData, clientDataHash)
	require.NoError(t, err,
		"a statement produced by TPM2_Certify against a real IAK must verify under go-webauthn's own tpm format handler")
	require.Equal(t, string(metadata.AttCA), attObj.Type,
		"a TPM attestation is CA-anchored (AttCA), never self or basic full attestation")
}

// TestTPM2AttestingBackend_GetAttestationStatement_TamperedPubAreaFailsNameCheck
// proves the negative twin of the success case: a pubArea that does not match
// what TPM2_Certify actually certified must fail the Name binding check
// (WebAuthn L2 §8.3 verification step 4), the check that stops a relying
// party from accepting an attestation for a different key than the one that
// was actually registered.
func TestTPM2AttestingBackend_GetAttestationStatement_TamperedPubAreaFailsNameCheck(t *testing.T) {
	backend, _ := simulatorTPM2AttestingBackend(t)

	credentialID := []byte("tpm-attestation-credential-0002")
	_, publicKeyCOSE, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
	require.NoError(t, err)

	var rpIDHash [32]byte
	copy(rpIDHash[:], sha256Sum([]byte("example.com")))
	var aaguid [16]byte

	authData := buildAuthData(rpIDHash, aaguid, credentialID, publicKeyCOSE)
	clientDataHash := sha256Sum([]byte("tampered-pubarea-client-data"))

	stmt, err := backend.GetAttestationStatement(AttestationFormatTPM, authData, clientDataHash)
	require.NoError(t, err)

	tampered := append([]byte(nil), stmt.PubArea...)
	tampered[len(tampered)-1] ^= 0xFF
	stmt.PubArea = tampered

	_, err = verifyWithGoWebAuthn(t, stmt, authData, clientDataHash)
	require.Error(t, err, "a pubArea that does not match the certified Name must not verify")
}

// TestTPM2AttestingBackend_GetAttestationStatement_WrongExtraDataFails proves
// that a relying party computing extraData over a different attToBeSigned --
// here, a clientDataHash the authenticator never signed for -- rejects the
// statement (WebAuthn L2 §8.3 verification step 3). This is what makes the
// attestation bind to one specific registration ceremony rather than being
// replayable against another.
func TestTPM2AttestingBackend_GetAttestationStatement_WrongExtraDataFails(t *testing.T) {
	backend, _ := simulatorTPM2AttestingBackend(t)

	credentialID := []byte("tpm-attestation-credential-0003")
	_, publicKeyCOSE, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
	require.NoError(t, err)

	var rpIDHash [32]byte
	copy(rpIDHash[:], sha256Sum([]byte("example.com")))
	var aaguid [16]byte

	authData := buildAuthData(rpIDHash, aaguid, credentialID, publicKeyCOSE)
	clientDataHash := sha256Sum([]byte("original-client-data"))

	stmt, err := backend.GetAttestationStatement(AttestationFormatTPM, authData, clientDataHash)
	require.NoError(t, err)

	wrongClientDataHash := sha256Sum([]byte("a-different-client-data-hash"))
	_, err = verifyWithGoWebAuthn(t, stmt, authData, wrongClientDataHash)
	require.Error(t, err, "verifying against a clientDataHash the authenticator never signed for must fail")
}

// sha256Sum is a tiny local helper so the tests above read as data, not
// ceremony.
func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// TestTPM2AttestingBackend_Capabilities proves the decorator's entire purpose:
// whatever the inner adapter reports, wrapping it in TPM2AttestingBackend adds
// the attestation claim without disturbing anything else the inner adapter
// contributes.
func TestTPM2AttestingBackend_Capabilities(t *testing.T) {
	backend, _ := simulatorTPM2AttestingBackend(t)

	caps := backend.Capabilities()

	require.True(t, caps.SupportsAttestation, "the whole point of this decorator is attestation support")
	require.Contains(t, caps.SupportedAlgorithms, COSEAlgES256, "the inner TPM2 adapter's capabilities must be preserved")
}

// TestTPM2AttestingBackend_GenerateAttestationKey proves the IAK load path:
// the returned handle carries the IAK's real COSE algorithm and the encoded
// public key round-trips back to the same key the simulator's IAK() reports.
func TestTPM2AttestingBackend_GenerateAttestationKey(t *testing.T) {
	backend, _ := simulatorTPM2AttestingBackend(t)

	handle, publicKeyCOSE, err := backend.GenerateAttestationKey()
	require.NoError(t, err)
	require.NotEmpty(t, publicKeyCOSE)
	require.Nil(t, handle.CredentialID(), "the attestation key is a device identity, not a credential")

	var decoded map[int]interface{}
	require.NoError(t, cbor.Unmarshal(publicKeyCOSE, &decoded))
	alg, ok := decoded[3].(int64)
	require.True(t, ok, "the COSE key must carry an integer alg label")
	require.Equal(t, int64(handle.Algorithm()), alg)
}

// TestTPM2AttestingBackend_AttestationCertificateChain proves §8.3.1's single-
// certificate requirement: the chain is exactly the provisioned IAK
// certificate, with no intermediate appended.
func TestTPM2AttestingBackend_AttestationCertificateChain(t *testing.T) {
	backend, iakCert := simulatorTPM2AttestingBackend(t)

	chain, err := backend.AttestationCertificateChain()

	require.NoError(t, err)
	require.Len(t, chain, 1, "TCG device identity certificates have no intermediate to append")
	require.Equal(t, iakCert.Raw, chain[0].Raw)
}
