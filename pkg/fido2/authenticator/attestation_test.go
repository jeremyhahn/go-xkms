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

package authenticator

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator/keybackend"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// testAttestationCA is a minimal stand-in for the attestation PKI an operator
// runs: a root, an optional intermediate, and the ability to issue attestation
// certificates that meet the WebAuthn Level 2 §8.2.1 requirements.
type testAttestationCA struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey

	intermediateCert *x509.Certificate
	intermediateKey  *ecdsa.PrivateKey
}

// newTestAttestationCA builds a root, and an intermediate when withIntermediate
// is set, so tests can cover both a direct issuance and a real chain.
func newTestAttestationCA(t *testing.T, withIntermediate bool) *testAttestationCA {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xkey Test Attestation Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	ca := &testAttestationCA{rootCert: rootCert, rootKey: rootKey}
	if !withIntermediate {
		return ca
	}

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "xkey Test Attestation Issuing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, intermediateKey.Public(), rootKey)
	require.NoError(t, err)
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	require.NoError(t, err)

	ca.intermediateCert = intermediateCert
	ca.intermediateKey = intermediateKey

	return ca
}

// issuer returns the certificate and key that sign attestation leaves.
func (ca *testAttestationCA) issuer() (*x509.Certificate, *ecdsa.PrivateKey) {
	if ca.intermediateCert != nil {
		return ca.intermediateCert, ca.intermediateKey
	}
	return ca.rootCert, ca.rootKey
}

// intermediates returns the DER intermediates that belong in x5c after the
// leaf, excluding the root.
func (ca *testAttestationCA) intermediates() [][]byte {
	if ca.intermediateCert == nil {
		return nil
	}
	return [][]byte{ca.intermediateCert.Raw}
}

// issueAttestationCert issues a §8.2.1-conformant attestation certificate for
// publicKey, binding it to aaguid through the id-fido-gen-ce-aaguid extension.
func (ca *testAttestationCA) issueAttestationCert(t *testing.T, publicKey crypto.PublicKey, aaguid []byte) []byte {
	t.Helper()

	extensionValue, err := keybackend.MarshalAAGUIDExtensionValue(aaguid)
	require.NoError(t, err)

	issuerCert, issuerKey := ca.issuer()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Automate The Things, LLC"},
			OrganizationalUnit: []string{keybackend.AttestationCertificateOU},
			CommonName:         "xkey FIDO2 Attestation",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{{
			Id:       keybackend.OIDFIDOGenCEAAGUID,
			Critical: false,
			Value:    extensionValue,
		}},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuerCert, publicKey, issuerKey)
	require.NoError(t, err)

	return der
}

// verifyChain checks that a leaf-first x5c chains to this CA's root, which is
// the check a relying party runs against its configured attestation roots.
func (ca *testAttestationCA) verifyChain(t *testing.T, x5c [][]byte) {
	t.Helper()
	require.NotEmpty(t, x5c)

	leaf, err := x509.ParseCertificate(x5c[0])
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(ca.rootCert)

	intermediates := x509.NewCertPool()
	for _, der := range x5c[1:] {
		cert, parseErr := x509.ParseCertificate(der)
		require.NoError(t, parseErr)
		intermediates.AddCert(cert)
	}

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// Attestation certificates carry no EKU; accepting any keeps the check
		// to what actually matters here, which is path building to the root.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	require.NoError(t, err)
}

// provisionAttestation walks the real Security Officer provisioning path:
// generate a device attestation key, take its CSR, have the CA certify it and
// install the resulting chain.
func provisionAttestation(t *testing.T, auth *Authenticator, ca *testAttestationCA) {
	t.Helper()

	require.NoError(t, auth.keyManager.InitializeSOPIN("securepin123"))

	signer, err := auth.attestation.GenerateAttestationKey()
	require.NoError(t, err)

	csrDER, err := auth.AttestationCSR()
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature())
	require.Contains(t, csr.Subject.OrganizationalUnit, keybackend.AttestationCertificateOU)

	leafDER := ca.issueAttestationCert(t, csr.PublicKey, auth.state.AAGUID[:])
	require.NoError(t, auth.InstallAttestationCertificate(leafDER, ca.intermediates()))

	// The CA certified the key the device holds, not some other key.
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	require.True(t, leaf.PublicKey.(*ecdsa.PublicKey).Equal(signer.Public()))
}

// newAttestationTestAuthenticator creates an authenticator that requests the
// given attestation format.
func newAttestationTestAuthenticator(t *testing.T, format string) *Authenticator {
	t.Helper()

	auth, err := NewAuthenticator(&Config{
		UserPresenceHandler:    NewAutoGrantHandler(),
		Storage:                NewMemoryStorage(),
		SupportedAlgorithms:    []int{COSEAlgES256},
		MaxCredentials:         100,
		MaxResidentCredentials: 25,
		PINMinLength:           4,
		PINMaxRetries:          8,
		AttestationFormat:      format,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })

	return auth
}

// makeAttestationTestCredential runs a registration and returns the response.
func makeAttestationTestCredential(t *testing.T, auth *Authenticator) *MakeCredentialResponse {
	t.Helper()

	clientDataHash := make([]byte, ClientDataHashSize)
	for i := range clientDataHash {
		clientDataHash[i] = byte(i)
	}

	resp, err := auth.MakeCredential(
		clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		User{ID: []byte("user-123"), Name: "test@example.com"},
		[]PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}},
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, resp)

	return resp
}

// TestMakeCredential_PackedAttestation is the acceptance test for issue #218:
// a device with a Security Officer-installed attestation key registers with
// fmt "packed", a non-empty x5c, a signature that verifies over
// authData ‖ clientDataHash against the leaf, and a chain that verifies to the
// issuing root.
func TestMakeCredential_PackedAttestation(t *testing.T) {
	for _, tc := range []struct {
		name             string
		withIntermediate bool
		expectedX5CLen   int
	}{
		{name: "issued directly by the root", withIntermediate: false, expectedX5CLen: 1},
		{name: "issued through an intermediate", withIntermediate: true, expectedX5CLen: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := newTestAttestationCA(t, tc.withIntermediate)
			auth := newAttestationTestAuthenticator(t, AttestationFormatPacked)
			provisionAttestation(t, auth, ca)

			clientDataHash := make([]byte, ClientDataHashSize)
			for i := range clientDataHash {
				clientDataHash[i] = byte(i)
			}

			resp, err := auth.MakeCredential(
				clientDataHash,
				RelyingParty{ID: "example.com", Name: "Example"},
				User{ID: []byte("user-123"), Name: "test@example.com"},
				[]PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}},
				nil,
			)
			require.NoError(t, err)
			require.Equal(t, AttestationFormatPacked, resp.Fmt)
			require.Equal(t, COSEAlgES256, resp.AttStmt["alg"])

			x5c, ok := resp.AttStmt["x5c"].([][]byte)
			require.True(t, ok, "packed attestation must carry x5c")
			require.Len(t, x5c, tc.expectedX5CLen)

			// §8.2 step 1: the signature verifies over authData ‖ clientDataHash
			// with the public key in the leaf certificate.
			leaf, err := x509.ParseCertificate(x5c[0])
			require.NoError(t, err)

			signature, ok := resp.AttStmt["sig"].([]byte)
			require.True(t, ok)
			require.NotEmpty(t, signature)

			signedData := append(append([]byte{}, resp.AuthData...), clientDataHash...)
			digest := sha256Sum(signedData)
			require.True(t,
				ecdsa.VerifyASN1(leaf.PublicKey.(*ecdsa.PublicKey), digest, signature),
				"attestation signature must verify over authData || clientDataHash")

			// §8.2 step 3: the AAGUID the certificate vouches for is the AAGUID
			// in the authenticator data.
			require.Equal(t, auth.state.AAGUID[:], resp.AuthData[37:53])

			ca.verifyChain(t, x5c)
		})
	}
}

// TestMakeCredential_PackedAttestationWithoutProvisioning proves an
// unprovisioned device still registers. Requiring provisioning would lock every
// device out of registration until a Security Officer reached it.
func TestMakeCredential_PackedAttestationWithoutProvisioning(t *testing.T) {
	auth := newAttestationTestAuthenticator(t, AttestationFormatPacked)

	resp := makeAttestationTestCredential(t, auth)

	require.Equal(t, AttestationFormatNone, resp.Fmt)
	require.Empty(t, resp.AttStmt)
}

// TestMakeCredential_PackedAttestationKeyWithoutCertificate covers the window
// between generating an attestation key and having it certified: there is a key
// but nothing vouches for it, so the device must not present a chainless packed
// statement.
func TestMakeCredential_PackedAttestationKeyWithoutCertificate(t *testing.T) {
	auth := newAttestationTestAuthenticator(t, AttestationFormatPacked)
	require.NoError(t, auth.keyManager.InitializeSOPIN("securepin123"))

	_, err := auth.attestation.GenerateAttestationKey()
	require.NoError(t, err)

	resp := makeAttestationTestCredential(t, auth)

	require.Equal(t, AttestationFormatNone, resp.Fmt)
	require.Empty(t, resp.AttStmt)
}

// TestSerializedState_ContainsNoPlaintextAttestationKey is the negative control
// for the wrapped-only design: no representation of the attestation private key
// may appear in the serialized state. The FIDO2 store is barrier-encrypted only
// when a barrier is active and falls back to a plain file otherwise, so a
// plaintext key in this state would be a plaintext key on disk.
func TestSerializedState_ContainsNoPlaintextAttestationKey(t *testing.T) {
	auth := newAttestationTestAuthenticator(t, AttestationFormatPacked)
	require.NoError(t, auth.keyManager.InitializeSOPIN("securepin123"))

	// Install a key whose bytes the test knows, so the search below looks for
	// this exact secret rather than for a shape.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, auth.keyManager.WrapAttestationKey(protectedBytes(t, pkcs8)))

	serializable, err := stateToSerializable(auth.state)
	require.NoError(t, err)

	encoded, err := json.Marshal(serializable)
	require.NoError(t, err)

	// The wrapped copies must be there — this is not an "everything is empty"
	// pass — and the private scalar must not be, in any encoding the state uses.
	require.NotEmpty(t, serializable.WrappedAttestSO)
	require.NotEmpty(t, serializable.WrappedAttestUser)

	// PrivateKey.Bytes gives the fixed-width big-endian scalar -- the same
	// encoding SEC 1 puts inside the PKCS#8 wrapper above, so it is the needle
	// a leak would actually contain. (key.D is deprecated as of Go 1.26.)
	scalar, err := key.Bytes()
	require.NoError(t, err)
	for name, needle := range map[string][]byte{
		"PKCS#8 DER":     pkcs8,
		"private scalar": scalar,
	} {
		require.False(t, bytes.Contains(encoded, needle),
			"the serialized state must not contain the attestation key's %s", name)
		require.False(t, bytes.Contains([]byte(base64.StdEncoding.EncodeToString(encoded)), needle),
			"the serialized state must not contain the attestation key's %s", name)
	}

	// Belt and braces: the same search over the raw JSON decoded from base64
	// fields, which is how []byte reaches the wire.
	require.False(t, bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(pkcs8))),
		"the serialized state must not contain the base64 of the attestation key")
	require.False(t, bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(scalar))),
		"the serialized state must not contain the base64 of the private scalar")
}

// TestMakeCredential_PackedAttestationAfterRestart is the positive control for
// availability: a provisioned identity survives serialization and a reload, and
// attestation resumes once the key hierarchy is unlocked.
//
// Before that unlock the device registers with "none". That is the fail-closed
// half of the design: the attestation key exists only as wrapped copies, so a
// device that has not been unlocked since boot cannot sign with it and does not
// pretend otherwise.
func TestMakeCredential_PackedAttestationAfterRestart(t *testing.T) {
	ca := newTestAttestationCA(t, true)
	dir := t.TempDir()

	newAuth := func() *Authenticator {
		backend, err := xkms.NewFileStorageBackend(dir)
		require.NoError(t, err)

		storage, err := NewBackendStorage(backend, "xkey/")
		require.NoError(t, err)
		storage.WaitForIndex()

		auth, err := NewAuthenticator(&Config{
			UserPresenceHandler:    NewAutoGrantHandler(),
			Storage:                storage,
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         100,
			MaxResidentCredentials: 25,
			PINMinLength:           4,
			PINMaxRetries:          8,
			AttestationFormat:      AttestationFormatPacked,
		})
		require.NoError(t, err)
		return auth
	}

	auth := newAuth()
	provisionAttestation(t, auth, ca)
	require.NoError(t, auth.storage.SaveState(auth.state))
	require.NoError(t, auth.Close())

	// A second authenticator over the same files models a restart.
	restarted := newAuth()
	defer func() { _ = restarted.Close() }()
	require.False(t, restarted.keyManager.IsUnlocked())

	// The identity survived: the wrapped key and the full chain are both back.
	require.NotEmpty(t, restarted.state.WrappedAttestSO)
	require.NotEmpty(t, restarted.state.AttestationCert)
	require.Len(t, restarted.state.AttestationCertChain, 1, "intermediates must survive the reload")

	// Locked: fail closed to "none" rather than sign with a key it cannot reach.
	locked := makeAttestationTestCredential(t, restarted)
	require.Equal(t, AttestationFormatNone, locked.Fmt)
	require.Empty(t, locked.AttStmt)

	// Unlocked: the same identity attests again, and still chains to the root.
	require.NoError(t, restarted.keyManager.UnlockWithSOPIN("securepin123"))

	resp := makeAttestationTestCredential(t, restarted)
	require.Equal(t, AttestationFormatPacked, resp.Fmt)

	x5c, ok := resp.AttStmt["x5c"].([][]byte)
	require.True(t, ok)
	require.Len(t, x5c, 2)
	ca.verifyChain(t, x5c)
}

// TestInstallAttestationCertificate_Rejections proves provisioning fails closed:
// a certificate that a relying party would reject never reaches the device.
func TestInstallAttestationCertificate_Rejections(t *testing.T) {
	otherAAGUID := [16]byte{0xAA, 0xBB, 0xCC, 0xDD}

	t.Run("rejects malformed DER", func(t *testing.T) {
		auth := newAttestationTestAuthenticator(t, AttestationFormatPacked)
		require.NoError(t, auth.keyManager.InitializeSOPIN("securepin123"))

		err := auth.InstallAttestationCertificate([]byte{0x01, 0x02, 0x03}, nil)

		require.ErrorIs(t, err, ErrAttestationChainInvalid)
	})

	t.Run("rejects a certificate issued for another key", func(t *testing.T) {
		ca := newTestAttestationCA(t, false)
		auth := newAttestationTestAuthenticator(t, AttestationFormatPacked)
		require.NoError(t, auth.keyManager.InitializeSOPIN("securepin123"))
		_, err := auth.attestation.GenerateAttestationKey()
		require.NoError(t, err)

		strangerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		leafDER := ca.issueAttestationCert(t, strangerKey.Public(), auth.state.AAGUID[:])

		err = auth.InstallAttestationCertificate(leafDER, nil)

		require.ErrorIs(t, err, ErrAttestationCertNotIssuedForKey)
	})

	t.Run("rejects a certificate vouching for another AAGUID", func(t *testing.T) {
		ca := newTestAttestationCA(t, false)
		auth := newAttestationTestAuthenticator(t, AttestationFormatPacked)
		require.NoError(t, auth.keyManager.InitializeSOPIN("securepin123"))
		signer, err := auth.attestation.GenerateAttestationKey()
		require.NoError(t, err)

		leafDER := ca.issueAttestationCert(t, signer.Public(), otherAAGUID[:])

		err = auth.InstallAttestationCertificate(leafDER, nil)

		require.ErrorIs(t, err, keybackend.ErrAttestationAAGUIDMismatch)
	})

	t.Run("rejects an out-of-order intermediate", func(t *testing.T) {
		ca := newTestAttestationCA(t, true)
		unrelated := newTestAttestationCA(t, true)
		auth := newAttestationTestAuthenticator(t, AttestationFormatPacked)
		require.NoError(t, auth.keyManager.InitializeSOPIN("securepin123"))
		signer, err := auth.attestation.GenerateAttestationKey()
		require.NoError(t, err)

		leafDER := ca.issueAttestationCert(t, signer.Public(), auth.state.AAGUID[:])

		err = auth.InstallAttestationCertificate(leafDER, unrelated.intermediates())

		require.ErrorIs(t, err, ErrAttestationChainInvalid)
	})

	t.Run("rejects a certificate with no attestation key installed", func(t *testing.T) {
		ca := newTestAttestationCA(t, false)
		auth := newAttestationTestAuthenticator(t, AttestationFormatPacked)

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		leafDER := ca.issueAttestationCert(t, key.Public(), auth.state.AAGUID[:])

		err = auth.InstallAttestationCertificate(leafDER, nil)

		require.ErrorIs(t, err, keybackend.ErrNoAttestationKey)
	})
}

// TestGenerateAttestationKey_DiscardsPreviousCertificate proves a rotation does
// not leave a certificate behind that vouches for a key the device no longer
// holds.
func TestGenerateAttestationKey_DiscardsPreviousCertificate(t *testing.T) {
	ca := newTestAttestationCA(t, false)
	auth := newAttestationTestAuthenticator(t, AttestationFormatPacked)
	provisionAttestation(t, auth, ca)
	require.NotEmpty(t, auth.state.AttestationCert)

	_, err := auth.attestation.GenerateAttestationKey()
	require.NoError(t, err)

	require.Empty(t, auth.state.AttestationCert)
	require.Empty(t, auth.state.AttestationCertChain)

	resp := makeAttestationTestCredential(t, auth)
	require.Equal(t, AttestationFormatNone, resp.Fmt)
}

// TestAttestationCSR_RequiresAKey proves the CSR path reports an unprovisioned
// device rather than emitting a request for a key that does not exist.
func TestAttestationCSR_RequiresAKey(t *testing.T) {
	auth := newAttestationTestAuthenticator(t, AttestationFormatPacked)

	_, err := auth.AttestationCSR()

	require.ErrorIs(t, err, keybackend.ErrNoAttestationKey)
}

// TestAttestationCertificateChain_ReportsCorruption proves a state whose stored
// certificate cannot be parsed is reported rather than silently skipped.
func TestAttestationCertificateChain_ReportsCorruption(t *testing.T) {
	auth := newAttestationTestAuthenticator(t, AttestationFormatPacked)
	auth.state.AttestationCert = []byte{0x30, 0x00}

	_, err := auth.attestation.AttestationCertificateChain()

	require.ErrorIs(t, err, ErrAttestationChainInvalid)
}

// sha256Sum returns the SHA-256 digest of data.
func sha256Sum(data []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(data)
	return h.Sum(nil)
}
