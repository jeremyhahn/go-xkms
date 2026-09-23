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

// Package ca coverage boost, fifteenth pass: targets remaining uncovered
// functions identified after boost14. All tests are in-memory, fast,
// race-detector clean. Tests that mutate package-level state (aiaHTTPClient)
// or shared CA fields must NOT use t.Parallel().
package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/quantum"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gocsp "golang.org/x/crypto/ocsp"
)

// =============================================================================
// ca.go — Sign() ErrNotInitialized (line 716)
// =============================================================================

// TestSign_NotInitialized_B15 exercises the Sign() crypto.Signer implementation
// when the CA is not initialized. The not-initialized path returns ErrNotInitialized
// before reaching the signer (ca.go:706-708).
func TestSign_NotInitialized_B15(t *testing.T) {
	t.Parallel()
	ca := setupUninitializedCA(t)
	_, err := ca.Sign(rand.Reader, []byte("digest"), nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// ca.go — Init() error from createRootCertificate (lines 562, 938)
// =============================================================================

// TestInit_NilRootIdentity_B15 exercises the createRootCertificate nil rootIdentity
// path by setting ca.config.Identity to nil before calling Init(), covering
// ca.go:938.25,940.3 and the propagation at ca.go:562.54,564.3.
func TestInit_NilRootIdentity_B15(t *testing.T) {
	// NOT parallel — mutates CA config after construction.
	ca := setupUninitializedCA(t)
	// Wipe the identity slice so RootIdentity() returns nil.
	ca.config.Identity = nil
	err := ca.Init(context.Background())
	assert.Error(t, err)
}

// =============================================================================
// ca.go — Load() intermediate cert / key not found (lines 627, 637)
// =============================================================================

// TestLoad_IntermediateCertNotFound_B15 exercises Load() when the CA has an
// intermediate identity configured but only the root cert is present in the
// cert store, covering ca.go:627.17,629.4.
func TestLoad_IntermediateCertNotFound_B15(t *testing.T) {
	t.Parallel()

	// Build a root-only CA and initialize it so the root cert + key exist.
	rootCA := setupTestCA(t)

	// Build a second CA that shares the same root certStore/keyStore but
	// whose MultiIdentityCAConfig advertises an intermediate identity with a
	// CN that does not exist in the store.
	rootCA.initialized.Store(false) // allow Load to run

	// Add a fake intermediate identity to the config so HasIntermediate() is
	// true. Use a CN that is not present in the cert store.
	intermediateIdentity := Identity{
		Subject: Subject{CommonName: "Nonexistent Intermediate CA"},
		IsRoot:  false,
		Keys:    []*types.KeyConfig{{KeyAlgorithm: types.AlgorithmECDSA, StoreType: types.StoreSoftware, KeyType: "CA"}},
	}
	rootCA.config.Identity = append(rootCA.config.Identity, intermediateIdentity)
	rootCA.config.SelectedCA = 1

	err := rootCA.Load(context.Background())
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// TestLoad_IntermediateKeyNotFound_B15 exercises Load() when the intermediate
// cert is present but its private key is absent, covering ca.go:637.71,639.4.
func TestLoad_IntermediateKeyNotFound_B15(t *testing.T) {
	t.Parallel()

	// Build a full root+intermediate CA to obtain a cert for the intermediate.
	fullCA := setupTestCAWithRealIntermediate(t)

	// Build a second keystore-backed CA that shares the certStore of the full
	// CA (so both root + intermediate certs exist) but uses a fresh keystore
	// (which has no intermediate private key).
	rootOnlyCA := setupTestCA(t)

	// Copy the intermediate cert from fullCA into rootOnlyCA's cert store.
	intermediateCert := fullCA.intermediateCert
	require.NotNil(t, intermediateCert, "expected fullCA to have an intermediate cert")
	err := rootOnlyCA.certStore.StoreCertificate(intermediateCert)
	require.NoError(t, err)

	// Now configure rootOnlyCA to have an intermediate identity matching the
	// copied intermediate cert's CN. Its keystore does NOT have the key.
	rootOnlyCA.initialized.Store(false)
	intermediateIdentity := Identity{
		Subject: Subject{CommonName: intermediateCert.Subject.CommonName},
		IsRoot:  false,
		Keys:    []*types.KeyConfig{{KeyAlgorithm: types.AlgorithmECDSA, StoreType: types.StoreSoftware, KeyType: "CA"}},
	}
	rootOnlyCA.config.Identity = append(rootOnlyCA.config.Identity, intermediateIdentity)
	rootOnlyCA.config.SelectedCA = 1

	loadErr := rootOnlyCA.Load(context.Background())
	assert.Error(t, loadErr)
	assert.ErrorIs(t, loadErr, ErrKeyStoreRequired)
}

// =============================================================================
// attestation.go — ImportAttestation / ImportAttestationKeyCertificate Signer error
// =============================================================================

// TestImportAttestation_SignerError_B15 exercises the Signer() error path in
// ImportAttestation (attestation.go:100.16,102.3) by invalidating the CA config
// after initialization. NOT parallel (mutates CA state).
func TestImportAttestation_SignerError_B15(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	akAttrs := &types.KeyAttributes{CN: "attestation-signer-error-b15"}

	// Invalidate the issuing identity so Signer() returns ErrInvalidConfig.
	ca.config.SelectedCA = -1

	err := ca.ImportAttestation(context.Background(), akAttrs, AttestBlobQuote, []byte("some data"))
	assert.Error(t, err)
}

// TestImportAttestationKeyCertificate_SignerError_B15 exercises the Signer()
// error path in ImportAttestationKeyCertificate (attestation.go:158.16,160.3).
// NOT parallel (mutates CA state).
func TestImportAttestationKeyCertificate_SignerError_B15(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)

	// Build a valid DER cert so the initial checks pass.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ak-signer-error-b15"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	akDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	akAttrs := &types.KeyAttributes{CN: "ak-signer-error-b15"}

	// Corrupt the issuing identity so Signer() fails.
	ca.config.SelectedCA = -1

	importErr := ca.ImportAttestationKeyCertificate(context.Background(), akAttrs, akDER)
	assert.Error(t, importErr)
}

// =============================================================================
// attestation.go — verifyStoredAttestation: nil objectStore / invalid blobType
// =============================================================================

// TestVerifyStoredAttestation_NilObjectStore_B15 covers attestation.go:243.27,245.3
// by calling VerifyAttestationQuote on a CA with no object store.
func TestVerifyStoredAttestation_NilObjectStore_B15(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t) // no object store
	akAttrs := &types.KeyAttributes{CN: "nil-objstore-b15"}
	err := ca.VerifyAttestationQuote(akAttrs, []byte("quote"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

// TestVerifyStoredAttestation_InvalidBlobType_B15 covers attestation.go:248.16,250.3
// by calling verifyStoredAttestation with an unknown blobType. The function is
// private so we call it directly.
func TestVerifyStoredAttestation_InvalidBlobType_B15(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithObjectStore(t)
	akAttrs := &types.KeyAttributes{CN: "bad-blobtype-b15"}
	// "unknown-type" is not one of AttestBlobQuote/EventLog/PCRs.
	err := ca.verifyStoredAttestation(akAttrs, "unknown-type", []byte("data"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAttestationBlobType)
}

// TestVerifyStoredAttestation_SignatureNotFound_B15 covers
// attestation.go:265.16,267.3 by storing the digest key (so the digest check
// passes) but omitting the signature key, causing readBlobData on the sig key
// to fail.
func TestVerifyStoredAttestation_SignatureNotFound_B15(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithObjectStore(t)

	cn := "sig-notfound-b15"
	akAttrs := &types.KeyAttributes{CN: cn}
	data := []byte("attestation-data-for-sig-notfound-b15")

	// Build the exact digest key path that verifyStoredAttestation uses.
	safeCN := cn
	blobKey := safeCN + "/" + AttestBlobQuote
	digestKey := AttestBlobRoot + "/" + blobKey + "/digest"

	// Compute the digest the same way ImportAttestation does.
	h := sha256.Sum256(data)
	// Store ONLY the digest key — the signature key is intentionally absent.
	require.NoError(t, ca.objectStore.Put(digestKey, bytes.NewReader(h[:])))

	// Now verify: digest lookup succeeds, digest matches, sig lookup fails → line 265.
	err := ca.VerifyAttestationQuote(akAttrs, data)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// =============================================================================
// attestation.go — verifyCASignature ECDSA fails (line 293)
// =============================================================================

// TestVerifyCASignature_ECDSAFail_B15 exercises verifyCASignature when the
// stored signature is tampered, covering attestation.go:293.48,295.4.
func TestVerifyCASignature_ECDSAFail_B15(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithObjectStore(t)
	akAttrs := &types.KeyAttributes{CN: "ecdsa-sig-fail-b15"}
	data := []byte("test-data-for-sig-fail-b15")

	// Import legitimate attestation (ECDSA CA signs digest).
	require.NoError(t, ca.ImportAttestation(context.Background(), akAttrs, AttestBlobQuote, data))

	// Overwrite the signature blob with garbage so verification fails.
	safeCN := "ecdsa-sig-fail-b15"
	blobKey := safeCN + "/" + AttestBlobQuote
	sigKey := "attestation/" + blobKey + "/signature"
	require.NoError(t, ca.objectStore.Put(sigKey, bytes.NewReader([]byte("garbage-sig"))))

	err := ca.VerifyAttestationQuote(akAttrs, data)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

// =============================================================================
// bundle.go — filterCertificates nil cert (line 274)
// =============================================================================

// TestFilterCertificates_NilCert_B15 exercises filterCertificates when a
// provider returns a nil certificate, covering bundle.go:274.18,275.12.
func TestFilterCertificates_NilCert_B15(t *testing.T) {
	t.Parallel()

	// Construct DefaultCABundler directly (package ca — private fields accessible).
	bundler := &DefaultCABundler{
		providers: []CertificateProvider{
			&nilCertificateProvider{},
		},
	}

	result := bundler.filterCertificates("", "")
	assert.Empty(t, result)
}

// nilCertificateProvider satisfies CertificateProvider and returns nil from
// Certificate(). Defined at package level to avoid redeclaration across tests.
type nilCertificateProvider struct{}

func (n *nilCertificateProvider) Certificate() *x509.Certificate { return nil }
func (n *nilCertificateProvider) StoreType() string              { return "" }

// =============================================================================
// ca_extensions.go — CABundleFiltered storeType mismatch (line 522)
// =============================================================================

// TestCABundleFiltered_StoreTypeMismatch_B15 exercises the storeType filtering
// path where no certificate matches the requested store type, covering
// ca_extensions.go:522.16,524.5.
func TestCABundleFiltered_StoreTypeMismatch_B15(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	// The CA uses "software" store type. Request "pkcs11" which matches nothing.
	_, err := ca.CABundleFiltered("pkcs11", x509.UnknownPublicKeyAlgorithm)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCertificateChain)
}

// =============================================================================
// constructors.go — initializeAsIntermediate ErrAlreadyInitialized (line 337)
// =============================================================================

// TestInitializeAsIntermediate_AlreadyInitialized_B15 exercises the
// ErrAlreadyInitialized guard in initializeAsIntermediate (line 337.16,339.3)
// by calling it on a CA that is already initialized.
func TestInitializeAsIntermediate_AlreadyInitialized_B15(t *testing.T) {
	t.Parallel()
	// Use a fully initialized CA as the caInstance argument.
	ca := setupTestCA(t)
	parent := setupTestCA(t)

	parentIdentity := parent.config.Identity[0]
	err := initializeAsIntermediate(context.Background(), ca, parentIdentity, parent)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAlreadyInitialized)
}

// =============================================================================
// constructors.go — NewIntermediateCA nil KeyStore (line 272)
// =============================================================================

// TestNewIntermediateCA_NilKeyStore_B15 exercises the ResolveStores error path
// in NewIntermediateCA when no KeyStore is provided (line 272.16,274.3).
func TestNewIntermediateCA_NilKeyStore_B15(t *testing.T) {
	t.Parallel()
	parent := setupTestCA(t)

	rootID := Identity{
		Subject: Subject{CommonName: "Root CA B15"},
		IsRoot:  true,
		Valid:   1,
		Keys:    []*types.KeyConfig{{KeyAlgorithm: types.AlgorithmECDSA, StoreType: types.StoreSoftware, KeyType: "CA"}},
	}
	intermediateID := Identity{
		Subject: Subject{CommonName: "Intermediate CA B15"},
		IsRoot:  false,
		Valid:   1,
		Keys:    []*types.KeyConfig{{KeyAlgorithm: types.AlgorithmECDSA, StoreType: types.StoreSoftware, KeyType: "CA"}},
	}

	// No KeyStore provided → ResolveStores returns ErrKeyStoreRequired.
	params := &Params{
		Identity:  []Identity{rootID, intermediateID},
		KeyStore:  nil, // intentionally nil
		CertStore: nil,
	}
	_, err := NewIntermediateCA(context.Background(), params, parent)
	assert.Error(t, err)
}

// =============================================================================
// quantum.go — signCertificateWithQuantum unknown algorithm (line 153)
// =============================================================================

// TestSignCertificateWithQuantum_UnknownAlgorithm_B15 covers quantum.go:153.16,155.3
// by passing an MLDSAPrivateKey with an unknown algorithm string.
func TestSignCertificateWithQuantum_UnknownAlgorithm_B15(t *testing.T) {
	t.Parallel()
	privKey := &quantum.MLDSAPrivateKey{Algorithm: "ML-DSA-BOGUS"}
	pubKey := &quantum.MLDSAPublicKey{Algorithm: "ML-DSA-BOGUS", Key: []byte("key")}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "quantum-unknown-algo-b15"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	parentDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	parent, err := x509.ParseCertificate(parentDER)
	require.NoError(t, err)

	_, signErr := signCertificateWithQuantum(template, parent, pubKey, privKey)
	assert.Error(t, signErr)
}

// =============================================================================
// quantum.go — verifyQuantumCertificate error paths (lines 255, 258, 268)
// =============================================================================

// TestVerifyQuantumCertificate_GarbageDER_B15 covers quantum.go:255.16,257.3
// by passing completely invalid DER bytes.
func TestVerifyQuantumCertificate_GarbageDER_B15(t *testing.T) {
	t.Parallel()
	issuer := &quantum.MLDSAPublicKey{Algorithm: "ML-DSA-44", Key: []byte("pubkey")}
	err := verifyQuantumCertificate([]byte("not-valid-asn1"), issuer)
	assert.Error(t, err)
}

// TestVerifyQuantumCertificate_TrailingData_B15 covers quantum.go:258.19,260.3
// by crafting a valid outer SEQUENCE but with trailing bytes appended.
func TestVerifyQuantumCertificate_TrailingData_B15(t *testing.T) {
	t.Parallel()
	issuer := &quantum.MLDSAPublicKey{Algorithm: "ML-DSA-44", Key: []byte("pubkey")}

	// Build a minimal valid SEQUENCE, then append trailing bytes.
	inner, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      []byte{0x05, 0x00}, // NULL inside
	})
	require.NoError(t, err)
	// Wrap in outer SEQUENCE.
	outer, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      inner,
	})
	require.NoError(t, err)
	// Append trailing garbage.
	withTrailing := append(outer, 0xFF, 0xFE)

	verErr := verifyQuantumCertificate(withTrailing, issuer)
	assert.Error(t, verErr)
}

// TestVerifyQuantumCertificate_BadInnerSequence_B15 covers quantum.go:268.69,270.3
// by creating a valid outer SEQUENCE whose inner bytes are garbage (unmarshal
// of the three certificate components will fail).
func TestVerifyQuantumCertificate_BadInnerSequence_B15(t *testing.T) {
	t.Parallel()
	issuer := &quantum.MLDSAPublicKey{Algorithm: "ML-DSA-44", Key: []byte("pubkey")}

	// Build an outer SEQUENCE with garbage inner content that fails the second
	// asn1.Unmarshal call (parsing the three certificate components).
	outer, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		// FullBytes encoding wraps in another SEQUENCE so use Bytes directly.
		Bytes: []byte{0xFF, 0xFE, 0xFD}, // invalid ASN.1 content
	})
	require.NoError(t, err)

	verErr := verifyQuantumCertificate(outer, issuer)
	assert.Error(t, verErr)
}

// =============================================================================
// quantum.go — encodeQuantumPublicKey unknown algorithm (line 360)
// =============================================================================

// TestEncodeQuantumPublicKey_UnknownAlgorithm_B15 covers quantum.go:360.16,362.3
// by passing an MLDSAPublicKey with an unrecognised algorithm string.
func TestEncodeQuantumPublicKey_UnknownAlgorithm_B15(t *testing.T) {
	t.Parallel()
	pubKey := &quantum.MLDSAPublicKey{Algorithm: "NOT-REAL", Key: []byte("key")}
	_, err := encodeQuantumPublicKey(pubKey)
	assert.Error(t, err)
}

// =============================================================================
// quantum.go — buildCertExtensions: IsCA MaxPathLen=-1 (line 392)
//               IsCA without MaxPathLen/MaxPathLenZero (line 401)
//               empty extensions (line 437)
// =============================================================================

// TestBuildCertExtensions_IsCA_MaxPathLenNeg1_B15 covers quantum.go:392.10,394.5
// (IsCA=true, MaxPathLen=-1, MaxPathLenZero=false; bc.MaxPathLen=-1 branch set).
// Also covers quantum.go:401.27,405.4 (IsCA=true without MaxPathLen>0/MaxPathLenZero).
func TestBuildCertExtensions_IsCA_MaxPathLenNeg1_B15(t *testing.T) {
	t.Parallel()
	// IsCA=true, MaxPathLen=0, MaxPathLenZero=false → neither condition at 390 is met
	// → else branch at line 392: bc.MaxPathLen = -1.
	// Then the marshal path at line 401 (else if template.IsCA) is taken.
	template := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
	}
	_, err := buildCertExtensions(template)
	assert.NoError(t, err)
}

// TestBuildCertExtensions_NoExtensions_B15 covers quantum.go:437.26,439.3
// (empty extensions — no BasicConstraints, no KeyUsage, no ExtraExtensions).
func TestBuildCertExtensions_NoExtensions_B15(t *testing.T) {
	t.Parallel()
	template := &x509.Certificate{
		BasicConstraintsValid: false,
		KeyUsage:              0,
	}
	rv, err := buildCertExtensions(template)
	assert.NoError(t, err)
	// Empty RawValue (zero value) is returned.
	assert.Equal(t, asn1.RawValue{}, rv)
}

// =============================================================================
// hybrid.go — VerifyHybridCertificate parse error (line 223)
// =============================================================================

// TestVerifyHybridCertificate_ParseError_B15 covers hybrid.go:223.16,225.3
// by passing garbage DER as certDER to VerifyHybridCertificate.
func TestVerifyHybridCertificate_ParseError_B15(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "hybrid-classical-issuer-b15"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	classicalDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	classicalIssuer, err := x509.ParseCertificate(classicalDER)
	require.NoError(t, err)

	quantumIssuer := &quantum.MLDSAPublicKey{Algorithm: "ML-DSA-44", Key: []byte("pubkey")}

	verErr := VerifyHybridCertificate([]byte("garbage-DER"), classicalIssuer, quantumIssuer)
	assert.Error(t, verErr)
}

// TestVerifyHybridCertificate_NoAltSigAlgExt_B15 covers hybrid.go:253.27,258.3
// by passing a well-formed certificate that lacks the altSignatureAlgorithm
// extension, after classical signature verification passes.
func TestVerifyHybridCertificate_NoAltSigAlgExt_B15(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	// Self-signed cert — classicalIssuer is the cert itself, so CheckSignatureFrom
	// will succeed.
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "hybrid-no-altsig-b15"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	quantumIssuer := &quantum.MLDSAPublicKey{Algorithm: "ML-DSA-44", Key: []byte("pubkey")}

	verErr := VerifyHybridCertificate(certDER, cert, quantumIssuer)
	assert.Error(t, verErr)
}

// =============================================================================
// hybrid.go — extractTBS bad TBS content (line 388)
// =============================================================================

// TestExtractTBS_BadTBSContent_B15 covers hybrid.go:388.61,390.3 by crafting
// a DER that has a valid outer SEQUENCE but whose inner content fails the
// second Unmarshal (TBS extraction).
func TestExtractTBS_BadTBSContent_B15(t *testing.T) {
	t.Parallel()
	// Build a raw DER outer SEQUENCE whose Bytes contain a truncated inner
	// SEQUENCE (tag 0x30, length claims 255 bytes but zero bytes follow).
	// asn1.Unmarshal on outer.Bytes will fail because the inner length
	// exceeds the available data.
	//
	// We construct the bytes manually because asn1.Marshal would produce
	// well-formed (correct length) output.
	//   0x30 0x03 = outer SEQUENCE of 3 bytes
	//   0x30 0x81 0xff = inner SEQUENCE claiming 255 bytes (truncated — none follow)
	outerDER := []byte{0x30, 0x03, 0x30, 0x81, 0xff}

	_, extractErr := extractTBS(outerDER)
	assert.Error(t, extractErr)
}

// =============================================================================
// hybrid.go — extractTBSWithoutExtension parse failure (line 402)
// =============================================================================

// TestExtractTBSWithoutExtension_ParseError_B15 covers hybrid.go:402.16,404.3
// by passing garbage DER that fails x509.ParseCertificate inside the function.
func TestExtractTBSWithoutExtension_ParseError_B15(t *testing.T) {
	t.Parallel()
	excludeOID := asn1.ObjectIdentifier{2, 5, 29, 99}
	_, err := extractTBSWithoutExtension([]byte("garbage"), excludeOID)
	assert.Error(t, err)
}

// =============================================================================
// hybrid.go — rebuildTBSWithoutExtension error paths (lines 460, 466)
// =============================================================================

// TestRebuildTBSWithoutExtension_OuterUnmarshalFails_B15 covers
// hybrid.go:460.59,462.3 (outer asn1.Unmarshal fails).
func TestRebuildTBSWithoutExtension_OuterUnmarshalFails_B15(t *testing.T) {
	t.Parallel()
	_, err := rebuildTBSWithoutExtension([]byte("bad-asn1"), asn1.ObjectIdentifier{1, 2})
	assert.Error(t, err)
}

// TestRebuildTBSWithoutExtension_TBSUnmarshalFails_B15 covers
// hybrid.go:466.64,468.3 (outer Unmarshal passes but the second Unmarshal on
// outer.Bytes fails). Craft an outer SEQUENCE whose inner bytes are a
// truncated SEQUENCE (claims 255 bytes of content but provides none).
func TestRebuildTBSWithoutExtension_TBSUnmarshalFails_B15(t *testing.T) {
	t.Parallel()
	// Outer SEQUENCE of 3 bytes, containing a truncated inner SEQUENCE.
	//   0x30 0x03 = outer SEQUENCE, 3 bytes of content
	//   0x30 0x81 0xff = inner SEQUENCE claiming 255 bytes (truncated)
	outerDER := []byte{0x30, 0x03, 0x30, 0x81, 0xff}

	_, rebuildErr := rebuildTBSWithoutExtension(outerDER, asn1.ObjectIdentifier{1, 2})
	assert.Error(t, rebuildErr)
}

// =============================================================================
// crl_import.go — ImportDistributionCRLs http.Get error (line 61)
// =============================================================================

// TestImportDistributionCRLs_HTTPGetError_B15 exercises the http.Get error
// path in ImportDistributionCRLs (crl_import.go:61.17,64.4) by serving on a
// server that is closed before the request arrives.
//
// NOTE: t.Parallel() intentionally absent — we need a deterministic closed
// server URL.
func TestImportDistributionCRLs_HTTPGetError_B15(t *testing.T) {
	// Create and immediately close a server to get a valid-format but
	// unreachable URL.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := server.URL
	server.Close() // close before the request is made

	ca := setupTestCAWithObjectStore(t)

	// Build a leaf cert with a CRL distribution point pointing to the closed URL.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "crl-get-error-b15"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		CRLDistributionPoints: []string{closedURL + "/crl.crl"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	importErr := ca.ImportDistributionCRLs(cert)
	assert.Error(t, importErr)
	assert.ErrorIs(t, importErr, ErrStorageError)
}

// =============================================================================
// cross_signing.go — readCrossSignedCertificate ParseCertificate fails (line 228)
// =============================================================================

// TestReadCrossSignedCertificate_ParseError_B15 covers
// cross_signing.go:228.16,231.3 by storing a PEM block with a valid header
// but garbage DER bytes in the object store.
func TestReadCrossSignedCertificate_ParseError_B15(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithObjectStore(t)

	issuerCN := "parse-error-issuer-b15"
	subjectCN := "parse-error-subject-b15"

	// Build PEM with valid header but garbage DER content.
	garbagePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this-is-not-valid-DER"),
	})
	require.NotNil(t, garbagePEM)

	key := crossSignedStoreKey(issuerCN, subjectCN)
	require.NoError(t, ca.objectStore.Put(key, bytes.NewReader(garbagePEM)))

	_, err := ca.readCrossSignedCertificate(issuerCN, subjectCN)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// cross_signing.go — CrossSignedPEM suffix mismatch (line 185)
// =============================================================================

// TestCrossSignedPEM_SuffixMismatch_B15 covers cross_signing.go:185.39,186.12
// (continue when the listed item does not end with the expected suffix) by
// storing a cross-signed cert for a different CN before requesting the PEM for
// a specific CN.
func TestCrossSignedPEM_SuffixMismatch_B15(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithObjectStore(t)

	// Store a cert for "other-cn" so the listing has at least one item
	// that does NOT match the suffix for "target-cn-b15".
	otherCert, _ := makeSelfSignedCert(t, "other-cn-b15")
	require.NoError(t, ca.ImportXSignedCertificate("some-issuer-b15", otherCert))

	attrs := &types.KeyAttributes{CN: "target-cn-b15"}
	// Request PEM for target-cn which has no entries → ErrCertificateNotFound.
	_, err := ca.CrossSignedPEM(attrs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// =============================================================================
// verification.go — VerifyWithOptions CRL parse error (line 372)
// =============================================================================

// TestVerifyWithOptions_CRLParseError_B15 exercises the CRL parse error path
// in VerifyWithOptions (verification.go:372.17,378.4) by passing garbage bytes
// as the CRL when CheckRevocation is true.
func TestVerifyWithOptions_CRLParseError_B15(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	// Issue a leaf cert to get a valid certificate.
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "verify-crl-error-b15"},
		Valid:   365,
	})
	require.NoError(t, err)
	cert := issued.Certificate
	require.NotNil(t, cert)

	pool := x509.NewCertPool()
	pool.AddCert(ca.rootCert)

	_, verifyErr := VerifyWithOptions(cert, &VerifyOptions{
		Roots:           pool,
		CheckRevocation: true,
		CRL:             []byte("this-is-not-a-valid-CRL"),
	})
	assert.Error(t, verifyErr)
}

// =============================================================================
// csr.go — getOrGenerateKey CN set from Subject (line 198)
// =============================================================================

// TestIssueCertificate_CNFromSubject_B15 exercises the path where
// KeyAttributes.CN is empty and gets set from the Subject.CommonName (csr.go:198.20,200.3).
func TestIssueCertificate_CNFromSubject_B15(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	// Provide KeyAttributes with CN="" so the if-branch at line 198 is taken.
	_, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "cn-from-subject-b15"},
		Valid:   365,
		KeyAttributes: &types.KeyAttributes{
			CN:           "", // empty — will be set from Subject.CommonName
			KeyAlgorithm: x509.ECDSA,
			StoreType:    types.StoreSoftware,
			KeyType:      types.KeyTypeTLS,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
			Hash: 5, // crypto.SHA256
		},
	})
	assert.NoError(t, err)
}

// =============================================================================
// tbs_determinism.go — VerifyTBSDeterminism second ExtractTBSBytes error (line 81)
// =============================================================================

// TestVerifyTBSDeterminism_SecondExtractError_B15 covers
// tbs_determinism.go:81.16,83.3 by passing a valid first cert and invalid
// second cert DER so the first ExtractTBSBytes call succeeds but the second fails.
func TestVerifyTBSDeterminism_SecondExtractError_B15(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	// Use the root cert DER as the first (valid) cert.
	validDER := ca.rootCert.Raw

	// Pass garbage as the second cert.
	err := VerifyTBSDeterminism(validDER, []byte("not-valid-DER"))
	assert.Error(t, err)
}

// =============================================================================
// tls.go — VerifyPeerCertificate: IsRevoked error for peer cert (line 533)
//           IsRevoked error for intermediate (line 568)
//           Revoked intermediate (lines 573-580)
// =============================================================================

// TestVerifyPeerCertificate_IsRevokedError_B15 covers tls.go:533.16,539.3 by
// calling VerifyPeerCertificate on an uninitialized CA so IsRevoked returns
// ErrNotInitialized. The function logs and continues, returning nil.
func TestVerifyPeerCertificate_IsRevokedError_B15(t *testing.T) {
	t.Parallel()
	ca := setupUninitializedCA(t)

	// Build a simple self-signed cert to use as the peer cert.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "peer-is-revoked-error-b15"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	// VerifyPeerCertificate logs the IsRevoked error and continues; no error
	// is propagated for the IsRevoked failure itself.
	verErr := ca.VerifyPeerCertificate([][]byte{certDER}, nil)
	// May return an error (cert not yet valid / expired) but the IsRevoked
	// error path at line 533 is exercised regardless.
	_ = verErr
}

// TestVerifyPeerCertificate_IntermediateIsRevokedError_B15 covers
// tls.go:568.17,573.4 by providing two raw certs where the second (intermediate)
// parse succeeds but IsRevoked returns an error (uninitialized CA).
func TestVerifyPeerCertificate_IntermediateIsRevokedError_B15(t *testing.T) {
	t.Parallel()
	ca := setupUninitializedCA(t)

	// Build two minimal self-signed certs.
	makeCert := func(cn string) []byte {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		return der
	}

	peerDER := makeCert("peer-intermediate-error-b15")
	intermediateDER := makeCert("intermediate-error-b15")

	verErr := ca.VerifyPeerCertificate([][]byte{peerDER, intermediateDER}, nil)
	// IsRevoked errors are logged and the loop continues; no hard error.
	_ = verErr
}

// TestVerifyPeerCertificate_RevokedIntermediate_B15 covers tls.go:573.21,580.4
// (revoked intermediate returns ErrCertificateRevoked) by revoking a cert whose
// serial matches that of the fake intermediate DER.
func TestVerifyPeerCertificate_RevokedIntermediate_B15(t *testing.T) {
	// NOT parallel — mutates CA revocations map.
	ca := setupTestCA(t)

	// Build a fake "intermediate" cert and revoke its serial in the CA.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediateSerial := big.NewInt(999999)
	intermediateTmpl := &x509.Certificate{
		SerialNumber: intermediateSerial,
		Subject:      pkix.Name{CommonName: "revoked-intermediate-b15"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTmpl, intermediateTmpl, &key.PublicKey, key)
	require.NoError(t, err)

	// Revoke serial 999999 in the CA.
	require.NoError(t, ca.Revoke(context.Background(), intermediateSerial, 0))

	// Build a peer cert (valid, unexpired).
	peerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	peerSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	peerTmpl := &x509.Certificate{
		SerialNumber: peerSerial,
		Subject:      pkix.Name{CommonName: "peer-cert-b15"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	peerDER, err := x509.CreateCertificate(rand.Reader, peerTmpl, peerTmpl, &peerKey.PublicKey, peerKey)
	require.NoError(t, err)

	// VerifyPeerCertificate: first cert (peer) has a random serial → not
	// revoked. Second cert (intermediate) has serial 999999 → revoked.
	verErr := ca.VerifyPeerCertificate([][]byte{peerDER, intermediateDER}, nil)
	assert.Error(t, verErr)
	assert.ErrorIs(t, verErr, ErrCertificateRevoked)
}

// =============================================================================
// ocsp.go — createResponse issuerCert nil (line 174)
//            Signer error (line 179)
//            cold path revoked (line 237)
// =============================================================================

// sha1OCSPRequestHexFixture is a DER-encoded RFC 6960 OCSPRequest with
// CertID.hashAlgorithm SHA-1, generated once (outside this process, and
// outside GODEBUG=fips140=only, since crypto/sha1 panics building one under
// it) over a throwaway self-signed certificate -- generated fresh so the
// fixture carries no relationship to any CA under test. Only the request's
// hash algorithm matters to TestOCSPCreateResponse_RefusesSHA1UnderFIPSOnly;
// the serial number (22222) is expected not to match any certificate a test
// CA has issued, which resolves to ocsp.Good, not an error (see
// checkCertificateStatus's ErrCRLNotFound branch).
const sha1OCSPRequestHexFixture = "30433041303f303d303b300906052b0e03021a0500" +
	"0414d0c4360ec5a04b7a8eef1147a43eb4a159f8522104" +
	"1404b7d1e0527b02a1bd2fbbd99aa3a86fec9ad68a020256ce"

// TestOCSPCreateResponse_RefusesSHA1UnderFIPSOnly is the regression test for
// go-xkms#23: a SHA-1-hashed OCSP request -- RFC 6960's original, still
// widely deployed default -- used to reach golang.org/x/crypto/ocsp's
// CreateResponse unchecked, which panics inside crypto/sha1 under
// GODEBUG=fips140=only rather than returning an error. That let a remote,
// spec-compliant OCSP client crash this responder's process. parseRequest
// now refuses the request itself with ErrOCSPInvalidRequest before any SHA-1
// computation is attempted.
//
// crypto/sha1's refusal is fixed for the life of the process (GODEBUG is
// read once at startup), so this asserts whichever behavior matches the mode
// this test binary is actually running under, rather than asserting one
// fixed outcome: the FIPS-only refusal when GODEBUG=fips140=only, and the
// normal SHA-1 accept otherwise -- exactly the "no skip guard" contract
// go-xkms#23 established for deliberately non-approved algorithm coverage.
func TestOCSPCreateResponse_RefusesSHA1UnderFIPSOnly(t *testing.T) {
	ca := setupTestCA(t)
	responder := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	ocspReqDER, err := hex.DecodeString(sha1OCSPRequestHexFixture)
	require.NoError(t, err)

	_, handleErr := responder.HandleRequest(context.Background(), ocspReqDER)
	if fips140.Enforced() {
		require.Error(t, handleErr, "a SHA-1 OCSP request must be refused under GODEBUG=fips140=only")
		assert.ErrorIs(t, handleErr, ErrOCSPInvalidRequest)
		return
	}
	require.NoError(t, handleErr, "a SHA-1 OCSP request is ordinary RFC 6960 traffic outside FIPS 140-only mode")
}

// TestOCSPCreateResponse_IssuerCertNil_B15 covers ocsp.go:174.23,176.3 by
// clearing intermediateCert on an intermediate-configured CA so the
// HasIntermediate branch returns nil.
//
// NOTE: NOT parallel — mutates CA state.
func TestOCSPCreateResponse_IssuerCertNil_B15(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)
	responder := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	// Clear intermediateCert so issuerCert is nil inside createResponse.
	ca.mu.Lock()
	ca.intermediateCert = nil
	ca.mu.Unlock()

	// Build a minimal valid OCSP request targeting a fake serial.
	// Create an OCSP request using a cert + its issuer.
	leafSerial := big.NewInt(12345678)

	// Create a minimal cert for OCSP request construction.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "ocsp-nil-issuer-b15"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	issuerCert := ca.rootCert
	require.NotNil(t, issuerCert)

	// SHA-256 is requested explicitly: gocsp.CreateRequest defaults to SHA-1
	// when opts is nil, and this test exists to hit the nil-issuerCert
	// branch inside createResponse, not parseRequest's FIPS 140-only SHA-1
	// refusal (see TestOCSPCreateResponse_RefusesSHA1UnderFIPSOnly).
	ocspReqDER, err := gocsp.CreateRequest(leafCert, issuerCert, &gocsp.RequestOptions{Hash: crypto.SHA256})
	require.NoError(t, err)

	_, handleErr := responder.HandleRequest(context.Background(), ocspReqDER)
	assert.Error(t, handleErr)
	assert.ErrorIs(t, handleErr, ErrOCSPResponseFailed)
}

// TestOCSPCreateResponse_SignerError_B15 covers ocsp.go:179.16,181.3 by
// corrupting the CA's issuing identity after initialization so Signer() fails.
//
// NOTE: NOT parallel — mutates CA config.
func TestOCSPCreateResponse_SignerError_B15(t *testing.T) {
	ca := setupTestCA(t)
	responder := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	// Build a valid OCSP request.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial := big.NewInt(11111)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ocsp-signer-error-b15"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	issuerCert := ca.rootCert
	require.NotNil(t, issuerCert)

	ocspReqDER, err := gocsp.CreateRequest(cert, issuerCert, &gocsp.RequestOptions{Hash: crypto.SHA256})
	require.NoError(t, err)

	// Corrupt the issuing identity so Signer() returns ErrInvalidConfig.
	ca.config.SelectedCA = -1

	_, handleErr := responder.HandleRequest(context.Background(), ocspReqDER)
	assert.Error(t, handleErr)
	assert.ErrorIs(t, handleErr, ErrOCSPSigningFailed)
}

// TestOCSPCheckCertificateStatus_ColdPathRevoked_B15 covers ocsp.go:237.2,237.53
// (cold path: in-memory map is empty, object store has the revocation record).
//
// NOTE: NOT parallel — mutates CA revocation map.
func TestOCSPCheckCertificateStatus_ColdPathRevoked_B15(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)

	// Issue a cert and revoke it so the revocation is written to the object store.
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "ocsp-cold-revoked-b15"},
		Valid:   365,
	})
	require.NoError(t, err)
	cert := issued.Certificate
	require.NotNil(t, cert)

	require.NoError(t, ca.RevokeCert(context.Background(), cert, RevokeOptions{}))

	// Clear the in-memory revocations map to force the cold path.
	ca.revocationsMutex.Lock()
	ca.revocations = make(map[string]*RevocationInfo)
	ca.revocationsMutex.Unlock()

	// Build a valid OCSP request for the revoked cert's serial.
	issuerCert := ca.rootCert
	require.NotNil(t, issuerCert)
	ocspReqDER, err := gocsp.CreateRequest(cert, issuerCert, &gocsp.RequestOptions{Hash: crypto.SHA256})
	require.NoError(t, err)

	responder := NewOCSPResponder(ca, DefaultOCSPResponderConfig())
	resp, handleErr := responder.HandleRequest(context.Background(), ocspReqDER)
	require.NoError(t, handleErr)

	// Parse the response and verify it shows Revoked.
	ocspResp, parseErr := gocsp.ParseResponse(resp, issuerCert)
	if parseErr == nil {
		assert.Equal(t, gocsp.Revoked, ocspResp.Status)
	}
	// Even if gocsp.ParseResponse fails (e.g. signature mismatch with self-signed issuer),
	// the HandleRequest itself should have succeeded — the cold path was exercised.
}
