//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/ecpoint"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verifyIAKSignature checks an RSA-PSS SHA-256 signature produced by the
// simulator's IAK over the supplied attestation structure. The digest scheme
// mirrors what the TPM signs internally: H(attest) with the key's name
// algorithm.
func verifyIAKSignature(t *testing.T, pub crypto.PublicKey, attested, signature []byte) error {
	t.Helper()

	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok, "the harness IAK is an RSA key, got %T", pub)

	digest := sha256.Sum256(attested)
	return rsa.VerifyPSS(rsaPub, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
}

// TestCertifyKey_UnknownKey_Rejected covers the failure path where the key to
// be certified cannot be resolved. The call must fail rather than certify some
// other key.
func TestCertifyKey_UnknownKey_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)

	// Never created, so no blobs exist in the backend.
	missing := &types.KeyAttributes{
		CN:            "never-created-key",
		KeyAlgorithm:  x509.RSA,
		KeyType:       types.KeyTypeTLS,
		Parent:        srkAttrs,
		StoreType:     types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
	}
	result, err := h.TPM.CertifyKey(missing, []byte("nonce"), h.Backend)
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)

	// An unoccupied persistent handle must also fail.
	unoccupied := &types.KeyAttributes{
		CN:            "empty-persistent-slot",
		KeyAlgorithm:  x509.RSA,
		Parent:        srkAttrs,
		StoreType:     types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{Handle: tpm2.TPMHandle(0x81FF0001)},
	}
	result, err = h.TPM.CertifyKey(unoccupied, []byte("nonce"), h.Backend)
	assert.Nil(t, result)
	assert.Error(t, err)
}

// TestExtractPublicKey_RSAAndECC_RoundTrip proves extractPublicKey recovers the
// exact key material the TPM holds for both supported algorithms, and rejects
// anything else. A silently-wrong modulus here would corrupt every attestation
// result that carries a public key.
func TestExtractPublicKey_RSAAndECC_RoundTrip(t *testing.T) {
	h := newSimHarness(t, nil)

	t.Run("RSA", func(t *testing.T) {
		_, srkPub, err := h.TPM.SSRKPublic()
		require.NoError(t, err)

		extracted, err := h.TPM.extractPublicKey(&srkPub)
		require.NoError(t, err)

		rsaPub, ok := extracted.(*rsa.PublicKey)
		require.True(t, ok, "got %T", extracted)

		unique, err := srkPub.Unique.RSA()
		require.NoError(t, err)
		assert.Equal(t, new(big.Int).SetBytes(unique.Buffer), rsaPub.N,
			"the extracted modulus must equal the TPM's public area modulus")
		assert.Equal(t, 65537, rsaPub.E)
	})

	t.Run("ECC", func(t *testing.T) {
		// Create a transient ECC primary so an ECC public area is available.
		primary, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
		}.Execute(h.TPM.transport)
		require.NoError(t, err)
		defer h.TPM.Flush(primary.ObjectHandle)

		pub, err := primary.OutPublic.Contents()
		require.NoError(t, err)

		extracted, err := h.TPM.extractPublicKey(pub)
		require.NoError(t, err)

		eccPub, ok := extracted.(*ecdsa.PublicKey)
		require.True(t, ok, "got %T", extracted)

		unique, err := pub.Unique.ECC()
		require.NoError(t, err)
		wantPub, err := ecpoint.PublicKey(eccPub.Curve, unique.X.Buffer, unique.Y.Buffer)
		require.NoError(t, err, "the extracted point must lie on the recovered curve")
		assert.Equal(t, wantPub, eccPub,
			"the extracted key must equal the TPM's public area coordinates")
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		keyedHash := &tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
		}
		extracted, err := h.TPM.extractPublicKey(keyedHash)
		assert.Nil(t, extracted)
		require.Error(t, err)
		assert.ErrorIs(t, err, store.ErrUnsupportedKeyAlgorithm)
	})

	t.Run("malformed RSA public area", func(t *testing.T) {
		// Type says RSA but the parameters union carries ECC detail, so the
		// RSADetail() accessor must fail rather than produce a bogus key.
		malformed := &tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC, &tpm2.TPMSECCParms{}),
		}
		extracted, err := h.TPM.extractPublicKey(malformed)
		assert.Nil(t, extracted)
		assert.Error(t, err)
	})
}

// TestQuote_SignatureVerifiesOverSelectedPCRs proves a quote is a genuine,
// nonce-bound, IAK-signed statement about the requested PCRs.
func TestQuote_SignatureVerifiesOverSelectedPCRs(t *testing.T) {
	h := newSimHarness(t, nil)

	nonce := []byte("quote-nonce-abcdef0123456789")
	quote, err := h.TPM.Quote(append([]uint{0}, h.TPM.config.PlatformPCRs...), nonce)
	require.NoError(t, err)
	require.NotEmpty(t, quote.Quoted)
	require.NotEmpty(t, quote.Signature)
	assert.Equal(t, nonce, quote.Nonce)

	iakPub, err := h.TPM.IAK()
	require.NoError(t, err)
	require.NoError(t, verifyIAKSignature(t, iakPub, quote.Quoted, quote.Signature),
		"the quote signature must verify under the IAK")

	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](quote.Quoted)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMGeneratedValue, attest.Magic)
	assert.Equal(t, tpm2.TPMSTAttestQuote, attest.Type)
	assert.Equal(t, nonce, attest.ExtraData.Buffer,
		"the nonce must be inside the signed quote, not merely alongside it")

	quoteInfo, err := attest.Attested.Quote()
	require.NoError(t, err)
	assert.NotEmpty(t, quoteInfo.PCRDigest.Buffer)
	assert.NotEmpty(t, quote.PCRs, "the quote must carry the PCR values it attests to")
}

// TestQuote_TamperedQuoteFailsVerification is the negative case: a quote whose
// signed body or PCR claim has been altered must not verify.
func TestQuote_TamperedQuoteFailsVerification(t *testing.T) {
	h := newSimHarness(t, nil)

	quote, err := h.TPM.Quote([]uint{0, 7}, []byte("tamper-quote-nonce"))
	require.NoError(t, err)

	iakPub, err := h.TPM.IAK()
	require.NoError(t, err)
	require.NoError(t, verifyIAKSignature(t, iakPub, quote.Quoted, quote.Signature))

	tampered := append([]byte(nil), quote.Quoted...)
	tampered[len(tampered)-1] ^= 0xFF
	assert.Error(t, verifyIAKSignature(t, iakPub, tampered, quote.Signature),
		"a quote with a modified PCR digest must not verify")

	badSig := append([]byte(nil), quote.Signature...)
	badSig[len(badSig)/2] ^= 0xFF
	assert.Error(t, verifyIAKSignature(t, iakPub, quote.Quoted, badSig))
}

// TestQuote_ReflectsPCRExtension proves the quote is actually a live
// measurement rather than a cached value: extending a PCR must change the
// signed PCR digest.
func TestQuote_ReflectsPCRExtension(t *testing.T) {
	h := newSimHarness(t, nil)

	pcr := h.TPM.config.PlatformPCRs[0]
	nonce := []byte("stable-nonce-for-comparison")

	before, err := h.TPM.Quote([]uint{pcr}, nonce)
	require.NoError(t, err)

	h.extendPlatformPCR(t, []byte("new-measurement"))

	after, err := h.TPM.Quote([]uint{pcr}, nonce)
	require.NoError(t, err)

	beforeAttest, err := tpm2.Unmarshal[tpm2.TPMSAttest](before.Quoted)
	require.NoError(t, err)
	afterAttest, err := tpm2.Unmarshal[tpm2.TPMSAttest](after.Quoted)
	require.NoError(t, err)

	beforeQuote, err := beforeAttest.Attested.Quote()
	require.NoError(t, err)
	afterQuote, err := afterAttest.Attested.Quote()
	require.NoError(t, err)

	assert.NotEqual(t, beforeQuote.PCRDigest.Buffer, afterQuote.PCRDigest.Buffer,
		"extending a PCR must change the signed PCR digest")
	assert.NotEqual(t, before.PCRs, after.PCRs)
}

// TestQuote_NotProvisioned_Rejected covers the guard clauses that protect
// Quote from running against an unprovisioned TPM.
func TestQuote_NotProvisioned_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	iakAttrs := h.TPM.iakAttrs
	require.NotNil(t, iakAttrs)

	h.TPM.iakAttrs = nil
	quote, err := h.TPM.Quote([]uint{0}, []byte("nonce"))
	assert.Equal(t, Quote{}, quote)
	assert.ErrorIs(t, err, ErrNotInitialized)

	// IAK present but with no parent EK.
	orphan := *iakAttrs
	orphan.Parent = nil
	h.TPM.iakAttrs = &orphan
	quote, err = h.TPM.Quote([]uint{0}, []byte("nonce"))
	assert.Equal(t, Quote{}, quote)
	assert.ErrorIs(t, err, ErrInvalidAKAttributes)

	h.TPM.iakAttrs = iakAttrs
}

// TestPlatformQuote_UsesConfiguredPlatformPCR proves PlatformQuote generates a
// fresh random nonce per call and quotes the configured platform PCR.
func TestPlatformQuote_UsesConfiguredPlatformPCR(t *testing.T) {
	h := newSimHarness(t, nil)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	first, nonceA, err := h.TPM.PlatformQuote(iakAttrs)
	require.NoError(t, err)
	require.NotEmpty(t, nonceA)

	second, nonceB, err := h.TPM.PlatformQuote(iakAttrs)
	require.NoError(t, err)

	assert.NotEqual(t, nonceA, nonceB, "each platform quote must use a fresh nonce")
	assert.Equal(t, nonceA, first.Nonce)
	assert.Equal(t, nonceB, second.Nonce)

	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](first.Quoted)
	require.NoError(t, err)
	assert.Equal(t, nonceA, attest.ExtraData.Buffer)
}

// TestMakeCredentialWithExternalEK_WrongEKCannotActivate proves the credential
// is genuinely bound to the EK it was made for: a challenge built from an
// unrelated RSA key must not activate on this TPM.
func TestMakeCredentialWithExternalEK_WrongEKCannotActivate(t *testing.T) {
	h := newSimHarness(t, nil)

	strangerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	strangerCert := selfSignedCertForKey(t, &strangerKey.PublicKey)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	_, iakTPMPub, err := h.TPM.ReadHandle(iakAttrs.TPMAttributes.Handle)
	require.NoError(t, err)
	iak2B := tpm2.New2B(iakTPMPub)
	iakPubBytes := iak2B.Bytes()

	blob, encSecret, _, err := h.TPM.MakeCredentialWithExternalEK(
		strangerCert, iakPubBytes, []byte("secret-for-another-tpm-000000000"))
	require.NoError(t, err, "building the challenge must succeed; only activation may fail")

	recovered, err := h.TPM.ActivateCredential(blob, encSecret)
	require.Error(t, err, "a credential bound to a foreign EK must not activate here")
	assert.Nil(t, recovered)
	assert.ErrorIs(t, err, ErrInvalidActivationCredential)
}

// TestMakeCredentialWithExternalEK_InvalidInputs covers the argument
// validation and the malformed-input paths.
func TestMakeCredentialWithExternalEK_InvalidInputs(t *testing.T) {
	h := newSimHarness(t, nil)

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	ekCert := selfSignedCertForKey(t, ekPub)

	t.Run("nil certificate", func(t *testing.T) {
		blob, sec, plain, err := h.TPM.MakeCredentialWithExternalEK(nil, []byte{0x01}, nil)
		assert.Nil(t, blob)
		assert.Nil(t, sec)
		assert.Nil(t, plain)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "EK certificate is required")
	})

	t.Run("empty IAK public area", func(t *testing.T) {
		blob, sec, plain, err := h.TPM.MakeCredentialWithExternalEK(ekCert, nil, nil)
		assert.Nil(t, blob)
		assert.Nil(t, sec)
		assert.Nil(t, plain)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "IAK public area bytes are required")
	})

	t.Run("malformed IAK public area", func(t *testing.T) {
		blob, sec, plain, err := h.TPM.MakeCredentialWithExternalEK(
			ekCert, []byte{0xDE, 0xAD, 0xBE, 0xEF}, nil)
		assert.Nil(t, blob)
		assert.Nil(t, sec)
		assert.Nil(t, plain)
		assert.Error(t, err, "a garbage public area must be rejected by TPM2_LoadExternal")
	})

	t.Run("unsupported certificate key type", func(t *testing.T) {
		// Ed25519 has no TPM public-area mapping in CertificateToTPMPublic.
		cert := selfSignedEd25519Cert(t)
		iakAttrs, err := h.TPM.IAKAttributes()
		require.NoError(t, err)
		_, iakTPMPub, err := h.TPM.ReadHandle(iakAttrs.TPMAttributes.Handle)
		require.NoError(t, err)

		iak2B := tpm2.New2B(iakTPMPub)
		blob, sec, plain, err := h.TPM.MakeCredentialWithExternalEK(
			cert, iak2B.Bytes(), nil)
		assert.Nil(t, blob)
		assert.Nil(t, sec)
		assert.Nil(t, plain)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported public key type")
	})
}

// TestMakeCredential_GeneratedSecretIsFreshAndActivates covers the local
// MakeCredential path (using this TPM's own EK) and proves the generated
// secret is not a constant.
func TestMakeCredential_GeneratedSecretIsFreshAndActivates(t *testing.T) {
	h := newSimHarness(t, nil)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	akName := iakAttrs.TPMAttributes.Name

	blobA, secretA, plainA, err := h.TPM.MakeCredential(akName, nil)
	require.NoError(t, err)
	assert.Len(t, plainA, 32, "a generated credential secret must be an AES-256 key")

	_, _, plainB, err := h.TPM.MakeCredential(akName, nil)
	require.NoError(t, err)
	assert.NotEqual(t, plainA, plainB, "generated credential secrets must not repeat")

	recovered, err := h.TPM.ActivateCredential(blobA, secretA)
	require.NoError(t, err)
	assert.Equal(t, plainA, recovered)
}

// TestActivateCredential_CorruptChallenge_Rejected proves a mangled credential
// blob is rejected with the typed error rather than yielding garbage that a
// caller might treat as a valid secret.
func TestActivateCredential_CorruptChallenge_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	blob, encSecret, _, err := h.TPM.MakeCredential(iakAttrs.TPMAttributes.Name, nil)
	require.NoError(t, err)

	corruptBlob := append([]byte(nil), blob...)
	corruptBlob[len(corruptBlob)-1] ^= 0xFF
	out, err := h.TPM.ActivateCredential(corruptBlob, encSecret)
	assert.Nil(t, out)
	assert.ErrorIs(t, err, ErrInvalidActivationCredential)

	corruptSecret := append([]byte(nil), encSecret...)
	corruptSecret[0] ^= 0xFF
	out, err = h.TPM.ActivateCredential(blob, corruptSecret)
	assert.Nil(t, out)
	assert.ErrorIs(t, err, ErrInvalidActivationCredential)
}

// TestAKProfile_UnprovisionedConfig_ReportsTypedError is the bad-input
// companion: when the configuration has no EK or IAK at all, AKProfile must
// report the specific missing-configuration error from the accessor rather than
// a bare not-initialized.
func TestAKProfile_UnprovisionedConfig_ReportsTypedError(t *testing.T) {
	h := newSimHarness(t, nil)

	savedIAK := h.TPM.config.IAK
	h.TPM.iakAttrs = nil
	h.TPM.config.IAK = nil
	t.Cleanup(func() { h.TPM.config.IAK = savedIAK })

	_, err := h.TPM.AKProfile()
	assert.ErrorIs(t, err, ErrIAKConfigNil,
		"a missing IAK configuration must surface as ErrIAKConfigNil, got %v", err)
}

// selfSignedCertForKey issues a throwaway self-signed certificate carrying the
// supplied public key, standing in for a manufacturer EK certificate. The
// signing key is unrelated to the subject key, which is fine: the code under
// test only reads cert.PublicKey.
func selfSignedCertForKey(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, signer)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// selfSignedEd25519Cert issues a throwaway Ed25519 certificate, an algorithm
// with no TPM 2.0 public-area mapping, used to exercise the unsupported-key
// rejection path in CertificateToTPMPublic.
func selfSignedEd25519Cert(t *testing.T) *x509.Certificate {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-ed25519"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// -----------------------------------------------------------------------
// VerifyCertify against a real (simulated) TPM
// -----------------------------------------------------------------------

// TestVerifyCertify_RoundTripsAgainstTheSimulator closes the loop: evidence
// produced by an actual TPM2_Certify is verified by the stateless verifier a
// CA uses, with no TPM on the verifying side.
//
// The unit tests build their fixtures by hand, which proves the logic but not
// that the two halves agree on encoding -- and they did not at first. The
// producer returned the raw signature value while the verifier expects a
// TPMT_SIGNATURE, and the public *areas* it needs to recompute the Name were
// not returned at all. Only a round trip catches that.
func TestVerifyCertify_RoundTripsAgainstTheSimulator(t *testing.T) {
	h := newSimHarness(t, nil)

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)

	nonce := []byte("enrollment-challenge-0123456789a")
	result, err := h.TPM.CertifyKey(srkAttrs, nonce, h.Backend)
	require.NoError(t, err)

	require.NotEmpty(t, result.CertifyInfoSignature,
		"the wire-form signature must be returned for a remote verifier")
	require.NotEmpty(t, result.AttestingKeyPublicArea)
	require.NotEmpty(t, result.AttestedKeyPublicArea)

	verified, err := VerifyCertify(
		result.CertifyInfo,
		result.CertifyInfoSignature,
		result.AttestingKeyPublicArea,
		result.AttestedKeyPublicArea,
		&VerifyCertifyOptions{ExpectedQualifyingData: nonce},
	)
	require.NoError(t, err, "a genuine TPM certification must verify")
	require.NotNil(t, verified)

	assert.Equal(t, nonce, verified.QualifyingData)

	// The Name the verifier accepted must be the one the TPM reports for the
	// handle, not merely self-consistent within the attestation.
	name, _, err := h.TPM.ReadHandle(srkAttrs.TPMAttributes.Handle)
	require.NoError(t, err)
	assert.Equal(t, name.Buffer, verified.SubjectName,
		"the verified name must be the TPM's own name for the certified key")
}

// TestVerifyCertify_SimulatorEvidence_RejectsAnotherKey is the rejection this
// whole mechanism exists for.
//
// The attestation is real: this TPM certified this key, signed by its own IAK,
// with a fresh nonce. It is presented alongside a *different* key's public
// area -- which is precisely what an attacker does when they pair genuine
// hardware evidence with a key they generated in software.
func TestVerifyCertify_SimulatorEvidence_RejectsAnotherKey(t *testing.T) {
	h := newSimHarness(t, nil)

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)

	nonce := []byte("enrollment-challenge-0123456789a")
	result, err := h.TPM.CertifyKey(srkAttrs, nonce, h.Backend)
	require.NoError(t, err)

	// A different key from the same TPM: the IAK. Genuinely resident, genuinely
	// attestable -- just not the key this certification describes.
	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	iakResult, err := h.TPM.CertifyKey(iakAttrs, nonce, h.Backend)
	require.NoError(t, err)

	_, err = VerifyCertify(
		result.CertifyInfo,
		result.CertifyInfoSignature,
		result.AttestingKeyPublicArea,
		iakResult.AttestedKeyPublicArea, // the wrong subject
		nil,
	)

	assert.ErrorIs(t, err, ErrCertifyNameMismatch,
		"evidence for one key must not certify another")
}

// TestVerifyCertify_SimulatorEvidence_RejectsAReplayedNonce proves freshness
// holds against real evidence, not only hand-built fixtures.
func TestVerifyCertify_SimulatorEvidence_RejectsAReplayedNonce(t *testing.T) {
	h := newSimHarness(t, nil)

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)

	result, err := h.TPM.CertifyKey(srkAttrs, []byte("the-first-challenge-0123456789ab"), h.Backend)
	require.NoError(t, err)

	_, err = VerifyCertify(
		result.CertifyInfo,
		result.CertifyInfoSignature,
		result.AttestingKeyPublicArea,
		result.AttestedKeyPublicArea,
		&VerifyCertifyOptions{
			ExpectedQualifyingData: []byte("a-later-challenge-0123456789abcd"),
		},
	)

	assert.ErrorIs(t, err, ErrCertifyQualifyingDataMismatch)
}

// TestVerifyCertify_SimulatorEvidence_RejectsTampering covers modification in
// transit of evidence that was genuine when it left the TPM.
func TestVerifyCertify_SimulatorEvidence_RejectsTampering(t *testing.T) {
	h := newSimHarness(t, nil)

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)

	nonce := []byte("enrollment-challenge-0123456789a")
	result, err := h.TPM.CertifyKey(srkAttrs, nonce, h.Backend)
	require.NoError(t, err)

	tampered := make([]byte, len(result.CertifyInfo))
	copy(tampered, result.CertifyInfo)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = VerifyCertify(
		tampered,
		result.CertifyInfoSignature,
		result.AttestingKeyPublicArea,
		result.AttestedKeyPublicArea,
		nil,
	)

	assert.ErrorIs(t, err, ErrCertifySignature)
}
