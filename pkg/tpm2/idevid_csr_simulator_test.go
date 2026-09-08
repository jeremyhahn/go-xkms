//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers the two device-identity enrollment ceremonies end to end on
// a real (simulated) TPM that owns both an IAK and an IDevID key:
//
//   - EnrollmentStrategyIAK                    -- the IAK signs the CSR
//   - EnrollmentStrategyIAK_IDEVID_SINGLE_PASS -- the IDevID signs the CSR
//
// The sibling file idevid_csr_roundtrip_simulator_test.go covers the wire codec
// and the nil/typed-error guards using an IAK-only device; this file covers what
// that device cannot express -- which key actually signs, and what happens when
// the CA verifies with the wrong ceremony, the wrong algorithm or the wrong
// padding configuration.
//
// Each test owns exactly one simulator via newSimHarness; the go-tpm-tools
// simulator is a process-global singleton so only one may be live at a time.

// identityHarness is a provisioned simulator-backed TPM2 that owns a complete
// device identity: an EK, an IAK created by Provision, and an IDevID minted on
// top of them. Provision deliberately stops after the IAK (see Provision in
// provision.go), so the IDevID is created here -- that is exactly why the tests
// this file replaces used to skip with "IDevID not available".
type identityHarness struct {
	*simHarness

	// IAK is the restricted attestation key that Provision created.
	IAK *types.KeyAttributes

	// IDevID is the unrestricted device identity signing key.
	IDevID *types.KeyAttributes

	// EKCert is a throwaway certificate over the TPM's real EK public key. A
	// simulator has no manufacturer certificate in NV RAM, and the CSR
	// structure requires one, so the test acts as the manufacturer.
	EKCert *x509.Certificate
}

// newIdentityHarness provisions a TPM, mints an IDevID and returns everything a
// device identity CSR needs. Any failure here is a broken test environment, not
// a reason to stop testing, so every step is fatal.
func newIdentityHarness(t *testing.T, strategy EnrollmentStrategy, pad bool) *identityHarness {
	t.Helper()

	h := newSimHarness(t, func(c *Config) {
		c.IdentityProvisioningStrategy = string(strategy)
		c.IDevID = &IDevIDConfig{
			CN:                 "device-id-001",
			Debug:              true,
			Hash:               crypto.SHA256.String(),
			Handle:             0x81020000,
			KeyAlgorithm:       x509.RSA.String(),
			Manufacturer:       "ATT",
			Model:              "xkms-test-device",
			Pad:                pad,
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			Serial:             "SN-0000-0001",
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		}
	})

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err, "provisioning must leave a usable IAK behind")

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err, "the provisioned EK must be readable")
	ekCert := selfSignedCertForKey(t, ekPub)

	idevidAttrs, csr, err := h.TPM.CreateIDevID(iakAttrs, ekCert, nil)
	require.NoError(t, err, "the TPM must be able to mint an IDevID under strategy %q", strategy)
	require.NotNil(t, idevidAttrs)
	require.NotNil(t, csr, "CreateIDevID must return the enrollment CSR it produced")

	return &identityHarness{
		simHarness: h,
		IAK:        iakAttrs,
		IDevID:     idevidAttrs,
		EKCert:     ekCert,
	}
}

// csr builds a fresh TCG-CSR-IDEVID from the harness under its configured
// enrollment strategy.
func (h *identityHarness) csr(t *testing.T) *TCG_CSR_IDEVID {
	t.Helper()

	csr, err := h.TPM.CreateTCG_CSR_IDEVID(h.EKCert, h.IAK, h.IDevID)
	require.NoError(t, err, "the TPM must be able to produce a device identity CSR")
	return &csr
}

// createTestEKCertificate creates a throwaway EK certificate over a freshly
// generated key. Callers that need the certificate to carry the TPM's real EK
// public key must use selfSignedCertForKey instead.
func createTestEKCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test TPM Manufacturer"},
			CommonName:   "Test EK Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	return cert
}

// TestTCGCSR_IAKStrategy_IsSignedByTheIAK covers Section 6.1.2 of the TCG device
// identity specification: under EnrollmentStrategyIAK the attestation key signs
// the CSR, even on a device that also owns an IDevID.
//
// The signer is chosen by a switch in CreateTCG_CSR_IDEVID, and nothing in the
// CSR names it -- the CA infers it from its own configured strategy. If the two
// switches ever disagree, a genuine device would be refused enrollment (or, far
// worse, a CSR signed by an unrestricted key would be accepted as attestation
// evidence). Asserting that the IAK verifies AND the IDevID does not pins the
// choice from both directions.
func TestTCGCSR_IAKStrategy_IsSignedByTheIAK(t *testing.T) {
	h := newIdentityHarness(t, EnrollmentStrategyIAK, false)
	csr := h.csr(t)

	t.Run("carries the device identity the CA will certify", func(t *testing.T) {
		assert.Equal(t, TCGCSRIDevIDStructVer, bytesToUint32(csr.StructVer),
			"the structure version must be 1.0 of an IDevID CSR, 0x01000100 (section 13.1)")
		assert.NotEmpty(t, csr.Signature, "the CSR must be signed")

		assert.Equal(t, []byte("xkms-test-device"), csr.CsrContents.ProdModel)
		assert.Equal(t, []byte("SN-0000-0001"), csr.CsrContents.ProdSerial)
		assert.Equal(t, h.EKCert.Raw, csr.CsrContents.EkCert,
			"the CA authenticates the device through this EK certificate")
		assert.Equal(t, h.IAK.TPMAttributes.BPublic.Bytes(), csr.CsrContents.AttestPub,
			"the attestation public area must be the device's IAK")
		assert.Equal(t, h.IDevID.TPMAttributes.BPublic.Bytes(), csr.CsrContents.SigningPub,
			"the signing public area must be the device's IDevID")
	})

	t.Run("verifies under the IAK", func(t *testing.T) {
		attrs, unpacked, err := h.TPM.VerifyTCG_CSR_IAK(csr, x509.SHA256WithRSAPSS)
		require.NoError(t, err, "a CSR signed by the IAK must verify under the IAK")
		require.NotNil(t, attrs)
		require.NotNil(t, unpacked)
		assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
		assert.True(t, attrs.TPMAttributes.Public.ObjectAttributes.Restricted,
			"the enrolling key must be reported as a restricted attestation key")
	})

	t.Run("does not verify under the IDevID", func(t *testing.T) {
		attrs, unpacked, err := h.TPM.VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err,
			"the IDevID did not sign this CSR, so the single-pass verifier must reject it")
		assert.ErrorIs(t, err, ErrInvalidSignature)
		assert.Nil(t, attrs)
		assert.Nil(t, unpacked)
	})

	t.Run("VerifyTCGCSR routes to the IAK verifier", func(t *testing.T) {
		// The subtest above establishes that the single-pass verifier rejects
		// this CSR, so a success here can only come from routing to the IAK
		// verifier that the configured strategy selects.
		attrs, unpacked, err := h.TPM.VerifyTCGCSR(csr, x509.SHA256WithRSAPSS)
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.NotNil(t, unpacked)
	})

	t.Run("the caller's signature algorithm governs verification", func(t *testing.T) {
		// The CSR is signed with RSA-PSS. A CA that asked for a different
		// algorithm must not have its request quietly reinterpreted: an
		// algorithm-confusion hole here would let a PKCS#1 v1.5 forgery be
		// checked as PSS, or vice versa.
		for name, algorithm := range map[string]x509.SignatureAlgorithm{
			"PKCS#1 v1.5 against a PSS signature": x509.SHA256WithRSA,
			"ECDSA against an RSA signature":      x509.ECDSAWithSHA256,
		} {
			t.Run(name, func(t *testing.T) {
				attrs, _, err := h.TPM.VerifyTCG_CSR_IAK(csr, algorithm)
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidSignature)
				assert.Nil(t, attrs)
			})
		}
	})

	t.Run("an unrecognised in-range hash algorithm is rejected", func(t *testing.T) {
		// 0xFFFF fits the uint16 the field is narrowed to, so it passes the
		// explicit range guard and reaches TPMAlgID.Hash(). That lookup must
		// fail closed rather than fall back to a default digest.
		bad := *csr
		bad.CsrContents = csr.CsrContents
		bad.CsrContents.HashAlgoId = [4]byte{0x00, 0x00, 0xFF, 0xFF}

		attrs, unpacked, err := h.TPM.VerifyTCG_CSR_IAK(&bad, x509.SHA256WithRSAPSS)
		require.Error(t, err, "an unknown TPM algorithm ID must be rejected")
		assert.NotErrorIs(t, err, ErrInvalidSignature,
			"the hash algorithm must be rejected before any signature check")
		assert.Nil(t, attrs)
		assert.Nil(t, unpacked)
	})
}

// TestTCGCSR_SinglePassStrategy_IsSignedByTheIDevID is the Section 6.2.2
// counterpart: under EnrollmentStrategyIAK_IDEVID_SINGLE_PASS the IDevID signs
// the CSR and the IAK only attests to the IDevID's TPM residency.
//
// Padding is enabled here. CreateTCG_CSR_IDEVID only appends the Pad field when
// config.IDevID.Pad is set, and the sibling roundtrip file explicitly requires
// the unpadded shape, so this is the only place the padded wire form is
// exercised against a real signature.
func TestTCGCSR_SinglePassStrategy_IsSignedByTheIDevID(t *testing.T) {
	h := newIdentityHarness(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, true)
	csr := h.csr(t)

	t.Run("verifies under the IDevID", func(t *testing.T) {
		attrs, unpacked, err := h.TPM.VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSAPSS)
		require.NoError(t, err, "a CSR signed by the IDevID must verify under the IDevID")
		require.NotNil(t, attrs)
		require.NotNil(t, unpacked)
		assert.False(t, attrs.TPMAttributes.Public.ObjectAttributes.Restricted,
			"the IDevID is an unrestricted signing key")
		assert.True(t, attrs.TPMAttributes.Public.ObjectAttributes.FixedTPM,
			"the IDevID must be bound to the TPM that reported it")
	})

	t.Run("does not verify under the IAK", func(t *testing.T) {
		attrs, unpacked, err := h.TPM.VerifyTCG_CSR_IAK(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err,
			"the IAK did not sign this CSR, so the IAK verifier must reject it")
		assert.ErrorIs(t, err, ErrInvalidSignature)
		assert.Nil(t, attrs)
		assert.Nil(t, unpacked)
	})

	t.Run("VerifyTCGCSR routes to the single-pass verifier", func(t *testing.T) {
		attrs, unpacked, err := h.TPM.VerifyTCGCSR(csr, x509.SHA256WithRSAPSS)
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.NotNil(t, unpacked)
	})

	t.Run("a tampered signature is rejected", func(t *testing.T) {
		bad := *csr
		bad.Signature = append([]byte(nil), csr.Signature...)
		require.NotEmpty(t, bad.Signature)
		bad.Signature[0] ^= 0xFF

		attrs, _, err := h.TPM.VerifyTCG_CSR_IDevID(&bad, x509.SHA256WithRSAPSS)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSignature)
		assert.Nil(t, attrs)
	})

	t.Run("a CSR declaring more payload than it carries is rejected", func(t *testing.T) {
		// UnpackIDevIDCSR copies each payload into a buffer sized by the
		// declared length. A declared length larger than the payload must be
		// reported as corruption rather than silently zero-filled, because the
		// verifier would otherwise hash bytes the device never signed.
		bad := *csr
		bad.CsrContents = csr.CsrContents
		bad.CsrContents.ProdModelSz = [4]byte{0x00, 0x00, 0x03, 0xE8} // 1000

		attrs, unpacked, err := h.TPM.VerifyTCG_CSR_IDevID(&bad, x509.SHA256WithRSAPSS)
		require.Error(t, err)
		assert.ErrorIs(t, err, store.ErrCorruptCopy)
		assert.Nil(t, attrs)
		assert.Nil(t, unpacked)
	})

	t.Run("the padded wire form is signature stable", func(t *testing.T) {
		padSz := bytesToUint32(csr.CsrContents.PadSz)
		require.Equal(t, int(padSz), len(csr.CsrContents.Pad),
			"the declared padding size must match the padding carried")
		require.Less(t, padSz, uint32(TCGCSRAlignment),
			"section 13.1: the pad is what brings the structure to a multiple of 16 bytes, never more")
		require.Zero(t, bytesToUint32(csr.Contents)%TCGCSRAlignment,
			"section 13.1: the padded structure size is a multiple of 16 bytes")

		encoded, err := csr.Marshal()
		require.NoError(t, err)

		decoded, err := UnmarshalIDevIDCSR(encoded)
		require.NoError(t, err, "a padded CSR must survive the wire")
		require.NotNil(t, decoded)
		assert.Equal(t, csr.CsrContents.PadSz, decoded.CsrContents.PadSz)
		assert.Equal(t, csr.CsrContents.Pad, decoded.CsrContents.Pad,
			"padding is covered by the signature, so it must round-trip exactly")

		// The decisive assertion: the signature still verifies over the decoded
		// structure. Any padding byte lost, added or reordered in transit would
		// change the digest and break enrollment for every padded device.
		attrs, _, err := h.TPM.VerifyTCG_CSR_IDevID(decoded, x509.SHA256WithRSAPSS)
		require.NoError(t, err, "a padded CSR must still verify after a wire round trip")
		require.NotNil(t, attrs)
	})
}

// TestCreateProdCaData covers the attestation payload the device carries to its
// CA in the CSR's ProdCaData field: a TPM2_Quote over the configured golden PCRs
// plus the encoded PCR values.
//
// The test this replaces could not assert anything at all. It skipped itself
// with "Cannot access TPM2 internal methods" whenever a type assertion that
// always succeeds appeared to fail, and then treated any error as "acceptable"
// -- so a createProdCaData that returned an error on every call would still
// have passed. The tests live in package tpm2, so the internals were reachable
// all along.
func TestCreateProdCaData(t *testing.T) {
	h := newSimHarness(t, nil)

	// Quote signs with the cached IAK attributes, which IAKAttributes populates.
	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	t.Run("transport-backed TPM still attests", func(t *testing.T) {
		// This is the regression guard for a silent attestation loss.
		//
		// createProdCaData used to short-circuit on a nil tpm.device, but that
		// field is populated only by the raw os.OpenFile branch of NewTPM2. A
		// unix-socket (".sock") TPM, a TCP/mssim TPM, the in-process simulator
		// and any injected transport all leave it nil while being perfectly
		// able to quote -- so every enrollment CSR from those deployments
		// carried no quote and no PCRs, announced by nothing louder than a
		// Debug line. The guard now tests tpm.transport, which is what the
		// commands actually travel over and is set on every path.
		require.Nil(t, h.TPM.device,
			"precondition: the harness supplies a transport, not a character device")
		require.NotNil(t, h.TPM.transport, "precondition: the harness has a transport")

		data, size, err := h.TPM.createProdCaData()
		require.NoError(t, err)
		assert.NotEmpty(t, data,
			"a transport-backed TPM must attest; dropping it silently strips the CSR's quote")
		assert.Equal(t, len(data), int(size))
	})

	t.Run("no transport yields no attestation", func(t *testing.T) {
		// The honest short-circuit: with nothing to talk to, there is no quote
		// to produce. Restored after the subtest so the rest keeps working.
		saved := h.TPM.transport
		h.TPM.transport = nil
		t.Cleanup(func() { h.TPM.transport = saved })

		data, size, err := h.TPM.createProdCaData()
		require.NoError(t, err)
		assert.Nil(t, data)
		assert.Zero(t, size)
	})

	t.Run("produces a verifiable quote over the golden PCRs", func(t *testing.T) {
		// No device workaround needed: the guard tests tpm.transport, which the
		// harness owns. Opening os.DevNull purely to satisfy a nil-check used
		// to be required here, which was itself a symptom of the defect.
		data, size, err := h.TPM.createProdCaData()
		require.NoError(t, err, "a provisioned TPM must be able to quote its golden PCRs")
		require.NotEmpty(t, data)
		require.Equal(t, len(data), int(size),
			"the returned size must describe the returned bytes")

		parsed, err := UnpackProdCaData(data)
		require.NoError(t, err, "the CA must be able to parse what the device packed")
		require.NotNil(t, parsed)
		assert.Equal(t, ProdCaDataVersion, parsed.Version)
		assert.Equal(t, int(parsed.QuotedSz), len(parsed.Quoted))
		assert.Equal(t, int(parsed.SignatureSz), len(parsed.Signature))
		assert.Equal(t, int(parsed.NonceSz), len(parsed.Nonce))
		assert.Equal(t, int(parsed.PCRsSz), len(parsed.PCRs))
		require.NotEmpty(t, parsed.PCRs, "the quoted PCR values must be carried")

		// The quoted blob must be a genuine TPMS_ATTEST produced by this TPM
		// over the nonce the device generated, not a replayed or fabricated
		// structure. TPM_GENERATED_VALUE is the field the TPM refuses to
		// produce over externally supplied data.
		attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](parsed.Quoted)
		require.NoError(t, err, "the quoted bytes must be a TPMS_ATTEST structure")
		assert.Equal(t, tpm2.TPMGeneratedValue, attest.Magic,
			"the quote must carry TPM_GENERATED_VALUE")
		assert.Equal(t, tpm2.TPMSTAttestQuote, attest.Type)
		assert.Equal(t, parsed.Nonce, attest.ExtraData.Buffer,
			"the quote must be bound to the nonce carried alongside it")

		quoteInfo, err := attest.Attested.Quote()
		require.NoError(t, err)
		require.NotEmpty(t, quoteInfo.PCRSelect.PCRSelections,
			"the quote must name the PCRs it covers")
		require.NotEmpty(t, quoteInfo.PCRDigest.Buffer)

		// Finally, the quote signature must verify under the IAK public key the
		// CA will be given. Without this the CA has no reason to believe the
		// PCR digest describes the enrolling device.
		rsaDetail, err := iakAttrs.TPMAttributes.Public.Parameters.RSADetail()
		require.NoError(t, err)
		rsaUnique, err := iakAttrs.TPMAttributes.Public.Unique.RSA()
		require.NoError(t, err)
		iakPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		require.NoError(t, err)

		digest := sha256.Sum256(parsed.Quoted)
		require.NoError(t,
			rsa.VerifyPSS(iakPub, crypto.SHA256, digest[:], parsed.Signature, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA256,
			}),
			"the quote must be signed by the device's IAK")
	})
}

// TestTCGCSR_SigningKeyMustBeCertifiedByTheAttestationKey covers the binding
// that makes an IDevID certificate mean what it says.
//
// Everything else in the CSR concerns *possession*: it is signed by the IDevID,
// so the requester holds that private key. A key generated in software is
// possessed just as fully. Only sgnCertifyInfo -- the IAK's TPM2_Certify over
// the IDevID -- shows the signing key lives in the same TPM as the attestation
// key, which is the whole claim being made.
//
// Before this was verified, a device with a genuine TPM could present a real EK,
// a real IAK, pass credential activation, and still be certified for a signing
// key the TPM had never seen.
func TestTCGCSR_SigningKeyMustBeCertifiedByTheAttestationKey(t *testing.T) {
	h := newIdentityHarness(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, true)

	t.Run("a genuine CSR carries a valid certification", func(t *testing.T) {
		csr := h.csr(t)

		_, unpacked, err := h.TPM.VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSAPSS)
		require.NoError(t, err)
		require.NotEmpty(t, unpacked.CsrContents.SgnCertifyInfo,
			"a real TPM must emit the IAK's certification of the IDevID")
		require.NotEmpty(t, unpacked.CsrContents.SgnCertifyInfoSig)

		// The same evidence must satisfy the standalone verifier, which is what
		// a CA with no TPM of its own runs.
		verified, err := VerifyCertifyRaw(
			unpacked.CsrContents.SgnCertifyInfo,
			unpacked.CsrContents.SgnCertifyInfoSig,
			unpacked.CsrContents.AttestPub,
			unpacked.CsrContents.SigningPub,
			nil,
		)
		require.NoError(t, err)
		require.NotEmpty(t, verified.SubjectName)
	})

	t.Run("a CSR whose certification is stripped is refused", func(t *testing.T) {
		csr := h.csr(t)
		stripped := *csr
		stripped.CsrContents.SgnCertifyInfo = nil
		stripped.CsrContents.SgnCertifyInfoSig = nil

		_, _, err := VerifyTCG_CSR_IDevID_Stateless(&stripped, x509.SHA256WithRSAPSS)

		// Absence must refuse rather than skip: an omitted proof is exactly
		// what an attacker submitting a software key would send.
		require.Error(t, err, "a CSR with no certification must not verify")
	})

	t.Run("a CSR certifying a different key is refused", func(t *testing.T) {
		csr := h.csr(t)

		// Swap in the IAK's own public area as the signing key. It is a real
		// key in this very TPM -- just not the one the certification covers,
		// which is precisely the substitution the Name check exists to catch.
		swapped := *csr
		swapped.CsrContents.SigningPub = csr.CsrContents.AttestPub

		_, _, err := VerifyTCG_CSR_IDevID_Stateless(&swapped, x509.SHA256WithRSAPSS)

		require.Error(t, err,
			"a certification of one key must not certify another")
	})

	t.Run("a CSR with a tampered certification is refused", func(t *testing.T) {
		csr := h.csr(t)
		tampered := *csr
		body := make([]byte, len(csr.CsrContents.SgnCertifyInfo))
		copy(body, csr.CsrContents.SgnCertifyInfo)
		require.NotEmpty(t, body)
		body[len(body)-1] ^= 0xFF
		tampered.CsrContents.SgnCertifyInfo = body

		_, _, err := VerifyTCG_CSR_IDevID_Stateless(&tampered, x509.SHA256WithRSAPSS)

		// Refused by the CSR's own self-signature, which covers the packed
		// contents and therefore the certification inside them. That check runs
		// first, so tampering never reaches the certify verifier -- the CSR is
		// rejected either way, just earlier and for a reason that is equally
		// true.
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSignature)
	})
}
