//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"io"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers the TCG-CSR-IDEVID wire format end to end: a CSR produced by
// a real TPM must survive marshalling and unmarshalling unchanged, verify under
// the attestation key that signed it, and be rejected when tampered with.
//
// Each test owns one simulator via newSimHarness; the go-tpm-tools simulator is
// a process-global singleton so only one may be live at a time.

// newCSRHarness returns a harness with an IDevID section configured.
//
// CreateTCG_CSR_IDEVID reads tpm.config.IDevID.Pad unconditionally, and
// createIDevIDContent dereferences the idevidAttrs argument unconditionally, so
// a CSR cannot be produced without both -- even under the IAK-only enrollment
// strategy that has no IDevID key. See
// TestCreateTCG_CSR_IDEVID_NilIDevIDAttributes_Panics, which pins that defect.
func newCSRHarness(t *testing.T) *simHarness {
	t.Helper()
	return newSimHarness(t, func(c *Config) {
		c.IDevID = &IDevIDConfig{
			CN:                 "device-id-001",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81020000,
			KeyAlgorithm:       x509.RSA.String(),
			Manufacturer:       "ATT",
			Model:              "xkms-test-device",
			Pad:                false,
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			Serial:             "SN-0000-0001",
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		}
	})
}

// buildDeviceCSR produces a signed TCG-CSR-IDEVID from the harness's TPM using
// the IAK enrollment strategy the harness is configured for. Under that
// strategy the IAK is the signer; the IAK attributes are supplied for the
// idevid argument as well because the content builder requires a non-nil value
// there regardless of strategy.
func buildDeviceCSR(t *testing.T, h *simHarness) *TCG_CSR_IDEVID {
	t.Helper()

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	ekCert := selfSignedCertForKey(t, ekPub)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	csr, err := h.TPM.CreateTCG_CSR_IDEVID(ekCert, iakAttrs, iakAttrs)
	require.NoError(t, err, "the TPM must be able to produce a device identity CSR")
	return &csr
}

// TestCreateTCG_CSR_IDEVID_NilIDevIDAttributes_ReturnsTypedError is the
// nil-dereference regression test.
//
// Under EnrollmentStrategyIAK the attestation key is the signer and there is no
// IDevID key at all -- IDevIDAttributes() correctly returns ErrIDevIDConfigNil
// for such a configuration. Passing the resulting nil idevidAttrs to
// CreateTCG_CSR_IDEVID used to panic: createIDevIDContent dereferenced it at
//
//	hashSz, err := ParseHashSize(idevidAttrs.Hash)
//
// having validated only ekCert for nil. CLAUDE.md requires library code to
// return errors rather than panic, and a panic here took down the enrolling
// daemon.
//
// Existing coverage missed it because TestCSRCreateTCG_CSR_IDEVID_WithIAKStrategy
// calls t.Skip in exactly the configuration that triggers it.
func TestCreateTCG_CSR_IDEVID_NilIDevIDAttributes_ReturnsTypedError(t *testing.T) {
	h := newCSRHarness(t)

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	ekCert := selfSignedCertForKey(t, ekPub)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		_, err = h.TPM.CreateTCG_CSR_IDEVID(ekCert, iakAttrs, nil)
	}, "nil IDevID attributes must be rejected with an error, not a panic")
	assert.ErrorIs(t, err, ErrIDevIDConfigNil,
		"the error must name the nil IDevID configuration")
}

// TestCreateTCG_CSR_IDEVID_NilAKAttributes_ReturnsTypedError is the companion
// guard: the attestation key attributes are dereferenced on the same path and
// must be checked too.
func TestCreateTCG_CSR_IDEVID_NilAKAttributes_ReturnsTypedError(t *testing.T) {
	h := newCSRHarness(t)

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	ekCert := selfSignedCertForKey(t, ekPub)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		_, err = h.TPM.CreateTCG_CSR_IDEVID(ekCert, nil, iakAttrs)
	}, "nil AK attributes must be rejected with an error, not a panic")
	assert.ErrorIs(t, err, ErrIAKConfigNil)
}

// TestCreateTCG_CSR_IDEVID_NilEKCert_ReturnsTypedError is the control showing
// the nil check that IS present works correctly, which is what the missing
// idevidAttrs check should look like.
func TestCreateTCG_CSR_IDEVID_NilEKCert_ReturnsTypedError(t *testing.T) {
	h := newCSRHarness(t)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	_, err = h.TPM.CreateTCG_CSR_IDEVID(nil, iakAttrs, iakAttrs)
	assert.ErrorIs(t, err, ErrInvalidEKCert,
		"a nil EK certificate is correctly reported as a typed error")
}

// TestTCGCSR_MarshalUnmarshal_RoundTripsExactly proves the TCG-CSR-IDEVID wire
// encoding is lossless. The CSR crosses a network boundary between a device and
// its CA, so any field dropped or mis-sized in the big-endian encoding would
// make the CA verify a different structure than the device signed.
func TestTCGCSR_MarshalUnmarshal_RoundTripsExactly(t *testing.T) {
	h := newCSRHarness(t)
	original := buildDeviceCSR(t, h)

	encoded, err := original.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	decoded, err := UnmarshalIDevIDCSR(encoded)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Fixed-width header fields must survive byte for byte.
	assert.Equal(t, original.StructVer, decoded.StructVer)
	assert.Equal(t, original.Contents, decoded.Contents)
	assert.Equal(t, original.SigSz, decoded.SigSz)

	// Every length field and variable-length payload in the contents must match.
	oc, dc := original.CsrContents, decoded.CsrContents
	assert.Equal(t, oc.StructVer, dc.StructVer)
	assert.Equal(t, oc.HashAlgoId, dc.HashAlgoId)
	assert.Equal(t, oc.HashSz, dc.HashSz)
	assert.Equal(t, oc.ProdModelSz, dc.ProdModelSz)
	assert.Equal(t, oc.ProdSerialSz, dc.ProdSerialSz)
	assert.Equal(t, oc.EkCertSZ, dc.EkCertSZ)
	assert.Equal(t, oc.AttestPubSZ, dc.AttestPubSZ)
	assert.Equal(t, oc.SigningPubSZ, dc.SigningPubSZ)

	assert.Equal(t, oc.ProdModel, dc.ProdModel)
	assert.Equal(t, oc.ProdSerial, dc.ProdSerial)
	assert.Equal(t, oc.EkCert, dc.EkCert, "the EK certificate must survive the round trip")
	assert.Equal(t, oc.AttestPub, dc.AttestPub, "the IAK public area must survive the round trip")
	assert.Equal(t, oc.SigningPub, dc.SigningPub)

	// Re-marshalling the decoded structure must reproduce the same bytes,
	// which is what makes the signature over it reproducible.
	reencoded, err := decoded.Marshal()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(encoded, reencoded),
		"re-marshalling a decoded CSR must reproduce identical bytes")
}

// TestTCGCSR_PackUnpackContent_ZeroLengthTrailingField_RoundTrips is the
// self-round-trip regression test for the TCG_IDEVID_CONTENT codec.
//
// UnpackIDevIDContent read every variable-length field with reader.Read.
// bytes.Reader.Read checks its position before the requested length, so a
// zero-length read at EOF returns io.EOF rather than (0, nil). The trailing Pad
// field is empty whenever config.IDevID.Pad is false -- the default -- so
// content produced by PackIDevIDContent could not be read back by
// UnpackIDevIDContent in the product's own default configuration.
//
// It was masked inside UnmarshalIDevIDCSR only because the signature follows
// the content there, so the final read is never at EOF. It bit any caller that
// packed and unpacked content on its own. io.ReadFull returns (0, nil) for an
// empty buffer, which fixes this and the short-read hole below together.
func TestTCGCSR_PackUnpackContent_ZeroLengthTrailingField_RoundTrips(t *testing.T) {
	h := newCSRHarness(t)
	csr := buildDeviceCSR(t, h)

	require.Zero(t, bytesToUint32(csr.CsrContents.PadSz),
		"precondition: padding is disabled so the trailing Pad field is empty")

	packed, err := PackIDevIDContent(&csr.CsrContents)
	require.NoError(t, err, "packing must succeed")
	require.NotEmpty(t, packed)

	unpacked, err := UnpackIDevIDContent(bytes.NewReader(packed))
	require.NoError(t, err,
		"content packed by PackIDevIDContent must be readable by UnpackIDevIDContent")
	require.NotNil(t, unpacked)

	assert.Equal(t, csr.CsrContents.EkCert, unpacked.EkCert,
		"the EK certificate must survive a self round trip")
	assert.Equal(t, csr.CsrContents.AttestPub, unpacked.AttestPub,
		"the IAK public area must survive a self round trip")
}

// TestTCGCSR_PackUnpackContent_RoundTripsWhenTrailingBytesFollow proves the
// codec itself is otherwise correct: give the reader one extra byte after the
// content -- exactly the situation inside UnmarshalIDevIDCSR, where the
// signature follows -- and every field round-trips faithfully. This isolates
// the defect above to the zero-length-read-at-EOF case rather than a general
// encoding fault.
func TestTCGCSR_PackUnpackContent_RoundTripsWhenTrailingBytesFollow(t *testing.T) {
	h := newCSRHarness(t)
	csr := buildDeviceCSR(t, h)

	packed, err := PackIDevIDContent(&csr.CsrContents)
	require.NoError(t, err)

	withTrailer := append(append([]byte(nil), packed...), 0x00)

	unpacked, err := UnpackIDevIDContent(bytes.NewReader(withTrailer))
	require.NoError(t, err)
	require.NotNil(t, unpacked)

	assert.Equal(t, csr.CsrContents.HashAlgoId, unpacked.HashAlgoId)
	assert.Equal(t, csr.CsrContents.EkCert, unpacked.EkCert,
		"the EK certificate must round-trip")
	assert.Equal(t, csr.CsrContents.AttestPub, unpacked.AttestPub,
		"the attestation public area must round-trip")
	assert.Equal(t, csr.CsrContents.ProdSerial, unpacked.ProdSerial)

	repacked, err := PackIDevIDContent(unpacked)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(packed, repacked),
		"re-packing unpacked content must reproduce identical bytes")
}

// TestUnpackIDevIDContent_ShortRead_IsRejected is the truncation regression
// test, and the security-relevant one in this file.
//
// UnpackIDevIDContent read every variable-length field with
//
//	if _, err := reader.Read(content.Pad); err != nil { ... }
//
// discarding the byte count. bytes.Reader.Read may return fewer bytes than
// requested with a nil error, so a message declaring a large field while
// carrying only part of it was accepted, with the unread tail of the
// destination left zero-filled. A verifier then parsed attacker-chosen
// truncated input into a structure it believed was complete. All fifteen read
// sites now use io.ReadFull, which reports a short read as io.ErrUnexpectedEOF.
//
// The content here is built by hand so exactly one field is short: every size
// is zero except the trailing Pad, which declares 100 bytes while only 50
// follow. Every zero-length read therefore happens while bytes remain, which
// isolates the short-read case from the zero-length-at-EOF case above.
func TestUnpackIDevIDContent_ShortRead_IsRejected(t *testing.T) {
	const declaredPad = 100
	const suppliedPad = 50

	// 16 four-byte size fields precede the variable-length payloads; only the
	// last (PadSz) is non-zero.
	header := make([]byte, 16*4)
	binary.BigEndian.PutUint32(header[15*4:], declaredPad)

	payload := bytes.Repeat([]byte{0xAA}, suppliedPad)
	blob := append(header, payload...)

	content, err := UnpackIDevIDContent(bytes.NewReader(blob))
	require.Error(t, err,
		"a blob declaring %d pad bytes but carrying %d must be rejected, not "+
			"zero-filled", declaredPad, suppliedPad)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF,
		"a truncated field must surface as a short read")
	assert.Nil(t, content,
		"no partially populated structure may escape to a verifier")
}

// TestUnpackIDevIDContent_ExactLength_IsAccepted is the companion proving the
// rejection above is not over-broad: the same shape with the declared number of
// bytes actually present must parse.
func TestUnpackIDevIDContent_ExactLength_IsAccepted(t *testing.T) {
	const padLen = 100

	header := make([]byte, 16*4)
	binary.BigEndian.PutUint32(header[15*4:], padLen)

	payload := bytes.Repeat([]byte{0xAA}, padLen)
	blob := append(header, payload...)

	content, err := UnpackIDevIDContent(bytes.NewReader(blob))
	require.NoError(t, err, "a complete blob must parse")
	require.NotNil(t, content)
	assert.Equal(t, payload, content.Pad,
		"the declared bytes must be read faithfully")
}

// TestUnpackIDevIDCSR_ConvertsFixedWidthFieldsToIntegers proves the unpacked
// view decodes the big-endian length fields consistently with the payloads they
// describe. A verifier reads lengths from here to slice the payloads, so a
// disagreement would let it read the wrong bytes.
func TestUnpackIDevIDCSR_ConvertsFixedWidthFieldsToIntegers(t *testing.T) {
	h := newCSRHarness(t)
	csr := buildDeviceCSR(t, h)

	unpacked, err := UnpackIDevIDCSR(csr)
	require.NoError(t, err)
	require.NotNil(t, unpacked)

	assert.Equal(t, int(unpacked.SigSz), len(unpacked.Signature),
		"the declared signature size must match the signature actually carried")
	assert.Equal(t, int(unpacked.CsrContents.EkCertSZ), len(unpacked.CsrContents.EkCert),
		"the declared EK certificate size must match the certificate carried")
	assert.Equal(t, int(unpacked.CsrContents.AttestPubSZ), len(unpacked.CsrContents.AttestPub),
		"the declared attestation public area size must match the area carried")

	assert.NotZero(t, unpacked.CsrContents.HashAlgoId, "a hash algorithm must be declared")
	assert.NotEmpty(t, unpacked.Signature, "the CSR must be signed")
}

// TestUnmarshalIDevIDCSR_MalformedInput_Rejected proves truncated or garbage
// input is refused rather than yielding a partially-populated structure. This
// is the CA's first contact with untrusted, attacker-controlled bytes, so it
// must fail closed.
func TestUnmarshalIDevIDCSR_MalformedInput_Rejected(t *testing.T) {
	for name, input := range map[string][]byte{
		"empty":                    {},
		"truncated struct version": {0x00},
		"header only":              {0x00, 0x00, 0x00, 0x01},
		"two header fields":        bytes.Repeat([]byte{0x00}, 8),
		"random bytes":             bytes.Repeat([]byte{0xAB}, 11),
	} {
		t.Run(name, func(t *testing.T) {
			csr, err := UnmarshalIDevIDCSR(input)
			require.Error(t, err, "malformed CSR bytes must be rejected")
			assert.Nil(t, csr)
		})
	}
}

// TestUnmarshalIDevIDCSR_TruncatedBody_Rejected proves a CSR whose header
// promises more content than the message actually carries is refused. Accepting
// it would let an attacker control how a verifier slices the remaining bytes.
func TestUnmarshalIDevIDCSR_TruncatedBody_Rejected(t *testing.T) {
	h := newCSRHarness(t)
	csr := buildDeviceCSR(t, h)

	encoded, err := csr.Marshal()
	require.NoError(t, err)
	require.Greater(t, len(encoded), 32)

	// Cut the message in half: the header still declares the full sizes.
	truncated := encoded[:len(encoded)/2]
	decoded, err := UnmarshalIDevIDCSR(truncated)
	require.Error(t, err, "a CSR truncated mid-body must be rejected")
	assert.Nil(t, decoded)
}

// TestVerifyTCGCSR_AcceptsGenuineCSRAndRejectsTampering is the core security
// property of device enrollment: a CSR really signed by the device's IAK must
// verify, and any modification to the signed content must make verification
// fail. Without the negative half, a verifier that ignored the signature
// entirely would still pass.
func TestVerifyTCGCSR_AcceptsGenuineCSRAndRejectsTampering(t *testing.T) {
	h := newCSRHarness(t)
	csr := buildDeviceCSR(t, h)

	// The genuine CSR verifies and yields the enrolling key's attributes.
	attrs, unpacked, err := h.TPM.VerifyTCGCSR(csr, x509.SHA256WithRSAPSS)
	require.NoError(t, err, "a CSR signed by the device IAK must verify")
	require.NotNil(t, attrs)
	require.NotNil(t, unpacked)

	t.Run("tampered signature", func(t *testing.T) {
		bad := *csr
		bad.Signature = append([]byte(nil), csr.Signature...)
		require.NotEmpty(t, bad.Signature)
		bad.Signature[0] ^= 0xFF

		gotAttrs, gotUnpacked, err := h.TPM.VerifyTCGCSR(&bad, x509.SHA256WithRSAPSS)
		require.Error(t, err, "a CSR with a corrupted signature must not verify")
		assert.Nil(t, gotAttrs)
		assert.Nil(t, gotUnpacked)
	})

	t.Run("tampered product serial", func(t *testing.T) {
		// Modify signed content without touching the signature. The device
		// serial ends up in the issued certificate, so silently accepting a
		// changed serial would let an attacker mint a certificate for another
		// device's identity.
		bad := *csr
		bad.CsrContents = csr.CsrContents
		bad.CsrContents.ProdSerial = append([]byte(nil), csr.CsrContents.ProdSerial...)
		require.NotEmpty(t, bad.CsrContents.ProdSerial)
		bad.CsrContents.ProdSerial[0] ^= 0xFF

		gotAttrs, _, err := h.TPM.VerifyTCGCSR(&bad, x509.SHA256WithRSAPSS)
		require.Error(t, err, "modified signed content must invalidate the signature")
		assert.Nil(t, gotAttrs)
	})

	t.Run("substituted attestation public key", func(t *testing.T) {
		// Swapping in a different IAK public area while keeping the original
		// signature is the classic key-substitution attack: the CA must not
		// issue a certificate binding the device identity to an attacker key.
		bad := *csr
		bad.CsrContents = csr.CsrContents
		bad.CsrContents.AttestPub = append([]byte(nil), csr.CsrContents.AttestPub...)
		require.Greater(t, len(bad.CsrContents.AttestPub), 8)
		bad.CsrContents.AttestPub[len(bad.CsrContents.AttestPub)-1] ^= 0xFF

		gotAttrs, _, err := h.TPM.VerifyTCGCSR(&bad, x509.SHA256WithRSAPSS)
		require.Error(t, err,
			"a substituted attestation public key must not verify against the original signature")
		assert.Nil(t, gotAttrs)
	})
}

// TestParseIdentityProvisioningStrategy_UnknownValue_FailsClosed is the
// fail-open regression test.
//
// The default arm used to return EnrollmentStrategyIAK_IDEVID_SINGLE_PASS:
//
//	default:
//	        return EnrollmentStrategyIAK_IDEVID_SINGLE_PASS
//
// so a typo in identity-provisioning-strategy silently selected the single-pass
// IAK+IDevID ceremony instead of whatever the operator intended, with no
// diagnostic. Two consequences followed:
//
//  1. An operator who configured IAK-only enrollment silently got a different
//     device-identity ceremony than they asked for.
//  2. ErrInvalidEnrollmentStrategy, returned by the default branch of
//     VerifyTCGCSR and CreateTCG_CSR_IDEVID, was unreachable dead code --
//     nothing could produce the unknown value those branches guard against.
//
// An unset value must still select the documented 6.2 default; only a value the
// operator typed and got wrong fails closed.
func TestParseIdentityProvisioningStrategy_UnknownValue_FailsClosed(t *testing.T) {
	for _, input := range []string{
		"not-a-real-strategy",
		"iak", // wrong case
		"iak-idevid",
	} {
		assert.Equal(t, EnrollmentStrategyUnknown, ParseIdentityProvisioningStrategy(input),
			"%q is not a valid strategy and must not be mapped to a real ceremony", input)
	}

	// Unset selects the documented default rather than failing.
	assert.Equal(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		ParseIdentityProvisioningStrategy(""))

	// The two documented values still map correctly.
	assert.Equal(t, EnrollmentStrategyIAK,
		ParseIdentityProvisioningStrategy(string(EnrollmentStrategyIAK)))
	assert.Equal(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		ParseIdentityProvisioningStrategy(string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)))
}

// TestVerifyTCGCSR_UnknownStrategy_ReportsInvalidStrategy is the end-to-end
// consequence, and the assertion that makes ErrInvalidEnrollmentStrategy
// reachable again.
//
// A misconfigured strategy used to route to the single-pass verifier, which
// then failed for an unrelated reason -- the CSR had been signed under a
// different ceremony -- producing a diagnostic that pointed at the CSR rather
// than at the configuration. The operator must now be told the strategy is
// invalid.
func TestVerifyTCGCSR_UnknownStrategy_ReportsInvalidStrategy(t *testing.T) {
	h := newCSRHarness(t)
	csr := buildDeviceCSR(t, h)

	saved := h.TPM.config.IdentityProvisioningStrategy
	h.TPM.config.IdentityProvisioningStrategy = "not-a-real-strategy"
	t.Cleanup(func() { h.TPM.config.IdentityProvisioningStrategy = saved })

	attrs, unpacked, err := h.TPM.VerifyTCGCSR(csr, x509.SHA256WithRSAPSS)
	require.Error(t, err)
	assert.Nil(t, attrs)
	assert.Nil(t, unpacked)
	assert.ErrorIs(t, err, ErrInvalidEnrollmentStrategy,
		"a misconfigured strategy must be reported as such, not as a CSR failure")
}

// TestCreateTCG_CSR_IDEVID_UnknownStrategy_ReportsInvalidStrategy is the same
// guard on the creation side, which has its own strategy switch.
func TestCreateTCG_CSR_IDEVID_UnknownStrategy_ReportsInvalidStrategy(t *testing.T) {
	h := newCSRHarness(t)

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	ekCert := selfSignedCertForKey(t, ekPub)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	saved := h.TPM.config.IdentityProvisioningStrategy
	h.TPM.config.IdentityProvisioningStrategy = "typo-strategy"
	t.Cleanup(func() { h.TPM.config.IdentityProvisioningStrategy = saved })

	_, err = h.TPM.CreateTCG_CSR_IDEVID(ekCert, iakAttrs, iakAttrs)
	assert.ErrorIs(t, err, ErrInvalidEnrollmentStrategy)
}

// TestVerifyTCG_CSR_IAK_MalformedAttestationKey_Rejected proves the verifier
// refuses a CSR whose attestation public area cannot be parsed, rather than
// proceeding with a zero-valued key.
func TestVerifyTCG_CSR_IAK_MalformedAttestationKey_Rejected(t *testing.T) {
	h := newCSRHarness(t)
	csr := buildDeviceCSR(t, h)

	bad := *csr
	bad.CsrContents = csr.CsrContents
	bad.CsrContents.AttestPub = []byte{0xFF, 0xFF, 0xFF, 0xFF}

	attrs, unpacked, err := h.TPM.VerifyTCG_CSR_IAK(&bad, x509.SHA256WithRSAPSS)
	require.Error(t, err, "an unparseable attestation public area must be rejected")
	assert.Nil(t, attrs)
	assert.Nil(t, unpacked)
}

// TestVerifyTCG_CSR_IAK_InvalidHashAlgorithm_Rejected proves a CSR declaring a
// hash algorithm the TPM does not recognise is refused. An attacker-chosen
// algorithm identifier must not reach the hash construction path.
func TestVerifyTCG_CSR_IAK_InvalidHashAlgorithm_Rejected(t *testing.T) {
	h := newCSRHarness(t)
	csr := buildDeviceCSR(t, h)

	bad := *csr
	bad.CsrContents = csr.CsrContents
	// 0xFFFFFFFF is not a valid TPM_ALG_ID and exceeds the uint16 the field
	// is narrowed to, exercising the explicit range guard.
	bad.CsrContents.HashAlgoId = [4]byte{0xFF, 0xFF, 0xFF, 0xFF}

	attrs, unpacked, err := h.TPM.VerifyTCG_CSR_IAK(&bad, x509.SHA256WithRSAPSS)
	require.Error(t, err, "an out-of-range hash algorithm ID must be rejected")
	assert.Nil(t, attrs)
	assert.Nil(t, unpacked)
}
