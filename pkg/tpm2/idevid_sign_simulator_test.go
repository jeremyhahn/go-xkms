//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers which bytes TPM2_Sign is actually asked to sign for each of
// the two device identity keys, on a real (simulated) TPM that owns both.
//
// TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.10 r9 makes the IAK
// Restricted and the IDevID Unrestricted, and the difference is the whole point
// of having two keys: a restricted key may sign nothing but a digest the TPM
// produced, while an unrestricted one signs whatever its owner hands it. The
// sibling file idevid_csr_simulator_test.go covers the enrollment ceremonies,
// which reach the TPM through SignValidate; this file covers Sign, which is the
// crypto.Signer entry point every TLS stack uses.
//
// Each test owns exactly one simulator via newSimHarness; the go-tpm-tools
// simulator is a process-global singleton so only one may be live at a time.

// signHarness is a provisioned simulator-backed TPM2 that owns an IAK and an
// RSASSA IDevID.
//
// The IDevID here is deliberately PKCS#1 v1.5 rather than the PSS key
// newIdentityHarness builds: a v1.5 signature can be verified with nothing but
// the public key and the digest, which is exactly the question these tests ask.
// The PSS path adds a salt-length and FIPS negotiation that would obscure it.
type signHarness struct {
	*simHarness

	// IAK is the restricted attestation key that Provision created.
	IAK *types.KeyAttributes

	// IDevID is the unrestricted device identity signing key.
	IDevID *types.KeyAttributes

	// IDevIDPublic is the IDevID's public key, as the TPM reported it.
	IDevIDPublic *rsa.PublicKey

	// IAKPublic is the IAK's public key, as the TPM reported it.
	IAKPublic *rsa.PublicKey
}

// newSignHarness provisions a TPM and mints an IDevID on top of it. Any failure
// here is a broken test environment, not a reason to stop testing, so every
// step is fatal.
func newSignHarness(t *testing.T) *signHarness {
	t.Helper()

	h := newSimHarness(t, func(c *Config) {
		c.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)

		// CreateIDevID unpacks the IAK's certification signature under the
		// IDevID's configured padding (see the isRSAPSS branch in key.go), so
		// the two have to agree for the harness to build at all.
		c.IAK.SignatureAlgorithm = x509.SHA256WithRSA.String()
		c.IDevID = &IDevIDConfig{
			CN:                 "device-id-001",
			Debug:              true,
			Hash:               crypto.SHA256.String(),
			Handle:             0x81020000,
			KeyAlgorithm:       x509.RSA.String(),
			Manufacturer:       "ATT",
			Model:              "xkms-test-device",
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			Serial:             "SN-0000-0001",
			SignatureAlgorithm: x509.SHA256WithRSA.String(),
		}
	})

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err, "provisioning must leave a usable IAK behind")

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err, "the provisioned EK must be readable")
	ekCert := selfSignedCertForKey(t, ekPub)

	idevidAttrs, _, err := h.TPM.CreateIDevID(iakAttrs, ekCert, nil)
	require.NoError(t, err, "the TPM must be able to mint an IDevID")
	require.NotNil(t, idevidAttrs)

	return &signHarness{
		simHarness:   h,
		IAK:          iakAttrs,
		IDevID:       idevidAttrs,
		IDevIDPublic: rsaPublicKeyOf(t, idevidAttrs),
		IAKPublic:    rsaPublicKeyOf(t, iakAttrs),
	}
}

// rsaPublicKeyOf parses the PKIX public key the TPM reported for a key.
func rsaPublicKeyOf(t *testing.T, attrs *types.KeyAttributes) *rsa.PublicKey {
	t.Helper()

	require.NotNil(t, attrs.TPMAttributes)
	require.NotEmpty(t, attrs.TPMAttributes.PublicKeyBytes,
		"the TPM must have reported a public key for %s", attrs.CN)

	pub, err := x509.ParsePKIXPublicKey(attrs.TPMAttributes.PublicKeyBytes)
	require.NoError(t, err)

	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok, "%s must be an RSA key", attrs.CN)
	return rsaPub
}

// tlsCertificateVerifyDigest builds the digest a TLS 1.3 client signs in its
// CertificateVerify message (RFC 8446, section 4.4.3): 64 spaces, the context
// string, a single zero byte, then the handshake transcript hash -- all hashed
// once. The caller of crypto.Signer.Sign hands this digest over already
// computed, which is precisely the input the IDevID has to sign verbatim.
func tlsCertificateVerifyDigest(transcript []byte) []byte {
	content := make([]byte, 0, 64+33+1+len(transcript))
	for i := 0; i < 64; i++ {
		content = append(content, 0x20)
	}
	content = append(content, []byte("TLS 1.3, client CertificateVerify")...)
	content = append(content, 0x00)
	content = append(content, transcript...)

	digest := sha256.Sum256(content)
	return digest[:]
}

// TestSign_IDevID_SignsTheCallersDigestVerbatim is the regression test for the
// defect this file was added for: the IDevID was routed through the restricted
// signing key's hash-ticket path, where the caller's digest is hashed a second
// time inside the TPM. The resulting signature is over H(digest), so no peer
// computing over digest can verify it -- a TLS CertificateVerify signed with a
// device's IDevID was rejected by every server that received one.
//
// The assertions pin both directions. Verifying over digest must succeed, and
// verifying over sha256(digest) must fail: without the second assertion this
// test would still pass if the two were ever confused again in the other
// direction.
func TestSign_IDevID_SignsTheCallersDigestVerbatim(t *testing.T) {
	h := newSignHarness(t)

	transcript := sha256.Sum256([]byte("handshake transcript"))
	digest := tlsCertificateVerifyDigest(transcript[:])

	signature, err := h.TPM.Sign(rand.Reader, digest, &store.SignerOpts{
		KeyAttributes: h.IDevID,
		Backend:       h.Backend,
	})
	require.NoError(t, err,
		"an unrestricted IDevID must be able to sign an externally supplied digest")
	require.NotEmpty(t, signature)

	t.Run("verifies over the digest the caller supplied", func(t *testing.T) {
		err := rsa.VerifyPKCS1v15(h.IDevIDPublic, crypto.SHA256, digest, signature)
		assert.NoError(t, err,
			"the signature must verify over the caller's digest; a TLS peer computes over exactly these bytes")
	})

	t.Run("does not verify over a digest of the digest", func(t *testing.T) {
		rehashed := sha256.Sum256(digest)
		err := rsa.VerifyPKCS1v15(h.IDevIDPublic, crypto.SHA256, rehashed[:], signature)
		assert.Error(t, err,
			"a signature over H(digest) is the defect this test exists to catch")
	})
}

// TestSign_IDevID_RejectsAWrongLengthDigest covers the error path of the same
// branch. TPM2_Sign requires the digest to be the size of the hash its scheme
// names and answers anything else with TPM_RC_SIZE; the package checks it first
// so the caller is told which length was expected.
func TestSign_IDevID_RejectsAWrongLengthDigest(t *testing.T) {
	h := newSignHarness(t)

	signature, err := h.TPM.Sign(rand.Reader, make([]byte, 48), &store.SignerOpts{
		KeyAttributes: h.IDevID,
		Backend:       h.Backend,
	})
	require.Error(t, err, "a SHA-384 sized digest cannot be signed under a SHA-256 scheme")
	assert.ErrorIs(t, err, ErrDigestLengthMismatch)
	assert.Nil(t, signature)
}

// TestSign_IAK_StillUsesTheTicketedPath is the companion that keeps the fix
// from being a security regression.
//
// A restricted signing key may only sign a digest the TPM produced, so the IAK
// hands its data to TPM2_Hash and signs the digest that comes back under the
// TPMT_TK_HASHCHECK ticket. That behaviour must survive unchanged: the
// signature is over H(data), and asserting it verifies there -- and not over
// data treated as a digest -- pins the restricted path from both sides.
func TestSign_IAK_StillUsesTheTicketedPath(t *testing.T) {
	h := newSignHarness(t)

	// The IAK's public area fixes SHA-256, so that is the only digest its
	// scheme can name.
	h.IAK.Hash = crypto.SHA256

	data := []byte("attestation payload the TPM will hash for us")
	hashed := sha256.Sum256(data)

	signature, err := h.TPM.Sign(rand.Reader, data, &store.SignerOpts{
		KeyAttributes: h.IAK,
		Backend:       h.Backend,
	})
	require.NoError(t, err, "the IAK must still sign through the hash-ticket path")
	require.NotEmpty(t, signature)

	t.Run("signs the digest the TPM produced", func(t *testing.T) {
		err := rsa.VerifyPKCS1v15(h.IAKPublic, crypto.SHA256, hashed[:], signature)
		assert.NoError(t, err,
			"a restricted key signs the digest TPM2_Hash returned, not the bytes it was handed")
	})

	t.Run("does not sign its input as though it were a digest", func(t *testing.T) {
		// Only a 32-byte input could be mistaken for a SHA-256 digest, so this
		// asserts the shape of the path rather than a second verification:
		// reaching the unrestricted path with this input would have failed
		// outright on the digest length.
		padded := make([]byte, 32)
		copy(padded, data)

		err := rsa.VerifyPKCS1v15(h.IAKPublic, crypto.SHA256, padded, signature)
		assert.Error(t, err)
	})
}

// TestSign_IAK_RefusesTPMGeneratedData covers the forgery guard the restricted
// path exists for.
//
// TPM2_Hash withholds its ticket -- answering with a NULL ticket -- when the
// data it hashed begins with TPM_GENERATED_VALUE, so that a restricted key
// cannot be lent to forging something shaped like the TPM's own attestation
// output (TCG TPM 2.0 Library Part 3, section 16.1). The package used to
// discard the result of that call and send the empty ticket on under the
// endorsement hierarchy, which earned a bare TPM_RC_TICKET naming a parameter
// number. It must report the refusal itself.
func TestSign_IAK_RefusesTPMGeneratedData(t *testing.T) {
	h := newSignHarness(t)

	h.IAK.Hash = crypto.SHA256

	// TPM_GENERATED_VALUE is 0xFF544347 ("\xffTCG"), the magic every structure
	// the TPM signs itself begins with.
	forged := append([]byte{0xFF, 0x54, 0x43, 0x47}, []byte("forged attestation structure")...)

	signature, err := h.TPM.Sign(rand.Reader, forged, &store.SignerOpts{
		KeyAttributes: h.IAK,
		Backend:       h.Backend,
	})
	require.Error(t, err,
		"a restricted key must not sign externally supplied attestation-shaped data")
	assert.ErrorIs(t, err, ErrRestrictedSignRefused)
	assert.Nil(t, signature)
}
