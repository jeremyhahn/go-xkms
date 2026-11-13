//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file measures on a real (simulated) TPM the claims the DevID templates
// rest on, rather than asserting them from the specification's text:
//
//   - that the unique string of section 7.3.1 changes the created key's Name,
//     which is the whole reason the specification requires it and the reason
//     adopting it re-keys every device identity;
//   - that "scheme->details = NULL" of Templates H-2 through H-4 cannot be
//     created at all, which is why those templates name a hash;
//   - that a TPM_ALG_NULL scheme IDevID -- Template H-1 for a signing DevID --
//     signs under a scheme supplied per TPM2_Sign command, in both paddings;
//   - that the templates the creation paths build are the templates the keys
//     they ship are derived from.
//
// Each test owns exactly one simulator; the go-tpm-tools simulator is a
// process-global singleton so only one may be live at a time.

// createDevIDPrimary creates a primary key from a DevID template on a bare
// simulator, with the template's key policy assigned as the creation path
// assigns it, and returns the Name the TPM derived.
func createDevIDPrimary(t *testing.T, sim SimulatorInterface, spec DevIDTemplateSpec) tpm2.TPM2BName {
	t.Helper()
	template, err := spec.Template()
	require.NoError(t, err)
	policy, err := DevIDKeyPolicyDigest(spec.Kind, template.NameAlg)
	require.NoError(t, err)
	template.AuthPolicy = tpm2.TPM2BDigest{Buffer: policy}
	require.NoError(t, assertDevIDTemplateConformant(spec.Kind, template))

	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(template),
	}.Execute(sim.Transport())
	require.NoError(t, err, "the template must be creatable")
	// Flush at once rather than at the end of the test: the simulator holds
	// only a handful of transient object contexts, and several of these keys
	// are created in one test.
	_, err = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(sim.Transport())
	require.NoError(t, err)
	return rsp.Name
}

// TestDevIDTemplate_UniqueChangesTheName is the measurement the whole change
// rests on.
//
// Section 7.3.1 requires the unique field to carry 'IDEVID' or 'IAK' precisely
// so that a device's identity keys are reproducible by anyone following the
// specification -- which only means anything if the field reaches the
// derivation. It does: the same template with a different unique produces a
// different Name on the same TPM, from the same Endorsement Primary Seed. That
// is also why adopting the string re-keys every device already provisioned.
func TestDevIDTemplate_UniqueChangesTheName(t *testing.T) {
	sim, err := OpenSimulator()
	require.NoError(t, err)
	defer sim.Close()

	spec := DevIDTemplateSpec{Kind: DevIDKeySigning, Algorithm: x509.RSA}
	withString := createDevIDPrimary(t, sim, spec)

	// The template this package created before the string was implemented:
	// the same key in every other respect, with unique zero-filled to the
	// modulus size.
	zeroed, err := spec.Template()
	require.NoError(t, err)
	policy, err := DevIDKeyPolicyDigest(DevIDKeySigning, zeroed.NameAlg)
	require.NoError(t, err)
	zeroed.AuthPolicy = tpm2.TPM2BDigest{Buffer: policy}
	zeroed.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)})
	zeroedRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
		InPublic:      tpm2.New2B(zeroed),
	}.Execute(sim.Transport())
	require.NoError(t, err)
	_, err = tpm2.FlushContext{FlushHandle: zeroedRsp.ObjectHandle}.Execute(sim.Transport())
	require.NoError(t, err)

	assert.NotEqual(t,
		hex.EncodeToString(zeroedRsp.Name.Buffer),
		hex.EncodeToString(withString.Buffer),
		"the unique field is a derivation input: setting 'IDEVID' re-keys the device")

	// The optional device string of section 7.3.1 does the same, which is what
	// makes it per-device.
	withDevice := createDevIDPrimary(t, sim, DevIDTemplateSpec{
		Kind:         DevIDKeySigning,
		Algorithm:    x509.RSA,
		DeviceString: "SN-0000-0001",
	})
	assert.NotEqual(t,
		hex.EncodeToString(withString.Buffer),
		hex.EncodeToString(withDevice.Buffer),
		"the device string is a derivation input too")

	// And it is deterministic: the same template recreates the same key, which
	// is what "Recoverable" means in section 7.2.1.
	again := createDevIDPrimary(t, sim, DevIDTemplateSpec{
		Kind:         DevIDKeySigning,
		Algorithm:    x509.RSA,
		DeviceString: "SN-0000-0001",
	})
	assert.Equal(t,
		hex.EncodeToString(withDevice.Buffer),
		hex.EncodeToString(again.Buffer),
		"a Recoverable key is recreated by recreating its template")
}

// TestDevIDTemplate_ECDSANullDetailsIsRefusedByTheTPM measures the conflict
// documented in DevIDTemplateSpec.eccTemplate.
//
// Templates H-2, H-3 and H-4 all say "scheme->scheme = TPM_ALG_ECDSA" AND
// "scheme->details = NULL". No TPM can carry both: the details of an ECDSA
// TPMT_ECC_SCHEME are a TPMS_SIG_SCHEME_ECDSA, whose hashAlg is a
// TPMI_ALG_HASH with no "+" decoration, so TPM_ALG_NULL is not admissible
// there. The TPM answers TPM_RC_HASH on inPublic, for every curve.
//
// **Do not "fix" the templates back to a NULL details.** They name the
// template's nameAlg instead, which is the pairing the specification itself
// uses when it names the suites in section 14 (Annex B, Table 24): "the ECDSA
// P-256/SHA-256 signature suite", "the ECDSA P-384/SHA-384 signature suite".
// This test is the reason that reading is not a guess: it is a measured fact
// with a failing command behind it rather than a claim in a comment, and a
// future TPM or go-tpm that accepts the pair announces itself by turning this
// red rather than by silently re-keying a fleet.
func TestDevIDTemplate_ECDSANullDetailsIsRefusedByTheTPM(t *testing.T) {
	sim, err := OpenSimulator()
	require.NoError(t, err)
	defer sim.Close()

	cases := []struct {
		name    string
		curve   elliptic.Curve
		curveID tpm2.TPMECCCurve
		nameAlg tpm2.TPMIAlgHash
	}{
		{"H-2 P-256", elliptic.P256(), tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256},
		{"H-3 P-384", elliptic.P384(), tpm2.TPMECCNistP384, tpm2.TPMAlgSHA384},
		{"H-4 P-521", elliptic.P521(), tpm2.TPMECCNistP521, tpm2.TPMAlgSHA512},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			template, err := DevIDTemplateSpec{
				Kind:      DevIDKeySigning,
				Algorithm: x509.ECDSA,
				Curve:     tc.curve,
			}.Template()
			require.NoError(t, err)
			policy, err := DevIDKeyPolicyDigest(DevIDKeySigning, template.NameAlg)
			require.NoError(t, err)
			template.AuthPolicy = tpm2.TPM2BDigest{Buffer: policy}

			// The literal table row: ECDSA with NULL details.
			setECCParms(&template, func(parms *tpm2.TPMSECCParms) {
				parms.Scheme = tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgNull}),
				}
			})

			_, err = tpm2.CreatePrimary{
				PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
				InPublic:      tpm2.New2B(template),
			}.Execute(sim.Transport())
			require.Error(t, err,
				"if this passes, scheme->details = NULL is creatable after all and the templates should carry it")
			assert.ErrorIs(t, err, tpm2.TPMRCHash)
		})
	}
}

// TestDevIDTemplate_EveryShippedSuiteCreates proves each exported template is
// a template a TPM will actually derive a key from -- including the P-384 and
// P-521 suites this change adds, which no other test would otherwise reach.
func TestDevIDTemplate_EveryShippedSuiteCreates(t *testing.T) {
	sim, err := OpenSimulator()
	require.NoError(t, err)
	defer sim.Close()

	specs := []struct {
		name string
		spec DevIDTemplateSpec
	}{
		{"H-1 RSA IDevID", DevIDTemplateSpec{Kind: DevIDKeySigning, Algorithm: x509.RSA}},
		{"H-1 RSASSA IAK", DevIDTemplateSpec{Kind: DevIDKeyAttestation, Algorithm: x509.RSA, Scheme: tpm2.TPMAlgRSASSA}},
		{"H-1 RSAPSS IAK", DevIDTemplateSpec{Kind: DevIDKeyAttestation, Algorithm: x509.RSA, Scheme: tpm2.TPMAlgRSAPSS}},
		{"H-2 P-256 IDevID", DevIDTemplateSpec{Kind: DevIDKeySigning, Algorithm: x509.ECDSA, Curve: elliptic.P256()}},
		{"H-2 P-256 IAK", DevIDTemplateSpec{Kind: DevIDKeyAttestation, Algorithm: x509.ECDSA, Curve: elliptic.P256()}},
		{"H-3 P-384 IDevID", DevIDTemplateSpec{Kind: DevIDKeySigning, Algorithm: x509.ECDSA, Curve: elliptic.P384()}},
		{"H-3 P-384 IAK", DevIDTemplateSpec{Kind: DevIDKeyAttestation, Algorithm: x509.ECDSA, Curve: elliptic.P384()}},
		{"H-4 P-521 IDevID", DevIDTemplateSpec{Kind: DevIDKeySigning, Algorithm: x509.ECDSA, Curve: elliptic.P521()}},
		{"H-4 P-521 IAK", DevIDTemplateSpec{Kind: DevIDKeyAttestation, Algorithm: x509.ECDSA, Curve: elliptic.P521()}},
	}
	names := make(map[string]string, len(specs))
	for _, tc := range specs {
		t.Run(tc.name, func(t *testing.T) {
			name := hex.EncodeToString(createDevIDPrimary(t, sim, tc.spec).Buffer)
			if other, clash := names[name]; clash {
				t.Errorf("%s derives the same key as %s; two suites are not distinct", tc.name, other)
			}
			names[name] = tc.name
		})
	}
}

// TestCreateIDevID_DerivesFromTheSpecTemplate closes the loop between the
// builder and the creation path: the key CreateIDevID persists is the key the
// template built from configuration derives, byte for byte, so a reader
// checking conformance against DevIDTemplateSpec is checking the shipped key.
func TestCreateIDevID_DerivesFromTheSpecTemplate(t *testing.T) {
	h := newSimHarness(t, func(c *Config) {
		c.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
		c.IDevID = idevidTestConfig("device-id-001", x509.SHA256WithRSA.String())
		c.DeviceString = "SN-0000-0001"
	})

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)

	idevidAttrs, _, err := h.TPM.CreateIDevID(iakAttrs, selfSignedCertForKey(t, ekPub), nil)
	require.NoError(t, err, "the configured device string must not stop the key being created")
	require.NotNil(t, idevidAttrs.TPMAttributes)

	readPub, err := tpm2.ReadPublic{ObjectHandle: idevidAttrs.TPMAttributes.Handle}.Execute(h.TPM.transport)
	require.NoError(t, err)

	// Rebuild the template from the same configuration and derive it again.
	// The endorsement seed has not changed, so the same template must give
	// the same Name.
	// The same endorsement authorization CreateIDevID used, resolved the same
	// way it resolves it.
	var hierarchyAuth []byte
	require.NotNil(t, iakAttrs.Parent, "the IAK's parent is the EK, which carries the endorsement auth")
	if iakAttrs.Parent.TPMAttributes != nil && iakAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = iakAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}

	template, err := DevIDTemplateSpec{
		Kind:         DevIDKeySigning,
		Algorithm:    x509.RSA,
		KeyBits:      2048,
		DeviceString: "SN-0000-0001",
	}.Template()
	require.NoError(t, err)
	policy, err := DevIDKeyPolicyDigest(DevIDKeySigning, template.NameAlg)
	require.NoError(t, err)
	template.AuthPolicy = tpm2.TPM2BDigest{Buffer: policy}

	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		InPublic: tpm2.New2B(template),
	}.Execute(h.TPM.transport)
	require.NoError(t, err)
	defer h.TPM.Flush(rsp.ObjectHandle)

	assert.Equal(t,
		hex.EncodeToString(readPub.Name.Buffer),
		hex.EncodeToString(rsp.Name.Buffer),
		"the persisted IDevID is derived from the DevIDTemplateSpec template")

	// The persisted key carries the Table 2 unique string's consequences, not
	// the string itself -- unique holds the derived modulus once the key
	// exists -- so what is checked here is the shape the template fixed.
	public, err := readPub.OutPublic.Contents()
	require.NoError(t, err)
	parms, err := public.Parameters.RSADetail()
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgNull, parms.Scheme.Scheme,
		"the shipped IDevID names no scheme, per Template H-1")
	assert.True(t, public.ObjectAttributes.AdminWithPolicy)
	assert.False(t, public.ObjectAttributes.Restricted)
}

// TestSign_IDevID_NullSchemeSignsBothPaddings is the behavioural half of the
// H-1 scheme change: a key that names no scheme takes one per TPM2_Sign
// command, which is what lets one device identity serve a PKCS#1 v1.5
// certificate signature and the RSA-PSS a TLS 1.3 handshake requires. Before
// the template named TPM_ALG_NULL, the second of these was impossible on the
// same key.
func TestSign_IDevID_NullSchemeSignsBothPaddings(t *testing.T) {
	h := newSimHarness(t, func(c *Config) {
		c.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
		c.IAK.SignatureAlgorithm = x509.SHA256WithRSA.String()
		c.IDevID = idevidTestConfig("device-id-001", x509.SHA256WithRSA.String())
	})

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	idevidAttrs, _, err := h.TPM.CreateIDevID(iakAttrs, selfSignedCertForKey(t, ekPub), nil)
	require.NoError(t, err)

	pub, err := x509.ParsePKIXPublicKey(idevidAttrs.TPMAttributes.PublicKeyBytes)
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)

	digest := sha256.Sum256([]byte("TLS 1.3 CertificateVerify transcript"))

	t.Run("PKCS#1 v1.5", func(t *testing.T) {
		signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
			KeyAttributes: idevidAttrs,
			Backend:       h.Backend,
		})
		require.NoError(t, err)
		assert.NoError(t, rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], signature))
	})

	t.Run("RSA-PSS on the same key", func(t *testing.T) {
		// A key whose template had named RSASSA would answer this request
		// with ErrSignSchemeMismatch, because inScheme has to match the key's
		// own scheme exactly (TCG TPM 2.0 Library Part 3, section 12.1).
		signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
			KeyAttributes: idevidAttrs,
			Backend:       h.Backend,
			PSSOptions: &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA256,
			},
		})
		require.NoError(t, err, "a TPM_ALG_NULL scheme key must be able to sign PSS")
		assert.NoError(t, rsa.VerifyPSS(rsaPub, crypto.SHA256, digest[:], signature,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}))
	})
}
