// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package tpm2

import (
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// This file is the single source of truth for the Recoverable IDevID/IAK key
// creation templates of TCG "TPM 2.0 Keys for Device Identity and
// Attestation", Version 1.00, Revision 12 (2021-10-08), section 7.3.4:
// Template H-0 (section 7.3.4.1, the common TPMA_OBJECT values), H-1 (RSA
// 2048, section 7.3.4.2), H-2 (ECC NIST P256, section 7.3.4.3), H-3 (ECC NIST
// P384, section 7.3.4.4) and H-4 (ECC NIST P521, section 7.3.4.5).
//
// Every field of a TPMT_PUBLIC is an input to a primary key's derivation, so a
// template that departs from the specification does not produce a slightly
// wrong key -- it produces a different key, under a different Name, that no
// other implementation of the specification can recreate. That is why the
// templates are built here rather than transcribed at each call site, and why
// assertDevIDTemplateConformant (key.go) re-checks the result of this builder
// immediately before TPM2_CreatePrimary.
//
// H-5 (ECC SM2 P256, section 7.3.4.6) is NOT implemented. It requires
// nameAlg = TPM_ALG_SM3_256 and curveID = TPM_ECC_SM2_P256; the reference
// simulator this package tests against refuses a template naming SM3_256 with
// TPM_RC_HASH, and crypto/elliptic cannot represent the SM2 curve, so a key on
// it could not be returned as the *ecdsa.PublicKey this package's creation API
// produces. Shipping an untestable template would be worse than saying so.
//
// A configuration that asks for it is refused, not silently substituted: an
// idevid.ecc.curve or iak.ecc.curve of "SM2" is rejected by types.ParseCurve
// with types.ErrUnknownCurve before it reaches this file, and any curve that
// does reach eccTemplate without a template is refused with
// ErrDevIDTemplateSuiteUnsupported.

// Unique strings for the IDevID/IAK key templates (section 7.3.1, Table 2):
//
//	Key Purpose   Required Unique String        Optional Unique String
//	IDevID        'IDEVID' (49 44 45 56 49 44)  'IDEVID'|<device_str>
//	IAK           'IAK'    (49 41 4B)           'IAK'|<device_str>
//
// "At the time of key creation, the unique field MUST be set to one of the
// strings shown in Table 2, indicating the key's purpose." Neither version of
// the string is NUL terminated -- the terminator is not supplied to the TPM --
// so these are used as their bare bytes and never padded out to the size of
// the unique field.
const (
	// DevIDUniqueIDevID is the required unique string of an IDevID key.
	DevIDUniqueIDevID = "IDEVID"

	// DevIDUniqueIAK is the required unique string of an IAK.
	DevIDUniqueIAK = "IAK"
)

// devidUniqueStrings maps each key kind onto the unique string Table 2
// requires of it.
var devidUniqueStrings = map[DevIDKeyKind]string{
	DevIDKeySigning:     DevIDUniqueIDevID,
	DevIDKeyAttestation: DevIDUniqueIAK,
}

// devidUniqueSizes reports the largest unique field each crypto suite can
// carry, which section 7.3.1 makes the bound on the combined string: "The
// combined string size MUST NOT be larger than the allowed unique size for the
// crypto suite selected."
//
// For RSA the bound is the modulus size, so it is computed from keyBits rather
// than tabulated. For ECC it is the size of a coordinate on the curve, which
// is what this table holds; TPM2_CreatePrimary answers TPM_RC_SIZE for
// anything larger.
var devidUniqueSizes = map[tpm2.TPMECCCurve]int{
	tpm2.TPMECCNistP256: 32,
	tpm2.TPMECCNistP384: 48,
	tpm2.TPMECCNistP521: 66,
}

// devidECCNameAlgs pairs each ECC suite with the nameAlg its template names:
// H-2 P-256 with SHA256, H-3 P-384 with SHA384, H-4 P-521 with SHA512.
var devidECCNameAlgs = map[tpm2.TPMECCCurve]tpm2.TPMIAlgHash{
	tpm2.TPMECCNistP256: tpm2.TPMAlgSHA256,
	tpm2.TPMECCNistP384: tpm2.TPMAlgSHA384,
	tpm2.TPMECCNistP521: tpm2.TPMAlgSHA512,
}

// devidNameAlgs is the set of hash algorithms a DevID template may name. It is
// the set for which the specification reserves a Policy NV Index and publishes
// a key policy (section 7.3.2, Tables 14-19); SM3_256 is reserved there too
// but is not implemented here. A template outside this set could be created
// but its authPolicy could not be computed, so it is refused up front.
var devidNameAlgs = map[tpm2.TPMIAlgHash]struct{}{
	tpm2.TPMAlgSHA256: {},
	tpm2.TPMAlgSHA384: {},
	tpm2.TPMAlgSHA512: {},
}

// DevIDUniqueString returns the bytes to place in the unique field of a
// Recoverable IDevID/IAK key template (section 7.3.1, Table 2): the required
// string for the key's purpose, followed by the optional per-device string.
//
// deviceString is the OEM's <device_str>. Section 7.3.1: "the device_str is a
// sequence of printable ASCII octets, unique per device, that are concatenated
// to the required unique string", and "If the device string is included, that
// string MUST be stored on the device so that it is available each time
// Primary keys are recreated." Storage is the OEM's choice -- TPM NV Index
// 0x01C90020 is reserved for it (section 7.3.3) -- so this package takes the
// string from configuration and leaves where it is kept to the deployment.
//
// The result is not NUL terminated. An empty deviceString yields the required
// string alone, which is the Table 2 default.
func DevIDUniqueString(kind DevIDKeyKind, deviceString string) ([]byte, error) {
	required, ok := devidUniqueStrings[kind]
	if !ok {
		return nil, &errs.Detail{Err: ErrDevIDUniqueString,
			Detail: fmt.Sprintf("no unique string is defined for %s", kind)}
	}
	for i := 0; i < len(deviceString); i++ {
		if c := deviceString[i]; c < 0x20 || c > 0x7E {
			return nil, &errs.Detail{Err: ErrDevIDUniqueString,
				Detail: fmt.Sprintf("device string octet %d is 0x%02x, which is not printable ASCII", i, c)}
		}
	}
	return []byte(required + deviceString), nil
}

// DevIDTemplateSpec names the crypto suite of a Recoverable IDevID/IAK key
// template. Its zero value is not usable: Kind has no default because an
// IDevID and an IAK differ in the one attribute -- Restricted -- that decides
// what the key may sign.
type DevIDTemplateSpec struct {
	// Kind selects the IDevID (H-x signing) or IAK (H-x attestation) shape.
	Kind DevIDKeyKind

	// Algorithm is x509.RSA for H-1 or x509.ECDSA for H-2 through H-4.
	Algorithm x509.PublicKeyAlgorithm

	// KeyBits is the RSA modulus size. Zero selects H-1's 2048.
	KeyBits uint16

	// Curve is the ECC curve. Nil selects H-2's NIST P-256.
	Curve elliptic.Curve

	// NameAlg is the template's nameAlg. Zero selects the suite's own: SHA256
	// for H-1 and H-2, SHA384 for H-3, SHA512 for H-4.
	NameAlg tpm2.TPMIAlgHash

	// Scheme selects an IAK's RSA signature scheme, which H-1 allows to be
	// either TPM_ALG_RSASSA ("AK - PKCSV1_5") or TPM_ALG_RSAPSS. Zero selects
	// RSASSA. It is ignored for every other combination: an RSA IDevID's
	// scheme is TPM_ALG_NULL and an ECC key's is TPM_ALG_ECDSA, in both cases
	// because the specification allows nothing else.
	Scheme tpm2.TPMAlgID

	// DeviceString is the optional per-device string of section 7.3.1,
	// appended to the required unique string. Empty means the required string
	// alone.
	DeviceString string
}

// Template builds the TPMT_PUBLIC for the spec.
//
// The returned template carries every field of H-0 and of its suite's H-x
// table except authPolicy, which is left empty: the authPolicy is the
// IDevID/IAK Key Policy for the template's nameAlg (section 7.3.6.6), it is
// computed by DevIDKeyPolicyDigest, and it is assigned by the creation path
// immediately before TPM2_CreatePrimary so that a template value can never go
// stale against the policy the package computes today.
func (spec DevIDTemplateSpec) Template() (tpm2.TPMTPublic, error) {
	unique, err := DevIDUniqueString(spec.Kind, spec.DeviceString)
	if err != nil {
		return tpm2.TPMTPublic{}, err
	}

	// Template H-0 (section 7.3.4.1, Table 3), the values common to H-1
	// through H-5. stClear, noDA and encryptedDuplication are CLEAR, which is
	// the zero value; decrypt is CLEAR because a DevID key is
	// "Not-decrypting" (sections 4.1 and 4.2).
	attributes := tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		AdminWithPolicy:     true,
		SignEncrypt:         true,
		Restricted:          spec.Kind == DevIDKeyAttestation,
	}

	switch spec.Algorithm {
	case x509.ECDSA:
		return spec.eccTemplate(attributes, unique)
	case x509.UnknownPublicKeyAlgorithm, x509.RSA:
		return spec.rsaTemplate(attributes, unique)
	default:
		return tpm2.TPMTPublic{}, &AlgorithmNotSupportedError{
			Requested: spec.Algorithm.String(),
			Supported: []string{"RSA", "ECDSA"},
		}
	}
}

// rsaTemplate builds Template H-1 (section 7.3.4.2, Table 4).
func (spec DevIDTemplateSpec) rsaTemplate(
	attributes tpm2.TPMAObject, unique []byte) (tpm2.TPMTPublic, error) {

	keyBits := spec.KeyBits
	if keyBits == 0 {
		keyBits = DefaultRSAKeyBits
	}
	if !containsInt(definedRSAKeyBits, int(keyBits)) {
		return tpm2.TPMTPublic{}, &KeySizeNotSupportedError{
			Requested: int(keyBits),
			Supported: definedRSAKeyBits,
		}
	}

	nameAlg, err := spec.resolveNameAlg(tpm2.TPMAlgSHA256)
	if err != nil {
		return tpm2.TPMTPublic{}, err
	}

	// Section 7.3.1: the combined unique string "MUST NOT be larger than the
	// allowed unique size for the crypto suite selected", which for RSA is the
	// modulus size. TPM2_CreatePrimary answers TPM_RC_SIZE for anything
	// larger.
	if err := checkDevIDUniqueSize(len(unique), int(keyBits)/8); err != nil {
		return tpm2.TPMTPublic{}, err
	}

	scheme, err := spec.rsaScheme(nameAlg)
	if err != nil {
		return tpm2.TPMTPublic{}, err
	}

	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgRSA,
		NameAlg:          nameAlg,
		ObjectAttributes: attributes,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				// symmetric->algorithm = TPM_ALG_NULL, stated rather than left
				// to the zero value. It is the same key either way today --
				// go-tpm tags the field gotpm:"nullable" and writes
				// TPM_ALG_NULL for the Go zero value, so a template omitting
				// it marshals identically (measured in
				// devid_template_test.go) -- but the specification names the
				// value, the Go zero value is TPM_ALG_ERROR rather than
				// TPM_ALG_NULL, and every field of a template is a derivation
				// input. Depending on a struct tag for a field that decides a
				// device's identity is not worth the two words it saves.
				Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
				Scheme:    scheme,
				KeyBits:   tpm2.TPMKeyBits(keyBits),
				// exponent = 0, which the TPM reads as the default 65537
				// (TCG TPM 2.0 Library Part 2, section 12.2.3.5).
				Exponent: 0,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{Buffer: unique},
		),
	}, nil
}

// rsaScheme resolves the TPMT_RSA_SCHEME of Template H-1.
//
// For the IDevID the table is unconditional: "scheme->scheme = TPM_ALG_NULL
// (Signing)", "scheme->details = NULL (Signing)". A key that names no scheme
// takes one from each TPM2_Sign command instead, which is what lets one device
// identity key serve both a PKCS#1 v1.5 certificate signature and the RSA-PSS
// a TLS 1.3 handshake requires.
//
// For the AK the same table names "TPM_ALG_RSASSA (AK - PKCSV1_5)" or
// "TPM_ALG_RSAPSS (AK)" with "TPM_ALG_SHA256 (AK)" details, and it must: a
// Restricted signing key may not name TPM_ALG_NULL (TCG TPM 2.0 Library Part 1,
// section 25.2.3), because the scheme is part of what a verifier of its
// attestations relies on. The details hash follows the template's nameAlg,
// which is SHA256 in H-1 itself.
func (spec DevIDTemplateSpec) rsaScheme(
	nameAlg tpm2.TPMIAlgHash) (tpm2.TPMTRSAScheme, error) {

	if spec.Kind != DevIDKeyAttestation {
		if spec.Scheme != 0 && spec.Scheme != tpm2.TPMAlgNull {
			return tpm2.TPMTRSAScheme{}, &errs.Detail{Err: ErrDevIDTemplateSuiteUnsupported,
				Detail: fmt.Sprintf(
					"an RSA IDevID names no signature scheme (H-1: TPM_ALG_NULL for signing), not %s",
					algorithmName(spec.Scheme))}
		}
		return tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull}, nil
	}

	scheme := spec.Scheme
	if scheme == 0 {
		scheme = tpm2.TPMAlgRSASSA
	}
	switch scheme {
	case tpm2.TPMAlgRSASSA:
		return tpm2.TPMTRSAScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSigSchemeRSASSA{HashAlg: nameAlg}),
		}, nil
	case tpm2.TPMAlgRSAPSS:
		return tpm2.TPMTRSAScheme{
			Scheme: tpm2.TPMAlgRSAPSS,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSAPSS,
				&tpm2.TPMSSigSchemeRSAPSS{HashAlg: nameAlg}),
		}, nil
	default:
		return tpm2.TPMTRSAScheme{}, &SchemeNotImplementedError{
			Requested:   algorithmName(scheme),
			Implemented: []string{"TPM_ALG_RSASSA", "TPM_ALG_RSAPSS"},
		}
	}
}

// eccTemplate builds Templates H-2, H-3 and H-4 (sections 7.3.4.3-7.3.4.5,
// Tables 5-7), which differ only in curve and nameAlg.
//
// A note on scheme->details. H-2 through H-4 name "scheme->scheme =
// TPM_ALG_ECDSA" together with "scheme->details = NULL", and no TPM can
// represent that pair: the details of a TPMT_ECC_SCHEME whose scheme is ECDSA
// are a TPMS_SIG_SCHEME_ECDSA, whose hashAlg is a TPMI_ALG_HASH carrying no "+"
// decoration, so TPM_ALG_NULL is not an admissible value there (TCG TPM 2.0
// Library Part 2, sections 11.1.9 and 12.2.3.6). Measured rather than assumed:
// TPM2_CreatePrimary refuses such a template with TPM_RC_HASH on inPublic, for
// P-256, P-384 and P-521 alike (devid_template_simulator_test.go pins this).
//
// One half of the row therefore has to give, and it is the details: the scheme
// stays TPM_ALG_ECDSA, which is the constraint the specification actually
// states and the TPM can carry, and the details name the template's own
// nameAlg.
//
// That resolution is the specification's own, not this package's. Section 14
// (Annex B, Table 24, the IEEE 802.1AR PICS) names the suites an implementation
// may claim conformance to as "the ECDSA P-256/SHA-256 signature suite"
// (ECDSA256) and "the ECDSA P-384/SHA-384 signature suite" (ECDSA384): the
// digest is bound to the curve, and the curve is bound to a nameAlg by
// Tables 5 and 6. So Table 5's "scheme->details = NULL" is read here as "the
// details are not an independent choice", and the value they take is the one
// Table 24 names. Table 24 lists no P-521 row -- it is a subset of 802.1AR's
// PICS -- so H-4's own nameAlg (SHA-512, section 7.3.4.5, Table 7) supplies
// the pairing there, by the same rule.
//
// Dropping to a TPM_ALG_NULL scheme would create -- it is what the package's
// general-purpose ECC templates do -- but it would discard the one thing
// Table 5 says about the scheme and would widen the key to sign under any
// scheme a caller names, which is the wrong direction for a device identity
// key. Do not "correct" this back to NULL:
// TestDevIDTemplate_ECDSANullDetailsIsRefusedByTheTPM exists to stop that.
func (spec DevIDTemplateSpec) eccTemplate(
	attributes tpm2.TPMAObject, unique []byte) (tpm2.TPMTPublic, error) {

	curve := spec.Curve
	if curve == nil {
		curve = elliptic.P256()
	}
	// A curve with no DevID template is refused as an unsupported crypto
	// suite rather than as an unknown curve, so that one error covers every
	// "the specification defines no template for this" case. Two curves reach
	// here: P-224, which Go can represent and some TPMs can create but which
	// section 7.3.4 gives no template; and, in principle, SM2 P-256 -- the
	// H-5 suite this package does not implement. SM2 cannot actually arrive:
	// crypto/elliptic has no SM2 curve, so a configuration naming it is
	// refused earlier by types.ParseCurve with types.ErrUnknownCurve.
	curveID, ok := eccCurveIDs[curve.Params().Name]
	if !ok {
		return tpm2.TPMTPublic{}, devidUnsupportedCurve(curve.Params().Name)
	}
	suiteNameAlg, ok := devidECCNameAlgs[curveID]
	if !ok {
		return tpm2.TPMTPublic{}, devidUnsupportedCurve(curve.Params().Name)
	}

	nameAlg, err := spec.resolveNameAlg(suiteNameAlg)
	if err != nil {
		return tpm2.TPMTPublic{}, err
	}
	if err := checkDevIDUniqueSize(len(unique), devidUniqueSizes[curveID]); err != nil {
		return tpm2.TPMTPublic{}, err
	}

	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          nameAlg,
		ObjectAttributes: attributes,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: nameAlg}),
				},
				CurveID: curveID,
				// kdf->scheme = TPM_ALG_NULL, stated for the same reason as
				// symmetric above.
				KDF: tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
			},
		),
		// The unique string goes in x, and y is left empty. The unique field of
		// a template is a derivation input rather than a point the TPM has to
		// validate -- TPM2_CreatePrimary returns the real point it derived --
		// so there is no y to supply, and section 7.3.1 speaks of one string.
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: unique},
				Y: tpm2.TPM2BECCParameter{},
			},
		),
	}, nil
}

// resolveNameAlg returns the template's nameAlg, defaulting to the suite's own
// and refusing a hash algorithm for which the specification publishes no key
// policy.
func (spec DevIDTemplateSpec) resolveNameAlg(
	suiteDefault tpm2.TPMIAlgHash) (tpm2.TPMIAlgHash, error) {

	nameAlg := spec.NameAlg
	if nameAlg == 0 {
		nameAlg = suiteDefault
	}
	if _, ok := devidNameAlgs[nameAlg]; !ok {
		return 0, &errs.Detail{Err: ErrDevIDTemplateSuiteUnsupported,
			Detail: fmt.Sprintf(
				"nameAlg %s has no IDevID/IAK key policy; section 7.3.2 reserves indices for SHA256, SHA384 and SHA512",
				algorithmName(tpm2.TPMAlgID(nameAlg)))}
	}
	return nameAlg, nil
}

// checkDevIDUniqueSize enforces section 7.3.1's bound on the combined unique
// string.
func checkDevIDUniqueSize(size, allowed int) error {
	if size > allowed {
		return &errs.Detail{Err: ErrDevIDUniqueStringTooLong,
			Detail: fmt.Sprintf("%d octets exceeds the %d the crypto suite allows", size, allowed)}
	}
	return nil
}

// devidCurveNames lists the curves a DevID template can name, for the error
// returned when a caller asks for another.
func devidCurveNames() []string {
	return []string{
		elliptic.P256().Params().Name,
		elliptic.P384().Params().Name,
		elliptic.P521().Params().Name,
	}
}

// devidUnsupportedCurve reports a curve for which section 7.3.4 defines no
// Recoverable IDevID/IAK template, naming the ones it does define and saying
// what became of the one suite that is defined but not implemented.
func devidUnsupportedCurve(requested string) error {
	return &errs.Detail{Err: ErrDevIDTemplateSuiteUnsupported,
		Detail: fmt.Sprintf(
			"curve %s has no IDevID/IAK template; H-2 through H-4 define %s. "+
				"H-5 (SM2 P-256) is not implemented: it requires nameAlg TPM_ALG_SM3_256, "+
				"which the TPMs this library is tested against do not implement",
			requested, strings.Join(devidCurveNames(), ", "))}
}

// mustDevIDTemplate builds a package-level template from a spec fixed in this
// package's source, and panics if the spec is invalid.
//
// It follows mustKeyTemplate: the spec is a literal that cannot depend on
// anything a caller supplies, so a failure is a mistake in this file, it is
// found the first time the package is loaded rather than at the first key
// creation, and there is no caller to return it to. Every spec that comes from
// outside goes through DevIDTemplateSpec.Template, which returns an error.
func mustDevIDTemplate(spec DevIDTemplateSpec) tpm2.TPMTPublic {
	template, err := spec.Template()
	if err != nil {
		panic("tpm: invalid built-in IDevID/IAK template: " + err.Error())
	}
	return template
}
