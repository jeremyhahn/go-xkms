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
	"sort"

	"github.com/google/go-tpm/tpm2"
)

// KeyTemplateSpec describes the key a caller wants, in the terms the caller
// thinks in, and is turned into the TPMT_PUBLIC that TPM2_Create or
// TPM2_CreateLoaded needs (TCG TPM 2.0 Library Part 2, section 12.2.4).
//
// It exists because a fixed set of templates cannot express what a TPM can do.
// A TPM 2.0 implementation chooses which algorithms and curves it implements,
// so the admissible combinations are a property of the device; a template
// constant is a decision made at compile time about hardware that has not been
// seen yet. Every field a caller leaves at its zero value is resolved from a
// documented default -- never from a silent substitution of something the
// device happens to have.
//
// The zero value describes an unrestricted RSA-2048 signing key with no fixed
// signature scheme, which is the default this package creates.
type KeyTemplateSpec struct {
	// Algorithm selects the key type: x509.RSA or x509.ECDSA. The zero value
	// (x509.UnknownPublicKeyAlgorithm) means RSA.
	Algorithm x509.PublicKeyAlgorithm

	// KeyBits is the RSA modulus size. Zero means DefaultRSAKeyBits. It is
	// ignored for ECC keys.
	KeyBits uint16

	// Curve is the ECC curve. Nil means elliptic.P256. It is ignored for RSA
	// keys.
	Curve elliptic.Curve

	// NameAlg is the object's name algorithm (Part 1, section 16). Zero means
	// SHA-256.
	NameAlg tpm2.TPMIAlgHash

	// Scheme fixes the key's signature or encryption scheme. Zero means
	// TPM_ALG_NULL: the key fixes nothing and the scheme is supplied per
	// operation in the command's inScheme (Part 3, section 12.1). A restricted
	// signing key may not use TPM_ALG_NULL and must name one.
	Scheme tpm2.TPMAlgID

	// SchemeHash is the hash algorithm of Scheme. It is required when Scheme is
	// anything other than TPM_ALG_NULL and must be absent otherwise.
	SchemeHash tpm2.TPMIAlgHash

	// Restricted marks the key as restricted (Part 1, section 25.2.3): it may
	// only operate on data the TPM itself produced. Attestation keys are
	// restricted; general-purpose keys are not.
	Restricted bool

	// Sign marks the key as a signing key. When neither Sign nor Decrypt is
	// set, the key is a signing key.
	Sign bool

	// Decrypt marks the key as a decryption key.
	Decrypt bool

	// AuthPolicy is the key's authorization policy digest, empty for a key
	// authorized by password alone.
	AuthPolicy tpm2.TPM2BDigest
}

// DefaultRSAKeyBits is the RSA modulus size used when a spec names none.
const DefaultRSAKeyBits uint16 = 2048

// definedRSAKeyBits lists the RSA modulus sizes TPM 2.0 defines, from the TCG
// Algorithm Registry's RSA_KEY_SIZES_BITS.
//
// This is not a claim about any particular device. There is no TPM_PT property
// that reports which moduli a TPM can create, so a device that declines a
// defined size answers when the key is created and that answer is surfaced to
// the caller unchanged.
var definedRSAKeyBits = []int{1024, 2048, 3072, 4096}

// eccCurveIDs maps the curves crypto/elliptic can represent onto their TPM
// curve identifiers (TCG Algorithm Registry, TPM_ECC_CURVE).
//
// The map is bounded by Go's side, not the TPM's: a TPM may implement SM2,
// Barreto-Naehrig or Brainpool curves, but a key on one of those cannot be
// returned as the *ecdsa.PublicKey this package's creation API produces, and
// KeyAttributes models a curve as an elliptic.Curve. Those curves are therefore
// out of reach until that type changes, and are refused by name rather than
// substituted.
var eccCurveIDs = map[string]tpm2.TPMECCCurve{
	elliptic.P224().Params().Name: tpm2.TPMECCNistP224,
	elliptic.P256().Params().Name: tpm2.TPMECCNistP256,
	elliptic.P384().Params().Name: tpm2.TPMECCNistP384,
	elliptic.P521().Params().Name: tpm2.TPMECCNistP521,
}

// implementedRSASchemes lists the RSA schemes this package can both create and
// then use. A scheme absent from this set is refused at creation rather than
// producing a key that exists but that no code path here can operate.
var implementedRSASchemes = map[tpm2.TPMAlgID]struct{}{
	tpm2.TPMAlgNull:   {},
	tpm2.TPMAlgRSASSA: {},
	tpm2.TPMAlgRSAPSS: {},
	tpm2.TPMAlgOAEP:   {},
}

// implementedECCSchemes lists the ECC schemes this package can both create and
// then use.
var implementedECCSchemes = map[tpm2.TPMAlgID]struct{}{
	tpm2.TPMAlgNull:  {},
	tpm2.TPMAlgECDSA: {},
	tpm2.TPMAlgECDH:  {},
}

// Template builds the TPMT_PUBLIC for the spec without consulting a device.
//
// It validates only what is true of every TPM 2.0 implementation: that the
// requested key size is one TPM 2.0 defines, that the curve is one this package
// can represent, that a named scheme carries a hash and TPM_ALG_NULL does not,
// and that a restricted signing key names a scheme (TCG TPM 2.0 Library Part 1,
// section 25.2.3). Whether a particular chip implements the result is a separate
// question, answered by TPM2.KeyTemplate.
func (spec KeyTemplateSpec) Template() (tpm2.TPMTPublic, error) {
	nameAlg := spec.NameAlg
	if nameAlg == 0 {
		nameAlg = tpm2.TPMAlgSHA256
	}

	scheme := spec.Scheme
	if scheme == 0 {
		scheme = tpm2.TPMAlgNull
	}

	sign := spec.Sign
	decrypt := spec.Decrypt
	if !sign && !decrypt {
		sign = true
	}

	if scheme == tpm2.TPMAlgNull {
		if spec.SchemeHash != 0 {
			return tpm2.TPMTPublic{}, ErrSchemeHashUnexpected
		}
		if spec.Restricted && sign {
			return tpm2.TPMTPublic{}, ErrRestrictedSchemeRequired
		}
	} else if spec.SchemeHash == 0 {
		return tpm2.TPMTPublic{}, ErrSchemeHashRequired
	}

	attributes := tpm2.TPMAObject{
		SignEncrypt:         sign,
		Decrypt:             decrypt,
		Restricted:          spec.Restricted,
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
	}

	switch spec.Algorithm {
	case x509.ECDSA:
		return spec.eccTemplate(nameAlg, scheme, attributes)
	case x509.UnknownPublicKeyAlgorithm, x509.RSA:
		return spec.rsaTemplate(nameAlg, scheme, attributes)
	default:
		return tpm2.TPMTPublic{}, &AlgorithmNotSupportedError{
			Requested: spec.Algorithm.String(),
			Supported: []string{"RSA", "ECDSA"},
		}
	}
}

// rsaTemplate builds the TPMT_PUBLIC of an RSA key (TCG TPM 2.0 Library Part 2,
// section 12.2.3.5).
func (spec KeyTemplateSpec) rsaTemplate(
	nameAlg tpm2.TPMIAlgHash,
	scheme tpm2.TPMAlgID,
	attributes tpm2.TPMAObject) (tpm2.TPMTPublic, error) {

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

	if _, ok := implementedRSASchemes[scheme]; !ok {
		return tpm2.TPMTPublic{}, &SchemeNotImplementedError{
			Requested:   algorithmName(scheme),
			Implemented: schemeNames(implementedRSASchemes),
		}
	}

	rsaScheme := tpm2.TPMTRSAScheme{Scheme: scheme}
	switch scheme {
	case tpm2.TPMAlgRSASSA:
		rsaScheme.Details = tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSigSchemeRSASSA{HashAlg: spec.SchemeHash})
	case tpm2.TPMAlgRSAPSS:
		rsaScheme.Details = tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgRSAPSS,
			&tpm2.TPMSSigSchemeRSAPSS{HashAlg: spec.SchemeHash})
	case tpm2.TPMAlgOAEP:
		rsaScheme.Details = tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgOAEP,
			&tpm2.TPMSEncSchemeOAEP{HashAlg: spec.SchemeHash})
	}

	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgRSA,
		NameAlg:          nameAlg,
		ObjectAttributes: attributes,
		AuthPolicy:       spec.AuthPolicy,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme:  rsaScheme,
				KeyBits: tpm2.TPMKeyBits(keyBits),
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, keyBits/8),
			},
		),
	}, nil
}

// eccTemplate builds the TPMT_PUBLIC of an ECC key (TCG TPM 2.0 Library Part 2,
// section 12.2.3.6).
func (spec KeyTemplateSpec) eccTemplate(
	nameAlg tpm2.TPMIAlgHash,
	scheme tpm2.TPMAlgID,
	attributes tpm2.TPMAObject) (tpm2.TPMTPublic, error) {

	curve := spec.Curve
	if curve == nil {
		curve = elliptic.P256()
	}
	curveID, ok := eccCurveIDs[curve.Params().Name]
	if !ok {
		return tpm2.TPMTPublic{}, &CurveNotSupportedError{
			Requested: curve.Params().Name,
			Supported: representableCurveNames(),
		}
	}

	if _, ok := implementedECCSchemes[scheme]; !ok {
		return tpm2.TPMTPublic{}, &SchemeNotImplementedError{
			Requested:   algorithmName(scheme),
			Implemented: schemeNames(implementedECCSchemes),
		}
	}

	eccScheme := tpm2.TPMTECCScheme{Scheme: scheme}
	switch scheme {
	case tpm2.TPMAlgECDSA:
		eccScheme.Details = tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgECDSA,
			&tpm2.TPMSSigSchemeECDSA{HashAlg: spec.SchemeHash})
	case tpm2.TPMAlgECDH:
		eccScheme.Details = tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgECDH,
			&tpm2.TPMSKeySchemeECDH{HashAlg: spec.SchemeHash})
	}

	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          nameAlg,
		ObjectAttributes: attributes,
		AuthPolicy:       spec.AuthPolicy,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: curveID,
				Scheme:  eccScheme,
			},
		),
	}, nil
}

// KeyTemplate builds the TPMT_PUBLIC for the spec and refuses anything this
// TPM does not implement.
//
// The device is the authority. TPM2_GetCapability reports the algorithm set
// (TPM_CAP_ALGS) and the curve set (TPM_CAP_ECC_CURVES), and a request outside
// either is answered here, by name, rather than sent to the TPM to return
// TPM_RC_CURVE or TPM_RC_SCHEME from inside a command whose failure the caller
// cannot interpret. A request the device does implement is never redirected to
// something else.
func (tpm *TPM2) KeyTemplate(spec KeyTemplateSpec) (tpm2.TPMTPublic, error) {
	template, err := spec.Template()
	if err != nil {
		return tpm2.TPMTPublic{}, err
	}

	caps, err := tpm.Capabilities()
	if err != nil {
		return tpm2.TPMTPublic{}, err
	}

	if !caps.SupportsAlgorithm(template.Type) {
		return tpm2.TPMTPublic{}, &AlgorithmNotSupportedError{
			Requested: algorithmName(template.Type),
			Supported: caps.AlgorithmNames(),
		}
	}
	if !caps.SupportsAlgorithm(template.NameAlg) {
		return tpm2.TPMTPublic{}, &AlgorithmNotSupportedError{
			Requested: algorithmName(template.NameAlg),
			Supported: caps.AlgorithmNames(),
		}
	}
	if spec.Scheme != 0 && spec.Scheme != tpm2.TPMAlgNull {
		if !caps.SupportsAlgorithm(spec.Scheme) {
			return tpm2.TPMTPublic{}, &AlgorithmNotSupportedError{
				Requested: algorithmName(spec.Scheme),
				Supported: caps.AlgorithmNames(),
			}
		}
	}
	if spec.SchemeHash != 0 && !caps.SupportsAlgorithm(spec.SchemeHash) {
		return tpm2.TPMTPublic{}, &AlgorithmNotSupportedError{
			Requested: algorithmName(spec.SchemeHash),
			Supported: caps.AlgorithmNames(),
		}
	}

	if template.Type == tpm2.TPMAlgECC {
		eccDetail, err := template.Parameters.ECCDetail()
		if err != nil {
			return tpm2.TPMTPublic{}, err
		}
		if !caps.SupportsCurve(eccDetail.CurveID) {
			requested := elliptic.P256().Params().Name
			if spec.Curve != nil {
				requested = spec.Curve.Params().Name
			}
			return tpm2.TPMTPublic{}, &CurveNotSupportedError{
				Requested: requested,
				Supported: caps.CurveNames(),
			}
		}
	}

	// Everything above is checked against what the device says it implements.
	// TPM2_TestParms asks the device to validate the combination as a whole,
	// which is the only way to learn the answer for an RSA modulus size -- no
	// capability property reports those -- and it catches any parameter
	// combination a device declines for reasons of its own.
	//
	// Without this the refusal arrived as a bare TPM_RC_VALUE or TPM_RC_SIZE
	// from inside TPM2_Create, naming a command parameter number rather than the
	// key size the caller asked for.
	parms := tpm2.TPMTPublicParms{
		Type:       template.Type,
		Parameters: template.Parameters,
	}
	if !tpm.SupportsParameters(parms) {
		if template.Type == tpm2.TPMAlgRSA {
			rsaDetail, err := template.Parameters.RSADetail()
			if err != nil {
				return tpm2.TPMTPublic{}, err
			}
			return tpm2.TPMTPublic{}, &KeySizeNotSupportedError{
				Requested: int(rsaDetail.KeyBits),
				Supported: tpm.SupportedRSAKeyBits(),
			}
		}
		return tpm2.TPMTPublic{}, &ParametersNotSupportedError{
			Requested: describeSpec(spec),
		}
	}

	return template, nil
}

// describeSpec renders a spec for an error message.
func describeSpec(spec KeyTemplateSpec) string {
	description := spec.Algorithm.String()
	if spec.Curve != nil {
		description += " " + spec.Curve.Params().Name
	}
	if spec.KeyBits != 0 {
		description += fmt.Sprintf(" %d-bit", spec.KeyBits)
	}
	if spec.Scheme != 0 && spec.Scheme != tpm2.TPMAlgNull {
		description += " " + algorithmName(spec.Scheme)
	}
	if spec.SchemeHash != 0 {
		description += "/" + algorithmName(spec.SchemeHash)
	}
	return description
}

// representableCurveNames lists the curves a spec can name, in a stable order.
func representableCurveNames() []string {
	return []string{
		elliptic.P224().Params().Name,
		elliptic.P256().Params().Name,
		elliptic.P384().Params().Name,
		elliptic.P521().Params().Name,
	}
}

// schemeNames renders a scheme set for an error message, in a stable order.
func schemeNames(schemes map[tpm2.TPMAlgID]struct{}) []string {
	names := make([]string, 0, len(schemes))
	for scheme := range schemes {
		names = append(names, algorithmName(scheme))
	}
	sort.Strings(names)
	return names
}

// mustKeyTemplate builds a template from a spec that is fixed in this package's
// source, and panics if the spec is invalid.
//
// It is used only for package-level template variables, where the spec is a
// literal and cannot depend on anything a caller supplies: a failure is a
// mistake in this file, it is discovered the first time the package is loaded
// rather than at the first key creation, and there is no caller to return it to.
// Every spec that comes from outside goes through Template or KeyTemplate, both
// of which return an error.
func mustKeyTemplate(spec KeyTemplateSpec) tpm2.TPMTPublic {
	template, err := spec.Template()
	if err != nil {
		panic("tpm: invalid built-in key template: " + err.Error())
	}
	return template
}

// containsInt reports whether values contains want.
func containsInt(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
