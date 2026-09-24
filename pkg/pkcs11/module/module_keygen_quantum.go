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

// Package module implements post-quantum key-pair generation for C_GenerateKeyPair.
//
// PKCS#11 v3.2 gives an application two ways to ask for a post-quantum key pair,
// and this file resolves both to the same answer:
//
//   - The v3.2 standard mechanism plus a parameter set on the key object:
//     CKM_ML_DSA_KEY_PAIR_GEN or CKM_ML_KEM_KEY_PAIR_GEN, with CKA_PARAMETER_SET
//     naming the level. §6.67.2 and §6.68.2 state that these mechanisms take no
//     mechanism parameter, so CKA_PARAMETER_SET is the only thing that says which
//     key to generate; without reading it the module could not tell ML-DSA-44
//     from ML-DSA-87.
//   - A per-level vendor mechanism that names the level itself, such as
//     CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN. These predate the v3.2 standard
//     identifiers and remain the form the module's own sign, verify and
//     encapsulation dispatch is written against.
//
// Both forms produce an identical key object: the same CKK_* key type, the same
// CKA_PARAMETER_SET, and key material from the same generator. Only
// CKA_KEY_GEN_MECHANISM differs, because that records what the caller named.
//
// Generation happens in this process rather than through the transport. The
// module is a Cryptoki provider whose own object store is the token: the
// encapsulation (module_kem.go) and signature-verification
// (module_verifysig.go) paths already read post-quantum key material straight
// out of CKA_VALUE, so a key pair generated here is immediately usable by them.
// Routing generation to the backend instead would return a key the module
// itself could not encapsulate under, since the transport's
// GenerateKeyResponse carries only a public-key PEM and no FIPS 203/204 key
// material.
//
// References:
//   - OASIS PKCS#11 v3.2 §6.67 (ML-DSA), §6.68 (ML-KEM)
//   - NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)
package module

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-enclave"
)

// quantumFamily names the post-quantum family a key-pair-generation mechanism
// belongs to. The zero value means the mechanism is not a post-quantum
// key-pair-generation mechanism at all.
type quantumFamily uint8

const (
	// quantumFamilyNone means the mechanism generates no post-quantum key pair.
	quantumFamilyNone quantumFamily = iota

	// quantumFamilyMLDSA is FIPS 204 ML-DSA (a signature family).
	quantumFamilyMLDSA

	// quantumFamilyMLKEM is FIPS 203 ML-KEM (a key-encapsulation family).
	quantumFamilyMLKEM
)

// quantumKeyGenSpec is the resolved answer to what C_GenerateKeyPair has been
// asked to generate: which family, which parameter set, the security level the
// QuantumCryptoManager selects a generator with, and the CKK_* key type the
// resulting objects carry.
type quantumKeyGenSpec struct {
	family quantumFamily

	// level is the generator selector: 44, 65 or 87 for ML-DSA; 512, 768 or
	// 1024 for ML-KEM.
	level int

	// parameterSet is the CK_PARAMETER_SET_TYPE stored as CKA_PARAMETER_SET on
	// both objects, so a key generated through the vendor mechanism is
	// afterwards indistinguishable from one generated through the standard
	// mechanism plus an explicit parameter set.
	parameterSet ParameterSetType

	// keyType is the standard v3.2 key type, CKK_ML_DSA or CKK_ML_KEM, for both
	// addressing forms. The vendor key types remain defined for objects
	// imported by applications that predate v3.2 (vendorToStandardKeyType maps
	// them), but a key this token generates is described in the standard
	// vocabulary.
	keyType KeyType
}

// quantumKeyGenVendorSpecs resolves the per-level vendor key-pair-generation
// mechanisms, each of which names its parameter set in the mechanism itself.
//
// The v3.2 standard mechanisms are deliberately absent: they carry no level, so
// they are resolved from CKA_PARAMETER_SET by resolveQuantumKeyGenSpec.
var quantumKeyGenVendorSpecs = map[MechanismType]quantumKeyGenSpec{
	CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN: {family: quantumFamilyMLDSA, level: 44, parameterSet: CKP_ML_DSA_44, keyType: CKK_ML_DSA},
	CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN: {family: quantumFamilyMLDSA, level: 65, parameterSet: CKP_ML_DSA_65, keyType: CKK_ML_DSA},
	CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN: {family: quantumFamilyMLDSA, level: 87, parameterSet: CKP_ML_DSA_87, keyType: CKK_ML_DSA},

	CKM_VENDOR_ML_KEM_512_KEY_GEN:  {family: quantumFamilyMLKEM, level: 512, parameterSet: CKP_ML_KEM_512, keyType: CKK_ML_KEM},
	CKM_VENDOR_ML_KEM_768_KEY_GEN:  {family: quantumFamilyMLKEM, level: 768, parameterSet: CKP_ML_KEM_768, keyType: CKK_ML_KEM},
	CKM_VENDOR_ML_KEM_1024_KEY_GEN: {family: quantumFamilyMLKEM, level: 1024, parameterSet: CKP_ML_KEM_1024, keyType: CKK_ML_KEM},
}

// mldsaParameterSetSpecs resolves a CKA_PARAMETER_SET value supplied alongside
// CKM_ML_DSA_KEY_PAIR_GEN. Parameter set values are scoped per algorithm — the
// same numeric 0x01 is ML-DSA-44 here and ML-KEM-512 in the table below — so the
// two families must never share one lookup.
var mldsaParameterSetSpecs = map[ParameterSetType]quantumKeyGenSpec{
	CKP_ML_DSA_44: {family: quantumFamilyMLDSA, level: 44, parameterSet: CKP_ML_DSA_44, keyType: CKK_ML_DSA},
	CKP_ML_DSA_65: {family: quantumFamilyMLDSA, level: 65, parameterSet: CKP_ML_DSA_65, keyType: CKK_ML_DSA},
	CKP_ML_DSA_87: {family: quantumFamilyMLDSA, level: 87, parameterSet: CKP_ML_DSA_87, keyType: CKK_ML_DSA},
}

// mlkemParameterSetSpecs is the ML-KEM analog of mldsaParameterSetSpecs. All
// three FIPS 203 parameter sets are generated.
//
// CKP_ML_KEM_512 was absent for a period because crypto/mlkem, which the 768 and
// 1024 packages wrap, implements only those two sets. pkg/quantum/mlkem512 now
// supplies 512 from CIRCL's FIPS 203 implementation -- note CIRCL also ships a
// kem/kyber/kyber512, the NIST round-3 submission, which is a different
// algorithm and is not what is used.
var mlkemParameterSetSpecs = map[ParameterSetType]quantumKeyGenSpec{
	CKP_ML_KEM_512:  {family: quantumFamilyMLKEM, level: 512, parameterSet: CKP_ML_KEM_512, keyType: CKK_ML_KEM},
	CKP_ML_KEM_768:  {family: quantumFamilyMLKEM, level: 768, parameterSet: CKP_ML_KEM_768, keyType: CKK_ML_KEM},
	CKP_ML_KEM_1024: {family: quantumFamilyMLKEM, level: 1024, parameterSet: CKP_ML_KEM_1024, keyType: CKK_ML_KEM},
}

// quantumStandardKeyGenParameterSets names, for each v3.2 standard key-pair
// generation mechanism, the per-algorithm table its CKA_PARAMETER_SET is read
// against.
var quantumStandardKeyGenParameterSets = map[MechanismType]map[ParameterSetType]quantumKeyGenSpec{
	CKM_ML_DSA_KEY_PAIR_GEN: mldsaParameterSetSpecs,
	CKM_ML_KEM_KEY_PAIR_GEN: mlkemParameterSetSpecs,
}

// parameterSetFromAttributeValue reads a CKA_PARAMETER_SET value.
//
// PKCS#11 v3.2 §4.10 types the attribute as CK_PARAMETER_SET_TYPE, an unsigned
// long. The value is read as a little-endian 32-bit quantity because that is
// what NewUint32Attribute writes and what the cgo boundary emits, and only the
// low four bytes are consulted so an eight-byte CK_ULONG from a C application
// reads identically on the little-endian platforms this module targets. A value
// shorter than four bytes names no parameter set.
func parameterSetFromAttributeValue(raw []byte) (ParameterSetType, bool) {
	if len(raw) < 4 {
		return 0, false
	}
	return ParameterSetType(binary.LittleEndian.Uint32(raw[:4])), true
}

// templateParameterSet finds CKA_PARAMETER_SET in the templates of a
// C_GenerateKeyPair call.
//
// The public key template is consulted first and the private key template
// second. PKCS#11 v3.2 puts CKA_PARAMETER_SET on both halves of an ML-DSA or
// ML-KEM key pair (§6.67.3, §6.68.3) and an application may legitimately state
// it on either, so requiring it on the public half alone would refuse a
// well-formed request.
func templateParameterSet(publicKeyTemplate, privateKeyTemplate []Attribute) (ParameterSetType, bool) {
	for _, template := range [][]Attribute{publicKeyTemplate, privateKeyTemplate} {
		if raw, present := templateAttribute(template, CKA_PARAMETER_SET); present {
			if parameterSet, ok := parameterSetFromAttributeValue(raw); ok {
				return parameterSet, true
			}
			// The attribute is present but too short to name a parameter set.
			// Continuing to the other template would let a malformed value be
			// silently replaced by a well-formed one on the other half of the
			// pair, so the search stops here and the caller reports the value
			// as invalid.
			return 0, false
		}
	}
	return 0, false
}

// resolveQuantumKeyGenSpec decides what post-quantum key pair, if any,
// C_GenerateKeyPair has been asked for.
//
// The second return value distinguishes "not a post-quantum request" from "a
// post-quantum request this token refuses": only when it is true has the
// mechanism been recognized as post-quantum, and only then is the error
// meaningful. A classical mechanism returns (zero spec, false, nil) and the
// caller proceeds down the backend path unchanged.
func resolveQuantumKeyGenSpec(mechType MechanismType, publicKeyTemplate, privateKeyTemplate []Attribute) (quantumKeyGenSpec, bool, error) {
	if spec, ok := quantumKeyGenVendorSpecs[mechType]; ok {
		return spec, true, nil
	}

	parameterSets, ok := quantumStandardKeyGenParameterSets[mechType]
	if !ok {
		return quantumKeyGenSpec{}, false, nil
	}

	parameterSet, present := templateParameterSet(publicKeyTemplate, privateKeyTemplate)
	if !present {
		// The mechanism carries no parameter and the templates name no
		// parameter set, so nothing in the request says which key to generate.
		// CKR_TEMPLATE_INCOMPLETE is in C_GenerateKeyPair's return table
		// (§5.18.2) and is exactly the condition: a required attribute is
		// missing. Defaulting to a level would hand back a key of a strength
		// the application never asked for.
		return quantumKeyGenSpec{}, true, NewPKCS11ErrorWithMessage(CKR_TEMPLATE_INCOMPLETE,
			"CKA_PARAMETER_SET is required for this key pair generation mechanism")
	}

	spec, ok := parameterSets[parameterSet]
	if !ok {
		return quantumKeyGenSpec{}, true, NewPKCS11ErrorWithMessage(CKR_PARAMETER_SET_NOT_SUPPORTED,
			"unsupported parameter set for this key pair generation mechanism")
	}
	return spec, true, nil
}

// quantumPrivateKeyPersistenceError refuses a post-quantum key pair whose
// private half would not survive the token being unloaded.
//
// A post-quantum private key is the one key class in this module whose only
// copy of its material is CKA_VALUE on the object itself. Generation happens in
// process (see the package comment), so the object carries no KeyID and no
// backend holds the seed. ModuleStorage.SaveObject withholds every attribute
// IsSensitiveAttribute names — CKA_VALUE among them — from a key object that
// protects its material, because the token store is a plaintext file and
// writing the seed there would place in the clear exactly the bytes
// CKA_SENSITIVE and CKA_EXTRACTABLE=CK_FALSE promise never leave the token.
//
// The two rules meet on a CKA_TOKEN=CK_TRUE post-quantum private key:
// C_GenerateKeyPair returned CKR_OK, the key worked for the life of the
// process, and after C_Finalize the restored object had no material at all, so
// C_Sign and C_DecapsulateKey failed on a handle the application had every
// reason to believe was a key. Nothing warned at generation time and the key
// was unrecoverable, which is why the request is refused where it is made.
//
// CKR_TEMPLATE_INCONSISTENT is in C_GenerateKeyPair's return table (v3.2
// §5.18.2), and §5.1 defines it as a template carrying conflicting attributes —
// which asking this token both to keep a key and to protect its only copy of
// that key is.
//
// The combination that IS storable stays allowed. A private key the application
// explicitly marks CKA_SENSITIVE=CK_FALSE and CKA_EXTRACTABLE=CK_TRUE makes no
// promise a plaintext store would break: Object.protectsSensitiveAttributes
// reports false for it, SaveObject persists its CKA_VALUE like any other
// attribute, and it comes back usable. Storing a protected seed instead of
// refusing would need the module's own store to be sealed — a
// barrier-backed storage.Backend the token unlocks at C_Login — which is a
// storage architecture decision that C_GenerateKeyPair cannot make on its own.
func quantumPrivateKeyPersistenceError(privateKeyTemplate []Attribute) error {
	if !templateBoolIsTrue(privateKeyTemplate, CKA_TOKEN, false) {
		return nil
	}

	// The fallbacks are applyClassDefaults' CKO_PRIVATE_KEY defaults, which are
	// what a template that states neither attribute inherits: sensitive, and
	// extractable. protectsSensitiveAttributes withholds the material when the
	// key is sensitive OR is not extractable, so both have to be answered.
	sensitive := templateBoolIsTrue(privateKeyTemplate, CKA_SENSITIVE, true)
	extractable := templateBoolIsTrue(privateKeyTemplate, CKA_EXTRACTABLE, true)
	if !sensitive && extractable {
		return nil
	}

	return NewPKCS11ErrorWithMessage(CKR_TEMPLATE_INCONSISTENT,
		"a CKA_TOKEN post-quantum private key must be CKA_SENSITIVE=CK_FALSE and CKA_EXTRACTABLE=CK_TRUE: this token cannot persist protected post-quantum key material")
}

// quantumGenerateKeyPair generates the key pair a resolved spec describes.
//
// It takes the module's quantumCrypto field as any and type-asserts it, the
// same shape kemEncapsulate and verifySigInit use, so the dispatch stays in one
// place and the caller does not depend on the concrete manager type.
func quantumGenerateKeyPair(quantumCrypto any, spec quantumKeyGenSpec) (*QuantumKeyPair, error) {
	qcm, ok := quantumCrypto.(*QuantumCryptoManager)
	if !ok || qcm == nil {
		return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID,
			"post-quantum key generation is not available in this build")
	}

	switch spec.family {
	case quantumFamilyMLDSA:
		return qcm.GenerateMLDSAKeyPair(spec.level)
	case quantumFamilyMLKEM:
		return qcm.GenerateMLKEMKeyPair(spec.level)
	default:
		return nil, NewPKCS11Error(CKR_MECHANISM_INVALID)
	}
}

// generateQuantumKeyPair completes C_GenerateKeyPair for a post-quantum
// mechanism: it generates the key material and builds the two token objects
// that carry it.
//
// The public key object holds the FIPS 203/204 encoded public key in CKA_VALUE
// and the private key object holds the seed, which is the representation
// pkg/quantum's Create constructors take and therefore the one the module's own
// signing, verification and decapsulation paths read back. Both objects carry
// CKA_PARAMETER_SET, without which C_EncapsulateKey and C_DecapsulateKey would
// have to infer the level from a key length.
//
// Neither object is given a KeyID or a BackendName, and that is what routes the
// pair's later use back here rather than to the transport: module_verifysig_quantum.go
// claims an ML-DSA C_Sign or C_Verify precisely when the key names no backend
// key, and module_kem.go reads the seed straight out of CKA_VALUE.
//
// A failure after the public key object exists destroys it before returning:
// C_GenerateKeyPair either creates both objects or none, and a caller that gets
// an error code receives no handle to clean up with.
func (m *Module) generateQuantumKeyPair(
	sessionHandle SessionHandle,
	session *Session,
	spec quantumKeyGenSpec,
	publicKeyTemplate, privateKeyTemplate []Attribute,
	ckaID []byte,
) (ObjectHandle, ObjectHandle, CK_RV) {
	// Refuse before generating: a key pair this token could not give back after
	// a restart must not be created at all, and generating first would burn
	// entropy on material about to be discarded.
	if persistErr := quantumPrivateKeyPersistenceError(privateKeyTemplate); persistErr != nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(persistErr)
	}

	keyPair, err := quantumGenerateKeyPair(m.quantumCrypto, spec)
	if err != nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(err)
	}
	// The seed is copied into the private key object below; the generator's own
	// copy is cleared so it does not outlive the call in this frame.
	defer enclave.Wipe(keyPair.SecretKey)

	parameterSetValue := NewUint32Attribute(CKA_PARAMETER_SET, uint32(spec.parameterSet)).Value

	access := NewAccessContext(sessionHandle, session)

	pubHandle, pubErr := m.objectManager.CreateGeneratedObject(
		access, CKO_PUBLIC_KEY, spec.keyType, publicKeyTemplate)
	if pubErr != nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(pubErr)
	}
	pubObj, pubGetErr := m.objectManager.getObjectUnchecked(pubHandle)
	if pubGetErr != nil {
		if destroyErr := m.objectManager.DestroyObject(access, pubHandle); destroyErr != nil {
			m.logStorageError("destroy public key after failed post-create lookup", destroyErr)
		}
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(pubGetErr)
	}
	pubObj.SetAttribute(CKA_ID, ckaID)
	pubObj.SetAttribute(CKA_PARAMETER_SET, parameterSetValue)
	pubObj.SetAttribute(CKA_VALUE, keyPair.PublicKey)

	privHandle, privErr := m.objectManager.CreateGeneratedObject(
		access, CKO_PRIVATE_KEY, spec.keyType, privateKeyTemplate)
	if privErr != nil {
		if destroyErr := m.objectManager.DestroyObject(access, pubHandle); destroyErr != nil {
			m.logStorageError("destroy public key after failed private key creation", destroyErr)
		}
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(privErr)
	}
	privObj, privGetErr := m.objectManager.getObjectUnchecked(privHandle)
	if privGetErr != nil {
		if destroyErr := m.objectManager.DestroyObject(access, pubHandle); destroyErr != nil {
			m.logStorageError("destroy public key after failed private key post-create lookup", destroyErr)
		}
		if destroyErr := m.objectManager.DestroyObject(access, privHandle); destroyErr != nil {
			m.logStorageError("destroy private key after failed post-create lookup", destroyErr)
		}
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), FromError(privGetErr)
	}
	privObj.SetAttribute(CKA_ID, ckaID)
	privObj.SetAttribute(CKA_PARAMETER_SET, parameterSetValue)
	privObj.SetAttribute(CKA_VALUE, copyBytes(keyPair.SecretKey))

	// Either both objects reach the store or neither object survives the call,
	// which is the same all-or-nothing rule the failure paths above keep for
	// object creation itself.
	if persistErr := m.persistNewObject(access, pubHandle, sessionHandle); persistErr != nil {
		if destroyErr := m.objectManager.DestroyObject(access, privHandle); destroyErr != nil {
			m.logStorageError("destroy private key of an unpersisted key pair", destroyErr)
		}
		// The public half is destroyed too. Every other failure path here does
		// so; leaving it behind returned no handles to the application while an
		// ML-DSA public key whose private half never existed, and whose CKA_ID
		// matches nothing, stayed findable until C_Finalize.
		if destroyErr := m.objectManager.DestroyObject(access, pubHandle); destroyErr != nil {
			m.logStorageError("destroy public key of an unpersisted key pair", destroyErr)
		}
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), CKR_DEVICE_ERROR
	}
	if persistErr := m.persistNewObject(access, privHandle, sessionHandle); persistErr != nil {
		if deleteErr := m.storage.DeleteObject(pubHandle); deleteErr != nil {
			m.logStorageError("delete public key of an unpersisted key pair", deleteErr)
		}
		if destroyErr := m.objectManager.DestroyObject(access, pubHandle); destroyErr != nil {
			m.logStorageError("destroy public key of an unpersisted key pair", destroyErr)
		}
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), CKR_DEVICE_ERROR
	}

	return pubHandle, privHandle, CKR_OK
}
