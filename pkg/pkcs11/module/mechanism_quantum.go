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

// Package module provides vendor-defined PKCS#11 quantum-safe cryptography mechanisms.
//
// Note: PKCS#11 v3.2 now defines standard mechanism IDs for these algorithms.
// The vendor-defined mechanisms are retained for backward compatibility. See
// mechanism_v32.go for the standard definitions and vendorToStandardMechanism
// for the mapping.
//
// Since OASIS PKCS#11 v3.0 did not define official mechanisms for post-quantum
// cryptographic algorithms, this implementation uses vendor-defined mechanism types
// starting at CKM_VENDOR_DEFINED (0x80000000).
//
// Supported algorithms:
//   - ML-DSA (Module-Lattice Digital Signature Algorithm) - NIST FIPS 204
//     Formerly known as Dilithium
//   - ML-KEM (Module-Lattice Key Encapsulation Mechanism) - NIST FIPS 203
//     Formerly known as Kyber
//
// References:
//   - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
//   - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
//   - OASIS PKCS#11 v3.0: Vendor-defined mechanisms (Section 6.1)
package module

// Vendor-defined quantum-safe mechanism constants (CKM_VENDOR_*)
// These use the vendor-defined range starting at 0x80000000.
//
// Mechanism numbering scheme:
//   - 0x80001xxx: ML-DSA (Dilithium) mechanisms
//   - 0x80002xxx: ML-KEM (Kyber) mechanisms
const (
	// ML-DSA (Dilithium) Mechanisms - NIST FIPS 204
	// Digital signature algorithm based on lattice problems

	// CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN generates ML-DSA-44 key pairs.
	// Security: NIST Category 2 (~128-bit classical, ~64-bit quantum)
	// Public key: 1312 bytes, Secret key: 2560 bytes, Signature: 2420 bytes
	CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN MechanismType = 0x80001001

	// CKM_VENDOR_ML_DSA_44 performs ML-DSA-44 signing and verification.
	CKM_VENDOR_ML_DSA_44 MechanismType = 0x80001002

	// CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN generates ML-DSA-65 key pairs.
	// Security: NIST Category 3 (~192-bit classical, ~96-bit quantum)
	// Public key: 1952 bytes, Secret key: 4032 bytes, Signature: 3309 bytes
	CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN MechanismType = 0x80001003

	// CKM_VENDOR_ML_DSA_65 performs ML-DSA-65 signing and verification.
	CKM_VENDOR_ML_DSA_65 MechanismType = 0x80001004

	// CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN generates ML-DSA-87 key pairs.
	// Security: NIST Category 5 (~256-bit classical, ~128-bit quantum)
	// Public key: 2592 bytes, Secret key: 4896 bytes, Signature: 4627 bytes
	CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN MechanismType = 0x80001005

	// CKM_VENDOR_ML_DSA_87 performs ML-DSA-87 signing and verification.
	CKM_VENDOR_ML_DSA_87 MechanismType = 0x80001006

	// ML-KEM (Kyber) Mechanisms - NIST FIPS 203
	// Key encapsulation mechanism based on lattice problems

	// CKM_VENDOR_ML_KEM_512_KEY_GEN generates ML-KEM-512 key pairs.
	// Security: NIST Category 1 (~128-bit classical, ~64-bit quantum)
	// Public key: 800 bytes, Secret key: 1632 bytes, Ciphertext: 768 bytes
	CKM_VENDOR_ML_KEM_512_KEY_GEN MechanismType = 0x80002001

	// CKM_VENDOR_ML_KEM_512_ENCAPSULATE performs ML-KEM-512 encapsulation.
	// Input: Public key, Output: (Ciphertext, Shared secret)
	CKM_VENDOR_ML_KEM_512_ENCAPSULATE MechanismType = 0x80002002

	// CKM_VENDOR_ML_KEM_512_DECAPSULATE performs ML-KEM-512 decapsulation.
	// Input: (Secret key, Ciphertext), Output: Shared secret
	CKM_VENDOR_ML_KEM_512_DECAPSULATE MechanismType = 0x80002003

	// CKM_VENDOR_ML_KEM_768_KEY_GEN generates ML-KEM-768 key pairs.
	// Security: NIST Category 3 (~192-bit classical, ~96-bit quantum)
	// Public key: 1184 bytes, Secret key: 2400 bytes, Ciphertext: 1088 bytes
	CKM_VENDOR_ML_KEM_768_KEY_GEN MechanismType = 0x80002004

	// CKM_VENDOR_ML_KEM_768_ENCAPSULATE performs ML-KEM-768 encapsulation.
	CKM_VENDOR_ML_KEM_768_ENCAPSULATE MechanismType = 0x80002005

	// CKM_VENDOR_ML_KEM_768_DECAPSULATE performs ML-KEM-768 decapsulation.
	CKM_VENDOR_ML_KEM_768_DECAPSULATE MechanismType = 0x80002006

	// CKM_VENDOR_ML_KEM_1024_KEY_GEN generates ML-KEM-1024 key pairs.
	// Security: NIST Category 5 (~256-bit classical, ~128-bit quantum)
	// Public key: 1568 bytes, Secret key: 3168 bytes, Ciphertext: 1568 bytes
	CKM_VENDOR_ML_KEM_1024_KEY_GEN MechanismType = 0x80002007

	// CKM_VENDOR_ML_KEM_1024_ENCAPSULATE performs ML-KEM-1024 encapsulation.
	CKM_VENDOR_ML_KEM_1024_ENCAPSULATE MechanismType = 0x80002008

	// CKM_VENDOR_ML_KEM_1024_DECAPSULATE performs ML-KEM-1024 decapsulation.
	CKM_VENDOR_ML_KEM_1024_DECAPSULATE MechanismType = 0x80002009
)

// Vendor-defined quantum-safe key type constants (CKK_VENDOR_*)
// These use the vendor-defined range starting at 0x80000000.
const (
	// CKK_VENDOR_ML_DSA is the key type for ML-DSA (Dilithium) keys.
	CKK_VENDOR_ML_DSA KeyType = 0x80000001

	// CKK_VENDOR_ML_KEM is the key type for ML-KEM (Kyber) keys.
	CKK_VENDOR_ML_KEM KeyType = 0x80000002
)

// Quantum mechanism categories for encapsulation operations.
const (
	// CategoryEncapsulate represents key encapsulation operations.
	CategoryEncapsulate MechanismCategory = 10 + iota

	// CategoryDecapsulate represents key decapsulation operations.
	CategoryDecapsulate
)

// ML-DSA key sizes in bytes per security level.
const (
	// ML-DSA-44 (NIST Category 2)
	MLDSA44PublicKeySize = 1312
	MLDSA44SecretKeySize = 2560
	MLDSA44SignatureSize = 2420

	// ML-DSA-65 (NIST Category 3)
	MLDSA65PublicKeySize = 1952
	MLDSA65SecretKeySize = 4032
	MLDSA65SignatureSize = 3309

	// ML-DSA-87 (NIST Category 5)
	MLDSA87PublicKeySize = 2592
	MLDSA87SecretKeySize = 4896
	MLDSA87SignatureSize = 4627
)

// ML-KEM key sizes in bytes per security level.
const (
	// ML-KEM-512 (NIST Category 1)
	MLKEM512PublicKeySize    = 800
	MLKEM512SecretKeySize    = 1632
	MLKEM512CiphertextSize   = 768
	MLKEM512SharedSecretSize = 32

	// ML-KEM-768 (NIST Category 3)
	MLKEM768PublicKeySize    = 1184
	MLKEM768SecretKeySize    = 2400
	MLKEM768CiphertextSize   = 1088
	MLKEM768SharedSecretSize = 32

	// ML-KEM-1024 (NIST Category 5)
	MLKEM1024PublicKeySize    = 1568
	MLKEM1024SecretKeySize    = 3168
	MLKEM1024CiphertextSize   = 1568
	MLKEM1024SharedSecretSize = 32
)

// quantumMechanismNames maps quantum mechanism types to their string names.
var quantumMechanismNames = map[MechanismType]string{
	// ML-DSA mechanisms
	CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN: "CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN",
	CKM_VENDOR_ML_DSA_44:              "CKM_VENDOR_ML_DSA_44",
	CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN: "CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN",
	CKM_VENDOR_ML_DSA_65:              "CKM_VENDOR_ML_DSA_65",
	CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN: "CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN",
	CKM_VENDOR_ML_DSA_87:              "CKM_VENDOR_ML_DSA_87",

	// ML-KEM mechanisms
	CKM_VENDOR_ML_KEM_512_KEY_GEN:      "CKM_VENDOR_ML_KEM_512_KEY_GEN",
	CKM_VENDOR_ML_KEM_512_ENCAPSULATE:  "CKM_VENDOR_ML_KEM_512_ENCAPSULATE",
	CKM_VENDOR_ML_KEM_512_DECAPSULATE:  "CKM_VENDOR_ML_KEM_512_DECAPSULATE",
	CKM_VENDOR_ML_KEM_768_KEY_GEN:      "CKM_VENDOR_ML_KEM_768_KEY_GEN",
	CKM_VENDOR_ML_KEM_768_ENCAPSULATE:  "CKM_VENDOR_ML_KEM_768_ENCAPSULATE",
	CKM_VENDOR_ML_KEM_768_DECAPSULATE:  "CKM_VENDOR_ML_KEM_768_DECAPSULATE",
	CKM_VENDOR_ML_KEM_1024_KEY_GEN:     "CKM_VENDOR_ML_KEM_1024_KEY_GEN",
	CKM_VENDOR_ML_KEM_1024_ENCAPSULATE: "CKM_VENDOR_ML_KEM_1024_ENCAPSULATE",
	CKM_VENDOR_ML_KEM_1024_DECAPSULATE: "CKM_VENDOR_ML_KEM_1024_DECAPSULATE",
}

// quantumKeyTypeNames maps quantum key types to their string names.
var quantumKeyTypeNames = map[KeyType]string{
	CKK_VENDOR_ML_DSA: "CKK_VENDOR_ML_DSA",
	CKK_VENDOR_ML_KEM: "CKK_VENDOR_ML_KEM",
}

// quantumMechanismRegistry contains descriptors for quantum-safe mechanisms.
var quantumMechanismRegistry = map[MechanismType]*MechanismDescriptor{
	// ML-DSA-44 (Dilithium2 equivalent)
	// Per PKCS#11 v3.2 sections 6.67.4/6.67.5, ulMinKeySize/ulMaxKeySize for
	// ML-DSA mechanisms specify the ML-DSA *public* key size *in bytes*. Each
	// vendor mechanism below is scoped to a single security level, so
	// MinKeySize == MaxKeySize == that level's public key size.
	CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN: {
		Type:         CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN,
		Name:         "CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN",
		Categories:   []MechanismCategory{CategoryKeyPairGen},
		MinKeySize:   MLDSA44PublicKeySize,
		MaxKeySize:   MLDSA44PublicKeySize,
		Flags:        CKF_GENERATE_KEY_PAIR | CKF_EXTENSION,
		FIPSApproved: true,
	},
	CKM_VENDOR_ML_DSA_44: {
		Type:         CKM_VENDOR_ML_DSA_44,
		Name:         "CKM_VENDOR_ML_DSA_44",
		Categories:   []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:   MLDSA44PublicKeySize,
		MaxKeySize:   MLDSA44PublicKeySize,
		Flags:        CKF_SIGN | CKF_VERIFY | CKF_EXTENSION,
		FIPSApproved: true,
	},

	// ML-DSA-65 (Dilithium3 equivalent)
	CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN: {
		Type:         CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN,
		Name:         "CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN",
		Categories:   []MechanismCategory{CategoryKeyPairGen},
		MinKeySize:   MLDSA65PublicKeySize,
		MaxKeySize:   MLDSA65PublicKeySize,
		Flags:        CKF_GENERATE_KEY_PAIR | CKF_EXTENSION,
		FIPSApproved: true,
	},
	CKM_VENDOR_ML_DSA_65: {
		Type:         CKM_VENDOR_ML_DSA_65,
		Name:         "CKM_VENDOR_ML_DSA_65",
		Categories:   []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:   MLDSA65PublicKeySize,
		MaxKeySize:   MLDSA65PublicKeySize,
		Flags:        CKF_SIGN | CKF_VERIFY | CKF_EXTENSION,
		FIPSApproved: true,
	},

	// ML-DSA-87 (Dilithium5 equivalent)
	CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN: {
		Type:         CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN,
		Name:         "CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN",
		Categories:   []MechanismCategory{CategoryKeyPairGen},
		MinKeySize:   MLDSA87PublicKeySize,
		MaxKeySize:   MLDSA87PublicKeySize,
		Flags:        CKF_GENERATE_KEY_PAIR | CKF_EXTENSION,
		FIPSApproved: true,
	},
	CKM_VENDOR_ML_DSA_87: {
		Type:         CKM_VENDOR_ML_DSA_87,
		Name:         "CKM_VENDOR_ML_DSA_87",
		Categories:   []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:   MLDSA87PublicKeySize,
		MaxKeySize:   MLDSA87PublicKeySize,
		Flags:        CKF_SIGN | CKF_VERIFY | CKF_EXTENSION,
		FIPSApproved: true,
	},

	// Per PKCS#11 v3.2 sections 6.68.4/6.68.5, ulMinKeySize/ulMaxKeySize for
	// ML-KEM mechanisms specify the ML-KEM *public* key size *in bytes*, for
	// both the key generation and the (en|de)capsulation direction -- never
	// the private key/seed size. Each vendor mechanism below is scoped to a
	// single security level, so MinKeySize == MaxKeySize == that level's
	// public key size.

	// The (en|de)capsulation mechanisms carry CKF_ENCAPSULATE / CKF_DECAPSULATE
	// rather than CKF_DERIVE. PKCS#11 v3.2 §5.20 gates C_EncapsulateKey and
	// C_DecapsulateKey on those flags and gates C_DeriveKey on CKF_DERIVE; none
	// of these mechanisms appears in C_DeriveKey's dispatch, so CKF_DERIVE told
	// CanDerive to answer true for an operation that always returns
	// CKR_MECHANISM_INVALID, while the flag that should have gated the
	// operation they DO perform went unset.

	// ML-KEM-512
	//
	// These descriptors were absent for a period, because crypto/mlkem -- which
	// the 768 and 1024 paths wrap -- implements only those two parameter sets,
	// and registering mechanisms the crypto layer could not perform advertised
	// three operations that failed after C_EncapsulateKey's size query had
	// already answered CKR_OK. pkg/quantum/mlkem512 now supplies the parameter
	// set from CIRCL's FIPS 203 implementation, so the operations are real and
	// the descriptors describe something the token does.
	CKM_VENDOR_ML_KEM_512_KEY_GEN: {
		Type:         CKM_VENDOR_ML_KEM_512_KEY_GEN,
		Name:         "CKM_VENDOR_ML_KEM_512_KEY_GEN",
		Categories:   []MechanismCategory{CategoryKeyPairGen},
		MinKeySize:   MLKEM512PublicKeySize,
		MaxKeySize:   MLKEM512PublicKeySize,
		Flags:        CKF_GENERATE_KEY_PAIR | CKF_EXTENSION,
		FIPSApproved: true,
	},
	CKM_VENDOR_ML_KEM_512_ENCAPSULATE: {
		Type:         CKM_VENDOR_ML_KEM_512_ENCAPSULATE,
		Name:         "CKM_VENDOR_ML_KEM_512_ENCAPSULATE",
		Categories:   []MechanismCategory{CategoryEncapsulate},
		MinKeySize:   MLKEM512PublicKeySize,
		MaxKeySize:   MLKEM512PublicKeySize,
		Flags:        CKF_ENCAPSULATE | CKF_EXTENSION,
		FIPSApproved: true,
	},
	CKM_VENDOR_ML_KEM_512_DECAPSULATE: {
		Type:         CKM_VENDOR_ML_KEM_512_DECAPSULATE,
		Name:         "CKM_VENDOR_ML_KEM_512_DECAPSULATE",
		Categories:   []MechanismCategory{CategoryDecapsulate},
		MinKeySize:   MLKEM512PublicKeySize,
		MaxKeySize:   MLKEM512PublicKeySize,
		Flags:        CKF_DECAPSULATE | CKF_EXTENSION,
		FIPSApproved: true,
	},

	// ML-KEM-768 (Kyber768 equivalent)
	CKM_VENDOR_ML_KEM_768_KEY_GEN: {
		Type:         CKM_VENDOR_ML_KEM_768_KEY_GEN,
		Name:         "CKM_VENDOR_ML_KEM_768_KEY_GEN",
		Categories:   []MechanismCategory{CategoryKeyPairGen},
		MinKeySize:   MLKEM768PublicKeySize,
		MaxKeySize:   MLKEM768PublicKeySize,
		Flags:        CKF_GENERATE_KEY_PAIR | CKF_EXTENSION,
		FIPSApproved: true,
	},
	CKM_VENDOR_ML_KEM_768_ENCAPSULATE: {
		Type:         CKM_VENDOR_ML_KEM_768_ENCAPSULATE,
		Name:         "CKM_VENDOR_ML_KEM_768_ENCAPSULATE",
		Categories:   []MechanismCategory{CategoryEncapsulate},
		MinKeySize:   MLKEM768PublicKeySize,
		MaxKeySize:   MLKEM768PublicKeySize,
		Flags:        CKF_ENCAPSULATE | CKF_EXTENSION,
		FIPSApproved: true,
	},
	CKM_VENDOR_ML_KEM_768_DECAPSULATE: {
		Type:         CKM_VENDOR_ML_KEM_768_DECAPSULATE,
		Name:         "CKM_VENDOR_ML_KEM_768_DECAPSULATE",
		Categories:   []MechanismCategory{CategoryDecapsulate},
		MinKeySize:   MLKEM768PublicKeySize,
		MaxKeySize:   MLKEM768PublicKeySize,
		Flags:        CKF_DECAPSULATE | CKF_EXTENSION,
		FIPSApproved: true,
	},

	// ML-KEM-1024 (Kyber1024 equivalent)
	CKM_VENDOR_ML_KEM_1024_KEY_GEN: {
		Type:         CKM_VENDOR_ML_KEM_1024_KEY_GEN,
		Name:         "CKM_VENDOR_ML_KEM_1024_KEY_GEN",
		Categories:   []MechanismCategory{CategoryKeyPairGen},
		MinKeySize:   MLKEM1024PublicKeySize,
		MaxKeySize:   MLKEM1024PublicKeySize,
		Flags:        CKF_GENERATE_KEY_PAIR | CKF_EXTENSION,
		FIPSApproved: true,
	},
	CKM_VENDOR_ML_KEM_1024_ENCAPSULATE: {
		Type:         CKM_VENDOR_ML_KEM_1024_ENCAPSULATE,
		Name:         "CKM_VENDOR_ML_KEM_1024_ENCAPSULATE",
		Categories:   []MechanismCategory{CategoryEncapsulate},
		MinKeySize:   MLKEM1024PublicKeySize,
		MaxKeySize:   MLKEM1024PublicKeySize,
		Flags:        CKF_ENCAPSULATE | CKF_EXTENSION,
		FIPSApproved: true,
	},
	CKM_VENDOR_ML_KEM_1024_DECAPSULATE: {
		Type:         CKM_VENDOR_ML_KEM_1024_DECAPSULATE,
		Name:         "CKM_VENDOR_ML_KEM_1024_DECAPSULATE",
		Categories:   []MechanismCategory{CategoryDecapsulate},
		MinKeySize:   MLKEM1024PublicKeySize,
		MaxKeySize:   MLKEM1024PublicKeySize,
		Flags:        CKF_DECAPSULATE | CKF_EXTENSION,
		FIPSApproved: true,
	},
}

// init registers quantum-safe mechanisms into the global registry.
func init() {
	// Register mechanism names
	for mechType, name := range quantumMechanismNames {
		mechanismNames[mechType] = name
	}

	// Register mechanism descriptors
	for mechType, desc := range quantumMechanismRegistry {
		mechanismRegistry[mechType] = desc
	}

	// Register key type names
	for keyType, name := range quantumKeyTypeNames {
		keyTypeNames[keyType] = name
	}
}

// GetQuantumMechanismDescriptor returns the descriptor for a quantum mechanism.
// Returns nil if the mechanism is not a quantum-safe mechanism.
//
// PKCS#11 v3.2 standardized CKM_ML_DSA and CKM_ML_KEM as the non-vendor
// replacements for the legacy per-level vendor mechanisms; their descriptors
// live in the global registry (populated by mechanism_v32.go's init), not in
// quantumMechanismRegistry. Fall back to the global registry for exactly
// those two mechanism types so dispatch code that gates on this function
// accepts the standard mechanisms as well as the vendor-defined ones.
func GetQuantumMechanismDescriptor(mechType MechanismType) *MechanismDescriptor {
	if desc, ok := quantumMechanismRegistry[mechType]; ok {
		// Apply the same FIPS choke point the classical GetMechanismDescriptor
		// applies, so this registry cannot become a second policy that diverges
		// from the first. Every mechanism here is a genuine FIPS 203/204
		// algorithm and is marked FIPSApproved, so this hides nothing today; it
		// is the guard that keeps a future non-approved PQC mechanism added to
		// quantumMechanismRegistry from being reachable under FIPS mode.
		if !desc.FIPSApproved && fipsModeEnabled() {
			return nil
		}
		return desc
	}
	if mechType == CKM_ML_DSA || mechType == CKM_ML_KEM {
		return GetMechanismDescriptor(mechType)
	}
	return nil
}

// IsQuantumMechanism returns true if the mechanism type is a quantum-safe mechanism.
func IsQuantumMechanism(mechType MechanismType) bool {
	_, ok := quantumMechanismRegistry[mechType]
	return ok
}

// IsMLDSAMechanism returns true if the mechanism is an ML-DSA mechanism,
// including both the legacy per-level vendor mechanisms and the PKCS#11 v3.2
// standard CKM_ML_DSA mechanism.
func IsMLDSAMechanism(mechType MechanismType) bool {
	if mechType == CKM_ML_DSA {
		return true
	}
	return mechType >= CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN &&
		mechType <= CKM_VENDOR_ML_DSA_87
}

// IsMLKEMMechanism returns true if the mechanism is an ML-KEM mechanism,
// including both the legacy per-level vendor mechanisms and the PKCS#11 v3.2
// standard CKM_ML_KEM mechanism.
func IsMLKEMMechanism(mechType MechanismType) bool {
	if mechType == CKM_ML_KEM {
		return true
	}
	return mechType >= CKM_VENDOR_ML_KEM_512_KEY_GEN &&
		mechType <= CKM_VENDOR_ML_KEM_1024_DECAPSULATE
}

// GetQuantumKeyType returns the key type for a quantum mechanism.
func GetQuantumKeyType(mechType MechanismType) KeyType {
	if IsMLDSAMechanism(mechType) {
		return CKK_VENDOR_ML_DSA
	}
	if IsMLKEMMechanism(mechType) {
		return CKK_VENDOR_ML_KEM
	}
	return CKK_VENDOR_DEFINED
}

// GetMLDSASecurityLevel returns the security level (44, 65, 87) for an ML-DSA mechanism.
// Returns 0 if the mechanism is not an ML-DSA mechanism.
func GetMLDSASecurityLevel(mechType MechanismType) int {
	switch mechType {
	case CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN, CKM_VENDOR_ML_DSA_44:
		return 44
	case CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN, CKM_VENDOR_ML_DSA_65:
		return 65
	case CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN, CKM_VENDOR_ML_DSA_87:
		return 87
	default:
		return 0
	}
}

// GetMLKEMSecurityLevel returns the security level (512, 768, 1024) for an ML-KEM mechanism.
// Returns 0 if the mechanism is not an ML-KEM mechanism.
func GetMLKEMSecurityLevel(mechType MechanismType) int {
	switch mechType {
	case CKM_VENDOR_ML_KEM_512_KEY_GEN,
		CKM_VENDOR_ML_KEM_512_ENCAPSULATE,
		CKM_VENDOR_ML_KEM_512_DECAPSULATE:
		return 512
	case CKM_VENDOR_ML_KEM_768_KEY_GEN,
		CKM_VENDOR_ML_KEM_768_ENCAPSULATE,
		CKM_VENDOR_ML_KEM_768_DECAPSULATE:
		return 768
	case CKM_VENDOR_ML_KEM_1024_KEY_GEN,
		CKM_VENDOR_ML_KEM_1024_ENCAPSULATE,
		CKM_VENDOR_ML_KEM_1024_DECAPSULATE:
		return 1024
	default:
		return 0
	}
}

// ResolveMLDSASecurityLevel returns the ML-DSA security level (44, 65, or 87)
// for a mechanism, falling back to inferring the level from the length of
// the associated key material when the mechanism is the PKCS#11 v3.2
// standard CKM_ML_DSA mechanism. Per spec section 6.67.4/6.67.5, CKM_ML_DSA
// carries no mechanism parameter -- the parameter set is selected by the
// key object's CKA_PARAMETER_SET attribute -- so callers that only have raw
// key bytes (not the key Object) can still resolve the level unambiguously
// when keyMaterialLen is an ML-DSA public key size, since the three ML-DSA
// public key sizes never collide (1312/1952/2592 bytes per FIPS 204).
// Returns 0 if the security level cannot be determined, which is expected
// when keyMaterialLen is a private-key seed rather than a public key, since
// this module stores all ML-DSA private keys as a fixed-size 32-byte seed
// regardless of security level; resolving that case requires the key
// object's CKA_PARAMETER_SET attribute, which callers with Object access
// should consult directly rather than relying on this fallback.
func ResolveMLDSASecurityLevel(mechType MechanismType, keyMaterialLen int) int {
	if level := GetMLDSASecurityLevel(mechType); level != 0 {
		return level
	}
	if mechType != CKM_ML_DSA {
		return 0
	}
	switch keyMaterialLen {
	case MLDSA44PublicKeySize:
		return 44
	case MLDSA65PublicKeySize:
		return 65
	case MLDSA87PublicKeySize:
		return 87
	default:
		return 0
	}
}

// ResolveMLKEMSecurityLevel is the ML-KEM analog of ResolveMLDSASecurityLevel,
// returning 512, 768, or 1024. It falls back to inferring the level from
// keyMaterialLen (an ML-KEM public key size: 800/1184/1568 bytes per FIPS
// 203) when the mechanism is the PKCS#11 v3.2 standard CKM_ML_KEM mechanism.
// Returns 0 if the security level cannot be determined, which is expected
// when keyMaterialLen is a private-key seed (this module stores all ML-KEM
// private keys as a fixed-size 64-byte seed regardless of security level);
// resolving that case requires the key object's CKA_PARAMETER_SET attribute.
func ResolveMLKEMSecurityLevel(mechType MechanismType, keyMaterialLen int) int {
	if level := GetMLKEMSecurityLevel(mechType); level != 0 {
		return level
	}
	if mechType != CKM_ML_KEM {
		return 0
	}
	switch keyMaterialLen {
	case MLKEM512PublicKeySize:
		return 512
	case MLKEM768PublicKeySize:
		return 768
	case MLKEM1024PublicKeySize:
		return 1024
	default:
		return 0
	}
}

// ListQuantumMechanisms returns all registered quantum-safe mechanism types.
func ListQuantumMechanisms() []MechanismType {
	mechanisms := make([]MechanismType, 0, len(quantumMechanismRegistry))
	for mechType := range quantumMechanismRegistry {
		mechanisms = append(mechanisms, mechType)
	}
	return mechanisms
}

// Vendor-to-Standard Mechanism Mapping (PKCS#11 v3.2 Backward Compatibility)
//
// PKCS#11 v3.2 standardized mechanism IDs for post-quantum algorithms that were
// previously vendor-defined. The mappings below allow applications using the old
// vendor-defined mechanisms to be automatically routed to the standard mechanisms.

// vendorToStandardMechanism maps vendor-defined mechanism types to their
// PKCS#11 v3.2 standard equivalents.
var vendorToStandardMechanism = map[MechanismType]MechanismType{
	// ML-DSA vendor → standard
	CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN: CKM_ML_DSA_KEY_PAIR_GEN,
	CKM_VENDOR_ML_DSA_44:              CKM_ML_DSA,
	CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN: CKM_ML_DSA_KEY_PAIR_GEN,
	CKM_VENDOR_ML_DSA_65:              CKM_ML_DSA,
	CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN: CKM_ML_DSA_KEY_PAIR_GEN,
	CKM_VENDOR_ML_DSA_87:              CKM_ML_DSA,
	// ML-KEM vendor → standard
	CKM_VENDOR_ML_KEM_512_KEY_GEN:      CKM_ML_KEM_KEY_PAIR_GEN,
	CKM_VENDOR_ML_KEM_768_KEY_GEN:      CKM_ML_KEM_KEY_PAIR_GEN,
	CKM_VENDOR_ML_KEM_1024_KEY_GEN:     CKM_ML_KEM_KEY_PAIR_GEN,
	CKM_VENDOR_ML_KEM_512_ENCAPSULATE:  CKM_ML_KEM,
	CKM_VENDOR_ML_KEM_768_ENCAPSULATE:  CKM_ML_KEM,
	CKM_VENDOR_ML_KEM_1024_ENCAPSULATE: CKM_ML_KEM,
	CKM_VENDOR_ML_KEM_512_DECAPSULATE:  CKM_ML_KEM,
	CKM_VENDOR_ML_KEM_768_DECAPSULATE:  CKM_ML_KEM,
	CKM_VENDOR_ML_KEM_1024_DECAPSULATE: CKM_ML_KEM,
}

// vendorToStandardKeyType maps vendor key types to standard v3.2 key types.
var vendorToStandardKeyType = map[KeyType]KeyType{
	CKK_VENDOR_ML_DSA: CKK_ML_DSA,
	CKK_VENDOR_ML_KEM: CKK_ML_KEM,
}

// GetStandardMechanism returns the standard v3.2 mechanism type for a vendor mechanism.
// Returns the input mechanism unchanged if no mapping exists.
func GetStandardMechanism(vendorMech MechanismType) MechanismType {
	if stdMech, ok := vendorToStandardMechanism[vendorMech]; ok {
		return stdMech
	}
	return vendorMech
}

// GetStandardKeyType returns the standard v3.2 key type for a vendor key type.
// Returns the input key type unchanged if no mapping exists.
func GetStandardKeyType(vendorKey KeyType) KeyType {
	if stdKey, ok := vendorToStandardKeyType[vendorKey]; ok {
		return stdKey
	}
	return vendorKey
}
