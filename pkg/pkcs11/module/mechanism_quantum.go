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
	CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN: {
		Type:       CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN,
		Name:       "CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		MinKeySize: MLDSA44PublicKeySize * 8, // in bits
		MaxKeySize: MLDSA44SecretKeySize * 8,
		Flags:      CKF_GENERATE_KEY_PAIR | CKF_EXTENSION,
	},
	CKM_VENDOR_ML_DSA_44: {
		Type:       CKM_VENDOR_ML_DSA_44,
		Name:       "CKM_VENDOR_ML_DSA_44",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA44PublicKeySize * 8,
		MaxKeySize: MLDSA44SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_EXTENSION,
	},

	// ML-DSA-65 (Dilithium3 equivalent)
	CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN: {
		Type:       CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN,
		Name:       "CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		MinKeySize: MLDSA65PublicKeySize * 8,
		MaxKeySize: MLDSA65SecretKeySize * 8,
		Flags:      CKF_GENERATE_KEY_PAIR | CKF_EXTENSION,
	},
	CKM_VENDOR_ML_DSA_65: {
		Type:       CKM_VENDOR_ML_DSA_65,
		Name:       "CKM_VENDOR_ML_DSA_65",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA65PublicKeySize * 8,
		MaxKeySize: MLDSA65SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_EXTENSION,
	},

	// ML-DSA-87 (Dilithium5 equivalent)
	CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN: {
		Type:       CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN,
		Name:       "CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		MinKeySize: MLDSA87PublicKeySize * 8,
		MaxKeySize: MLDSA87SecretKeySize * 8,
		Flags:      CKF_GENERATE_KEY_PAIR | CKF_EXTENSION,
	},
	CKM_VENDOR_ML_DSA_87: {
		Type:       CKM_VENDOR_ML_DSA_87,
		Name:       "CKM_VENDOR_ML_DSA_87",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA87PublicKeySize * 8,
		MaxKeySize: MLDSA87SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_EXTENSION,
	},

	// ML-KEM-512 (Kyber512 equivalent)
	CKM_VENDOR_ML_KEM_512_KEY_GEN: {
		Type:       CKM_VENDOR_ML_KEM_512_KEY_GEN,
		Name:       "CKM_VENDOR_ML_KEM_512_KEY_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		MinKeySize: MLKEM512PublicKeySize * 8,
		MaxKeySize: MLKEM512SecretKeySize * 8,
		Flags:      CKF_GENERATE_KEY_PAIR | CKF_EXTENSION,
	},
	CKM_VENDOR_ML_KEM_512_ENCAPSULATE: {
		Type:       CKM_VENDOR_ML_KEM_512_ENCAPSULATE,
		Name:       "CKM_VENDOR_ML_KEM_512_ENCAPSULATE",
		Categories: []MechanismCategory{CategoryEncapsulate},
		MinKeySize: MLKEM512PublicKeySize * 8,
		MaxKeySize: MLKEM512PublicKeySize * 8,
		Flags:      CKF_DERIVE | CKF_EXTENSION,
	},
	CKM_VENDOR_ML_KEM_512_DECAPSULATE: {
		Type:       CKM_VENDOR_ML_KEM_512_DECAPSULATE,
		Name:       "CKM_VENDOR_ML_KEM_512_DECAPSULATE",
		Categories: []MechanismCategory{CategoryDecapsulate},
		MinKeySize: MLKEM512SecretKeySize * 8,
		MaxKeySize: MLKEM512SecretKeySize * 8,
		Flags:      CKF_DERIVE | CKF_EXTENSION,
	},

	// ML-KEM-768 (Kyber768 equivalent)
	CKM_VENDOR_ML_KEM_768_KEY_GEN: {
		Type:       CKM_VENDOR_ML_KEM_768_KEY_GEN,
		Name:       "CKM_VENDOR_ML_KEM_768_KEY_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		MinKeySize: MLKEM768PublicKeySize * 8,
		MaxKeySize: MLKEM768SecretKeySize * 8,
		Flags:      CKF_GENERATE_KEY_PAIR | CKF_EXTENSION,
	},
	CKM_VENDOR_ML_KEM_768_ENCAPSULATE: {
		Type:       CKM_VENDOR_ML_KEM_768_ENCAPSULATE,
		Name:       "CKM_VENDOR_ML_KEM_768_ENCAPSULATE",
		Categories: []MechanismCategory{CategoryEncapsulate},
		MinKeySize: MLKEM768PublicKeySize * 8,
		MaxKeySize: MLKEM768PublicKeySize * 8,
		Flags:      CKF_DERIVE | CKF_EXTENSION,
	},
	CKM_VENDOR_ML_KEM_768_DECAPSULATE: {
		Type:       CKM_VENDOR_ML_KEM_768_DECAPSULATE,
		Name:       "CKM_VENDOR_ML_KEM_768_DECAPSULATE",
		Categories: []MechanismCategory{CategoryDecapsulate},
		MinKeySize: MLKEM768SecretKeySize * 8,
		MaxKeySize: MLKEM768SecretKeySize * 8,
		Flags:      CKF_DERIVE | CKF_EXTENSION,
	},

	// ML-KEM-1024 (Kyber1024 equivalent)
	CKM_VENDOR_ML_KEM_1024_KEY_GEN: {
		Type:       CKM_VENDOR_ML_KEM_1024_KEY_GEN,
		Name:       "CKM_VENDOR_ML_KEM_1024_KEY_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		MinKeySize: MLKEM1024PublicKeySize * 8,
		MaxKeySize: MLKEM1024SecretKeySize * 8,
		Flags:      CKF_GENERATE_KEY_PAIR | CKF_EXTENSION,
	},
	CKM_VENDOR_ML_KEM_1024_ENCAPSULATE: {
		Type:       CKM_VENDOR_ML_KEM_1024_ENCAPSULATE,
		Name:       "CKM_VENDOR_ML_KEM_1024_ENCAPSULATE",
		Categories: []MechanismCategory{CategoryEncapsulate},
		MinKeySize: MLKEM1024PublicKeySize * 8,
		MaxKeySize: MLKEM1024PublicKeySize * 8,
		Flags:      CKF_DERIVE | CKF_EXTENSION,
	},
	CKM_VENDOR_ML_KEM_1024_DECAPSULATE: {
		Type:       CKM_VENDOR_ML_KEM_1024_DECAPSULATE,
		Name:       "CKM_VENDOR_ML_KEM_1024_DECAPSULATE",
		Categories: []MechanismCategory{CategoryDecapsulate},
		MinKeySize: MLKEM1024SecretKeySize * 8,
		MaxKeySize: MLKEM1024SecretKeySize * 8,
		Flags:      CKF_DERIVE | CKF_EXTENSION,
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
func GetQuantumMechanismDescriptor(mechType MechanismType) *MechanismDescriptor {
	return quantumMechanismRegistry[mechType]
}

// IsQuantumMechanism returns true if the mechanism type is a quantum-safe mechanism.
func IsQuantumMechanism(mechType MechanismType) bool {
	_, ok := quantumMechanismRegistry[mechType]
	return ok
}

// IsMLDSAMechanism returns true if the mechanism is an ML-DSA mechanism.
func IsMLDSAMechanism(mechType MechanismType) bool {
	return mechType >= CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN &&
		mechType <= CKM_VENDOR_ML_DSA_87
}

// IsMLKEMMechanism returns true if the mechanism is an ML-KEM mechanism.
func IsMLKEMMechanism(mechType MechanismType) bool {
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
