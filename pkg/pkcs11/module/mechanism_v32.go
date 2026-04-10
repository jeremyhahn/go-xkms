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

// Package module provides PKCS#11 v3.2 post-quantum cryptography mechanism definitions.
//
// This file implements the official standard mechanism types defined in the
// OASIS PKCS#11 v3.2 CSD01 specification for post-quantum cryptographic algorithms.
// These mechanisms use the standard (non-vendor) mechanism range, replacing
// the vendor-defined mechanisms in mechanism_quantum.go for production use.
//
// Supported algorithms:
//   - ML-DSA (Module-Lattice Digital Signature Algorithm) - NIST FIPS 204
//   - ML-KEM (Module-Lattice Key Encapsulation Mechanism) - NIST FIPS 203
//   - SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) - NIST FIPS 205
//   - HSS/LMS (Hash-Based Signatures) - RFC 8554
//   - XMSS/XMSS^MT (eXtended Merkle Signature Scheme) - RFC 8391
//   - HashML-DSA (Pre-hashed ML-DSA variants)
//   - HashSLH-DSA (Pre-hashed SLH-DSA variants)
//
// References:
//   - OASIS PKCS#11 v3.2 CSD01: pkcs11t.h
//   - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
//   - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
//   - NIST FIPS 205: Stateless Hash-Based Digital Signature Standard
//   - RFC 8554: Leighton-Micali Hash-Based Signatures (LMS)
//   - RFC 8391: XMSS: eXtended Merkle Signature Scheme
package module

// v3.2 mechanism categories for encapsulation operations.
// These use unexported names to avoid symbol conflicts with the vendor-defined
// CategoryEncapsulate and CategoryDecapsulate in mechanism_quantum.go
// (build-tagged with "quantum"). Both use identical numeric values for
// compatibility when mechanisms from either source are registered together.
const (
	v32CategoryEncapsulate MechanismCategory = 10
	v32CategoryDecapsulate MechanismCategory = 11
)

// v3.2 PQC key sizes in bytes per algorithm and security level.
// These mirror the values in mechanism_quantum.go (build-tagged "quantum")
// using unexported names to avoid duplicate symbol errors when both files
// are compiled together.
const (
	// ML-DSA-44 (NIST Category 2)
	v32MLDSA44PublicKeySize = 1312
	v32MLDSA44SecretKeySize = 2560

	// ML-DSA-87 (NIST Category 5)
	v32MLDSA87PublicKeySize = 2592
	v32MLDSA87SecretKeySize = 4896

	// ML-KEM-512 (NIST Category 1)
	v32MLKEM512PublicKeySize = 800
	v32MLKEM512SecretKeySize = 1632

	// ML-KEM-1024 (NIST Category 5)
	v32MLKEM1024PublicKeySize = 1568
	v32MLKEM1024SecretKeySize = 3168
)

// PKCS#11 v3.2 Post-Quantum Mechanism Type Constants (CKM_*)
// Reference: OASIS PKCS#11 v3.2 CSD01 pkcs11t.h
const (
	// ML-KEM (FIPS 203) Mechanisms
	// Module-Lattice Key Encapsulation Mechanism (formerly Kyber)

	// CKM_ML_KEM_KEY_PAIR_GEN generates ML-KEM key pairs.
	// Supports security levels ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
	CKM_ML_KEM_KEY_PAIR_GEN MechanismType = 0x0000000f

	// CKM_ML_KEM performs ML-KEM encapsulation and decapsulation.
	CKM_ML_KEM MechanismType = 0x00000017

	// ML-DSA (FIPS 204) Mechanisms
	// Module-Lattice Digital Signature Algorithm (formerly Dilithium)

	// CKM_ML_DSA_KEY_PAIR_GEN generates ML-DSA key pairs.
	// Supports security levels ML-DSA-44, ML-DSA-65, and ML-DSA-87.
	CKM_ML_DSA_KEY_PAIR_GEN MechanismType = 0x0000001c

	// CKM_ML_DSA performs ML-DSA signing and verification.
	CKM_ML_DSA MechanismType = 0x0000001d

	// HashML-DSA Mechanisms (pre-hashed ML-DSA variants)

	// CKM_HASH_ML_DSA performs HashML-DSA signing and verification (multi-part capable).
	CKM_HASH_ML_DSA MechanismType = 0x0000001f

	// CKM_HASH_ML_DSA_SHA224 performs HashML-DSA with SHA-224 (single-part only).
	CKM_HASH_ML_DSA_SHA224 MechanismType = 0x00000023

	// CKM_HASH_ML_DSA_SHA256 performs HashML-DSA with SHA-256 (single-part only).
	CKM_HASH_ML_DSA_SHA256 MechanismType = 0x00000024

	// CKM_HASH_ML_DSA_SHA384 performs HashML-DSA with SHA-384 (single-part only).
	CKM_HASH_ML_DSA_SHA384 MechanismType = 0x00000025

	// CKM_HASH_ML_DSA_SHA512 performs HashML-DSA with SHA-512 (single-part only).
	CKM_HASH_ML_DSA_SHA512 MechanismType = 0x00000026

	// CKM_HASH_ML_DSA_SHA3_224 performs HashML-DSA with SHA3-224 (single-part only).
	CKM_HASH_ML_DSA_SHA3_224 MechanismType = 0x00000027

	// CKM_HASH_ML_DSA_SHA3_256 performs HashML-DSA with SHA3-256 (single-part only).
	CKM_HASH_ML_DSA_SHA3_256 MechanismType = 0x00000028

	// CKM_HASH_ML_DSA_SHA3_384 performs HashML-DSA with SHA3-384 (single-part only).
	CKM_HASH_ML_DSA_SHA3_384 MechanismType = 0x00000029

	// CKM_HASH_ML_DSA_SHA3_512 performs HashML-DSA with SHA3-512 (single-part only).
	CKM_HASH_ML_DSA_SHA3_512 MechanismType = 0x0000002a

	// CKM_HASH_ML_DSA_SHAKE128 performs HashML-DSA with SHAKE128 (single-part only).
	CKM_HASH_ML_DSA_SHAKE128 MechanismType = 0x0000002b

	// CKM_HASH_ML_DSA_SHAKE256 performs HashML-DSA with SHAKE256 (single-part only).
	CKM_HASH_ML_DSA_SHAKE256 MechanismType = 0x0000002c

	// SLH-DSA (FIPS 205) Mechanisms
	// Stateless Hash-Based Digital Signature Algorithm (formerly SPHINCS+)

	// CKM_SLH_DSA_KEY_PAIR_GEN generates SLH-DSA key pairs.
	CKM_SLH_DSA_KEY_PAIR_GEN MechanismType = 0x0000002d

	// CKM_SLH_DSA performs SLH-DSA signing and verification.
	CKM_SLH_DSA MechanismType = 0x0000002e

	// HashSLH-DSA Mechanisms (pre-hashed SLH-DSA variants)

	// CKM_HASH_SLH_DSA performs HashSLH-DSA signing and verification (multi-part capable).
	CKM_HASH_SLH_DSA MechanismType = 0x00000034

	// CKM_HASH_SLH_DSA_SHA224 performs HashSLH-DSA with SHA-224 (single-part only).
	CKM_HASH_SLH_DSA_SHA224 MechanismType = 0x00000036

	// CKM_HASH_SLH_DSA_SHA256 performs HashSLH-DSA with SHA-256 (single-part only).
	CKM_HASH_SLH_DSA_SHA256 MechanismType = 0x00000037

	// CKM_HASH_SLH_DSA_SHA384 performs HashSLH-DSA with SHA-384 (single-part only).
	CKM_HASH_SLH_DSA_SHA384 MechanismType = 0x00000038

	// CKM_HASH_SLH_DSA_SHA512 performs HashSLH-DSA with SHA-512 (single-part only).
	CKM_HASH_SLH_DSA_SHA512 MechanismType = 0x00000039

	// CKM_HASH_SLH_DSA_SHA3_224 performs HashSLH-DSA with SHA3-224 (single-part only).
	CKM_HASH_SLH_DSA_SHA3_224 MechanismType = 0x0000003a

	// CKM_HASH_SLH_DSA_SHA3_256 performs HashSLH-DSA with SHA3-256 (single-part only).
	CKM_HASH_SLH_DSA_SHA3_256 MechanismType = 0x0000003b

	// CKM_HASH_SLH_DSA_SHA3_384 performs HashSLH-DSA with SHA3-384 (single-part only).
	CKM_HASH_SLH_DSA_SHA3_384 MechanismType = 0x0000003c

	// CKM_HASH_SLH_DSA_SHA3_512 performs HashSLH-DSA with SHA3-512 (single-part only).
	CKM_HASH_SLH_DSA_SHA3_512 MechanismType = 0x0000003d

	// CKM_HASH_SLH_DSA_SHAKE128 performs HashSLH-DSA with SHAKE128 (single-part only).
	CKM_HASH_SLH_DSA_SHAKE128 MechanismType = 0x0000003e

	// CKM_HASH_SLH_DSA_SHAKE256 performs HashSLH-DSA with SHAKE256 (single-part only).
	CKM_HASH_SLH_DSA_SHAKE256 MechanismType = 0x0000003f

	// TLS 1.2 Extended Master Key Mechanisms

	// CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE derives an extended master secret (TLS 1.2).
	CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE MechanismType = 0x00000056

	// CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH derives an extended master secret using DH (TLS 1.2).
	CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH MechanismType = 0x00000057

	// HSS/LMS (RFC 8554) Mechanisms
	// Hierarchical Signature Scheme / Leighton-Micali Signature

	// CKM_HSS_KEY_PAIR_GEN generates HSS/LMS key pairs.
	CKM_HSS_KEY_PAIR_GEN MechanismType = 0x00004032

	// CKM_HSS performs HSS/LMS signing and verification.
	CKM_HSS MechanismType = 0x00004033

	// XMSS (RFC 8391) Mechanisms
	// eXtended Merkle Signature Scheme

	// CKM_XMSS_KEY_PAIR_GEN generates XMSS key pairs.
	CKM_XMSS_KEY_PAIR_GEN MechanismType = 0x00004034

	// CKM_XMSSMT_KEY_PAIR_GEN generates XMSS^MT (multi-tree) key pairs.
	CKM_XMSSMT_KEY_PAIR_GEN MechanismType = 0x00004035

	// CKM_XMSS performs XMSS signing and verification.
	CKM_XMSS MechanismType = 0x00004036

	// CKM_XMSSMT performs XMSS^MT signing and verification.
	CKM_XMSSMT MechanismType = 0x00004037

	// ECDH Key Wrap Mechanisms (v3.2)

	// CKM_ECDH_X_AES_KEY_WRAP wraps/unwraps keys using ECDH with AES key wrap.
	CKM_ECDH_X_AES_KEY_WRAP MechanismType = 0x00004038

	// CKM_ECDH_COF_AES_KEY_WRAP wraps/unwraps keys using ECDH cofactor with AES key wrap.
	CKM_ECDH_COF_AES_KEY_WRAP MechanismType = 0x00004039

	// CKM_PUB_KEY_FROM_PRIV_KEY derives a public key from a private key.
	CKM_PUB_KEY_FROM_PRIV_KEY MechanismType = 0x0000403a
)

// v32MechanismNames maps v3.2 PQC mechanism types to their string names.
var v32MechanismNames = map[MechanismType]string{
	// ML-KEM mechanisms
	CKM_ML_KEM_KEY_PAIR_GEN: "CKM_ML_KEM_KEY_PAIR_GEN",
	CKM_ML_KEM:              "CKM_ML_KEM",

	// ML-DSA mechanisms
	CKM_ML_DSA_KEY_PAIR_GEN: "CKM_ML_DSA_KEY_PAIR_GEN",
	CKM_ML_DSA:              "CKM_ML_DSA",

	// HashML-DSA mechanisms
	CKM_HASH_ML_DSA:          "CKM_HASH_ML_DSA",
	CKM_HASH_ML_DSA_SHA224:   "CKM_HASH_ML_DSA_SHA224",
	CKM_HASH_ML_DSA_SHA256:   "CKM_HASH_ML_DSA_SHA256",
	CKM_HASH_ML_DSA_SHA384:   "CKM_HASH_ML_DSA_SHA384",
	CKM_HASH_ML_DSA_SHA512:   "CKM_HASH_ML_DSA_SHA512",
	CKM_HASH_ML_DSA_SHA3_224: "CKM_HASH_ML_DSA_SHA3_224",
	CKM_HASH_ML_DSA_SHA3_256: "CKM_HASH_ML_DSA_SHA3_256",
	CKM_HASH_ML_DSA_SHA3_384: "CKM_HASH_ML_DSA_SHA3_384",
	CKM_HASH_ML_DSA_SHA3_512: "CKM_HASH_ML_DSA_SHA3_512",
	CKM_HASH_ML_DSA_SHAKE128: "CKM_HASH_ML_DSA_SHAKE128",
	CKM_HASH_ML_DSA_SHAKE256: "CKM_HASH_ML_DSA_SHAKE256",

	// SLH-DSA mechanisms
	CKM_SLH_DSA_KEY_PAIR_GEN: "CKM_SLH_DSA_KEY_PAIR_GEN",
	CKM_SLH_DSA:              "CKM_SLH_DSA",

	// HashSLH-DSA mechanisms
	CKM_HASH_SLH_DSA:          "CKM_HASH_SLH_DSA",
	CKM_HASH_SLH_DSA_SHA224:   "CKM_HASH_SLH_DSA_SHA224",
	CKM_HASH_SLH_DSA_SHA256:   "CKM_HASH_SLH_DSA_SHA256",
	CKM_HASH_SLH_DSA_SHA384:   "CKM_HASH_SLH_DSA_SHA384",
	CKM_HASH_SLH_DSA_SHA512:   "CKM_HASH_SLH_DSA_SHA512",
	CKM_HASH_SLH_DSA_SHA3_224: "CKM_HASH_SLH_DSA_SHA3_224",
	CKM_HASH_SLH_DSA_SHA3_256: "CKM_HASH_SLH_DSA_SHA3_256",
	CKM_HASH_SLH_DSA_SHA3_384: "CKM_HASH_SLH_DSA_SHA3_384",
	CKM_HASH_SLH_DSA_SHA3_512: "CKM_HASH_SLH_DSA_SHA3_512",
	CKM_HASH_SLH_DSA_SHAKE128: "CKM_HASH_SLH_DSA_SHAKE128",
	CKM_HASH_SLH_DSA_SHAKE256: "CKM_HASH_SLH_DSA_SHAKE256",

	// HSS/LMS mechanisms
	CKM_HSS_KEY_PAIR_GEN: "CKM_HSS_KEY_PAIR_GEN",
	CKM_HSS:              "CKM_HSS",

	// XMSS mechanisms
	CKM_XMSS_KEY_PAIR_GEN:   "CKM_XMSS_KEY_PAIR_GEN",
	CKM_XMSS:                "CKM_XMSS",
	CKM_XMSSMT_KEY_PAIR_GEN: "CKM_XMSSMT_KEY_PAIR_GEN",
	CKM_XMSSMT:              "CKM_XMSSMT",

	// TLS 1.2 extended master key mechanisms
	CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE:    "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE",
	CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH: "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH",

	// ECDH key wrap mechanisms
	CKM_ECDH_X_AES_KEY_WRAP:   "CKM_ECDH_X_AES_KEY_WRAP",
	CKM_ECDH_COF_AES_KEY_WRAP: "CKM_ECDH_COF_AES_KEY_WRAP",

	// Public key from private key
	CKM_PUB_KEY_FROM_PRIV_KEY: "CKM_PUB_KEY_FROM_PRIV_KEY",
}

// v32MechanismRegistry contains descriptors for v3.2 standard PQC mechanisms.
var v32MechanismRegistry = map[MechanismType]*MechanismDescriptor{
	// ML-KEM (FIPS 203) - Key Encapsulation
	CKM_ML_KEM_KEY_PAIR_GEN: {
		Type:       CKM_ML_KEM_KEY_PAIR_GEN,
		Name:       "CKM_ML_KEM_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		MinKeySize: v32MLKEM512PublicKeySize * 8,  // ML-KEM-512 public key in bits
		MaxKeySize: v32MLKEM1024SecretKeySize * 8, // ML-KEM-1024 secret key in bits
		Flags:      CKF_GENERATE_KEY_PAIR,
	},
	CKM_ML_KEM: {
		Type:       CKM_ML_KEM,
		Name:       "CKM_ML_KEM",
		Categories: []MechanismCategory{v32CategoryEncapsulate, v32CategoryDecapsulate},
		MinKeySize: v32MLKEM512PublicKeySize * 8,
		MaxKeySize: v32MLKEM1024SecretKeySize * 8,
		Flags:      CKF_ENCAPSULATE | CKF_DECAPSULATE,
	},

	// ML-DSA (FIPS 204) - Digital Signatures
	CKM_ML_DSA_KEY_PAIR_GEN: {
		Type:       CKM_ML_DSA_KEY_PAIR_GEN,
		Name:       "CKM_ML_DSA_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		MinKeySize: v32MLDSA44PublicKeySize * 8, // ML-DSA-44 public key in bits
		MaxKeySize: v32MLDSA87SecretKeySize * 8, // ML-DSA-87 secret key in bits
		Flags:      CKF_GENERATE_KEY_PAIR,
	},
	CKM_ML_DSA: {
		Type:       CKM_ML_DSA,
		Name:       "CKM_ML_DSA",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: v32MLDSA44PublicKeySize * 8,
		MaxKeySize: v32MLDSA87SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},

	// HashML-DSA - multi-part capable
	CKM_HASH_ML_DSA: {
		Type:       CKM_HASH_ML_DSA,
		Name:       "CKM_HASH_ML_DSA",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: v32MLDSA44PublicKeySize * 8,
		MaxKeySize: v32MLDSA87SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY,
	},

	// HashML-DSA SHA variants - single-part sign/verify only
	CKM_HASH_ML_DSA_SHA224: {
		Type:       CKM_HASH_ML_DSA_SHA224,
		Name:       "CKM_HASH_ML_DSA_SHA224",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: v32MLDSA44PublicKeySize * 8,
		MaxKeySize: v32MLDSA87SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_ML_DSA_SHA256: {
		Type:       CKM_HASH_ML_DSA_SHA256,
		Name:       "CKM_HASH_ML_DSA_SHA256",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: v32MLDSA44PublicKeySize * 8,
		MaxKeySize: v32MLDSA87SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_ML_DSA_SHA384: {
		Type:       CKM_HASH_ML_DSA_SHA384,
		Name:       "CKM_HASH_ML_DSA_SHA384",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: v32MLDSA44PublicKeySize * 8,
		MaxKeySize: v32MLDSA87SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_ML_DSA_SHA512: {
		Type:       CKM_HASH_ML_DSA_SHA512,
		Name:       "CKM_HASH_ML_DSA_SHA512",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: v32MLDSA44PublicKeySize * 8,
		MaxKeySize: v32MLDSA87SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_ML_DSA_SHA3_224: {
		Type:       CKM_HASH_ML_DSA_SHA3_224,
		Name:       "CKM_HASH_ML_DSA_SHA3_224",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: v32MLDSA44PublicKeySize * 8,
		MaxKeySize: v32MLDSA87SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_ML_DSA_SHA3_256: {
		Type:       CKM_HASH_ML_DSA_SHA3_256,
		Name:       "CKM_HASH_ML_DSA_SHA3_256",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: v32MLDSA44PublicKeySize * 8,
		MaxKeySize: v32MLDSA87SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_ML_DSA_SHA3_384: {
		Type:       CKM_HASH_ML_DSA_SHA3_384,
		Name:       "CKM_HASH_ML_DSA_SHA3_384",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: v32MLDSA44PublicKeySize * 8,
		MaxKeySize: v32MLDSA87SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_ML_DSA_SHA3_512: {
		Type:       CKM_HASH_ML_DSA_SHA3_512,
		Name:       "CKM_HASH_ML_DSA_SHA3_512",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: v32MLDSA44PublicKeySize * 8,
		MaxKeySize: v32MLDSA87SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_ML_DSA_SHAKE128: {
		Type:       CKM_HASH_ML_DSA_SHAKE128,
		Name:       "CKM_HASH_ML_DSA_SHAKE128",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: v32MLDSA44PublicKeySize * 8,
		MaxKeySize: v32MLDSA87SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_ML_DSA_SHAKE256: {
		Type:       CKM_HASH_ML_DSA_SHAKE256,
		Name:       "CKM_HASH_ML_DSA_SHAKE256",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: v32MLDSA44PublicKeySize * 8,
		MaxKeySize: v32MLDSA87SecretKeySize * 8,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},

	// SLH-DSA (FIPS 205) - Stateless Hash-Based Signatures
	CKM_SLH_DSA_KEY_PAIR_GEN: {
		Type:       CKM_SLH_DSA_KEY_PAIR_GEN,
		Name:       "CKM_SLH_DSA_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		Flags:      CKF_GENERATE_KEY_PAIR,
	},
	CKM_SLH_DSA: {
		Type:       CKM_SLH_DSA,
		Name:       "CKM_SLH_DSA",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},

	// HashSLH-DSA - multi-part capable
	CKM_HASH_SLH_DSA: {
		Type:       CKM_HASH_SLH_DSA,
		Name:       "CKM_HASH_SLH_DSA",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY,
	},

	// HashSLH-DSA SHA variants - single-part sign/verify only
	CKM_HASH_SLH_DSA_SHA224: {
		Type:       CKM_HASH_SLH_DSA_SHA224,
		Name:       "CKM_HASH_SLH_DSA_SHA224",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_SLH_DSA_SHA256: {
		Type:       CKM_HASH_SLH_DSA_SHA256,
		Name:       "CKM_HASH_SLH_DSA_SHA256",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_SLH_DSA_SHA384: {
		Type:       CKM_HASH_SLH_DSA_SHA384,
		Name:       "CKM_HASH_SLH_DSA_SHA384",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_SLH_DSA_SHA512: {
		Type:       CKM_HASH_SLH_DSA_SHA512,
		Name:       "CKM_HASH_SLH_DSA_SHA512",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_SLH_DSA_SHA3_224: {
		Type:       CKM_HASH_SLH_DSA_SHA3_224,
		Name:       "CKM_HASH_SLH_DSA_SHA3_224",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_SLH_DSA_SHA3_256: {
		Type:       CKM_HASH_SLH_DSA_SHA3_256,
		Name:       "CKM_HASH_SLH_DSA_SHA3_256",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_SLH_DSA_SHA3_384: {
		Type:       CKM_HASH_SLH_DSA_SHA3_384,
		Name:       "CKM_HASH_SLH_DSA_SHA3_384",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_SLH_DSA_SHA3_512: {
		Type:       CKM_HASH_SLH_DSA_SHA3_512,
		Name:       "CKM_HASH_SLH_DSA_SHA3_512",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_SLH_DSA_SHAKE128: {
		Type:       CKM_HASH_SLH_DSA_SHAKE128,
		Name:       "CKM_HASH_SLH_DSA_SHAKE128",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_HASH_SLH_DSA_SHAKE256: {
		Type:       CKM_HASH_SLH_DSA_SHAKE256,
		Name:       "CKM_HASH_SLH_DSA_SHAKE256",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},

	// HSS/LMS (RFC 8554) - Stateful Hash-Based Signatures
	CKM_HSS_KEY_PAIR_GEN: {
		Type:       CKM_HSS_KEY_PAIR_GEN,
		Name:       "CKM_HSS_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		Flags:      CKF_GENERATE_KEY_PAIR,
	},
	CKM_HSS: {
		Type:       CKM_HSS,
		Name:       "CKM_HSS",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},

	// XMSS (RFC 8391) - Single-Tree
	CKM_XMSS_KEY_PAIR_GEN: {
		Type:       CKM_XMSS_KEY_PAIR_GEN,
		Name:       "CKM_XMSS_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		Flags:      CKF_GENERATE_KEY_PAIR,
	},
	CKM_XMSS: {
		Type:       CKM_XMSS,
		Name:       "CKM_XMSS",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},

	// XMSS^MT (RFC 8391) - Multi-Tree
	CKM_XMSSMT_KEY_PAIR_GEN: {
		Type:       CKM_XMSSMT_KEY_PAIR_GEN,
		Name:       "CKM_XMSSMT_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		Flags:      CKF_GENERATE_KEY_PAIR,
	},
	CKM_XMSSMT: {
		Type:       CKM_XMSSMT,
		Name:       "CKM_XMSSMT",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      CKF_SIGN | CKF_VERIFY,
	},

	// TLS 1.2 Extended Master Key Derivation
	CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE: {
		Type:       CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
		Name:       "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE",
		Categories: []MechanismCategory{CategoryDerive},
		Flags:      CKF_DERIVE,
	},
	CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH: {
		Type:       CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
		Name:       "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH",
		Categories: []MechanismCategory{CategoryDerive},
		Flags:      CKF_DERIVE,
	},

	// ECDH Key Wrap Mechanisms
	CKM_ECDH_X_AES_KEY_WRAP: {
		Type:       CKM_ECDH_X_AES_KEY_WRAP,
		Name:       "CKM_ECDH_X_AES_KEY_WRAP",
		Categories: []MechanismCategory{CategoryWrap, CategoryUnwrap},
		Flags:      CKF_WRAP | CKF_UNWRAP,
	},
	CKM_ECDH_COF_AES_KEY_WRAP: {
		Type:       CKM_ECDH_COF_AES_KEY_WRAP,
		Name:       "CKM_ECDH_COF_AES_KEY_WRAP",
		Categories: []MechanismCategory{CategoryWrap, CategoryUnwrap},
		Flags:      CKF_WRAP | CKF_UNWRAP,
	},

	// Public Key from Private Key
	CKM_PUB_KEY_FROM_PRIV_KEY: {
		Type:       CKM_PUB_KEY_FROM_PRIV_KEY,
		Name:       "CKM_PUB_KEY_FROM_PRIV_KEY",
		Categories: []MechanismCategory{CategoryDerive},
		Flags:      CKF_DERIVE,
	},
}

// v32KeyTypeMap provides O(1) lookup from v3.2 mechanism type to standard key type.
var v32KeyTypeMap = map[MechanismType]KeyType{
	CKM_ML_KEM_KEY_PAIR_GEN:   CKK_ML_KEM,
	CKM_ML_KEM:                CKK_ML_KEM,
	CKM_ML_DSA_KEY_PAIR_GEN:   CKK_ML_DSA,
	CKM_ML_DSA:                CKK_ML_DSA,
	CKM_HASH_ML_DSA:           CKK_ML_DSA,
	CKM_HASH_ML_DSA_SHA224:    CKK_ML_DSA,
	CKM_HASH_ML_DSA_SHA256:    CKK_ML_DSA,
	CKM_HASH_ML_DSA_SHA384:    CKK_ML_DSA,
	CKM_HASH_ML_DSA_SHA512:    CKK_ML_DSA,
	CKM_HASH_ML_DSA_SHA3_224:  CKK_ML_DSA,
	CKM_HASH_ML_DSA_SHA3_256:  CKK_ML_DSA,
	CKM_HASH_ML_DSA_SHA3_384:  CKK_ML_DSA,
	CKM_HASH_ML_DSA_SHA3_512:  CKK_ML_DSA,
	CKM_HASH_ML_DSA_SHAKE128:  CKK_ML_DSA,
	CKM_HASH_ML_DSA_SHAKE256:  CKK_ML_DSA,
	CKM_SLH_DSA_KEY_PAIR_GEN:  CKK_SLH_DSA,
	CKM_SLH_DSA:               CKK_SLH_DSA,
	CKM_HASH_SLH_DSA:          CKK_SLH_DSA,
	CKM_HASH_SLH_DSA_SHA224:   CKK_SLH_DSA,
	CKM_HASH_SLH_DSA_SHA256:   CKK_SLH_DSA,
	CKM_HASH_SLH_DSA_SHA384:   CKK_SLH_DSA,
	CKM_HASH_SLH_DSA_SHA512:   CKK_SLH_DSA,
	CKM_HASH_SLH_DSA_SHA3_224: CKK_SLH_DSA,
	CKM_HASH_SLH_DSA_SHA3_256: CKK_SLH_DSA,
	CKM_HASH_SLH_DSA_SHA3_384: CKK_SLH_DSA,
	CKM_HASH_SLH_DSA_SHA3_512: CKK_SLH_DSA,
	CKM_HASH_SLH_DSA_SHAKE128: CKK_SLH_DSA,
	CKM_HASH_SLH_DSA_SHAKE256: CKK_SLH_DSA,
	CKM_HSS_KEY_PAIR_GEN:      CKK_HSS,
	CKM_HSS:                   CKK_HSS,
	CKM_XMSS_KEY_PAIR_GEN:     CKK_XMSS,
	CKM_XMSS:                  CKK_XMSS,
	CKM_XMSSMT_KEY_PAIR_GEN:   CKK_XMSSMT,
	CKM_XMSSMT:                CKK_XMSSMT,
	CKM_ECDH_X_AES_KEY_WRAP:   CKK_EC,
	CKM_ECDH_COF_AES_KEY_WRAP: CKK_EC,
}

// init registers v3.2 PQC mechanisms into the global registry.
func init() {
	for mechType, name := range v32MechanismNames {
		mechanismNames[mechType] = name
	}

	for mechType, desc := range v32MechanismRegistry {
		mechanismRegistry[mechType] = desc
	}
}

// IsV32PQCMechanism returns true if the mechanism type is a v3.2 standard
// post-quantum cryptography mechanism.
func IsV32PQCMechanism(mechType MechanismType) bool {
	_, ok := v32MechanismRegistry[mechType]
	return ok
}

// GetV32KeyType returns the standard CKK_* key type for a v3.2 PQC mechanism.
// Returns CKK_VENDOR_DEFINED if the mechanism is not a recognized v3.2 PQC mechanism.
func GetV32KeyType(mechType MechanismType) KeyType {
	if kt, ok := v32KeyTypeMap[mechType]; ok {
		return kt
	}
	return CKK_VENDOR_DEFINED
}
