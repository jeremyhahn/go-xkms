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

// The v3.2 descriptors below use the canonical MechanismCategory and PQC key
// size constants from mechanism_quantum.go directly.
//
// They used to shadow them under v32-prefixed names, justified by a claimed
// "quantum" build tag on that file. No such tag exists -- every *_quantum.go
// file in this package compiles unconditionally -- so the shadows guarded
// against a conflict that could not occur, and left three independent spellings
// of the same numbers: these constants, the canonical ones, and a pair of bare
// 10 and 11 literals in module_kem.go. Renumbering CategoryEncapsulate, a plain
// iota expression, would have desynchronised them silently: CKM_ML_KEM
// registered under one category while isEncapsulateMechanism tested another,
// and C_EncapsulateKey refusing the only KEM the module advertises.

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

// v32MechanismNames maps the v3.2 mechanism types this file defines to their
// string names, for diagnostics. init merges it into the global mechanismNames
// table that GetMechanismName and MechanismType.String read.
//
// A name here says nothing about whether the module can perform the mechanism;
// v32MechanismRegistry answers that, and several entries below are named
// precisely so that refusing them is legible.
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

	// The five below name mechanisms the module refuses: they have no
	// v32MechanismRegistry descriptor (see the note at the end of that table
	// for why). Their names are kept on purpose, so the refusal reads
	// "CKM_ECDH_X_AES_KEY_WRAP" rather than "CKM_UNKNOWN(0x00004038)".

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
	// Per spec section 6.68.4, ulMinKeySize/ulMaxKeySize for ML-KEM mechanisms
	// specify the supported range of the ML-KEM *public* key size *in bytes*
	// (not bits, and not the private key/seed size).
	CKM_ML_KEM_KEY_PAIR_GEN: {
		Type:       CKM_ML_KEM_KEY_PAIR_GEN,
		Name:       "CKM_ML_KEM_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		// The floor is ML-KEM-768's public key, not ML-KEM-512's: this module
		// implements only the 768 and 1024 parameter sets, and CK_MECHANISM_INFO's
		// key-size range is what an application reads to decide what to ask for.
		MinKeySize: MLKEM512PublicKeySize,  // ML-KEM-512 public key, bytes
		MaxKeySize: MLKEM1024PublicKeySize, // ML-KEM-1024 public key, bytes
		Flags:      CKF_GENERATE_KEY_PAIR,
		Advertised: true,
		// FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) are approved NIST
		// standards, so these remain available under FIPS mode.
		FIPSApproved: true,
	},
	// Per spec section 6.68.5, ulMinKeySize/ulMaxKeySize for CKM_ML_KEM
	// likewise specify the ML-KEM public key size range in bytes.
	CKM_ML_KEM: {
		Type:       CKM_ML_KEM,
		Name:       "CKM_ML_KEM",
		Categories: []MechanismCategory{CategoryEncapsulate, CategoryDecapsulate},
		// The floor is the ML-KEM-768 public key, not ML-KEM-512's. Advertising
		// 800 told applications this token serves a parameter set it does not
		// implement, and CK_MECHANISM_INFO's key-size range is exactly what an
		// application reads to decide what to ask for (v3.2 §5.5).
		MinKeySize: MLKEM512PublicKeySize,
		MaxKeySize: MLKEM1024PublicKeySize,
		Flags:      CKF_ENCAPSULATE | CKF_DECAPSULATE,
		Advertised: true,
		// FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) are approved NIST
		// standards, so these remain available under FIPS mode.
		FIPSApproved: true,
	},

	// ML-DSA (FIPS 204) - Digital Signatures
	//
	// Per spec sections 6.67.4/6.67.5, ulMinKeySize/ulMaxKeySize for ML-DSA
	// mechanisms specify the supported range of the ML-DSA *public* key size
	// *in bytes* (not bits, and not the private key/seed size).
	CKM_ML_DSA_KEY_PAIR_GEN: {
		Type:       CKM_ML_DSA_KEY_PAIR_GEN,
		Name:       "CKM_ML_DSA_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		MinKeySize: MLDSA44PublicKeySize, // ML-DSA-44 public key, bytes
		MaxKeySize: MLDSA87PublicKeySize, // ML-DSA-87 public key, bytes
		Flags:      CKF_GENERATE_KEY_PAIR,
		Advertised: true,
		// FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) are approved NIST
		// standards, so these remain available under FIPS mode.
		FIPSApproved: true,
	},
	CKM_ML_DSA: {
		Type:       CKM_ML_DSA,
		Name:       "CKM_ML_DSA",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA44PublicKeySize,
		MaxKeySize: MLDSA87PublicKeySize,
		Flags:      CKF_SIGN | CKF_VERIFY,
		Advertised: true,
		// FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) are approved NIST
		// standards, so these remain available under FIPS mode.
		FIPSApproved: true,
	},

	// HashML-DSA (pre-hash ML-DSA) and its per-hash variants.
	//
	// No operation flags: IsMLDSAMechanism recognises only CKM_ML_DSA and the
	// vendor ML-DSA range, so nothing routes a CKM_HASH_ML_DSA* mechanism to the
	// ML-DSA signer -- the pre-hash construction (hash the message with the named
	// digest, then sign per FIPS 204 §5.4) is not implemented. Carrying CKF_SIGN
	// let CryptoManager.SignInit admit the mechanism, so C_SignInit answered
	// CKR_OK and the operation then failed deep in C_Sign, after the caller had
	// committed to it. Matches the CKM_SLH_DSA / CKM_HSS / CKM_XMSS precedent
	// below: the descriptor stays so the constant resolves and C_GetMechanismInfo
	// can describe the parameter set, but every *Init refuses it at the gate.
	CKM_HASH_ML_DSA: {
		Type:       CKM_HASH_ML_DSA,
		Name:       "CKM_HASH_ML_DSA",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA44PublicKeySize,
		MaxKeySize: MLDSA87PublicKeySize,
		Flags:      0,
	},
	CKM_HASH_ML_DSA_SHA224: {
		Type:       CKM_HASH_ML_DSA_SHA224,
		Name:       "CKM_HASH_ML_DSA_SHA224",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA44PublicKeySize,
		MaxKeySize: MLDSA87PublicKeySize,
		Flags:      0,
	},
	CKM_HASH_ML_DSA_SHA256: {
		Type:       CKM_HASH_ML_DSA_SHA256,
		Name:       "CKM_HASH_ML_DSA_SHA256",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA44PublicKeySize,
		MaxKeySize: MLDSA87PublicKeySize,
		Flags:      0,
	},
	CKM_HASH_ML_DSA_SHA384: {
		Type:       CKM_HASH_ML_DSA_SHA384,
		Name:       "CKM_HASH_ML_DSA_SHA384",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA44PublicKeySize,
		MaxKeySize: MLDSA87PublicKeySize,
		Flags:      0,
	},
	CKM_HASH_ML_DSA_SHA512: {
		Type:       CKM_HASH_ML_DSA_SHA512,
		Name:       "CKM_HASH_ML_DSA_SHA512",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA44PublicKeySize,
		MaxKeySize: MLDSA87PublicKeySize,
		Flags:      0,
	},
	CKM_HASH_ML_DSA_SHA3_224: {
		Type:       CKM_HASH_ML_DSA_SHA3_224,
		Name:       "CKM_HASH_ML_DSA_SHA3_224",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA44PublicKeySize,
		MaxKeySize: MLDSA87PublicKeySize,
		Flags:      0,
	},
	CKM_HASH_ML_DSA_SHA3_256: {
		Type:       CKM_HASH_ML_DSA_SHA3_256,
		Name:       "CKM_HASH_ML_DSA_SHA3_256",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA44PublicKeySize,
		MaxKeySize: MLDSA87PublicKeySize,
		Flags:      0,
	},
	CKM_HASH_ML_DSA_SHA3_384: {
		Type:       CKM_HASH_ML_DSA_SHA3_384,
		Name:       "CKM_HASH_ML_DSA_SHA3_384",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA44PublicKeySize,
		MaxKeySize: MLDSA87PublicKeySize,
		Flags:      0,
	},
	CKM_HASH_ML_DSA_SHA3_512: {
		Type:       CKM_HASH_ML_DSA_SHA3_512,
		Name:       "CKM_HASH_ML_DSA_SHA3_512",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA44PublicKeySize,
		MaxKeySize: MLDSA87PublicKeySize,
		Flags:      0,
	},
	CKM_HASH_ML_DSA_SHAKE128: {
		Type:       CKM_HASH_ML_DSA_SHAKE128,
		Name:       "CKM_HASH_ML_DSA_SHAKE128",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA44PublicKeySize,
		MaxKeySize: MLDSA87PublicKeySize,
		Flags:      0,
	},
	CKM_HASH_ML_DSA_SHAKE256: {
		Type:       CKM_HASH_ML_DSA_SHAKE256,
		Name:       "CKM_HASH_ML_DSA_SHAKE256",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: MLDSA44PublicKeySize,
		MaxKeySize: MLDSA87PublicKeySize,
		Flags:      0,
	},

	// SLH-DSA (FIPS 205) - Stateless Hash-Based Signatures
	CKM_SLH_DSA_KEY_PAIR_GEN: {
		Type:       CKM_SLH_DSA_KEY_PAIR_GEN,
		Name:       "CKM_SLH_DSA_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		// No CKF_GENERATE_KEY_PAIR: see CKM_SLH_DSA above.
		Flags: 0,
	},
	CKM_SLH_DSA: {
		Type:       CKM_SLH_DSA,
		Name:       "CKM_SLH_DSA",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		// No operation flags: this module has no SLH-DSA / HSS / XMSS
		// implementation. Go's standard library provides none and pkg/quantum
		// carries only Kyber, ML-KEM and ML-DSA. Carrying CKF_SIGN made
		// CryptoManager.SignInit admit the mechanism, so C_SignInit answered
		// CKR_OK and the operation then failed from the backend -- the caller
		// learned the token could not do it only after committing to it. The
		// descriptor stays so the constant resolves and C_GetMechanismInfo can
		// describe the parameter set, but every *Init now refuses it with
		// CKR_MECHANISM_INVALID at the gate.
		Flags: 0,
	},

	// HashSLH-DSA (pre-hash SLH-DSA) and its per-hash variants.
	//
	// No operation flags: the module has no SLH-DSA implementation at all (see
	// CKM_SLH_DSA above), so the pre-hash variants have nothing to route to
	// either. Advertising CKF_SIGN made C_SignInit answer CKR_OK and then fail in
	// C_Sign; the descriptors stay for constant resolution and C_GetMechanismInfo
	// only, and every *Init refuses them at the gate.
	CKM_HASH_SLH_DSA: {
		Type:       CKM_HASH_SLH_DSA,
		Name:       "CKM_HASH_SLH_DSA",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      0,
	},
	CKM_HASH_SLH_DSA_SHA224: {
		Type:       CKM_HASH_SLH_DSA_SHA224,
		Name:       "CKM_HASH_SLH_DSA_SHA224",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      0,
	},
	CKM_HASH_SLH_DSA_SHA256: {
		Type:       CKM_HASH_SLH_DSA_SHA256,
		Name:       "CKM_HASH_SLH_DSA_SHA256",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      0,
	},
	CKM_HASH_SLH_DSA_SHA384: {
		Type:       CKM_HASH_SLH_DSA_SHA384,
		Name:       "CKM_HASH_SLH_DSA_SHA384",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      0,
	},
	CKM_HASH_SLH_DSA_SHA512: {
		Type:       CKM_HASH_SLH_DSA_SHA512,
		Name:       "CKM_HASH_SLH_DSA_SHA512",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      0,
	},
	CKM_HASH_SLH_DSA_SHA3_224: {
		Type:       CKM_HASH_SLH_DSA_SHA3_224,
		Name:       "CKM_HASH_SLH_DSA_SHA3_224",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      0,
	},
	CKM_HASH_SLH_DSA_SHA3_256: {
		Type:       CKM_HASH_SLH_DSA_SHA3_256,
		Name:       "CKM_HASH_SLH_DSA_SHA3_256",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      0,
	},
	CKM_HASH_SLH_DSA_SHA3_384: {
		Type:       CKM_HASH_SLH_DSA_SHA3_384,
		Name:       "CKM_HASH_SLH_DSA_SHA3_384",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      0,
	},
	CKM_HASH_SLH_DSA_SHA3_512: {
		Type:       CKM_HASH_SLH_DSA_SHA3_512,
		Name:       "CKM_HASH_SLH_DSA_SHA3_512",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      0,
	},
	CKM_HASH_SLH_DSA_SHAKE128: {
		Type:       CKM_HASH_SLH_DSA_SHAKE128,
		Name:       "CKM_HASH_SLH_DSA_SHAKE128",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      0,
	},
	CKM_HASH_SLH_DSA_SHAKE256: {
		Type:       CKM_HASH_SLH_DSA_SHAKE256,
		Name:       "CKM_HASH_SLH_DSA_SHAKE256",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		Flags:      0,
	},

	// HSS/LMS (RFC 8554) - Stateful Hash-Based Signatures
	CKM_HSS_KEY_PAIR_GEN: {
		Type:       CKM_HSS_KEY_PAIR_GEN,
		Name:       "CKM_HSS_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		// No CKF_GENERATE_KEY_PAIR: see CKM_SLH_DSA above.
		Flags: 0,
	},
	CKM_HSS: {
		Type:       CKM_HSS,
		Name:       "CKM_HSS",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		// No operation flags: this module has no SLH-DSA / HSS / XMSS
		// implementation. Go's standard library provides none and pkg/quantum
		// carries only Kyber, ML-KEM and ML-DSA. Carrying CKF_SIGN made
		// CryptoManager.SignInit admit the mechanism, so C_SignInit answered
		// CKR_OK and the operation then failed from the backend -- the caller
		// learned the token could not do it only after committing to it. The
		// descriptor stays so the constant resolves and C_GetMechanismInfo can
		// describe the parameter set, but every *Init now refuses it with
		// CKR_MECHANISM_INVALID at the gate.
		Flags: 0,
	},

	// XMSS (RFC 8391) - Single-Tree
	CKM_XMSS_KEY_PAIR_GEN: {
		Type:       CKM_XMSS_KEY_PAIR_GEN,
		Name:       "CKM_XMSS_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		// No CKF_GENERATE_KEY_PAIR: see CKM_SLH_DSA above.
		Flags: 0,
	},
	CKM_XMSS: {
		Type:       CKM_XMSS,
		Name:       "CKM_XMSS",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		// No operation flags: this module has no SLH-DSA / HSS / XMSS
		// implementation. Go's standard library provides none and pkg/quantum
		// carries only Kyber, ML-KEM and ML-DSA. Carrying CKF_SIGN made
		// CryptoManager.SignInit admit the mechanism, so C_SignInit answered
		// CKR_OK and the operation then failed from the backend -- the caller
		// learned the token could not do it only after committing to it. The
		// descriptor stays so the constant resolves and C_GetMechanismInfo can
		// describe the parameter set, but every *Init now refuses it with
		// CKR_MECHANISM_INVALID at the gate.
		Flags: 0,
	},

	// XMSS^MT (RFC 8391) - Multi-Tree
	CKM_XMSSMT_KEY_PAIR_GEN: {
		Type:       CKM_XMSSMT_KEY_PAIR_GEN,
		Name:       "CKM_XMSSMT_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		// No CKF_GENERATE_KEY_PAIR: see CKM_SLH_DSA above.
		Flags: 0,
	},
	CKM_XMSSMT: {
		Type:       CKM_XMSSMT,
		Name:       "CKM_XMSSMT",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		// No operation flags: this module has no SLH-DSA / HSS / XMSS
		// implementation. Go's standard library provides none and pkg/quantum
		// carries only Kyber, ML-KEM and ML-DSA. Carrying CKF_SIGN made
		// CryptoManager.SignInit admit the mechanism, so C_SignInit answered
		// CKR_OK and the operation then failed from the backend -- the caller
		// learned the token could not do it only after committing to it. The
		// descriptor stays so the constant resolves and C_GetMechanismInfo can
		// describe the parameter set, but every *Init now refuses it with
		// CKR_MECHANISM_INVALID at the gate.
		Flags: 0,
	},

	// TLS 1.2 Extended Master Key Derivation, the ECDH AES key wraps, and
	// CKM_PUB_KEY_FROM_PRIV_KEY have no descriptor here, deliberately.
	//
	// CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE, its _DH variant and
	// CKM_PUB_KEY_FROM_PRIV_KEY carried CKF_DERIVE but are not among the
	// mechanisms C_DeriveKey dispatches on, so every use returned
	// CKR_MECHANISM_INVALID after the descriptor had already said the module
	// could derive with them. CKM_ECDH_X_AES_KEY_WRAP and
	// CKM_ECDH_COF_AES_KEY_WRAP carried CKF_WRAP and CKF_UNWRAP but nothing
	// routes either to a wrapping algorithm, so C_WrapKey resolved them to a
	// bare mechanism name the service refuses.
	//
	// Leaving them registered but unadvertised was the worst of both states:
	// C_GetMechanismList hid them, so no application could discover them, while
	// GetMechanismDescriptor still resolved them for any caller that named the
	// raw constant and let the failure surface deep inside the operation. With
	// no entry the refusal is immediate and honest, and each becomes a
	// candidate to restore the moment its operation works end to end.
	//
	// It is only the descriptor that is absent. The five constants and their
	// v32MechanismNames entries stay, because a name is a diagnostic and not a
	// capability: nothing consults mechanismNames to decide whether an
	// operation may proceed -- that is mechanismRegistry's job, via
	// IsMechanismSupported, CanWrap/CanUnwrap/CanDerive and
	// validateInitMechanism -- while MechanismType.String() reads it for every
	// error and log line the module emits. Dropping the names would turn
	// "CKM_ECDH_X_AES_KEY_WRAP: CKR_MECHANISM_INVALID" into
	// "CKM_UNKNOWN(0x00004038): CKR_MECHANISM_INVALID" and leave the operator
	// to decode the constant by hand, which is a worse refusal for no gain.
	//
	// v32KeyTypeMap is the opposite case and its two ECDH entries are gone: it
	// answers "what CKK_* key type does this mechanism produce", which is only
	// asked of a mechanism the module can perform, so entries for mechanisms it
	// refuses are unreachable by construction. Restoring a descriptor is the
	// point at which the matching key-type entry comes back with it.
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
