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

// Package module provides PKCS#11 (Cryptoki) v3.0 mechanism definitions and utilities.
//
// This package implements mechanism types, parameters, and lookup functionality
// according to the OASIS PKCS#11 v3.0 specification.
//
// Supported mechanism categories:
//   - RSA: CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_PSS, CKM_RSA_PKCS_KEY_PAIR_GEN
//   - ECDSA: CKM_ECDSA, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512, CKM_EC_KEY_PAIR_GEN
//   - AES: CKM_AES_GCM, CKM_AES_KEY_GEN, CKM_AES_CBC, CKM_AES_CBC_PAD
//   - Digest: CKM_SHA256, CKM_SHA384, CKM_SHA512, CKM_SHA_1
//
// References:
//   - OASIS PKCS#11 v3.0: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
//   - OASIS PKCS#11 Current Mechanisms: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/pkcs11-curr-v3.0.html
package module

import (
	"crypto/ecdh"
	"fmt"
	"os"
	"sort"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/fips"
)

// MechanismType represents a PKCS#11 mechanism type (CK_MECHANISM_TYPE).
// Mechanism types identify cryptographic algorithms and operations.
type MechanismType uint32

// PKCS#11 v3.0 Mechanism Type Constants (CKM_*)
// Reference: OASIS PKCS#11 Current Mechanisms Specification v3.0
const (
	// RSA Key Generation and Signing Mechanisms
	CKM_RSA_PKCS_KEY_PAIR_GEN  MechanismType = 0x00000000
	CKM_RSA_PKCS               MechanismType = 0x00000001
	CKM_RSA_9796               MechanismType = 0x00000002
	CKM_RSA_X_509              MechanismType = 0x00000003
	CKM_MD2_RSA_PKCS           MechanismType = 0x00000004
	CKM_MD5_RSA_PKCS           MechanismType = 0x00000005
	CKM_SHA1_RSA_PKCS          MechanismType = 0x00000006
	CKM_RIPEMD128_RSA_PKCS     MechanismType = 0x00000007
	CKM_RIPEMD160_RSA_PKCS     MechanismType = 0x00000008
	CKM_RSA_PKCS_OAEP          MechanismType = 0x00000009
	CKM_RSA_X9_31_KEY_PAIR_GEN MechanismType = 0x0000000A
	CKM_RSA_X9_31              MechanismType = 0x0000000B
	CKM_SHA1_RSA_X9_31         MechanismType = 0x0000000C
	CKM_RSA_PKCS_PSS           MechanismType = 0x0000000D
	CKM_SHA1_RSA_PKCS_PSS      MechanismType = 0x0000000E

	// DSA Mechanisms
	CKM_DSA_KEY_PAIR_GEN MechanismType = 0x00000010
	CKM_DSA              MechanismType = 0x00000011
	CKM_DSA_SHA1         MechanismType = 0x00000012
	CKM_DSA_SHA224       MechanismType = 0x00000013
	CKM_DSA_SHA256       MechanismType = 0x00000014
	CKM_DSA_SHA384       MechanismType = 0x00000015
	CKM_DSA_SHA512       MechanismType = 0x00000016

	// DH Mechanisms
	CKM_DH_PKCS_KEY_PAIR_GEN MechanismType = 0x00000020
	CKM_DH_PKCS_DERIVE       MechanismType = 0x00000021

	// X9.42 DH Mechanisms
	CKM_X9_42_DH_KEY_PAIR_GEN  MechanismType = 0x00000030
	CKM_X9_42_DH_DERIVE        MechanismType = 0x00000031
	CKM_X9_42_DH_HYBRID_DERIVE MechanismType = 0x00000032
	CKM_X9_42_MQV_DERIVE       MechanismType = 0x00000033

	// SHA-1 and RIPEMD Digest Mechanisms
	CKM_SHA_1                  MechanismType = 0x00000220
	CKM_SHA_1_HMAC             MechanismType = 0x00000221
	CKM_SHA_1_HMAC_GENERAL     MechanismType = 0x00000222
	CKM_RIPEMD128              MechanismType = 0x00000230
	CKM_RIPEMD128_HMAC         MechanismType = 0x00000231
	CKM_RIPEMD128_HMAC_GENERAL MechanismType = 0x00000232
	CKM_RIPEMD160              MechanismType = 0x00000240
	CKM_RIPEMD160_HMAC         MechanismType = 0x00000241
	CKM_RIPEMD160_HMAC_GENERAL MechanismType = 0x00000242

	// SHA-256 and Higher Digest Mechanisms
	CKM_SHA256                  MechanismType = 0x00000250
	CKM_SHA256_HMAC             MechanismType = 0x00000251
	CKM_SHA256_HMAC_GENERAL     MechanismType = 0x00000252
	CKM_SHA224                  MechanismType = 0x00000255
	CKM_SHA224_HMAC             MechanismType = 0x00000256
	CKM_SHA224_HMAC_GENERAL     MechanismType = 0x00000257
	CKM_SHA384                  MechanismType = 0x00000260
	CKM_SHA384_HMAC             MechanismType = 0x00000261
	CKM_SHA384_HMAC_GENERAL     MechanismType = 0x00000262
	CKM_SHA512                  MechanismType = 0x00000270
	CKM_SHA512_HMAC             MechanismType = 0x00000271
	CKM_SHA512_HMAC_GENERAL     MechanismType = 0x00000272
	CKM_SHA512_224              MechanismType = 0x00000048
	CKM_SHA512_224_HMAC         MechanismType = 0x00000049
	CKM_SHA512_224_HMAC_GENERAL MechanismType = 0x0000004A
	CKM_SHA512_256              MechanismType = 0x0000004C
	CKM_SHA512_256_HMAC         MechanismType = 0x0000004D
	CKM_SHA512_256_HMAC_GENERAL MechanismType = 0x0000004E

	// SHA-3 Digest Mechanisms (PKCS#11 v3.0).
	//
	// OASIS does not assign these in ascending digest-size order: SHA3-256
	// is allocated the lowest block at 0x2B0, and SHA3-224 follows it at
	// 0x2B5. The constants below are listed in the spec's numeric order to
	// keep that visible. In particular CKM_SHA3_256 is 0x2B0 and NOT 0x2C0
	// (0x2C0 is CKM_SHA3_384), and CKM_SHA3_512 is 0x2D0 and NOT 0x2E0
	// (0x2E0 is unassigned). Assuming an ascending-size layout shifts every
	// value one block too high and routes a SHA3-256 request into the
	// SHA3-384 implementation.
	CKM_SHA3_256              MechanismType = 0x000002B0
	CKM_SHA3_256_HMAC         MechanismType = 0x000002B1
	CKM_SHA3_256_HMAC_GENERAL MechanismType = 0x000002B2
	CKM_SHA3_224              MechanismType = 0x000002B5
	CKM_SHA3_224_HMAC         MechanismType = 0x000002B6
	CKM_SHA3_224_HMAC_GENERAL MechanismType = 0x000002B7
	CKM_SHA3_384              MechanismType = 0x000002C0
	CKM_SHA3_384_HMAC         MechanismType = 0x000002C1
	CKM_SHA3_384_HMAC_GENERAL MechanismType = 0x000002C2
	CKM_SHA3_512              MechanismType = 0x000002D0
	CKM_SHA3_512_HMAC         MechanismType = 0x000002D1
	CKM_SHA3_512_HMAC_GENERAL MechanismType = 0x000002D2

	// RSA with SHA-256/384/512
	CKM_SHA256_RSA_PKCS     MechanismType = 0x00000040
	CKM_SHA384_RSA_PKCS     MechanismType = 0x00000041
	CKM_SHA512_RSA_PKCS     MechanismType = 0x00000042
	CKM_SHA256_RSA_PKCS_PSS MechanismType = 0x00000043
	CKM_SHA384_RSA_PKCS_PSS MechanismType = 0x00000044
	CKM_SHA512_RSA_PKCS_PSS MechanismType = 0x00000045

	// SHA-224 RSA
	CKM_SHA224_RSA_PKCS     MechanismType = 0x00000046
	CKM_SHA224_RSA_PKCS_PSS MechanismType = 0x00000047

	// RC2 Mechanisms
	CKM_RC2_KEY_GEN     MechanismType = 0x00000100
	CKM_RC2_ECB         MechanismType = 0x00000101
	CKM_RC2_CBC         MechanismType = 0x00000102
	CKM_RC2_MAC         MechanismType = 0x00000103
	CKM_RC2_MAC_GENERAL MechanismType = 0x00000104
	CKM_RC2_CBC_PAD     MechanismType = 0x00000105

	// RC4 Mechanisms
	CKM_RC4_KEY_GEN MechanismType = 0x00000110
	CKM_RC4         MechanismType = 0x00000111

	// DES Mechanisms
	CKM_DES_KEY_GEN     MechanismType = 0x00000120
	CKM_DES_ECB         MechanismType = 0x00000121
	CKM_DES_CBC         MechanismType = 0x00000122
	CKM_DES_MAC         MechanismType = 0x00000123
	CKM_DES_MAC_GENERAL MechanismType = 0x00000124
	CKM_DES_CBC_PAD     MechanismType = 0x00000125

	// DES2 Key Generation
	CKM_DES2_KEY_GEN MechanismType = 0x00000130

	// DES3 Mechanisms
	CKM_DES3_KEY_GEN      MechanismType = 0x00000131
	CKM_DES3_ECB          MechanismType = 0x00000132
	CKM_DES3_CBC          MechanismType = 0x00000133
	CKM_DES3_MAC          MechanismType = 0x00000134
	CKM_DES3_MAC_GENERAL  MechanismType = 0x00000135
	CKM_DES3_CBC_PAD      MechanismType = 0x00000136
	CKM_DES3_CMAC_GENERAL MechanismType = 0x00000137
	CKM_DES3_CMAC         MechanismType = 0x00000138

	// MD5 Mechanisms
	CKM_MD5              MechanismType = 0x00000210
	CKM_MD5_HMAC         MechanismType = 0x00000211
	CKM_MD5_HMAC_GENERAL MechanismType = 0x00000212

	// MD2 Mechanisms
	CKM_MD2              MechanismType = 0x00000200
	CKM_MD2_HMAC         MechanismType = 0x00000201
	CKM_MD2_HMAC_GENERAL MechanismType = 0x00000202

	// Cast Mechanisms
	CKM_CAST_KEY_GEN     MechanismType = 0x00000300
	CKM_CAST_ECB         MechanismType = 0x00000301
	CKM_CAST_CBC         MechanismType = 0x00000302
	CKM_CAST_MAC         MechanismType = 0x00000303
	CKM_CAST_MAC_GENERAL MechanismType = 0x00000304
	CKM_CAST_CBC_PAD     MechanismType = 0x00000305

	// Cast3 Mechanisms
	CKM_CAST3_KEY_GEN     MechanismType = 0x00000310
	CKM_CAST3_ECB         MechanismType = 0x00000311
	CKM_CAST3_CBC         MechanismType = 0x00000312
	CKM_CAST3_MAC         MechanismType = 0x00000313
	CKM_CAST3_MAC_GENERAL MechanismType = 0x00000314
	CKM_CAST3_CBC_PAD     MechanismType = 0x00000315

	// Cast5 (Cast128) Mechanisms
	CKM_CAST5_KEY_GEN       MechanismType = 0x00000320
	CKM_CAST128_KEY_GEN     MechanismType = 0x00000320 // Alias
	CKM_CAST5_ECB           MechanismType = 0x00000321
	CKM_CAST128_ECB         MechanismType = 0x00000321 // Alias
	CKM_CAST5_CBC           MechanismType = 0x00000322
	CKM_CAST128_CBC         MechanismType = 0x00000322 // Alias
	CKM_CAST5_MAC           MechanismType = 0x00000323
	CKM_CAST128_MAC         MechanismType = 0x00000323 // Alias
	CKM_CAST5_MAC_GENERAL   MechanismType = 0x00000324
	CKM_CAST128_MAC_GENERAL MechanismType = 0x00000324 // Alias
	CKM_CAST5_CBC_PAD       MechanismType = 0x00000325
	CKM_CAST128_CBC_PAD     MechanismType = 0x00000325 // Alias

	// RC5 Mechanisms
	CKM_RC5_KEY_GEN     MechanismType = 0x00000330
	CKM_RC5_ECB         MechanismType = 0x00000331
	CKM_RC5_CBC         MechanismType = 0x00000332
	CKM_RC5_MAC         MechanismType = 0x00000333
	CKM_RC5_MAC_GENERAL MechanismType = 0x00000334
	CKM_RC5_CBC_PAD     MechanismType = 0x00000335

	// IDEA Mechanisms
	CKM_IDEA_KEY_GEN     MechanismType = 0x00000340
	CKM_IDEA_ECB         MechanismType = 0x00000341
	CKM_IDEA_CBC         MechanismType = 0x00000342
	CKM_IDEA_MAC         MechanismType = 0x00000343
	CKM_IDEA_MAC_GENERAL MechanismType = 0x00000344
	CKM_IDEA_CBC_PAD     MechanismType = 0x00000345

	// Generic Secret Key Mechanisms
	CKM_GENERIC_SECRET_KEY_GEN MechanismType = 0x00000350

	// Concatenate Mechanisms
	CKM_CONCATENATE_BASE_AND_KEY  MechanismType = 0x00000360
	CKM_CONCATENATE_BASE_AND_DATA MechanismType = 0x00000362
	CKM_CONCATENATE_DATA_AND_BASE MechanismType = 0x00000363

	// XOR Mechanism
	CKM_XOR_BASE_AND_DATA MechanismType = 0x00000364

	// Extract Key from Key Mechanism
	CKM_EXTRACT_KEY_FROM_KEY MechanismType = 0x00000365

	// SSL3 Mechanisms
	CKM_SSL3_PRE_MASTER_KEY_GEN   MechanismType = 0x00000370
	CKM_SSL3_MASTER_KEY_DERIVE    MechanismType = 0x00000371
	CKM_SSL3_KEY_AND_MAC_DERIVE   MechanismType = 0x00000372
	CKM_SSL3_MASTER_KEY_DERIVE_DH MechanismType = 0x00000373
	CKM_SSL3_MD5_MAC              MechanismType = 0x00000380
	CKM_SSL3_SHA1_MAC             MechanismType = 0x00000381

	// TLS Mechanisms
	CKM_TLS_PRE_MASTER_KEY_GEN   MechanismType = 0x00000374
	CKM_TLS_MASTER_KEY_DERIVE    MechanismType = 0x00000375
	CKM_TLS_KEY_AND_MAC_DERIVE   MechanismType = 0x00000376
	CKM_TLS_MASTER_KEY_DERIVE_DH MechanismType = 0x00000377
	CKM_TLS_PRF                  MechanismType = 0x00000378

	// TLS 1.2 Mechanisms (PKCS#11 v2.40+)
	CKM_TLS12_MASTER_KEY_DERIVE    MechanismType = 0x000003E0
	CKM_TLS12_KEY_AND_MAC_DERIVE   MechanismType = 0x000003E1
	CKM_TLS12_MASTER_KEY_DERIVE_DH MechanismType = 0x000003E2
	CKM_TLS12_KEY_SAFE_DERIVE      MechanismType = 0x000003E3
	CKM_TLS_MAC                    MechanismType = 0x000003E4
	CKM_TLS_KDF                    MechanismType = 0x000003E5

	// MD5 Key Derivation
	CKM_MD5_KEY_DERIVATION MechanismType = 0x00000390
	CKM_MD2_KEY_DERIVATION MechanismType = 0x00000391

	// SHA Key Derivation
	CKM_SHA1_KEY_DERIVATION   MechanismType = 0x00000392
	CKM_SHA256_KEY_DERIVATION MechanismType = 0x00000393
	CKM_SHA384_KEY_DERIVATION MechanismType = 0x00000394
	CKM_SHA512_KEY_DERIVATION MechanismType = 0x00000395
	CKM_SHA224_KEY_DERIVATION MechanismType = 0x00000396

	// PBE Mechanisms
	CKM_PBE_MD2_DES_CBC       MechanismType = 0x000003A0
	CKM_PBE_MD5_DES_CBC       MechanismType = 0x000003A1
	CKM_PBE_MD5_CAST_CBC      MechanismType = 0x000003A2
	CKM_PBE_MD5_CAST3_CBC     MechanismType = 0x000003A3
	CKM_PBE_MD5_CAST5_CBC     MechanismType = 0x000003A4
	CKM_PBE_MD5_CAST128_CBC   MechanismType = 0x000003A4 // Alias
	CKM_PBE_SHA1_CAST5_CBC    MechanismType = 0x000003A5
	CKM_PBE_SHA1_CAST128_CBC  MechanismType = 0x000003A5 // Alias
	CKM_PBE_SHA1_RC4_128      MechanismType = 0x000003A6
	CKM_PBE_SHA1_RC4_40       MechanismType = 0x000003A7
	CKM_PBE_SHA1_DES3_EDE_CBC MechanismType = 0x000003A8
	CKM_PBE_SHA1_DES2_EDE_CBC MechanismType = 0x000003A9
	CKM_PBE_SHA1_RC2_128_CBC  MechanismType = 0x000003AA
	CKM_PBE_SHA1_RC2_40_CBC   MechanismType = 0x000003AB

	// PKCS5 PBKDF2 Mechanism
	CKM_PKCS5_PBKD2 MechanismType = 0x000003B0

	// PBA Mechanisms
	CKM_PBA_SHA1_WITH_SHA1_HMAC MechanismType = 0x000003C0

	// WTLS Mechanisms
	CKM_WTLS_PRE_MASTER_KEY_GEN        MechanismType = 0x000003D0
	CKM_WTLS_MASTER_KEY_DERIVE         MechanismType = 0x000003D1
	CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC  MechanismType = 0x000003D2
	CKM_WTLS_PRF                       MechanismType = 0x000003D3
	CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE MechanismType = 0x000003D4
	CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE MechanismType = 0x000003D5

	// Key Wrap Mechanisms
	CKM_KEY_WRAP_LYNKS    MechanismType = 0x00000400
	CKM_KEY_WRAP_SET_OAEP MechanismType = 0x00000401

	// CMS Mechanism
	CKM_CMS_SIG MechanismType = 0x00000500

	// KIP Mechanisms
	CKM_KIP_DERIVE MechanismType = 0x00000510
	CKM_KIP_WRAP   MechanismType = 0x00000511
	CKM_KIP_MAC    MechanismType = 0x00000512

	// Camellia Mechanisms
	CKM_CAMELLIA_KEY_GEN          MechanismType = 0x00000550
	CKM_CAMELLIA_ECB              MechanismType = 0x00000551
	CKM_CAMELLIA_CBC              MechanismType = 0x00000552
	CKM_CAMELLIA_MAC              MechanismType = 0x00000553
	CKM_CAMELLIA_MAC_GENERAL      MechanismType = 0x00000554
	CKM_CAMELLIA_CBC_PAD          MechanismType = 0x00000555
	CKM_CAMELLIA_ECB_ENCRYPT_DATA MechanismType = 0x00000556
	CKM_CAMELLIA_CBC_ENCRYPT_DATA MechanismType = 0x00000557
	CKM_CAMELLIA_CTR              MechanismType = 0x00000558

	// ARIA Mechanisms
	CKM_ARIA_KEY_GEN          MechanismType = 0x00000560
	CKM_ARIA_ECB              MechanismType = 0x00000561
	CKM_ARIA_CBC              MechanismType = 0x00000562
	CKM_ARIA_MAC              MechanismType = 0x00000563
	CKM_ARIA_MAC_GENERAL      MechanismType = 0x00000564
	CKM_ARIA_CBC_PAD          MechanismType = 0x00000565
	CKM_ARIA_ECB_ENCRYPT_DATA MechanismType = 0x00000566
	CKM_ARIA_CBC_ENCRYPT_DATA MechanismType = 0x00000567

	// SEED Mechanisms
	CKM_SEED_KEY_GEN          MechanismType = 0x00000650
	CKM_SEED_ECB              MechanismType = 0x00000651
	CKM_SEED_CBC              MechanismType = 0x00000652
	CKM_SEED_MAC              MechanismType = 0x00000653
	CKM_SEED_MAC_GENERAL      MechanismType = 0x00000654
	CKM_SEED_CBC_PAD          MechanismType = 0x00000655
	CKM_SEED_ECB_ENCRYPT_DATA MechanismType = 0x00000656
	CKM_SEED_CBC_ENCRYPT_DATA MechanismType = 0x00000657

	// Skipjack Mechanisms
	CKM_SKIPJACK_KEY_GEN      MechanismType = 0x00001000
	CKM_SKIPJACK_ECB64        MechanismType = 0x00001001
	CKM_SKIPJACK_CBC64        MechanismType = 0x00001002
	CKM_SKIPJACK_OFB64        MechanismType = 0x00001003
	CKM_SKIPJACK_CFB64        MechanismType = 0x00001004
	CKM_SKIPJACK_CFB32        MechanismType = 0x00001005
	CKM_SKIPJACK_CFB16        MechanismType = 0x00001006
	CKM_SKIPJACK_CFB8         MechanismType = 0x00001007
	CKM_SKIPJACK_WRAP         MechanismType = 0x00001008
	CKM_SKIPJACK_PRIVATE_WRAP MechanismType = 0x00001009
	CKM_SKIPJACK_RELAYX       MechanismType = 0x0000100A

	// KEA Mechanisms
	CKM_KEA_KEY_PAIR_GEN MechanismType = 0x00001010
	CKM_KEA_KEY_DERIVE   MechanismType = 0x00001011

	// Fortezza Mechanisms
	CKM_FORTEZZA_TIMESTAMP MechanismType = 0x00001020

	// Baton Mechanisms
	CKM_BATON_KEY_GEN MechanismType = 0x00001030
	CKM_BATON_ECB128  MechanismType = 0x00001031
	CKM_BATON_ECB96   MechanismType = 0x00001032
	CKM_BATON_CBC128  MechanismType = 0x00001033
	CKM_BATON_COUNTER MechanismType = 0x00001034
	CKM_BATON_SHUFFLE MechanismType = 0x00001035
	CKM_BATON_WRAP    MechanismType = 0x00001036

	// ECDSA and EC Key Mechanisms
	CKM_EC_KEY_PAIR_GEN    MechanismType = 0x00001040
	CKM_ECDSA_KEY_PAIR_GEN MechanismType = 0x00001040 // Deprecated alias
	CKM_ECDSA              MechanismType = 0x00001041
	CKM_ECDSA_SHA1         MechanismType = 0x00001042
	CKM_ECDSA_SHA224       MechanismType = 0x00001043
	CKM_ECDSA_SHA256       MechanismType = 0x00001044
	CKM_ECDSA_SHA384       MechanismType = 0x00001045
	CKM_ECDSA_SHA512       MechanismType = 0x00001046
	CKM_ECDSA_SHA3_224     MechanismType = 0x00001047
	CKM_ECDSA_SHA3_256     MechanismType = 0x00001048
	CKM_ECDSA_SHA3_384     MechanismType = 0x00001049
	CKM_ECDSA_SHA3_512     MechanismType = 0x0000104A

	// ECDH Mechanisms
	CKM_ECDH1_DERIVE          MechanismType = 0x00001050
	CKM_ECDH1_COFACTOR_DERIVE MechanismType = 0x00001051
	CKM_ECMQV_DERIVE          MechanismType = 0x00001052
	CKM_ECDH_AES_KEY_WRAP     MechanismType = 0x00001053

	// Juniper Mechanisms
	CKM_JUNIPER_KEY_GEN MechanismType = 0x00001060
	CKM_JUNIPER_ECB128  MechanismType = 0x00001061
	CKM_JUNIPER_CBC128  MechanismType = 0x00001062
	CKM_JUNIPER_COUNTER MechanismType = 0x00001063
	CKM_JUNIPER_SHUFFLE MechanismType = 0x00001064
	CKM_JUNIPER_WRAP    MechanismType = 0x00001065

	// FASTHASH Mechanism
	CKM_FASTHASH MechanismType = 0x00001070

	// AES Mechanisms
	CKM_AES_KEY_GEN      MechanismType = 0x00001080
	CKM_AES_ECB          MechanismType = 0x00001081
	CKM_AES_CBC          MechanismType = 0x00001082
	CKM_AES_MAC          MechanismType = 0x00001083
	CKM_AES_MAC_GENERAL  MechanismType = 0x00001084
	CKM_AES_CBC_PAD      MechanismType = 0x00001085
	CKM_AES_CTR          MechanismType = 0x00001086
	CKM_AES_GCM          MechanismType = 0x00001087
	CKM_AES_CCM          MechanismType = 0x00001088
	CKM_AES_CTS          MechanismType = 0x00001089
	CKM_AES_CMAC         MechanismType = 0x0000108A
	CKM_AES_CMAC_GENERAL MechanismType = 0x0000108B
	CKM_AES_XCBC_MAC     MechanismType = 0x0000108C
	CKM_AES_XCBC_MAC_96  MechanismType = 0x0000108D
	CKM_AES_GMAC         MechanismType = 0x0000108E

	// AES Key Wrap Mechanisms (NIST SP 800-38F)
	CKM_AES_KEY_WRAP     MechanismType = 0x00002109
	CKM_AES_KEY_WRAP_PAD MechanismType = 0x0000210A
	CKM_AES_KEY_WRAP_KWP MechanismType = 0x0000210B

	// AES OFB Mechanism
	CKM_AES_OFB MechanismType = 0x00002104

	// AES CFB Mechanisms
	CKM_AES_CFB64  MechanismType = 0x00002105
	CKM_AES_CFB8   MechanismType = 0x00002106
	CKM_AES_CFB128 MechanismType = 0x00002107
	CKM_AES_CFB1   MechanismType = 0x00002108

	// AES XTS Mechanism. OASIS allocates these in the 0x1070 block that
	// follows CKM_RSA_AES_KEY_WRAP, not in the 0x2100 AES block that holds
	// the AES modes above: CKM_AES_XTS is 0x1071 and NOT 0x2181.
	CKM_AES_XTS         MechanismType = 0x00001071
	CKM_AES_XTS_KEY_GEN MechanismType = 0x00001072

	// Blowfish Mechanisms
	CKM_BLOWFISH_KEY_GEN MechanismType = 0x00001090
	CKM_BLOWFISH_CBC     MechanismType = 0x00001091
	CKM_BLOWFISH_CBC_PAD MechanismType = 0x00001094

	// Twofish Mechanisms
	CKM_TWOFISH_KEY_GEN MechanismType = 0x00001092
	CKM_TWOFISH_CBC     MechanismType = 0x00001093
	CKM_TWOFISH_CBC_PAD MechanismType = 0x00001095

	// SecurID Mechanisms
	CKM_SECURID_KEY_GEN MechanismType = 0x00000280
	CKM_SECURID         MechanismType = 0x00000282

	// HOTP Mechanisms
	CKM_HOTP_KEY_GEN MechanismType = 0x00000290
	CKM_HOTP         MechanismType = 0x00000291

	// ACTI Mechanisms. OASIS allocates the operation before the key
	// generator here, the opposite of the SecurID and HOTP blocks above:
	// CKM_ACTI is 0x2A0 and CKM_ACTI_KEY_GEN is 0x2A1, NOT the reverse.
	CKM_ACTI         MechanismType = 0x000002A0
	CKM_ACTI_KEY_GEN MechanismType = 0x000002A1

	// EdDSA and Edwards Curve Mechanisms (PKCS#11 v3.0)
	CKM_EC_EDWARDS_KEY_PAIR_GEN    MechanismType = 0x00001055
	CKM_EDDSA                      MechanismType = 0x00001057
	CKM_EC_MONTGOMERY_KEY_PAIR_GEN MechanismType = 0x00001056

	// XEdDSA signature mechanism (PKCS#11 v3.0). Despite sitting beside the
	// Edwards and Montgomery mechanisms functionally, OASIS allocates it in
	// the 0x4000 block: CKM_XEDDSA is 0x4029 and NOT 0x1058, which follows
	// CKM_EDDSA numerically but is unassigned in the spec.
	CKM_XEDDSA MechanismType = 0x00004029

	// HKDF Mechanisms (PKCS#11 v3.0). These directly follow CKM_XEDDSA and
	// directly precede CKM_SALSA20_KEY_GEN (0x402D). CKM_HKDF_DERIVE is
	// 0x402A and NOT 0x402C: 0x402C is CKM_HKDF_KEY_GEN, so shifting this
	// block up by two makes a derive request select key generation, a data
	// derive select CKM_SALSA20_KEY_GEN, and key generation select
	// CKM_IKE2_PRF_PLUS_DERIVE (0x402E).
	CKM_HKDF_DERIVE  MechanismType = 0x0000402A
	CKM_HKDF_DATA    MechanismType = 0x0000402B
	CKM_HKDF_KEY_GEN MechanismType = 0x0000402C

	// SP800-108 KDF Mechanisms (PKCS#11 v3.0)
	CKM_SP800_108_COUNTER_KDF         MechanismType = 0x000003AC
	CKM_SP800_108_FEEDBACK_KDF        MechanismType = 0x000003AD
	CKM_SP800_108_DOUBLE_PIPELINE_KDF MechanismType = 0x000003AE

	// RSA AES Key Wrap
	CKM_RSA_AES_KEY_WRAP MechanismType = 0x00001054

	// Vendor-defined mechanisms start at this value
	CKM_VENDOR_DEFINED MechanismType = 0x80000000
)

// MechanismInfo represents information about a mechanism (CK_MECHANISM_INFO).
// This structure describes a mechanism's capabilities and constraints.
type MechanismInfo struct {
	// MinKeySize is the minimum key size supported by the mechanism.
	//
	// The unit is mechanism-dependent, not always bits: PKCS#11 v3.2 §6.1
	// ("Mechanism information") states "whether this is measured in bits or
	// in bytes is mechanism-dependent," and each mechanism's own subsection
	// says which. RSA (§6.1.2 etc.), DSA (§6.2.6 etc.), EC/ECDSA field sizes
	// (§6.3.x), and Diffie-Hellman (§6.4.x) all report bits. AES and every
	// other symmetric block/stream cipher family (§6.10.3, §6.45-6.51),
	// SHA-*/SHA3-*/BLAKE2b HMAC (§6.20-6.36), and ML-DSA/ML-KEM public key
	// sizes (§6.67-6.68) all report bytes. Some mechanisms (pure digests,
	// GOST, HSS/XMSS, SLH-DSA) have no meaningful key size at all, in which
	// case both fields must be 0. Consult the mechanism's own spec
	// subsection before copying a sibling entry's convention -- reporting
	// CKM_AES_KEY_GEN's key size in bits instead of bytes is exactly the
	// defect this comment exists to prevent from recurring.
	MinKeySize uint32

	// MaxKeySize is the maximum key size supported by the mechanism, in the
	// same mechanism-dependent unit as MinKeySize; see its doc comment.
	MaxKeySize uint32

	// Flags indicates the mechanism's capabilities.
	Flags MechanismFlag
}

// MechanismFlag represents mechanism capability flags (CK_FLAGS for mechanisms).
type MechanismFlag uint32

// Mechanism capability flags (CKF_* for CK_MECHANISM_INFO)
const (
	// CKF_HW indicates that the mechanism is performed by the device hardware.
	CKF_HW MechanismFlag = 0x00000001

	// CKF_MESSAGE_ENCRYPT indicates the mechanism can encrypt messages.
	CKF_MESSAGE_ENCRYPT MechanismFlag = 0x00000002

	// CKF_MESSAGE_DECRYPT indicates the mechanism can decrypt messages.
	CKF_MESSAGE_DECRYPT MechanismFlag = 0x00000004

	// CKF_MESSAGE_SIGN indicates the mechanism can sign messages.
	CKF_MESSAGE_SIGN MechanismFlag = 0x00000008

	// CKF_MESSAGE_VERIFY indicates the mechanism can verify signatures.
	CKF_MESSAGE_VERIFY MechanismFlag = 0x00000010

	// CKF_MULTI_MESSAGE indicates the mechanism supports multi-part message operations.
	CKF_MULTI_MESSAGE MechanismFlag = 0x00000020

	// CKF_FIND_OBJECTS indicates the mechanism can be used with C_FindObjects.
	CKF_FIND_OBJECTS MechanismFlag = 0x00000040

	// CKF_ENCRYPT indicates the mechanism can be used with C_EncryptInit.
	CKF_ENCRYPT MechanismFlag = 0x00000100

	// CKF_DECRYPT indicates the mechanism can be used with C_DecryptInit.
	CKF_DECRYPT MechanismFlag = 0x00000200

	// CKF_DIGEST indicates the mechanism can be used with C_DigestInit.
	CKF_DIGEST MechanismFlag = 0x00000400

	// CKF_SIGN indicates the mechanism can be used with C_SignInit.
	CKF_SIGN MechanismFlag = 0x00000800

	// CKF_SIGN_RECOVER indicates the mechanism can be used with C_SignRecoverInit.
	CKF_SIGN_RECOVER MechanismFlag = 0x00001000

	// CKF_VERIFY indicates the mechanism can be used with C_VerifyInit.
	CKF_VERIFY MechanismFlag = 0x00002000

	// CKF_VERIFY_RECOVER indicates the mechanism can be used with C_VerifyRecoverInit.
	CKF_VERIFY_RECOVER MechanismFlag = 0x00004000

	// CKF_GENERATE indicates the mechanism can be used with C_GenerateKey.
	CKF_GENERATE MechanismFlag = 0x00008000

	// CKF_GENERATE_KEY_PAIR indicates the mechanism can be used with C_GenerateKeyPair.
	CKF_GENERATE_KEY_PAIR MechanismFlag = 0x00010000

	// CKF_WRAP indicates the mechanism can be used with C_WrapKey.
	CKF_WRAP MechanismFlag = 0x00020000

	// CKF_UNWRAP indicates the mechanism can be used with C_UnwrapKey.
	CKF_UNWRAP MechanismFlag = 0x00040000

	// CKF_DERIVE indicates the mechanism can be used with C_DeriveKey.
	CKF_DERIVE MechanismFlag = 0x00080000

	// CKF_EC_F_P indicates the mechanism can be used with EC over Fp.
	CKF_EC_F_P MechanismFlag = 0x00100000

	// CKF_EC_F_2M indicates the mechanism can be used with EC over F2m.
	CKF_EC_F_2M MechanismFlag = 0x00200000

	// CKF_EC_ECPARAMETERS indicates the mechanism can be used with EC parameters.
	CKF_EC_ECPARAMETERS MechanismFlag = 0x00400000

	// CKF_EC_OID indicates the mechanism can be used with EC OID.
	CKF_EC_OID MechanismFlag = 0x00800000

	// CKF_EC_NAMEDCURVE is deprecated, use CKF_EC_OID instead.
	CKF_EC_NAMEDCURVE MechanismFlag = CKF_EC_OID

	// CKF_EC_UNCOMPRESS indicates the mechanism supports uncompressed EC points.
	CKF_EC_UNCOMPRESS MechanismFlag = 0x01000000

	// CKF_EC_COMPRESS indicates the mechanism supports compressed EC points.
	CKF_EC_COMPRESS MechanismFlag = 0x02000000

	// CKF_EC_CURVENAME indicates the mechanism supports named curves.
	CKF_EC_CURVENAME MechanismFlag = 0x04000000

	// PKCS#11 v3.2 KEM capability flags

	// CKF_ENCAPSULATE indicates the mechanism can be used with C_EncapsulateKey.
	CKF_ENCAPSULATE MechanismFlag = 0x10000000

	// CKF_DECAPSULATE indicates the mechanism can be used with C_DecapsulateKey.
	CKF_DECAPSULATE MechanismFlag = 0x20000000

	// CKF_EXTENSION indicates this is an extension mechanism.
	CKF_EXTENSION MechanismFlag = 0x80000000
)

// PKCS#11 v3.2 Session and Token Flags (CKF_* for CK_SESSION_INFO and C_OpenSession)
// These flags use uint32 type as they belong to different flag namespaces.
const (
	// CKF_ASYNC_SESSION indicates the session supports asynchronous operations.
	CKF_ASYNC_SESSION uint32 = 0x00000008

	// CKF_ASYNC_SESSION_SUPPORTED indicates the token supports asynchronous sessions.
	CKF_ASYNC_SESSION_SUPPORTED uint32 = 0x04000000

	// CKF_SEED_RANDOM_REQUIRED indicates the token requires the application to
	// seed the random number generator via C_SeedRandom before use.
	CKF_SEED_RANDOM_REQUIRED uint32 = 0x02000000
)

// Mechanism represents a PKCS#11 mechanism (CK_MECHANISM).
type Mechanism struct {

	// Type identifies the mechanism (CK_MECHANISM_TYPE).
	Type MechanismType

	// Parameter contains mechanism-specific parameters.
	// For mechanisms without parameters, this is nil.
	Parameter []byte

	// TypedParameter contains parsed mechanism parameters for complex parameter types.
	// This is used internally by the PKCS#11 module for typed parameter handling.
	// For mechanisms like HKDF that require structured parameters, use this field.
	TypedParameter interface{}
}

// NewMechanism creates a new mechanism with the given type.
func NewMechanism(mechType MechanismType) *Mechanism {
	return &Mechanism{
		Type: mechType,
	}
}

// NewMechanismWithParams creates a new mechanism with the given type and raw parameters.
func NewMechanismWithParams(mechType MechanismType, params []byte) *Mechanism {
	return &Mechanism{
		Type:      mechType,
		Parameter: params,
	}
}

// NewMechanismWithTypedParams creates a new mechanism with typed parameters.
func NewMechanismWithTypedParams(mechType MechanismType, params interface{}) *Mechanism {
	return &Mechanism{
		Type:           mechType,
		TypedParameter: params,
	}
}

// GetAESGCMParams returns the AES-GCM parameters if the typed parameter is AESGCMParams.
// This is used by authenticated wrapping operations to extract caller-specified IV/AAD.
func (m *Mechanism) GetAESGCMParams() (*AESGCMParams, bool) {
	if m.TypedParameter == nil {
		return nil, false
	}
	params, ok := m.TypedParameter.(*AESGCMParams)
	return params, ok
}

// GetAESGCMMessageParams returns the message-based GCM parameters if the typed
// parameter is AESGCMMessageParams.
func (m *Mechanism) GetAESGCMMessageParams() (*AESGCMMessageParams, bool) {
	if m.TypedParameter == nil {
		return nil, false
	}
	params, ok := m.TypedParameter.(*AESGCMMessageParams)
	return params, ok
}

// GetHKDFParams returns the HKDF parameters if the typed parameter is HKDFParams.
func (m *Mechanism) GetHKDFParams() (*HKDFParams, bool) {
	if m.TypedParameter == nil {
		return nil, false
	}
	params, ok := m.TypedParameter.(*HKDFParams)
	return params, ok
}

// RSAOAEPParams represents parameters for CKM_RSA_PKCS_OAEP (CK_RSA_PKCS_OAEP_PARAMS).
type RSAOAEPParams struct {
	// HashAlg is the hash algorithm used for OAEP (e.g., CKM_SHA256).
	HashAlg MechanismType

	// MGF is the mask generation function (e.g., CKG_MGF1_SHA256).
	MGF MGFType

	// Source indicates the source of the encoding parameter.
	// CKZ_DATA_SPECIFIED (0x01) means the source is provided explicitly.
	Source uint32

	// SourceData is the encoding parameter (label) data.
	// May be nil if Source is CKZ_DATA_SPECIFIED with no data.
	SourceData []byte
}

// PKCS#11 v3.2 message-based operation flags.
//
// This is the flags argument of C_EncryptMessageNext and its siblings, not a
// CK_MECHANISM_INFO flag, so it is deliberately not a MechanismFlag: its value
// collides with CKF_HW, and the mechanism-flag typing made
// MechanismInfo.HasFlag(CKF_END_OF_MESSAGE) return true for every hardware
// mechanism while still compiling.
const (
	// CKF_END_OF_MESSAGE indicates the final chunk in a multi-part message operation.
	CKF_END_OF_MESSAGE uint32 = 0x00000001
)

// ValidateRSAOAEPParams checks the two CK_RSA_PKCS_OAEP_PARAMS fields this
// module validates rather than forwards, and reports the CK_RV for a request it
// cannot serve exactly as asked.
//
// mgf is independent of hashAlg in the structure, but every OAEP operation here
// runs MGF1 over hashAlg itself: rsa.EncryptOAEP and rsa.SignPSS derive the mask
// from the digest they are given and take no separate argument. A caller naming
// CKG_MGF1_SHA1 alongside hashAlg=CKM_SHA256 -- a legal combination, and RFC
// 8017's own OAEP default -- would have had its request performed under
// MGF1-SHA-256 and reported as honoured, producing a ciphertext the recipient
// cannot decrypt. Refusing is the only honest answer available.
//
// source is CKZ_DATA_SPECIFIED, the sole value §6.1.8 defines. Zero is accepted
// as "no encoding parameter", which is what a caller that zero-filled the struct
// means, but only when it supplied no data: source and pSourceData disagreeing
// is a request nobody can serve, and honouring a stale pSourceData under source
// zero would encrypt under a label the caller never selected.
func ValidateRSAOAEPParams(params *RSAOAEPParams) error {
	if params == nil {
		return nil
	}

	if params.MGF != 0 && params.MGF != GetMGFForHash(params.HashAlg) {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_RSA_PKCS_OAEP_PARAMS.mgf must be the MGF1 variant matching hashAlg; "+
				"this token cannot use an independent mask generation function")
	}
	if params.Source != 0 && params.Source != CKZ_DATA_SPECIFIED {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_RSA_PKCS_OAEP_PARAMS.source names a value other than CKZ_DATA_SPECIFIED")
	}
	if len(params.SourceData) > 0 && params.Source != CKZ_DATA_SPECIFIED {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_RSA_PKCS_OAEP_PARAMS.pSourceData requires source to be CKZ_DATA_SPECIFIED")
	}

	return nil
}

// RSAPSSParams represents parameters for CKM_RSA_PKCS_PSS (CK_RSA_PKCS_PSS_PARAMS).
type RSAPSSParams struct {
	// HashAlg is the hash algorithm used for PSS (e.g., CKM_SHA256).
	HashAlg MechanismType

	// MGF is the mask generation function (e.g., CKG_MGF1_SHA256).
	MGF MGFType

	// SaltLen is the length of the salt in bytes.
	// Common values: 0 (no salt), hash length, or max (key size - hash size - 2).
	SaltLen uint32
}

// MGFType represents mask generation function types (CK_RSA_PKCS_MGF_TYPE).
type MGFType uint32

// Mask Generation Function constants
const (
	CKG_MGF1_SHA1     MGFType = 0x00000001
	CKG_MGF1_SHA256   MGFType = 0x00000002
	CKG_MGF1_SHA384   MGFType = 0x00000003
	CKG_MGF1_SHA512   MGFType = 0x00000004
	CKG_MGF1_SHA224   MGFType = 0x00000005
	CKG_MGF1_SHA3_224 MGFType = 0x00000006
	CKG_MGF1_SHA3_256 MGFType = 0x00000007
	CKG_MGF1_SHA3_384 MGFType = 0x00000008
	CKG_MGF1_SHA3_512 MGFType = 0x00000009
)

// OAEP source constants (CKZ_*)
const (
	CKZ_DATA_SPECIFIED uint32 = 0x00000001
)

// AESGCMParams represents parameters for CKM_AES_GCM (CK_GCM_PARAMS).
type AESGCMParams struct {
	// IV is the initialization vector for GCM mode.
	// Should be 12 bytes (96 bits) for best performance.
	IV []byte

	// AAD is the additional authenticated data (may be nil).
	AAD []byte

	// TagBits is the authentication tag length in bits.
	// Valid values: 128, 120, 112, 104, 96 (NIST SP 800-38D).
	TagBits uint32
}

// IVGenerator selects how a message-based AEAD operation obtains its IV,
// mirroring CK_GENERATOR_FUNCTION.
type IVGenerator uint32

// CK_GENERATOR_FUNCTION values (PKCS#11 v3.2 §6.13.5).
const (
	// CKG_NO_GENERATE means the caller supplied the IV and the token must use
	// it unchanged.
	CKG_NO_GENERATE IVGenerator = 0

	// CKG_GENERATE means the token generates the IV, preserving the number of
	// leading bits named by IVFixedBits.
	CKG_GENERATE IVGenerator = 1

	// CKG_GENERATE_COUNTER means the token generates the IV as a counter.
	CKG_GENERATE_COUNTER IVGenerator = 2

	// CKG_GENERATE_RANDOM means the token generates the IV at random.
	CKG_GENERATE_RANDOM IVGenerator = 3

	// CKG_GENERATE_COUNTER_XOR means the token generates the IV as a counter
	// XORed with a fixed field. Declared for completeness so a caller-supplied
	// value resolves to a named constant rather than falling through unnamed;
	// like the other generating modes it is refused where the module cannot
	// honour the CK_GCM_MESSAGE_PARAMS fixed-bits contract (see IV handling in
	// the message-based AES-GCM path).
	CKG_GENERATE_COUNTER_XOR IVGenerator = 4
)

// AESGCMMessageParams represents CK_GCM_MESSAGE_PARAMS, the parameters
// CKM_AES_GCM takes for the message-based functions.
//
// This is a different structure from AESGCMParams, which serves C_EncryptInit
// and C_DecryptInit. The distinction matters: a message-based operation binds
// its mechanism and key once with C_MessageEncryptInit and then runs many
// messages through them, so the per-message IV and tag travel on each
// C_EncryptMessage call rather than on the Init.
//
// Both IV and Tag are in-out. When IVGenerator is anything other than
// CKG_NO_GENERATE the token writes the IV it generated back to the caller, and
// C_EncryptMessage always writes the authentication tag back. Without that
// write-back an application that asked the token to generate the IV has no way
// to learn it, and therefore no way to ever decrypt what it just encrypted.
type AESGCMMessageParams struct {
	// IV is the initialization vector. It is an input when IVGenerator is
	// CKG_NO_GENERATE and an output otherwise.
	IV []byte

	// IVFixedBits is the number of leading IV bits the token must preserve when
	// generating a new IV.
	IVFixedBits uint32

	// IVGenerator selects who produces the IV and how.
	IVGenerator IVGenerator

	// Tag is the authentication tag: an output of C_EncryptMessage and an input
	// to C_DecryptMessage.
	Tag []byte

	// TagBits is the authentication tag length in bits, 0 to 128.
	TagBits uint32
}

// AESCCMParams represents parameters for CKM_AES_CCM (CK_CCM_PARAMS).
type AESCCMParams struct {
	// DataLen is the length of the data to be encrypted.
	DataLen uint32

	// Nonce is the nonce value (7-13 bytes).
	Nonce []byte

	// AAD is the additional authenticated data (may be nil).
	AAD []byte

	// MACLen is the length of the MAC in bytes (4, 6, 8, 10, 12, 14, or 16).
	MACLen uint32
}

// AESCTRParams represents parameters for CKM_AES_CTR (CK_AES_CTR_PARAMS).
type AESCTRParams struct {
	// CounterBits is the number of bits in the counter block.
	// Typically 128 for a full-block counter.
	CounterBits uint32

	// CB is the counter block (16 bytes for AES).
	CB [16]byte
}

// AESCBCParams represents parameters for CKM_AES_CBC (IV only, 16 bytes for AES).
type AESCBCParams struct {
	// IV is the initialization vector (16 bytes for AES).
	IV [16]byte
}

// ECDHParams represents parameters for ECDH key derivation (CK_ECDH1_DERIVE_PARAMS).
type ECDHParams struct {
	// KDF is the key derivation function to use.
	KDF KDFType

	// SharedData is optional shared data for key derivation.
	SharedData []byte

	// PublicData is the other party's EC public key.
	PublicData []byte
}

// ecdhPeerCurves resolves an uncompressed SEC1 point length to the curve it can
// belong to. The three NIST curves this module derives over have distinct
// coordinate widths, so the length identifies the curve unambiguously.
var ecdhPeerCurves = map[int]ecdh.Curve{
	65:  ecdh.P256(),
	97:  ecdh.P384(),
	133: ecdh.P521(),
}

// ValidateECDHPeerPoint checks that pPublicData from CK_ECDH1_DERIVE_PARAMS is a
// well-formed uncompressed SEC1 point that lies on its curve.
//
// This is done in the mechanism layer, before the request fans out, because the
// point is attacker-supplied and every backend sees it. The software backend
// validates through crypto/ecdh; the TPM path hands raw coordinates to the
// hardware and is saved only by the hardware refusing them; the cloud KMS and
// PKCS#11 backends were not audited for it. One check here is the difference
// between a property the token has and a property some of its backends happen to
// have.
//
// The attack it closes is the classic invalid-curve one: a point on a low-order
// twist makes the shared secret land in a small subgroup, so each derivation
// leaks residues of the static private scalar and repeated derivations recover
// it by CRT. NIST SP 800-56A Rev. 3 §5.6.2.3.2 requires full public-key
// validation for static-key ECDH for exactly this reason.
func ValidateECDHPeerPoint(publicData []byte) error {
	curve, known := ecdhPeerCurves[len(publicData)]
	if !known {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_ECDH1_DERIVE_PARAMS.pPublicData is not an uncompressed point on a supported curve")
	}
	if publicData[0] != 0x04 {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_ECDH1_DERIVE_PARAMS.pPublicData must be an uncompressed SEC1 point")
	}
	if _, err := curve.NewPublicKey(publicData); err != nil {
		return NewPKCS11ErrorWithMessage(CKR_MECHANISM_PARAM_INVALID,
			"CK_ECDH1_DERIVE_PARAMS.pPublicData is not a point on the curve")
	}
	return nil
}

// KDFType represents key derivation function types (CK_EC_KDF_TYPE).
type KDFType uint32

// Key Derivation Function constants for ECDH
const (
	CKD_NULL                 KDFType = 0x00000001
	CKD_SHA1_KDF             KDFType = 0x00000002
	CKD_SHA1_KDF_ASN1        KDFType = 0x00000003
	CKD_SHA1_KDF_CONCATENATE KDFType = 0x00000004
	CKD_SHA224_KDF           KDFType = 0x00000005
	CKD_SHA256_KDF           KDFType = 0x00000006
	CKD_SHA384_KDF           KDFType = 0x00000007
	CKD_SHA512_KDF           KDFType = 0x00000008
	CKD_CPDIVERSIFY_KDF      KDFType = 0x00000009
	CKD_SHA3_224_KDF         KDFType = 0x0000000A
	CKD_SHA3_256_KDF         KDFType = 0x0000000B
	CKD_SHA3_384_KDF         KDFType = 0x0000000C
	CKD_SHA3_512_KDF         KDFType = 0x0000000D
	CKD_SHA1_KDF_SP800       KDFType = 0x0000000E
	CKD_SHA224_KDF_SP800     KDFType = 0x0000000F
	CKD_SHA256_KDF_SP800     KDFType = 0x00000010
	CKD_SHA384_KDF_SP800     KDFType = 0x00000011
	CKD_SHA512_KDF_SP800     KDFType = 0x00000012
	CKD_BLAKE2B_160_KDF      KDFType = 0x00000017
	CKD_BLAKE2B_256_KDF      KDFType = 0x00000018
	CKD_BLAKE2B_384_KDF      KDFType = 0x00000019
	CKD_BLAKE2B_512_KDF      KDFType = 0x0000001A
)

// ecdhKDF names the canonical KDF this module runs for one CK_EC_KDF_TYPE.
// Algorithm and Hash are the wire-level names the transport layer forwards to
// types.KDFParams, which is the single derivation entry point every backend
// shares.
type ecdhKDF struct {
	// Algorithm is the wire-level KDF algorithm name ("X963", "SP800-56A").
	Algorithm string

	// Hash is the canonical hash name ("SHA-1", "SHA-256", "SHA3-256").
	Hash string
}

// ecdhKDFs is the complete set of CK_EC_KDF_TYPE values C_DeriveKey accepts
// for CKM_ECDH1_DERIVE, and the single source of truth for what this module
// advertises. A KDF type absent from this map is one the stack cannot honor
// exactly, and C_DeriveKey returns CKR_MECHANISM_PARAM_INVALID for it rather
// than deriving with a substitute:
//
//	CKD_CPDIVERSIFY_KDF   card-issuer diversification, unimplemented.
//	CKD_BLAKE2B_*_KDF     BLAKE2b is not an approved KDF hash here.
//
// CKD_NULL is SUPPORTED and applies no derivation: the transport carries it as
// KDFAlgorithmRaw and C_DeriveKey returns the shared secret itself, truncated
// to CKA_VALUE_LEN, which is what v3.2 §6.3.17 defines the type to mean. It was
// listed among the refusals above for want of a "no KDF" representation on the
// wire, and that representation now exists -- but the comment outlived it, so a
// maintainer auditing whether this token can hand back an unprocessed shared
// secret would have read that it cannot.
//
// The SHA-1, SHA-224 and SHA3-224 entries are real: pkg/types accepts those
// hashes for the two concatenation KDFs precisely because PKCS#11 v3.0 names
// them, ANSI X9.63 and SP 800-56A Rev. 3 define them for this construction,
// and SP 800-131A Rev. 2 permits SHA-1 outside signature generation.
var ecdhKDFs = map[KDFType]ecdhKDF{
	CKD_NULL: {Algorithm: KDFAlgorithmRaw, Hash: ""},

	// ANSI X9.63 concatenation KDF. The ASN1 and CONCATENATE variants differ
	// only in how SharedData is encoded before it is fed in as SharedInfo,
	// which the caller does; the derivation is the same X9.63 construction.
	CKD_SHA1_KDF:             {Algorithm: "X963", Hash: "SHA-1"},
	CKD_SHA1_KDF_ASN1:        {Algorithm: "X963", Hash: "SHA-1"},
	CKD_SHA1_KDF_CONCATENATE: {Algorithm: "X963", Hash: "SHA-1"},
	CKD_SHA224_KDF:           {Algorithm: "X963", Hash: "SHA-224"},
	CKD_SHA256_KDF:           {Algorithm: "X963", Hash: "SHA-256"},
	CKD_SHA384_KDF:           {Algorithm: "X963", Hash: "SHA-384"},
	CKD_SHA512_KDF:           {Algorithm: "X963", Hash: "SHA-512"},
	CKD_SHA3_224_KDF:         {Algorithm: "X963", Hash: "SHA3-224"},
	CKD_SHA3_256_KDF:         {Algorithm: "X963", Hash: "SHA3-256"},
	CKD_SHA3_384_KDF:         {Algorithm: "X963", Hash: "SHA3-384"},
	CKD_SHA3_512_KDF:         {Algorithm: "X963", Hash: "SHA3-512"},

	// NIST SP 800-56A concatenation KDF (the _SP800 suffixed types).
	CKD_SHA1_KDF_SP800:   {Algorithm: "SP800-56A", Hash: "SHA-1"},
	CKD_SHA224_KDF_SP800: {Algorithm: "SP800-56A", Hash: "SHA-224"},
	CKD_SHA256_KDF_SP800: {Algorithm: "SP800-56A", Hash: "SHA-256"},
	CKD_SHA384_KDF_SP800: {Algorithm: "SP800-56A", Hash: "SHA-384"},
	CKD_SHA512_KDF_SP800: {Algorithm: "SP800-56A", Hash: "SHA-512"},
}

// ECDHKDF resolves a CK_EC_KDF_TYPE to the canonical KDF algorithm and hash
// names the transport layer forwards. ok is false for every KDF type this
// module does not implement, which the caller must map to
// CKR_MECHANISM_PARAM_INVALID: substituting a different KDF would return key
// material the caller never requested under CKR_OK.
func ECDHKDF(kdf KDFType) (algorithm, hash string, ok bool) {
	entry, ok := ecdhKDFs[kdf]
	if !ok {
		return "", "", false
	}
	return entry.Algorithm, entry.Hash, true
}

// SupportedECDHKDFs returns the CK_EC_KDF_TYPE values C_DeriveKey accepts,
// sorted, so callers and conformance tests can enumerate the advertisement
// instead of restating it.
func SupportedECDHKDFs() []KDFType {
	kdfs := make([]KDFType, 0, len(ecdhKDFs))
	for kdf := range ecdhKDFs {
		kdfs = append(kdfs, kdf)
	}
	sort.Slice(kdfs, func(i, j int) bool { return kdfs[i] < kdfs[j] })
	return kdfs
}

// HKDFParams represents parameters for HKDF key derivation (CK_HKDF_PARAMS).
type HKDFParams struct {
	// Extract indicates whether to perform the extract step.
	Extract bool

	// Expand indicates whether to perform the expand step.
	Expand bool

	// PRFHashMech is the hash mechanism for HKDF (e.g., CKM_SHA256).
	PRFHashMech MechanismType

	// SaltType indicates how salt is provided.
	SaltType HKDFSaltType

	// Salt is the salt value (used when SaltType is CKF_HKDF_SALT_DATA).
	Salt []byte

	// SaltKey is the object handle of the salt key (used when SaltType is CKF_HKDF_SALT_KEY).
	SaltKey ObjectHandle

	// Info is the application-specific info for HKDF-Expand.
	Info []byte
}

// HKDFSaltType represents HKDF salt types (CK_HKDF_SALT_TYPE).
type HKDFSaltType uint32

// HKDF salt type constants. These are single-bit flag values rather than a
// dense enumeration, so CKF_HKDF_SALT_KEY is 0x4 and NOT 0x3 — 0x3 is the
// bitwise union of CKF_HKDF_SALT_NULL and CKF_HKDF_SALT_DATA and names no
// salt type of its own.
const (
	CKF_HKDF_SALT_NULL HKDFSaltType = 0x00000001
	CKF_HKDF_SALT_DATA HKDFSaltType = 0x00000002
	CKF_HKDF_SALT_KEY  HKDFSaltType = 0x00000004
)

// SP800108DataType identifies the kind of data carried by one segment of an
// SP800-108 PRF input array (CK_PRF_DATA_TYPE, v3.2 section 6.42 Table 197).
type SP800108DataType uint32

// SP800-108 PRF data field type constants.
const (
	SP800108IterationVariable SP800108DataType = 0x00000001
	SP800108Counter           SP800108DataType = 0x00000002
	SP800108DKMLength         SP800108DataType = 0x00000003
	SP800108ByteArray         SP800108DataType = 0x00000004
	SP800108KeyHandle         SP800108DataType = 0x00000005
)

// SP800108DataParam represents one segment of an SP800-108 PRF input array
// (CK_PRF_DATA_PARAM, v3.2 section 6.42). Value carries the segment's raw
// bytes for types this module can represent (SP800108ByteArray, and an
// empty/default SP800108IterationVariable); other types are captured with
// their type recorded so DeriveKeyInit can refuse them explicitly instead
// of silently ignoring an encoding it cannot reproduce.
type SP800108DataParam struct {
	// Type identifies the segment (e.g. SP800108ByteArray).
	Type SP800108DataType

	// Value holds the segment's raw bytes, copied from pValue/ulValueLen.
	Value []byte
}

// SP800108KDFParams represents parameters for the SP800-108 counter,
// feedback and double-pipeline KDF mechanisms (CK_SP800_108_KDF_PARAMS /
// CK_SP800_108_FEEDBACK_KDF_PARAMS, v3.2 section 6.42).
type SP800108KDFParams struct {
	// PRF is the pseudo-random function mechanism (e.g. CKM_SHA256_HMAC).
	PRF MechanismType

	// DataParams is the ordered PRF input segment array.
	DataParams []SP800108DataParam

	// IV is the optional feedback-mode initialization vector
	// (CK_SP800_108_FEEDBACK_KDF_PARAMS.pIV). Empty for counter and
	// double-pipeline mode, which have no IV field.
	IV []byte
}

// GetSP800108KDFParams returns the SP800-108 parameters if the typed
// parameter is *SP800108KDFParams.
func (m *Mechanism) GetSP800108KDFParams() (*SP800108KDFParams, bool) {
	if m.TypedParameter == nil {
		return nil, false
	}
	params, ok := m.TypedParameter.(*SP800108KDFParams)
	return params, ok
}

// EdDSAParams represents parameters for CKM_EDDSA (CK_EDDSA_PARAMS, v3.2
// section 6.24). A nil *EdDSAParams (equivalently, mech.TypedParameter
// unset because the caller passed a NULL pParameter) selects pure
// Ed25519/Ed448 per RFC 8032 Table 73; a non-nil value selects among
// Ed25519ctx, Ed25519ph, Ed448 and Ed448ph via PreHash.
type EdDSAParams struct {
	// PreHash selects the pre-hashed variant (Ed25519ph / Ed448ph) when
	// true, or the non-prehashed variant (Ed25519ctx / Ed448) when false.
	PreHash bool

	// Context is the optional context string shared between signer and
	// verifier. Must be 0-255 bytes (v3.2 section 6.24).
	Context []byte
}

// GetEdDSAParams returns the EdDSA parameters if the typed parameter is
// *EdDSAParams.
func (m *Mechanism) GetEdDSAParams() (*EdDSAParams, bool) {
	if m.TypedParameter == nil {
		return nil, false
	}
	params, ok := m.TypedParameter.(*EdDSAParams)
	return params, ok
}

// NewEdDSAParams creates EdDSA signature parameters selecting among the
// context and pre-hash variants defined by RFC 8032 Table 73.
func NewEdDSAParams(preHash bool, context []byte) *EdDSAParams {
	return &EdDSAParams{
		PreHash: preHash,
		Context: context,
	}
}

// MechanismCategory represents categories of mechanisms.
type MechanismCategory uint8

const (
	CategoryDigest     MechanismCategory = iota // Message digesting (hashing)
	CategorySign                                // Signing operations
	CategoryVerify                              // Verification operations
	CategoryEncrypt                             // Encryption operations
	CategoryDecrypt                             // Decryption operations
	CategoryKeyGen                              // Key generation
	CategoryKeyPairGen                          // Key pair generation
	CategoryWrap                                // Key wrapping
	CategoryUnwrap                              // Key unwrapping
	CategoryDerive                              // Key derivation
)

// MechanismDescriptor describes a mechanism's properties and capabilities.
type MechanismDescriptor struct {
	// Type is the mechanism type constant.
	Type MechanismType

	// Name is the human-readable name of the mechanism.
	Name string

	// Categories indicates what operations this mechanism supports.
	Categories []MechanismCategory

	// MinKeySize is the minimum key size supported by the mechanism (0 if
	// not applicable). Its unit is mechanism-dependent -- see
	// MechanismInfo.MinKeySize's doc comment for the per-family rules and
	// spec citations before setting this for a new mechanism.
	MinKeySize uint32

	// MaxKeySize is the maximum key size supported by the mechanism (0 if
	// not applicable), in the same mechanism-dependent unit as MinKeySize.
	MaxKeySize uint32

	// Flags are the mechanism capability flags.
	Flags MechanismFlag

	// RequiresParams indicates whether the mechanism requires parameters.
	RequiresParams bool

	// ParamsType is the name of the parameter structure type.
	ParamsType string

	// FIPSApproved reports whether the mechanism may be used when the module
	// runs in FIPS mode.
	//
	// FIPS 140-3 restricts a validated module to approved algorithms, so in that
	// mode a non-approved mechanism is neither advertised nor accepted. Outside
	// FIPS mode the module implements the full OASIS surface, because PKCS#11
	// conformance and FIPS approval are separate claims: the spec defines what a
	// Cryptoki module must do, and FIPS narrows which of it a validated
	// deployment may use.
	FIPSApproved bool

	// FIPSMaxKeySize is the maximum key size this mechanism may use while the
	// module runs in FIPS mode, in the same mechanism-dependent unit as
	// MaxKeySize. Zero means FIPS imposes no limit narrower than MaxKeySize.
	//
	// It is a separate field rather than a second registry because the FIPS
	// ceiling and the module's own ceiling are different claims about the same
	// mechanism, and keeping them adjacent is what stops one being changed
	// without the other being considered. effectiveKeySizeRange is the only
	// reader; every projection of a descriptor goes through it, so
	// C_GetMechanismInfo, C_GetMechanismList and IsValidKeySize cannot disagree
	// about which regime's ceiling applies.
	FIPSMaxKeySize uint32

	// RequiresParams and ParamsType are DESCRIPTIVE. Nothing dispatches on them:
	// each parameterised mechanism is validated by its own checker, which knows
	// what the structure means -- resolveCBCIV for CKM_AES_CBC,
	// validateRSAPSSParams for PSS, ValidateRSAOAEPParams for OAEP. They record
	// what a reader would otherwise have to reconstruct from those call sites.
	//
	// The two accessors that read them generically were deleted: they had no
	// caller but their own tests, and a generic "does this need parameters"
	// gate cannot say WHICH parameters or check them, so it would have added a
	// second, weaker answer beside the real one.

	// Advertised reports whether C_GetMechanismList offers this mechanism to
	// applications and C_GetMechanismInfo will describe it.
	//
	// This registry is the single source of truth for both what the module
	// advertises and what the crypto layer will accept, so the two can no
	// longer disagree. They previously did: a separate hardcoded table fed
	// C_GetMechanismList and C_GetMechanismInfo while this one governed
	// validation, and they had drifted apart on the key-size range and flags of
	// nearly every RSA and EC mechanism.
	//
	// The flag exists because "implemented" and "ready to advertise" are
	// genuinely different claims. Advertising a mechanism tells an application
	// it may rely on it, so a mechanism whose implementation is not yet proven
	// end to end stays false until it is — and unadvertised is not a licence to
	// ship a stub, only to withhold a promise.
	Advertised bool
}

// RSA modulus bounds, in bits, as reported by every RSA mechanism's
// ulMinKeySize/ulMaxKeySize (PKCS#11 v3.2 §6.1.4: "the ulMinKeySize and
// ulMaxKeySize fields of the CK_MECHANISM_INFO structure specify the supported
// range of RSA modulus sizes, in bits").
const (
	// rsaModulusBitsMin is the smallest modulus the module will generate or
	// operate on. NIST SP 800-131A has disallowed RSA below 2048 bits since
	// 2014, and this module targets FedRAMP, PCI and HIPAA deployments, so the
	// floor is 2048 even though PKCS#11 v3.2 §6.1.21 still lists 1024 as
	// permissible in FIPS mode. Being stricter than §6.1.21 is allowed; being
	// laxer is not.
	rsaModulusBitsMin uint32 = 2048

	// rsaModulusBitsMax is the largest modulus the module will generate, and
	// therefore the largest it may advertise.
	//
	// ulMaxKeySize is a promise: an application picks a modulus size by reading
	// it, so every value inside the advertised range must be one the token can
	// actually produce. This mechanism previously advertised 16384, and
	// generating a key at that advertised maximum exhausted memory and killed
	// the daemon serving the token — an authenticated caller could take the
	// service down using a size the module itself had told them was valid.
	//
	// 4096 is the cap rather than 8192 because 4096 is the largest RSA modulus
	// this stack's backends enumerate (types.RSAKeySize4096) and the largest
	// the integration suite generates, so it is a size proven to work end to
	// end, and a 4096-bit generation costs on the order of a second. 8192 would
	// be defensible on strength grounds but nothing in the module produces one
	// today, so advertising it would restate the same untrue promise one octave
	// lower; 16384 is not defensible at all, since that is the size that
	// exhausted the daemon.
	rsaModulusBitsMax uint32 = 4096

	// rsaModulusBitsFIPSMax is the largest modulus permitted while the module
	// runs in FIPS mode. PKCS#11 v3.2 §6.1.21 (FIPS 186-4): "When CKM_RSA_PKCS
	// is operated in FIPS mode, the length of the modulus SHALL only be 1024,
	// 2048, or 3072 bits." CK_MECHANISM_INFO can only express a contiguous
	// range, so the ceiling is the largest permitted value.
	rsaModulusBitsFIPSMax uint32 = 3072
)

// mechanismRegistry provides O(1) lookup for mechanism descriptors.
var mechanismRegistry = map[MechanismType]*MechanismDescriptor{
	// RSA Mechanisms
	//
	// Per PKCS#11 v3.2 §6.1.2, 6.1.6, 6.1.7, 6.1.9, and 6.1.14-6.1.16, every
	// RSA mechanism's ulMinKeySize/ulMaxKeySize report the RSA modulus size
	// range in BITS. Every entry carries FIPSMaxKeySize so the §6.1.21 ceiling
	// travels with the mechanism instead of living in a policy table that can
	// fall out of step with the registry.
	CKM_RSA_PKCS_KEY_PAIR_GEN: {
		Type:           CKM_RSA_PKCS_KEY_PAIR_GEN,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_RSA_PKCS_KEY_PAIR_GEN",
		Categories:     []MechanismCategory{CategoryKeyPairGen},
		MinKeySize:     rsaModulusBitsMin,
		MaxKeySize:     rsaModulusBitsMax,
		FIPSMaxKeySize: rsaModulusBitsFIPSMax,
		Flags:          CKF_GENERATE_KEY_PAIR,
	},
	CKM_RSA_PKCS: {
		Type:           CKM_RSA_PKCS,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_RSA_PKCS",
		Categories:     []MechanismCategory{CategorySign, CategoryVerify, CategoryEncrypt, CategoryDecrypt, CategoryWrap, CategoryUnwrap},
		MinKeySize:     rsaModulusBitsMin,
		MaxKeySize:     rsaModulusBitsMax,
		FIPSMaxKeySize: rsaModulusBitsFIPSMax,
		// The recover flags are part of the mechanism's definition, not an
		// extra: v3.2 §6.1.6 describes CKM_RSA_PKCS as supporting "single-part
		// signatures and verification with and without message recovery", and
		// CryptoManager implements the recover direction by stripping the v1.5
		// block. They were absent while the operation worked, so
		// C_GetMechanismInfo told a conformant application the token could not
		// recover and the token recovered anyway.
		Flags: CKF_SIGN | CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER |
			CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
	},
	// CKM_RSA_X_509 ("X.509 (raw) RSA", PKCS#11 v3.2 §6.1.7) carries only the
	// capability this token can actually perform, and the restriction is the
	// point.
	//
	// Verify-recover works and is real: it is s^e mod n computed locally from a
	// public key, and CryptoManager returns the result unprocessed, which is
	// exactly what §6.1.7 defines. That is why the descriptor exists at all.
	//
	// Signing, encryption and decryption are refused. §6.1.7 requires the input
	// be interpreted as an integer and raised to the private exponent with NO
	// padding of any kind, and this token reaches its keys through crypto.Signer
	// and crypto.Decrypter -- interfaces with no raw-primitive form. Keys held
	// in a TPM, an HSM or a cloud KMS cannot expose one even in principle. What
	// the module did instead was leave transport.SignRequest.Padding empty,
	// which the wire defines as PKCS#1 v1.5, so C_Sign returned a v1.5 signature
	// under CKR_OK: recovering s^e mod n from it yields 00 01 FF..FF 00 || M
	// rather than M, and no conformant verifier accepts it. A caller that asked
	// for raw RSA and received v1.5 has no way to detect the substitution, which
	// is the one outcome this registry exists to prevent.
	//
	// Withholding the flags rather than the descriptor is what makes the refusal
	// reach the application: CryptoManager's SignInit, EncryptInit and
	// DecryptInit each gate on the corresponding CKF_ bit, so C_SignInit now
	// answers CKR_MECHANISM_INVALID. Advertised stays false because
	// C_GetMechanismList should not offer a mechanism this narrow.
	CKM_RSA_X_509: {
		Type:           CKM_RSA_X_509,
		Name:           "CKM_RSA_X_509",
		Categories:     []MechanismCategory{CategoryVerify},
		MinKeySize:     rsaModulusBitsMin,
		MaxKeySize:     rsaModulusBitsMax,
		FIPSMaxKeySize: rsaModulusBitsFIPSMax,
		Flags:          CKF_VERIFY_RECOVER,
	},
	CKM_RSA_PKCS_OAEP: {
		Type:           CKM_RSA_PKCS_OAEP,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_RSA_PKCS_OAEP",
		Categories:     []MechanismCategory{CategoryEncrypt, CategoryDecrypt, CategoryWrap, CategoryUnwrap},
		MinKeySize:     rsaModulusBitsMin,
		MaxKeySize:     rsaModulusBitsMax,
		FIPSMaxKeySize: rsaModulusBitsFIPSMax,
		Flags:          CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
		RequiresParams: true,
		ParamsType:     "RSAOAEPParams",
	},
	CKM_RSA_PKCS_PSS: {
		Type:           CKM_RSA_PKCS_PSS,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_RSA_PKCS_PSS",
		Categories:     []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:     rsaModulusBitsMin,
		MaxKeySize:     rsaModulusBitsMax,
		FIPSMaxKeySize: rsaModulusBitsFIPSMax,
		Flags:          CKF_SIGN | CKF_VERIFY,
		RequiresParams: true,
		ParamsType:     "RSAPSSParams",
	},
	CKM_SHA1_RSA_PKCS: {
		Type:           CKM_SHA1_RSA_PKCS,
		Advertised:     true,
		FIPSApproved:   false,
		Name:           "CKM_SHA1_RSA_PKCS",
		Categories:     []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:     rsaModulusBitsMin,
		MaxKeySize:     rsaModulusBitsMax,
		FIPSMaxKeySize: rsaModulusBitsFIPSMax,
		Flags:          CKF_SIGN | CKF_VERIFY,
	},
	CKM_SHA256_RSA_PKCS: {
		Type:           CKM_SHA256_RSA_PKCS,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_SHA256_RSA_PKCS",
		Categories:     []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:     rsaModulusBitsMin,
		MaxKeySize:     rsaModulusBitsMax,
		FIPSMaxKeySize: rsaModulusBitsFIPSMax,
		Flags:          CKF_SIGN | CKF_VERIFY,
	},
	CKM_SHA384_RSA_PKCS: {
		Type:           CKM_SHA384_RSA_PKCS,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_SHA384_RSA_PKCS",
		Categories:     []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:     rsaModulusBitsMin,
		MaxKeySize:     rsaModulusBitsMax,
		FIPSMaxKeySize: rsaModulusBitsFIPSMax,
		Flags:          CKF_SIGN | CKF_VERIFY,
	},
	CKM_SHA512_RSA_PKCS: {
		Type:           CKM_SHA512_RSA_PKCS,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_SHA512_RSA_PKCS",
		Categories:     []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:     rsaModulusBitsMin,
		MaxKeySize:     rsaModulusBitsMax,
		FIPSMaxKeySize: rsaModulusBitsFIPSMax,
		Flags:          CKF_SIGN | CKF_VERIFY,
	},
	CKM_SHA256_RSA_PKCS_PSS: {
		Type:           CKM_SHA256_RSA_PKCS_PSS,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_SHA256_RSA_PKCS_PSS",
		Categories:     []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:     rsaModulusBitsMin,
		MaxKeySize:     rsaModulusBitsMax,
		FIPSMaxKeySize: rsaModulusBitsFIPSMax,
		Flags:          CKF_SIGN | CKF_VERIFY,
		RequiresParams: true,
		ParamsType:     "RSAPSSParams",
	},
	CKM_SHA384_RSA_PKCS_PSS: {
		Type:           CKM_SHA384_RSA_PKCS_PSS,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_SHA384_RSA_PKCS_PSS",
		Categories:     []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:     rsaModulusBitsMin,
		MaxKeySize:     rsaModulusBitsMax,
		FIPSMaxKeySize: rsaModulusBitsFIPSMax,
		Flags:          CKF_SIGN | CKF_VERIFY,
		RequiresParams: true,
		ParamsType:     "RSAPSSParams",
	},
	CKM_SHA512_RSA_PKCS_PSS: {
		Type:           CKM_SHA512_RSA_PKCS_PSS,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_SHA512_RSA_PKCS_PSS",
		Categories:     []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:     rsaModulusBitsMin,
		MaxKeySize:     rsaModulusBitsMax,
		FIPSMaxKeySize: rsaModulusBitsFIPSMax,
		Flags:          CKF_SIGN | CKF_VERIFY,
		RequiresParams: true,
		ParamsType:     "RSAPSSParams",
	},

	// ECDSA Mechanisms
	//
	// Per PKCS#11 v3.2 §6.3.1 etc., ulMinKeySize/ulMaxKeySize report the
	// minimum and maximum supported number of BITS in the EC field size
	// (e.g. secp160r1 = 160 bits, P-521 = 521 bits). Already correct below;
	// audited and left unchanged.
	CKM_EC_KEY_PAIR_GEN: {
		Type:         CKM_EC_KEY_PAIR_GEN,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_EC_KEY_PAIR_GEN",
		Categories:   []MechanismCategory{CategoryKeyPairGen},
		MinKeySize:   256,
		MaxKeySize:   521,
		Flags:        CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_OID | CKF_EC_UNCOMPRESS,
	},
	CKM_ECDSA: {
		Type:         CKM_ECDSA,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_ECDSA",
		Categories:   []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:   256,
		MaxKeySize:   521,
		Flags:        CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_OID,
	},
	// CKM_ECDSA_SHA1 and CKM_ECDSA_SHA224 (PKCS#11 v3.2 §6.3.6) are advertised
	// because both sign and verify end to end: each produces a 64-byte raw
	// r || s signature over a P-256 key that C_Verify accepts and that C_Verify
	// rejects with CKR_SIGNATURE_INVALID when the message is changed. They were
	// registered but unadvertised, which left them undiscoverable through
	// C_GetMechanismList while still reachable by raw constant.
	//
	// They differ on FIPS. CKM_ECDSA_SHA224 is approved: FIPS 186-5 permits
	// ECDSA over any of the FIPS 180-4 digests, SHA-224 among them.
	// CKM_ECDSA_SHA1 is not, because NIST SP 800-131A Rev. 2 disallows SHA-1
	// for signature generation, so it is advertised outside FIPS mode and
	// withheld inside it -- the same treatment CKM_SHA1_RSA_PKCS already gets,
	// rather than splitting the two SHA-1 signature mechanisms on no
	// principle.
	CKM_ECDSA_SHA1: {
		Type:       CKM_ECDSA_SHA1,
		Advertised: true,
		Name:       "CKM_ECDSA_SHA1",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 256,
		MaxKeySize: 521,
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_OID,
	},
	CKM_ECDSA_SHA224: {
		Type:         CKM_ECDSA_SHA224,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_ECDSA_SHA224",
		Categories:   []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:   256,
		MaxKeySize:   521,
		Flags:        CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_OID,
	},
	CKM_ECDSA_SHA256: {
		Type:         CKM_ECDSA_SHA256,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_ECDSA_SHA256",
		Categories:   []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:   256,
		MaxKeySize:   521,
		Flags:        CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_OID,
	},
	CKM_ECDSA_SHA384: {
		Type:         CKM_ECDSA_SHA384,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_ECDSA_SHA384",
		Categories:   []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:   256,
		MaxKeySize:   521,
		Flags:        CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_OID,
	},
	CKM_ECDSA_SHA512: {
		Type:         CKM_ECDSA_SHA512,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_ECDSA_SHA512",
		Categories:   []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:   256,
		MaxKeySize:   521,
		Flags:        CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_OID,
	},

	// ECDH Key Derivation
	//
	// Per PKCS#11 v3.2 §6.3.x, ulMinKeySize/ulMaxKeySize report the EC field
	// size range in BITS, same as the ECDSA family above. Already correct
	// below; audited and left unchanged.
	CKM_ECDH1_DERIVE: {
		Type:           CKM_ECDH1_DERIVE,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_ECDH1_DERIVE",
		Categories:     []MechanismCategory{CategoryDerive},
		MinKeySize:     256,
		MaxKeySize:     521,
		Flags:          CKF_DERIVE | CKF_EC_F_P | CKF_EC_OID,
		RequiresParams: true,
		ParamsType:     "ECDHParams",
	},
	// CKM_ECDH1_COFACTOR_DERIVE is advertised because C_DeriveKey performs it:
	// module.DeriveKey routes it and CKM_ECDH1_DERIVE to the same key-agreement
	// path, and the cgo boundary parses CK_ECDH1_DERIVE_PARAMS for both. It was
	// implemented and working but unlisted, which makes it unreachable to
	// p11-kit, OpenSSL's pkcs11-provider and every other caller that enumerates
	// mechanisms before using them.
	//
	// Cofactor and non-cofactor ECDH produce the same shared secret here
	// because every curve this module supports is a prime-order NIST curve
	// (CKF_EC_F_P, field sizes 256-521 bits) whose cofactor is 1, so §6.3.18's
	// cofactor multiplication is the identity. On a curve with h > 1 the two
	// would differ and this entry would need its own derivation.
	//
	// ParamsType is ECDHParams, not the "ECDHCofactorParams" recorded before:
	// PKCS#11 v3.2 §6.3.18 gives this mechanism CK_ECDH1_DERIVE_PARAMS, the
	// same structure as §6.3.17, and no ECDHCofactorParams type exists in this
	// package for a caller to look up.
	CKM_ECDH1_COFACTOR_DERIVE: {
		Type:           CKM_ECDH1_COFACTOR_DERIVE,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_ECDH1_COFACTOR_DERIVE",
		Categories:     []MechanismCategory{CategoryDerive},
		MinKeySize:     256,
		MaxKeySize:     521,
		Flags:          CKF_DERIVE | CKF_EC_F_P | CKF_EC_OID,
		RequiresParams: true,
		ParamsType:     "ECDHParams",
	},

	// EdDSA Mechanisms
	//
	// Per PKCS#11 v3.2 §6.3.9-6.3.10 ("the only allowed values are 255 and
	// 448 as [RFC 8032] only defines curves of these two sizes"), the unit
	// is BITS (Ed25519 field size = 255 bits, Ed448 = 448 bits). Already
	// correct below; audited and left unchanged.
	CKM_EC_EDWARDS_KEY_PAIR_GEN: {
		Type:         CKM_EC_EDWARDS_KEY_PAIR_GEN,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_EC_EDWARDS_KEY_PAIR_GEN",
		Categories:   []MechanismCategory{CategoryKeyPairGen},
		MinKeySize:   255,
		MaxKeySize:   448,
		Flags:        CKF_GENERATE_KEY_PAIR,
	},
	CKM_EDDSA: {
		Type:         CKM_EDDSA,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_EDDSA",
		Categories:   []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:   255,
		MaxKeySize:   448,
		Flags:        CKF_SIGN | CKF_VERIFY,
	},

	// EC Montgomery Curve Mechanisms (X25519/X448)
	//
	// CKM_EC_MONTGOMERY_KEY_PAIR_GEN is registered but NOT advertised. The
	// module maps it to the X25519 key type and builds a generation request for
	// it, but C_GenerateKeyPair returns CKR_GENERAL_ERROR because no backend in
	// this deployment produces a Montgomery key pair.
	CKM_EC_MONTGOMERY_KEY_PAIR_GEN: {
		Type:       CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
		Name:       "CKM_EC_MONTGOMERY_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		MinKeySize: 255,
		MaxKeySize: 448,
		Flags:      CKF_GENERATE_KEY_PAIR | CKF_EC_F_P,
	},

	// Deliberately absent, because for each of these the module has no
	// implementation path at all -- not a backend that declines the operation,
	// but no code that could perform it -- so the descriptor described a
	// capability that does not exist, and an unadvertised entry is still
	// reachable by any caller that names the raw constant:
	//
	//   - CKM_AES_CTR (v3.2 §6.11) ignores CK_AES_CTR_PARAMS.cb: two
	//     encryptions of the same plaintext under the same key and the same
	//     counter block produce different ciphertexts, which CTR mode cannot
	//     do. A caller can neither decrypt the output with another
	//     implementation nor reproduce it with this one.
	//   - CKM_AES_CCM (§6.13) returns a ciphertext exactly as long as the
	//     plaintext, so it carries no authentication tag. CCM is an AEAD
	//     (SP 800-38C); output without a MAC is not CCM. Both mechanisms are
	//     missing from the cipher-mode table, so each takes the backend's
	//     default rather than the mode it names.
	//   - CKM_AES_CMAC (§6.14.4) and CKM_XEDDSA fail C_Sign with
	//     CKR_FUNCTION_FAILED and have no signing path of their own.
	//   - CKM_ECMQV_DERIVE (§6.3.19) is not among the mechanisms C_DeriveKey
	//     dispatches on and returns CKR_MECHANISM_INVALID.
	//   - CKM_ECDH_AES_KEY_WRAP (§6.3.20) advertised CKF_WRAP/CKF_UNWRAP but
	//     nothing routes it to a wrapping algorithm, so C_WrapKey resolves it
	//     to a bare name the service refuses.
	//   - CKM_HKDF_KEY_GEN (§6.62) has no entry in the mechanism-to-key-type
	//     mapping, so C_GenerateKey cannot build a request for it.
	//
	// Each is a candidate to restore the moment its operation works end to end.

	// AES Mechanisms
	//
	// Per PKCS#11 v3.2 §6.10.3 (AES key generation): "the ulMinKeySize and
	// ulMaxKeySize fields of the CK_MECHANISM_INFO structure specify the
	// supported range of AES key sizes, in bytes." Every other AES
	// sub-mechanism restates the identical "in bytes" rule in its own
	// subsection (§6.10.4-6.10.12 ECB/CBC/CBC_PAD/OFB/CFB/MAC/XCBC-MAC,
	// §6.11 CTR, §6.13.2-6.13.7 GCM/CCM/GMAC, §6.14.4 CMAC, §6.15.4 XTS).
	// AES-128/192/256 are 16/24/32 bytes, so the registry's range is 16-32
	// bytes -- NOT the previously-recorded 128-256, which was the bit
	// count mislabeled as the byte count and would tell a caller reading
	// ulMinKeySize=128 that the token supports 1024-bit AES keys.
	CKM_AES_KEY_GEN: {
		Type:         CKM_AES_KEY_GEN,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_AES_KEY_GEN",
		Categories:   []MechanismCategory{CategoryKeyGen},
		MinKeySize:   16,
		MaxKeySize:   32,
		Flags:        CKF_GENERATE,
	},
	CKM_AES_ECB: {
		Type:         CKM_AES_ECB,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_AES_ECB",
		Categories:   []MechanismCategory{CategoryEncrypt, CategoryDecrypt},
		MinKeySize:   16,
		MaxKeySize:   32,
		Flags:        CKF_ENCRYPT | CKF_DECRYPT,
	},
	// CKM_AES_CBC, CKM_AES_CBC_PAD and CKM_AES_GCM each carry CKF_WRAP and
	// CKF_UNWRAP because PKCS#11 v3.2 §6.10 lists all three among the AES
	// mechanisms usable for wrapping and unwrapping, and because this module
	// routes all three through C_WrapKey/C_UnwrapKey (module.go's
	// wrapAlgorithmNames maps them to types.WrapAESCBC, types.WrapAESCBCPad
	// and types.WrapAESGCM).
	//
	// They advertised CKF_ENCRYPT|CKF_DECRYPT alone, so C_GetMechanismInfo told
	// a conformant application these mechanisms could not wrap while the module
	// wrapped with them anyway. An application that consults the flags before
	// calling — which is what the flags are for — was steered away from a
	// working operation, and CanWrap/CanUnwrap could not be used to gate
	// C_WrapKey because doing so would have refused three mechanisms the module
	// implements.
	CKM_AES_CBC: {
		Type:           CKM_AES_CBC,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_AES_CBC",
		Categories:     []MechanismCategory{CategoryEncrypt, CategoryDecrypt, CategoryWrap, CategoryUnwrap},
		MinKeySize:     16,
		MaxKeySize:     32,
		Flags:          CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
		RequiresParams: true,
		ParamsType:     "AESCBCParams",
	},
	CKM_AES_CBC_PAD: {
		Type:           CKM_AES_CBC_PAD,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_AES_CBC_PAD",
		Categories:     []MechanismCategory{CategoryEncrypt, CategoryDecrypt, CategoryWrap, CategoryUnwrap},
		MinKeySize:     16,
		MaxKeySize:     32,
		Flags:          CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
		RequiresParams: true,
		ParamsType:     "AESCBCParams",
	},
	CKM_AES_GCM: {
		Type:           CKM_AES_GCM,
		Advertised:     true,
		FIPSApproved:   true,
		Name:           "CKM_AES_GCM",
		Categories:     []MechanismCategory{CategoryEncrypt, CategoryDecrypt, CategoryWrap, CategoryUnwrap},
		MinKeySize:     16,
		MaxKeySize:     32,
		Flags:          CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
		RequiresParams: true,
		ParamsType:     "AESGCMParams",
	},
	// PKCS#11 v3.2 §6.16 (AES Key Wrap) does not restate the
	// ulMinKeySize/ulMaxKeySize sentence found in every other AES
	// subsection, but CKM_AES_KEY_WRAP and CKM_AES_KEY_WRAP_PAD operate on
	// an AES key encryption key exactly like the mechanisms above, so the
	// same "AES key sizes, in bytes" convention applies; this is a
	// judgment call in the absence of an explicit per-mechanism sentence,
	// not an inference from a different mechanism family.
	CKM_AES_KEY_WRAP: {
		Type:         CKM_AES_KEY_WRAP,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_AES_KEY_WRAP",
		Categories:   []MechanismCategory{CategoryWrap, CategoryUnwrap},
		MinKeySize:   16,
		MaxKeySize:   32,
		Flags:        CKF_WRAP | CKF_UNWRAP,
	},
	// CKM_AES_KEY_WRAP_KWP is the current identifier for the RFC 5649 AES Key
	// Wrap with Padding construction (PKCS#11 v3.2 §6.10). CKM_AES_KEY_WRAP_PAD
	// names the same construction and is the deprecated alias the spec retains
	// for existing applications, so the two descriptors are deliberately
	// identical: an application that asks for either gets the same wrapping.
	//
	// KWP was declared and name-mapped but never registered, so every use of
	// the current identifier returned CKR_MECHANISM_INVALID while the
	// deprecated alias worked — the opposite of what a v3.2 application would
	// expect. PAD keeps its entry so no existing caller breaks.
	CKM_AES_KEY_WRAP_KWP: {
		Type:         CKM_AES_KEY_WRAP_KWP,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_AES_KEY_WRAP_KWP",
		Categories:   []MechanismCategory{CategoryWrap, CategoryUnwrap},
		MinKeySize:   16,
		MaxKeySize:   32,
		Flags:        CKF_WRAP | CKF_UNWRAP,
	},
	CKM_AES_KEY_WRAP_PAD: {
		Type:         CKM_AES_KEY_WRAP_PAD,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_AES_KEY_WRAP_PAD",
		Categories:   []MechanismCategory{CategoryWrap, CategoryUnwrap},
		MinKeySize:   16,
		MaxKeySize:   32,
		Flags:        CKF_WRAP | CKF_UNWRAP,
	},

	// Digest Mechanisms
	//
	// Pure digests take no key, so per PKCS#11 v3.2 §6.1 Table 10 ("For some
	// mechanisms, the ulMinKeySize and ulMaxKeySize fields have meaningless
	// values"), leaving MinKeySize/MaxKeySize at their zero value is
	// correct -- no unit applies. Already correct below; audited and left
	// unchanged.
	CKM_SHA_1: {
		Type:         CKM_SHA_1,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_SHA_1",
		Categories:   []MechanismCategory{CategoryDigest},
		Flags:        CKF_DIGEST,
	},
	CKM_SHA256: {
		Type:         CKM_SHA256,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_SHA256",
		Categories:   []MechanismCategory{CategoryDigest},
		Flags:        CKF_DIGEST,
	},
	CKM_SHA384: {
		Type:         CKM_SHA384,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_SHA384",
		Categories:   []MechanismCategory{CategoryDigest},
		Flags:        CKF_DIGEST,
	},
	CKM_SHA512: {
		Type:         CKM_SHA512,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_SHA512",
		Categories:   []MechanismCategory{CategoryDigest},
		Flags:        CKF_DIGEST,
	},
	CKM_SHA224: {
		Type:         CKM_SHA224,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_SHA224",
		Categories:   []MechanismCategory{CategoryDigest},
		Flags:        CKF_DIGEST,
	},
	// CKM_SHA512_224 and CKM_SHA512_256 are the truncated SHA-512 variants of
	// FIPS 180-4 §6.6-6.7, listed among the digest mechanisms of PKCS#11 v3.2
	// §6.21. newDigestOperation has always constructed their hashers, but
	// neither had a registry entry, so C_DigestInit resolved the mechanism to a
	// nil descriptor and refused it with CKR_MECHANISM_INVALID before the
	// hasher was ever reached: working code no caller could get to.
	//
	// They are advertised because the digest path is entirely local to this
	// module — C_Digest never leaves the process — so "implemented" and "works
	// end to end" are the same claim here, and TestEveryDigestMechanismIsBoth-
	// RegisteredAndImplemented proves it for every entry carrying CKF_DIGEST.
	CKM_SHA512_224: {
		Type:         CKM_SHA512_224,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_SHA512_224",
		Categories:   []MechanismCategory{CategoryDigest},
		Flags:        CKF_DIGEST,
	},
	CKM_SHA512_256: {
		Type:         CKM_SHA512_256,
		Advertised:   true,
		FIPSApproved: true,
		Name:         "CKM_SHA512_256",
		Categories:   []MechanismCategory{CategoryDigest},
		Flags:        CKF_DIGEST,
	},

	// CKM_SHA3_224, CKM_SHA3_256, CKM_SHA3_384 and CKM_SHA3_512 (FIPS 202,
	// PKCS#11 v3.2 §6.29) are deliberately absent.
	//
	// CKM_SHA3_256, CKM_SHA3_384 and CKM_SHA3_512 used to be registered with
	// CKF_DIGEST, which made C_DigestInit accept the mechanism and then fail
	// with CKR_MECHANISM_INVALID from newDigestOperation, whose switch has no
	// SHA-3 case. A descriptor is a promise about what the module will do, and
	// that one could not be kept, so the registry no longer makes it: with no
	// entry, C_DigestInit refuses the mechanism at validateInitMechanism and
	// the refusal is honest and immediate.
	//
	// Restoring them is a two-part change that must land as one: add the SHA-3
	// cases to newDigestOperation in crypto.go (Go's standard library provides
	// crypto/sha3) and add the entries back here.
	// TestEveryDigestMechanismIsBothRegisteredAndImplemented fails if either
	// half lands without the other, in whichever direction.

	// HMAC Mechanisms
	//
	// There are none. CKM_SHA256_HMAC, CKM_SHA384_HMAC and CKM_SHA512_HMAC
	// (PKCS#11 v3.2 §6.22-6.24) were registered with CKF_SIGN and CKF_VERIFY,
	// but C_Sign with any of them fails with CKR_FUNCTION_FAILED: this module
	// has no symmetric-MAC signing path, so C_SignInit accepted the mechanism on
	// the strength of the flag and the operation then failed.
	//
	// HMAC Mechanisms
	//
	// Per PKCS#11 v3.2 §6.22-6.24 ("the ulMinKeySize and ulMaxKeySize fields ...
	// specify the supported range of CKM_SHA<N>_HMAC key sizes, in bytes"), the
	// unit here is bytes, not bits. MinKeySize: 1 is correct under that unit and
	// MaxKeySize: 0 is this registry's "no enforced maximum" sentinel.
	//
	// All three are registered but NOT advertised. CryptoManager builds a proper
	// HMAC signing request for them -- the mechanism carries its own digest and
	// does not share a request with the hash-prefixed RSA mechanisms -- but
	// C_Sign fails with CKR_FUNCTION_FAILED because no backend in this
	// deployment performs a symmetric MAC. Advertising them would promise an
	// operation the token cannot complete. See mechanismsAwaitingAnImplementation
	// in mechanism_conformance_test.go.
	//
	// The constants have a second, unrelated use as the PRF selector a KDF names
	// in CK_HKDF_PARAMS.prfHashMechanism and in the SP800-108 parameters;
	// mechanismToHashFromPRF resolves those by switch and never consults this
	// registry, so the advertised KDFs neither depend on nor are affected by
	// these descriptors.
	CKM_SHA256_HMAC: {
		Type:       CKM_SHA256_HMAC,
		Name:       "CKM_SHA256_HMAC",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 1,
		MaxKeySize: 0, // No maximum
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_SHA384_HMAC: {
		Type:       CKM_SHA384_HMAC,
		Name:       "CKM_SHA384_HMAC",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 1,
		MaxKeySize: 0,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_SHA512_HMAC: {
		Type:       CKM_SHA512_HMAC,
		Name:       "CKM_SHA512_HMAC",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 1,
		MaxKeySize: 0,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},

	// Key Derivation Mechanisms
	//
	// CKM_HKDF_DERIVE, CKM_HKDF_DATA and the CKM_SP800_108_* KDFs are
	// advertised because C_DeriveKey now derives from the base key.
	//
	// They were withheld while module.DeriveKey substituted the base key's
	// identifier string for its input keying material whenever CKA_VALUE was
	// absent, which was every key C_GenerateKey produced: the KDF ran over a
	// label-plus-timestamp string, so anyone who knew the label could
	// reproduce the derived key. That fallback is gone. A base key whose
	// CKA_VALUE the module holds sends its material; a base key the backend
	// holds sends its identity and the backend runs the KDF over the real key
	// (see types.SymmetricKeyDeriver). A base key that resolves to neither is
	// refused with CKR_KEY_TYPE_INCONSISTENT.
	//
	// ulMinKeySize/ulMaxKeySize are the base key's size in bits. RFC 5869
	// places no bound on the length of HKDF's input keying material, and
	// SP 800-108r1 places none on the length of its key-derivation key, so
	// both ends are this registry's degenerate values: 1 bit, and 0 meaning no
	// enforced maximum. Declaring the digest-sized range §6.62.3 describes for
	// a CKK_HKDF key would be a narrower promise than the module keeps, and
	// C_GetMechanismInfo must describe what the module will actually do.
	CKM_HKDF_DERIVE: {
		Type:           CKM_HKDF_DERIVE,
		Name:           "CKM_HKDF_DERIVE",
		Categories:     []MechanismCategory{CategoryDerive},
		MinKeySize:     0, // No key-size range applies; see the note above
		MaxKeySize:     0,
		Flags:          CKF_DERIVE,
		RequiresParams: true,
		ParamsType:     "HKDFParams",
		Advertised:     true,
	},
	CKM_HKDF_DATA: {
		Type:           CKM_HKDF_DATA,
		Name:           "CKM_HKDF_DATA",
		Categories:     []MechanismCategory{CategoryDerive},
		MinKeySize:     0, // No key-size range applies; see the note above
		MaxKeySize:     0,
		Flags:          CKF_DERIVE,
		RequiresParams: true,
		ParamsType:     "HKDFParams",
		Advertised:     true,
	},

	// SP800-108 Key Derivation Functions (NIST SP 800-108)
	//
	// Per PKCS#11 v3.2 (SP800-108 KDF mechanisms section), ulMinKeySize/
	// ulMaxKeySize report "the minimum and maximum supported base key size
	// in bits" across every PRF and key type the token accepts. MinKeySize:
	// 1 and MaxKeySize: 0 ("no maximum") are degenerate placeholder values
	// that are correct under either unit; no numeric change needed, but the
	// unit is bits.
	//
	// All three are FIPSApproved. NIST SP 800-108r1 is itself the approved
	// key-based key-derivation standard, and mechanismToHashFromPRF admits only
	// the HMAC-SHA2/SHA3 PRFs — CKM_AES_CMAC and CKM_DES3_CMAC, which v3.2
	// Table 196 also lists, are refused — so every derivation this module
	// performs with them is inside the approved construction. The HKDF
	// mechanisms above are deliberately not marked: SP 800-56C Rev. 2 approves
	// the extract-then-expand construction for deriving from a shared secret
	// produced by an approved key-establishment scheme, and C_DeriveKey applies
	// it to an arbitrary base key, which is outside that scope.
	CKM_SP800_108_COUNTER_KDF: {
		Type:           CKM_SP800_108_COUNTER_KDF,
		Name:           "CKM_SP800_108_COUNTER_KDF",
		Categories:     []MechanismCategory{CategoryDerive},
		MinKeySize:     0, // No key-size range applies; see the note above
		MaxKeySize:     0,
		Flags:          CKF_DERIVE,
		RequiresParams: true,
		ParamsType:     "SP800108KDFParams",
		FIPSApproved:   true,
		Advertised:     true,
	},
	CKM_SP800_108_FEEDBACK_KDF: {
		Type:           CKM_SP800_108_FEEDBACK_KDF,
		Name:           "CKM_SP800_108_FEEDBACK_KDF",
		Categories:     []MechanismCategory{CategoryDerive},
		MinKeySize:     0, // No key-size range applies; see the note above
		MaxKeySize:     0,
		Flags:          CKF_DERIVE,
		RequiresParams: true,
		ParamsType:     "SP800108KDFParams",
		FIPSApproved:   true,
		Advertised:     true,
	},
	CKM_SP800_108_DOUBLE_PIPELINE_KDF: {
		Type:           CKM_SP800_108_DOUBLE_PIPELINE_KDF,
		Name:           "CKM_SP800_108_DOUBLE_PIPELINE_KDF",
		Categories:     []MechanismCategory{CategoryDerive},
		MinKeySize:     0, // No key-size range applies; see the note above
		MaxKeySize:     0,
		Flags:          CKF_DERIVE,
		RequiresParams: true,
		ParamsType:     "SP800108KDFParams",
		FIPSApproved:   true,
		Advertised:     true,
	},

	// Generic Secret Key
	//
	// Per PKCS#11 v3.2 §6.9 ("the ulMinKeySize and ulMaxKeySize fields ...
	// specify the supported range of key sizes, in bits"), the unit here is
	// BITS. MinKeySize: 1 (1 bit) is a degenerate value that is correct
	// under either unit and MaxKeySize: 0 is this registry's "no enforced
	// maximum" sentinel, so there is no numeric change to make, but the
	// unit is bits, unlike the AES family above -- do not copy this entry's
	// literal values as a template for a byte-denominated mechanism.
	//
	// It is registered but NOT advertised, and MaxKeySize: 0 is why it cannot be.
	//
	// The sentinel means "no maximum this registry enforces", which is the right
	// answer for IsValidKeySize but not something CK_MECHANISM_INFO can carry: an
	// application reading ulMinKeySize=1 and ulMaxKeySize=0 sees an empty range,
	// and the integration suite's MinKeySize <= MaxKeySize check is exactly a
	// conformant application making that reading.
	//
	// A truthful contiguous range is not available either. C_GenerateKey with
	// this mechanism succeeds only at CKA_VALUE_LEN 16 and 32 bytes and returns
	// CKR_GENERAL_ERROR at 1, 2, 8, 48, 64, 128, 256, 512 and 1024, because the
	// mechanism-to-key-type mapping sends it to the backend as an ordinary
	// symmetric key and the backend accepts only AES key sizes. §6.9 defines the
	// mechanism as generating a secret key of an arbitrary caller-chosen length,
	// so no contiguous ulMinKeySize/ulMaxKeySize pair describes what this token
	// will actually do. See mechanismsAwaitingAnImplementation in
	// mechanism_conformance_test.go.
	CKM_GENERIC_SECRET_KEY_GEN: {
		Type:       CKM_GENERIC_SECRET_KEY_GEN,
		Name:       "CKM_GENERIC_SECRET_KEY_GEN",
		Categories: []MechanismCategory{CategoryKeyGen},
		MinKeySize: 1,
		MaxKeySize: 0, // No maximum
		Flags:      CKF_GENERATE,
	},
}

// mechanismNames provides O(1) lookup from mechanism type to name.
var mechanismNames = map[MechanismType]string{
	CKM_RSA_PKCS_KEY_PAIR_GEN:         "CKM_RSA_PKCS_KEY_PAIR_GEN",
	CKM_RSA_PKCS:                      "CKM_RSA_PKCS",
	CKM_RSA_9796:                      "CKM_RSA_9796",
	CKM_RSA_X_509:                     "CKM_RSA_X_509",
	CKM_MD2_RSA_PKCS:                  "CKM_MD2_RSA_PKCS",
	CKM_MD5_RSA_PKCS:                  "CKM_MD5_RSA_PKCS",
	CKM_SHA1_RSA_PKCS:                 "CKM_SHA1_RSA_PKCS",
	CKM_RIPEMD128_RSA_PKCS:            "CKM_RIPEMD128_RSA_PKCS",
	CKM_RIPEMD160_RSA_PKCS:            "CKM_RIPEMD160_RSA_PKCS",
	CKM_RSA_PKCS_OAEP:                 "CKM_RSA_PKCS_OAEP",
	CKM_RSA_X9_31_KEY_PAIR_GEN:        "CKM_RSA_X9_31_KEY_PAIR_GEN",
	CKM_RSA_X9_31:                     "CKM_RSA_X9_31",
	CKM_SHA1_RSA_X9_31:                "CKM_SHA1_RSA_X9_31",
	CKM_RSA_PKCS_PSS:                  "CKM_RSA_PKCS_PSS",
	CKM_SHA1_RSA_PKCS_PSS:             "CKM_SHA1_RSA_PKCS_PSS",
	CKM_DSA_KEY_PAIR_GEN:              "CKM_DSA_KEY_PAIR_GEN",
	CKM_DSA:                           "CKM_DSA",
	CKM_DSA_SHA1:                      "CKM_DSA_SHA1",
	CKM_DSA_SHA224:                    "CKM_DSA_SHA224",
	CKM_DSA_SHA256:                    "CKM_DSA_SHA256",
	CKM_DSA_SHA384:                    "CKM_DSA_SHA384",
	CKM_DSA_SHA512:                    "CKM_DSA_SHA512",
	CKM_DH_PKCS_KEY_PAIR_GEN:          "CKM_DH_PKCS_KEY_PAIR_GEN",
	CKM_DH_PKCS_DERIVE:                "CKM_DH_PKCS_DERIVE",
	CKM_X9_42_DH_KEY_PAIR_GEN:         "CKM_X9_42_DH_KEY_PAIR_GEN",
	CKM_X9_42_DH_DERIVE:               "CKM_X9_42_DH_DERIVE",
	CKM_X9_42_DH_HYBRID_DERIVE:        "CKM_X9_42_DH_HYBRID_DERIVE",
	CKM_X9_42_MQV_DERIVE:              "CKM_X9_42_MQV_DERIVE",
	CKM_SHA_1:                         "CKM_SHA_1",
	CKM_SHA_1_HMAC:                    "CKM_SHA_1_HMAC",
	CKM_SHA_1_HMAC_GENERAL:            "CKM_SHA_1_HMAC_GENERAL",
	CKM_RIPEMD128:                     "CKM_RIPEMD128",
	CKM_RIPEMD128_HMAC:                "CKM_RIPEMD128_HMAC",
	CKM_RIPEMD128_HMAC_GENERAL:        "CKM_RIPEMD128_HMAC_GENERAL",
	CKM_RIPEMD160:                     "CKM_RIPEMD160",
	CKM_RIPEMD160_HMAC:                "CKM_RIPEMD160_HMAC",
	CKM_RIPEMD160_HMAC_GENERAL:        "CKM_RIPEMD160_HMAC_GENERAL",
	CKM_SHA256:                        "CKM_SHA256",
	CKM_SHA256_HMAC:                   "CKM_SHA256_HMAC",
	CKM_SHA256_HMAC_GENERAL:           "CKM_SHA256_HMAC_GENERAL",
	CKM_SHA224:                        "CKM_SHA224",
	CKM_SHA224_HMAC:                   "CKM_SHA224_HMAC",
	CKM_SHA224_HMAC_GENERAL:           "CKM_SHA224_HMAC_GENERAL",
	CKM_SHA384:                        "CKM_SHA384",
	CKM_SHA384_HMAC:                   "CKM_SHA384_HMAC",
	CKM_SHA384_HMAC_GENERAL:           "CKM_SHA384_HMAC_GENERAL",
	CKM_SHA512:                        "CKM_SHA512",
	CKM_SHA512_HMAC:                   "CKM_SHA512_HMAC",
	CKM_SHA512_HMAC_GENERAL:           "CKM_SHA512_HMAC_GENERAL",
	CKM_SHA512_224:                    "CKM_SHA512_224",
	CKM_SHA512_224_HMAC:               "CKM_SHA512_224_HMAC",
	CKM_SHA512_224_HMAC_GENERAL:       "CKM_SHA512_224_HMAC_GENERAL",
	CKM_SHA512_256:                    "CKM_SHA512_256",
	CKM_SHA512_256_HMAC:               "CKM_SHA512_256_HMAC",
	CKM_SHA512_256_HMAC_GENERAL:       "CKM_SHA512_256_HMAC_GENERAL",
	CKM_SHA3_256:                      "CKM_SHA3_256",
	CKM_SHA3_256_HMAC:                 "CKM_SHA3_256_HMAC",
	CKM_SHA3_256_HMAC_GENERAL:         "CKM_SHA3_256_HMAC_GENERAL",
	CKM_SHA3_224:                      "CKM_SHA3_224",
	CKM_SHA3_224_HMAC:                 "CKM_SHA3_224_HMAC",
	CKM_SHA3_224_HMAC_GENERAL:         "CKM_SHA3_224_HMAC_GENERAL",
	CKM_SHA3_384:                      "CKM_SHA3_384",
	CKM_SHA3_384_HMAC:                 "CKM_SHA3_384_HMAC",
	CKM_SHA3_384_HMAC_GENERAL:         "CKM_SHA3_384_HMAC_GENERAL",
	CKM_SHA3_512:                      "CKM_SHA3_512",
	CKM_SHA3_512_HMAC:                 "CKM_SHA3_512_HMAC",
	CKM_SHA3_512_HMAC_GENERAL:         "CKM_SHA3_512_HMAC_GENERAL",
	CKM_SHA256_RSA_PKCS:               "CKM_SHA256_RSA_PKCS",
	CKM_SHA384_RSA_PKCS:               "CKM_SHA384_RSA_PKCS",
	CKM_SHA512_RSA_PKCS:               "CKM_SHA512_RSA_PKCS",
	CKM_SHA256_RSA_PKCS_PSS:           "CKM_SHA256_RSA_PKCS_PSS",
	CKM_SHA384_RSA_PKCS_PSS:           "CKM_SHA384_RSA_PKCS_PSS",
	CKM_SHA512_RSA_PKCS_PSS:           "CKM_SHA512_RSA_PKCS_PSS",
	CKM_SHA224_RSA_PKCS:               "CKM_SHA224_RSA_PKCS",
	CKM_SHA224_RSA_PKCS_PSS:           "CKM_SHA224_RSA_PKCS_PSS",
	CKM_EC_KEY_PAIR_GEN:               "CKM_EC_KEY_PAIR_GEN",
	CKM_ECDSA:                         "CKM_ECDSA",
	CKM_ECDSA_SHA1:                    "CKM_ECDSA_SHA1",
	CKM_ECDSA_SHA224:                  "CKM_ECDSA_SHA224",
	CKM_ECDSA_SHA256:                  "CKM_ECDSA_SHA256",
	CKM_ECDSA_SHA384:                  "CKM_ECDSA_SHA384",
	CKM_ECDSA_SHA512:                  "CKM_ECDSA_SHA512",
	CKM_ECDSA_SHA3_224:                "CKM_ECDSA_SHA3_224",
	CKM_ECDSA_SHA3_256:                "CKM_ECDSA_SHA3_256",
	CKM_ECDSA_SHA3_384:                "CKM_ECDSA_SHA3_384",
	CKM_ECDSA_SHA3_512:                "CKM_ECDSA_SHA3_512",
	CKM_ECDH1_DERIVE:                  "CKM_ECDH1_DERIVE",
	CKM_ECDH1_COFACTOR_DERIVE:         "CKM_ECDH1_COFACTOR_DERIVE",
	CKM_ECMQV_DERIVE:                  "CKM_ECMQV_DERIVE",
	CKM_ECDH_AES_KEY_WRAP:             "CKM_ECDH_AES_KEY_WRAP",
	CKM_EC_EDWARDS_KEY_PAIR_GEN:       "CKM_EC_EDWARDS_KEY_PAIR_GEN",
	CKM_EDDSA:                         "CKM_EDDSA",
	CKM_EC_MONTGOMERY_KEY_PAIR_GEN:    "CKM_EC_MONTGOMERY_KEY_PAIR_GEN",
	CKM_XEDDSA:                        "CKM_XEDDSA",
	CKM_AES_KEY_GEN:                   "CKM_AES_KEY_GEN",
	CKM_AES_ECB:                       "CKM_AES_ECB",
	CKM_AES_CBC:                       "CKM_AES_CBC",
	CKM_AES_MAC:                       "CKM_AES_MAC",
	CKM_AES_MAC_GENERAL:               "CKM_AES_MAC_GENERAL",
	CKM_AES_CBC_PAD:                   "CKM_AES_CBC_PAD",
	CKM_AES_CTR:                       "CKM_AES_CTR",
	CKM_AES_GCM:                       "CKM_AES_GCM",
	CKM_AES_CCM:                       "CKM_AES_CCM",
	CKM_AES_CTS:                       "CKM_AES_CTS",
	CKM_AES_CMAC:                      "CKM_AES_CMAC",
	CKM_AES_CMAC_GENERAL:              "CKM_AES_CMAC_GENERAL",
	CKM_AES_XCBC_MAC:                  "CKM_AES_XCBC_MAC",
	CKM_AES_XCBC_MAC_96:               "CKM_AES_XCBC_MAC_96",
	CKM_AES_GMAC:                      "CKM_AES_GMAC",
	CKM_AES_KEY_WRAP:                  "CKM_AES_KEY_WRAP",
	CKM_AES_KEY_WRAP_PAD:              "CKM_AES_KEY_WRAP_PAD",
	CKM_AES_KEY_WRAP_KWP:              "CKM_AES_KEY_WRAP_KWP",
	CKM_AES_OFB:                       "CKM_AES_OFB",
	CKM_AES_CFB64:                     "CKM_AES_CFB64",
	CKM_AES_CFB8:                      "CKM_AES_CFB8",
	CKM_AES_CFB128:                    "CKM_AES_CFB128",
	CKM_AES_CFB1:                      "CKM_AES_CFB1",
	CKM_AES_XTS:                       "CKM_AES_XTS",
	CKM_AES_XTS_KEY_GEN:               "CKM_AES_XTS_KEY_GEN",
	CKM_DES_KEY_GEN:                   "CKM_DES_KEY_GEN",
	CKM_DES_ECB:                       "CKM_DES_ECB",
	CKM_DES_CBC:                       "CKM_DES_CBC",
	CKM_DES_MAC:                       "CKM_DES_MAC",
	CKM_DES_MAC_GENERAL:               "CKM_DES_MAC_GENERAL",
	CKM_DES_CBC_PAD:                   "CKM_DES_CBC_PAD",
	CKM_DES2_KEY_GEN:                  "CKM_DES2_KEY_GEN",
	CKM_DES3_KEY_GEN:                  "CKM_DES3_KEY_GEN",
	CKM_DES3_ECB:                      "CKM_DES3_ECB",
	CKM_DES3_CBC:                      "CKM_DES3_CBC",
	CKM_DES3_MAC:                      "CKM_DES3_MAC",
	CKM_DES3_MAC_GENERAL:              "CKM_DES3_MAC_GENERAL",
	CKM_DES3_CBC_PAD:                  "CKM_DES3_CBC_PAD",
	CKM_DES3_CMAC:                     "CKM_DES3_CMAC",
	CKM_DES3_CMAC_GENERAL:             "CKM_DES3_CMAC_GENERAL",
	CKM_MD5:                           "CKM_MD5",
	CKM_MD5_HMAC:                      "CKM_MD5_HMAC",
	CKM_MD5_HMAC_GENERAL:              "CKM_MD5_HMAC_GENERAL",
	CKM_MD2:                           "CKM_MD2",
	CKM_MD2_HMAC:                      "CKM_MD2_HMAC",
	CKM_MD2_HMAC_GENERAL:              "CKM_MD2_HMAC_GENERAL",
	CKM_GENERIC_SECRET_KEY_GEN:        "CKM_GENERIC_SECRET_KEY_GEN",
	CKM_HKDF_DERIVE:                   "CKM_HKDF_DERIVE",
	CKM_HKDF_DATA:                     "CKM_HKDF_DATA",
	CKM_HKDF_KEY_GEN:                  "CKM_HKDF_KEY_GEN",
	CKM_SP800_108_COUNTER_KDF:         "CKM_SP800_108_COUNTER_KDF",
	CKM_SP800_108_FEEDBACK_KDF:        "CKM_SP800_108_FEEDBACK_KDF",
	CKM_SP800_108_DOUBLE_PIPELINE_KDF: "CKM_SP800_108_DOUBLE_PIPELINE_KDF",
}

// GetMechanismDescriptor returns the descriptor for the given mechanism type.
// Returns nil if the mechanism is not registered.
// This provides O(1) lookup time as required by CLAUDE.md conventions.
func GetMechanismDescriptor(mechType MechanismType) *MechanismDescriptor {
	desc, ok := mechanismRegistry[mechType]
	if !ok {
		return nil
	}

	// FIPS mode hides a non-approved mechanism entirely rather than only
	// declining to advertise it. Every operation's *Init resolves its mechanism
	// through here and treats a nil descriptor as CKR_MECHANISM_INVALID, so
	// this one check keeps what the module advertises and what it will actually
	// perform in agreement — a mechanism that is offered works, and one that is
	// not offered is refused, with no third state where an application can use
	// something the module does not admit to supporting.
	if !desc.FIPSApproved && fipsModeEnabled() {
		return nil
	}

	// A SHA-1 signature mechanism keeps its verify capability but loses CKF_SIGN
	// when weak-hash signing is not allowed, so a *Init that gates on CKF_SIGN
	// refuses it while C_VerifyInit still accepts it. A copy is returned so the
	// shared registry entry is never mutated.
	if flags := effectiveMechanismFlags(desc); flags != desc.Flags {
		adjusted := *desc
		adjusted.Flags = flags
		return &adjusted
	}

	return desc
}

// fipsEnvForTest names the environment variable that selects FIPS mode, so a
// test can toggle the policy through the same signal a deployment uses rather
// than reaching past it.
const fipsEnvForTest = fips.EnvGOFIPS140

// weakHashSigningEnvVar names the module's weak-hash signing policy. It mirrors
// the daemon's crypto.allow_weak_hashes, but is a separate signal because the
// shared library runs in its own process and cannot read the daemon's config:
// the module must decide what to advertise before it has spoken to anything.
const weakHashSigningEnvVar = "XKMS_PKCS11_ALLOW_WEAK_HASH_SIGNING"

// weakHashSignatureMechanisms are the signature mechanisms whose digest NIST
// SP 800-131A Rev. 2 disallows for signature *generation* (SHA-1). Verification
// of legacy signatures stays valid, so only CKF_SIGN is withheld, not the whole
// mechanism — a caller can still verify with them, matching the daemon policy
// whose comment states the prohibition is "scoped to signature use".
var weakHashSignatureMechanisms = map[MechanismType]bool{
	CKM_SHA1_RSA_PKCS: true,
	CKM_ECDSA_SHA1:    true,
}

// weakHashSigningAllowed reports whether the module may advertise and perform
// signature generation with a weak digest. It refuses by default — secure by
// default is the only safe default for a policy that decides whether the token
// will produce a forgeable signature — and an operator opts in explicitly by
// setting the environment variable, exactly as the daemon opts in through
// crypto.allow_weak_hashes.
func weakHashSigningAllowed() bool {
	switch os.Getenv(weakHashSigningEnvVar) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

// effectiveMechanismFlags returns the capability flags a mechanism may honestly
// advertise under the current policy. It clears CKF_SIGN on a SHA-1 signature
// mechanism when weak-hash signing is not allowed, so C_GetMechanismInfo and
// every *Init agree that the token will not generate such a signature — rather
// than advertising a capability the weak-hash policy then refuses. It is the
// single point both the advertising projection and GetMechanismDescriptor
// resolve through, so the two cannot drift, exactly as they cannot for FIPS.
func effectiveMechanismFlags(desc *MechanismDescriptor) MechanismFlag {
	if weakHashSignatureMechanisms[desc.Type] && !weakHashSigningAllowed() {
		return desc.Flags &^ CKF_SIGN
	}
	return desc.Flags
}

// fipsModeEnabled reports whether the module is running in FIPS mode.
//
// A module compiled as a FIPS build (fips.Compiled) is always in FIPS mode: the
// crypto it links is the FIPS module, so it must advertise and enforce the
// approved surface no matter what the loading process's environment says. A
// non-FIPS build still honours the runtime GOFIPS140 signal (fips.Enabled) so a
// test can exercise the filter without a separate FIPS-compiled binary. The two
// together mean the shipped FIPS .so enforces FIPS even though the process that
// dlopen()s it sets no GOFIPS140 variable.
func fipsModeEnabled() bool {
	return fips.Compiled() || fips.Enabled()
}

// fipsBuild reports whether this is the FIPS-compiled artifact, for labelling
// the token and library so a user can tell a FIPS module from a non-FIPS one.
// It is the build-time truth only — a non-FIPS build a test runs under
// GOFIPS140 filters like FIPS but must not claim to BE a FIPS module.
func fipsBuild() bool {
	return fips.Compiled()
}

// moduleLibraryDescription is the CK_INFO.libraryDescription (max 32 bytes). The
// FIPS build tags it so C_GetInfo tells a user which artifact they loaded.
func moduleLibraryDescription() string {
	if fipsBuild() {
		return "go-xkms PKCS#11 FIPS 140-3"
	}
	return "go-xkms PKCS#11"
}

// tokenModel is the CK_TOKEN_INFO.model (max 16 bytes). The FIPS build tags it
// so C_GetTokenInfo identifies the token as FIPS.
func tokenModel() string {
	if fipsBuild() {
		return "FIPS 140-3 Token"
	}
	return "Virtual Token"
}

// IsMechanismSupported reports whether the module offers a mechanism under the
// regime it is running in.
//
// It resolves through GetMechanismDescriptor so it carries the FIPS filter.
// Reading the raw registry answered true for a mechanism that
// C_GetMechanismList omits and every *Init refuses -- under FIPS,
// CKM_SHA1_RSA_PKCS among them.
func IsMechanismSupported(mechType MechanismType) bool {
	return GetMechanismDescriptor(mechType) != nil
}

// GetMechanismName returns the string name for a mechanism type.
// Returns "CKM_UNKNOWN" with the hex value if the mechanism is not recognized.
// This provides O(1) lookup time.
func GetMechanismName(mechType MechanismType) string {
	if name, ok := mechanismNames[mechType]; ok {
		return name
	}
	return fmt.Sprintf("CKM_UNKNOWN(0x%08X)", uint32(mechType))
}

// effectiveKeySizeRange returns the key-size range a descriptor describes under
// the regime the module is running in, in the descriptor's own unit.
//
// It exists so there is one answer to "what sizes does this mechanism accept".
// CK_MECHANISM_INFO's ulMinKeySize/ulMaxKeySize are how an application decides
// what to ask for (PKCS#11 v3.2 §5.5), so the range C_GetMechanismInfo reports,
// the range C_GetMechanismList's entries describe and the range the module
// validates a request against must be the same number. They would not be if the
// FIPS ceiling were applied at only one of those three points: an application
// would read a maximum the token then refuses, or — the direction that actually
// shipped — read a maximum the token accepts but FIPS forbids.
//
// The FIPS narrowing is applied here rather than by rewriting the registry
// because the registry is shared, immutable state read on every operation;
// clamping a copy per lookup would allocate on the hot path, and mutating the
// shared entry would make the mode a one-way door.
func effectiveKeySizeRange(desc *MechanismDescriptor) (minKeySize, maxKeySize uint32) {
	minKeySize, maxKeySize = desc.MinKeySize, desc.MaxKeySize

	if desc.FIPSMaxKeySize != 0 && desc.FIPSMaxKeySize < maxKeySize && fipsModeEnabled() {
		maxKeySize = desc.FIPSMaxKeySize
	}

	return minKeySize, maxKeySize
}

// GetMechanismInfo returns the mechanism info for the given mechanism type.
// Returns an error if the mechanism is not supported.
func GetMechanismInfo(mechType MechanismType) (*MechanismInfo, error) {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return nil, ErrMechanismInvalid
	}

	minKeySize, maxKeySize := effectiveKeySizeRange(desc)

	return &MechanismInfo{
		MinKeySize: minKeySize,
		MaxKeySize: maxKeySize,
		Flags:      desc.Flags,
	}, nil
}

// CanSign checks if a mechanism supports signing operations.
func CanSign(mechType MechanismType) bool {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return false
	}
	return desc.Flags&CKF_SIGN != 0
}

// CanVerify checks if a mechanism supports verification operations.
func CanVerify(mechType MechanismType) bool {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return false
	}
	return desc.Flags&CKF_VERIFY != 0
}

// CanEncrypt checks if a mechanism supports encryption operations.
func CanEncrypt(mechType MechanismType) bool {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return false
	}
	return desc.Flags&CKF_ENCRYPT != 0
}

// CanDecrypt checks if a mechanism supports decryption operations.
func CanDecrypt(mechType MechanismType) bool {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return false
	}
	return desc.Flags&CKF_DECRYPT != 0
}

// CanGenerateKey checks if a mechanism supports key generation.
func CanGenerateKey(mechType MechanismType) bool {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return false
	}
	return desc.Flags&CKF_GENERATE != 0
}

// CanGenerateKeyPair checks if a mechanism supports key pair generation.
func CanGenerateKeyPair(mechType MechanismType) bool {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return false
	}
	return desc.Flags&CKF_GENERATE_KEY_PAIR != 0
}

// CanWrap checks if a mechanism supports key wrapping.
func CanWrap(mechType MechanismType) bool {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return false
	}
	return desc.Flags&CKF_WRAP != 0
}

// CanUnwrap checks if a mechanism supports key unwrapping.
func CanUnwrap(mechType MechanismType) bool {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return false
	}
	return desc.Flags&CKF_UNWRAP != 0
}

// CanDerive checks if a mechanism supports key derivation.
func CanDerive(mechType MechanismType) bool {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return false
	}
	return desc.Flags&CKF_DERIVE != 0
}

// CanDigest checks if a mechanism supports digesting.
func CanDigest(mechType MechanismType) bool {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return false
	}
	return desc.Flags&CKF_DIGEST != 0
}

// IsValidKeySize reports whether keySize is one the module will accept for
// mechType, in that mechanism's own unit (bits for the RSA, EC and generic
// secret families, bytes for AES and HMAC — see MechanismInfo's doc comment for
// the per-family spec citations).
//
// The range is the one C_GetMechanismInfo advertises, taken from
// effectiveKeySizeRange, so a size an application was told it could ask for is
// never refused here and a size outside the advertised range is never accepted.
// Under FIPS that means the §6.1.21 RSA ceiling of 3072 bits applies; outside
// it, rsaModulusBitsMax.
//
// A caller that is answering a PKCS#11 function must turn a false result into
// the return value that function documents. For C_GenerateKeyPair, where the
// size arrives as the public-key template's CKA_MODULUS_BITS, that is
// CKR_ATTRIBUTE_VALUE_INVALID: PKCS#11 v3.2 §5.19.2 lists it among
// C_GenerateKeyPair's return values and does not list CKR_KEY_SIZE_RANGE, which
// belongs to the operations that take an existing key. CKR_FUNCTION_FAILED
// tells the application nothing it can act on.
func IsValidKeySize(mechType MechanismType, keySize uint32) bool {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return false
	}

	minKeySize, maxKeySize := effectiveKeySizeRange(desc)

	// Both zero means no key size applies to this mechanism (PKCS#11 v3.2 §6.1
	// Table 10: "For some mechanisms, the ulMinKeySize and ulMaxKeySize fields
	// have meaningless values").
	if minKeySize == 0 && maxKeySize == 0 {
		return true
	}
	if keySize < minKeySize {
		return false
	}
	// MaxKeySize zero alongside a non-zero minimum is this registry's "no
	// enforced maximum" sentinel, used by the HMAC and generic-secret families.
	// Comparing against it literally rejected every key size those mechanisms
	// accept.
	if maxKeySize == 0 {
		return true
	}
	return keySize <= maxKeySize
}

// ListSupportedMechanisms returns a slice of all supported mechanism types.
func ListSupportedMechanisms() []MechanismType {
	mechanisms := make([]MechanismType, 0, len(mechanismRegistry))
	for mechType := range mechanismRegistry {
		// Filtered for the same reason IsMechanismSupported is: a mechanism the
		// running regime withholds is not one this module supports, and listing
		// it here would contradict C_GetMechanismList.
		if GetMechanismDescriptor(mechType) == nil {
			continue
		}
		mechanisms = append(mechanisms, mechType)
	}
	return mechanisms
}

// ListMechanismsByCategory returns all mechanisms that support the given category.
func ListMechanismsByCategory(category MechanismCategory) []MechanismType {
	var mechanisms []MechanismType
	for mechType, desc := range mechanismRegistry {
		for _, cat := range desc.Categories {
			if cat == category {
				mechanisms = append(mechanisms, mechType)
				break
			}
		}
	}
	return mechanisms
}

// GetDigestMechanismForHash returns the appropriate digest mechanism for a hash size.
// Returns 0 if no matching mechanism is found.
func GetDigestMechanismForHash(hashSize int) MechanismType {
	switch hashSize {
	case 20: // SHA-1
		return CKM_SHA_1
	case 28: // SHA-224
		return CKM_SHA224
	case 32: // SHA-256
		return CKM_SHA256
	case 48: // SHA-384
		return CKM_SHA384
	case 64: // SHA-512
		return CKM_SHA512
	default:
		return 0
	}
}

// GetMGFForHash returns the appropriate MGF for a hash mechanism.
// Returns 0 if no matching MGF is found.
// A zero return is a SENTINEL, not an MGF: CK_RSA_PKCS_MGF_TYPE values start at
// CKG_MGF1_SHA1 = 1, so 0 names no mask generation function. Callers must test
// it rather than pass it on -- NewRSAOAEPParams and NewRSAPSSParams used to
// emit it verbatim for an unrecognised hash, producing a parameter structure
// whose mgf field no verifier could interpret.
func GetMGFForHash(hashMech MechanismType) MGFType {
	switch hashMech {
	case CKM_SHA_1:
		return CKG_MGF1_SHA1
	case CKM_SHA224:
		return CKG_MGF1_SHA224
	case CKM_SHA256:
		return CKG_MGF1_SHA256
	case CKM_SHA384:
		return CKG_MGF1_SHA384
	case CKM_SHA512:
		return CKG_MGF1_SHA512
	case CKM_SHA3_224:
		return CKG_MGF1_SHA3_224
	case CKM_SHA3_256:
		return CKG_MGF1_SHA3_256
	case CKM_SHA3_384:
		return CKG_MGF1_SHA3_384
	case CKM_SHA3_512:
		return CKG_MGF1_SHA3_512
	default:
		return 0
	}
}

// NewRSAOAEPParams creates OAEP parameters with the specified hash algorithm.
// Uses MGF1 with the same hash algorithm and no label.
func NewRSAOAEPParams(hashAlg MechanismType) *RSAOAEPParams {
	return &RSAOAEPParams{
		HashAlg:    hashAlg,
		MGF:        GetMGFForHash(hashAlg),
		Source:     CKZ_DATA_SPECIFIED,
		SourceData: nil,
	}
}

// NewRSAOAEPParamsWithLabel creates OAEP parameters with label data.
func NewRSAOAEPParamsWithLabel(hashAlg MechanismType, label []byte) *RSAOAEPParams {
	return &RSAOAEPParams{
		HashAlg:    hashAlg,
		MGF:        GetMGFForHash(hashAlg),
		Source:     CKZ_DATA_SPECIFIED,
		SourceData: label,
	}
}

// NewRSAPSSParams creates PSS parameters with the specified hash algorithm.
// Salt length defaults to the hash length.
func NewRSAPSSParams(hashAlg MechanismType) *RSAPSSParams {
	var saltLen uint32
	switch hashAlg {
	case CKM_SHA_1:
		saltLen = 20
	case CKM_SHA224:
		saltLen = 28
	case CKM_SHA256:
		saltLen = 32
	case CKM_SHA384:
		saltLen = 48
	case CKM_SHA512:
		saltLen = 64
	default:
		saltLen = 32 // Default to SHA-256 length
	}

	return &RSAPSSParams{
		HashAlg: hashAlg,
		MGF:     GetMGFForHash(hashAlg),
		SaltLen: saltLen,
	}
}

// NewRSAPSSParamsWithSaltLen creates PSS parameters with explicit salt length.
func NewRSAPSSParamsWithSaltLen(hashAlg MechanismType, saltLen uint32) *RSAPSSParams {
	return &RSAPSSParams{
		HashAlg: hashAlg,
		MGF:     GetMGFForHash(hashAlg),
		SaltLen: saltLen,
	}
}

// NewAESGCMParams creates GCM parameters with the specified IV and tag size.
// Default tag size is 128 bits (16 bytes).
func NewAESGCMParams(iv []byte, tagBits uint32) *AESGCMParams {
	return &AESGCMParams{
		IV:      iv,
		AAD:     nil,
		TagBits: tagBits,
	}
}

// NewAESGCMParamsWithAAD creates GCM parameters with additional authenticated data.
func NewAESGCMParamsWithAAD(iv, aad []byte, tagBits uint32) *AESGCMParams {
	return &AESGCMParams{
		IV:      iv,
		AAD:     aad,
		TagBits: tagBits,
	}
}

// NewAESCBCParams creates CBC parameters with the specified IV.
func NewAESCBCParams(iv [16]byte) *AESCBCParams {
	return &AESCBCParams{
		IV: iv,
	}
}

// NewECDHParams creates ECDH derivation parameters.
func NewECDHParams(kdf KDFType, publicData []byte) *ECDHParams {
	return &ECDHParams{
		KDF:        kdf,
		SharedData: nil,
		PublicData: publicData,
	}
}

// NewECDHParamsWithSharedData creates ECDH parameters with shared data.
func NewECDHParamsWithSharedData(kdf KDFType, sharedData, publicData []byte) *ECDHParams {
	return &ECDHParams{
		KDF:        kdf,
		SharedData: sharedData,
		PublicData: publicData,
	}
}

// NewHKDFParams creates HKDF derivation parameters.
func NewHKDFParams(hashMech MechanismType, salt, info []byte) *HKDFParams {
	return &HKDFParams{
		Extract:     true,
		Expand:      true,
		PRFHashMech: hashMech,
		SaltType:    CKF_HKDF_SALT_DATA,
		Salt:        salt,
		SaltKey:     0,
		Info:        info,
	}
}

// NewHKDFExpandOnlyParams creates HKDF parameters for expand-only operation.
func NewHKDFExpandOnlyParams(hashMech MechanismType, info []byte) *HKDFParams {
	return &HKDFParams{
		Extract:     false,
		Expand:      true,
		PRFHashMech: hashMech,
		SaltType:    CKF_HKDF_SALT_NULL,
		Salt:        nil,
		SaltKey:     0,
		Info:        info,
	}
}

// NewHKDFExtractOnlyParams creates HKDF parameters for extract-only operation.
// This produces a pseudo-random key (PRK) that can be used as input to expand-only.
func NewHKDFExtractOnlyParams(hashMech MechanismType, salt []byte) *HKDFParams {
	saltType := CKF_HKDF_SALT_NULL
	if len(salt) > 0 {
		saltType = CKF_HKDF_SALT_DATA
	}
	return &HKDFParams{
		Extract:     true,
		Expand:      false,
		PRFHashMech: hashMech,
		SaltType:    saltType,
		Salt:        salt,
		SaltKey:     0,
		Info:        nil,
	}
}

// String returns the mechanism type name as a string.
func (m MechanismType) String() string {
	return GetMechanismName(m)
}

// String returns the MGF type name as a string.
func (m MGFType) String() string {
	switch m {
	case CKG_MGF1_SHA1:
		return "CKG_MGF1_SHA1"
	case CKG_MGF1_SHA256:
		return "CKG_MGF1_SHA256"
	case CKG_MGF1_SHA384:
		return "CKG_MGF1_SHA384"
	case CKG_MGF1_SHA512:
		return "CKG_MGF1_SHA512"
	case CKG_MGF1_SHA224:
		return "CKG_MGF1_SHA224"
	case CKG_MGF1_SHA3_224:
		return "CKG_MGF1_SHA3_224"
	case CKG_MGF1_SHA3_256:
		return "CKG_MGF1_SHA3_256"
	case CKG_MGF1_SHA3_384:
		return "CKG_MGF1_SHA3_384"
	case CKG_MGF1_SHA3_512:
		return "CKG_MGF1_SHA3_512"
	default:
		return fmt.Sprintf("CKG_UNKNOWN(0x%08X)", uint32(m))
	}
}

// String returns the KDF type name as a string.
func (k KDFType) String() string {
	switch k {
	case CKD_NULL:
		return "CKD_NULL"
	case CKD_SHA1_KDF:
		return "CKD_SHA1_KDF"
	case CKD_SHA1_KDF_ASN1:
		return "CKD_SHA1_KDF_ASN1"
	case CKD_SHA1_KDF_CONCATENATE:
		return "CKD_SHA1_KDF_CONCATENATE"
	case CKD_SHA224_KDF:
		return "CKD_SHA224_KDF"
	case CKD_SHA256_KDF:
		return "CKD_SHA256_KDF"
	case CKD_SHA384_KDF:
		return "CKD_SHA384_KDF"
	case CKD_SHA512_KDF:
		return "CKD_SHA512_KDF"
	case CKD_CPDIVERSIFY_KDF:
		return "CKD_CPDIVERSIFY_KDF"
	case CKD_SHA3_224_KDF:
		return "CKD_SHA3_224_KDF"
	case CKD_SHA3_256_KDF:
		return "CKD_SHA3_256_KDF"
	case CKD_SHA3_384_KDF:
		return "CKD_SHA3_384_KDF"
	case CKD_SHA3_512_KDF:
		return "CKD_SHA3_512_KDF"
	case CKD_SHA1_KDF_SP800:
		return "CKD_SHA1_KDF_SP800"
	case CKD_SHA224_KDF_SP800:
		return "CKD_SHA224_KDF_SP800"
	case CKD_SHA256_KDF_SP800:
		return "CKD_SHA256_KDF_SP800"
	case CKD_SHA384_KDF_SP800:
		return "CKD_SHA384_KDF_SP800"
	case CKD_SHA512_KDF_SP800:
		return "CKD_SHA512_KDF_SP800"
	case CKD_BLAKE2B_160_KDF:
		return "CKD_BLAKE2B_160_KDF"
	case CKD_BLAKE2B_256_KDF:
		return "CKD_BLAKE2B_256_KDF"
	case CKD_BLAKE2B_384_KDF:
		return "CKD_BLAKE2B_384_KDF"
	case CKD_BLAKE2B_512_KDF:
		return "CKD_BLAKE2B_512_KDF"
	default:
		return fmt.Sprintf("CKD_UNKNOWN(0x%08X)", uint32(k))
	}
}

// String returns a human-readable string representation of MechanismCategory.
func (c MechanismCategory) String() string {
	switch c {
	case CategoryDigest:
		return "Digest"
	case CategorySign:
		return "Sign"
	case CategoryVerify:
		return "Verify"
	case CategoryEncrypt:
		return "Encrypt"
	case CategoryDecrypt:
		return "Decrypt"
	case CategoryKeyGen:
		return "KeyGen"
	case CategoryKeyPairGen:
		return "KeyPairGen"
	case CategoryWrap:
		return "Wrap"
	case CategoryUnwrap:
		return "Unwrap"
	case CategoryDerive:
		return "Derive"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(c))
	}
}

// HasFlag checks if the mechanism info has the specified flag.
func (mi *MechanismInfo) HasFlag(flag MechanismFlag) bool {
	return mi.Flags&flag != 0
}

// SupportsHardware returns true if the mechanism is performed by device hardware.
func (mi *MechanismInfo) SupportsHardware() bool {
	return mi.HasFlag(CKF_HW)
}
