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
	"fmt"
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

	// SHA-3 Digest Mechanisms (PKCS#11 v3.0)
	CKM_SHA3_224              MechanismType = 0x000002B5
	CKM_SHA3_224_HMAC         MechanismType = 0x000002B6
	CKM_SHA3_224_HMAC_GENERAL MechanismType = 0x000002B7
	CKM_SHA3_256              MechanismType = 0x000002C0
	CKM_SHA3_256_HMAC         MechanismType = 0x000002C1
	CKM_SHA3_256_HMAC_GENERAL MechanismType = 0x000002C2
	CKM_SHA3_384              MechanismType = 0x000002D0
	CKM_SHA3_384_HMAC         MechanismType = 0x000002D1
	CKM_SHA3_384_HMAC_GENERAL MechanismType = 0x000002D2
	CKM_SHA3_512              MechanismType = 0x000002E0
	CKM_SHA3_512_HMAC         MechanismType = 0x000002E1
	CKM_SHA3_512_HMAC_GENERAL MechanismType = 0x000002E2

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

	// AES XTS Mechanism
	CKM_AES_XTS         MechanismType = 0x00002181
	CKM_AES_XTS_KEY_GEN MechanismType = 0x00002182

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

	// ACTI Mechanisms
	CKM_ACTI_KEY_GEN MechanismType = 0x000002A0
	CKM_ACTI         MechanismType = 0x000002A1

	// EdDSA and Edwards Curve Mechanisms (PKCS#11 v3.0)
	CKM_EC_EDWARDS_KEY_PAIR_GEN    MechanismType = 0x00001055
	CKM_EDDSA                      MechanismType = 0x00001057
	CKM_EC_MONTGOMERY_KEY_PAIR_GEN MechanismType = 0x00001056

	// X25519/X448 Key Derivation (PKCS#11 v3.0)
	CKM_XEDDSA MechanismType = 0x00001058

	// HKDF Mechanism (PKCS#11 v3.0)
	CKM_HKDF_DERIVE  MechanismType = 0x0000402C
	CKM_HKDF_DATA    MechanismType = 0x0000402D
	CKM_HKDF_KEY_GEN MechanismType = 0x0000402E

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
	// MinKeySize is the minimum key size in bits supported by the mechanism.
	MinKeySize uint32

	// MaxKeySize is the maximum key size in bits supported by the mechanism.
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

	// CKF_END_OF_MESSAGE indicates the final chunk in a multi-part message operation.
	CKF_END_OF_MESSAGE MechanismFlag = 0x00000001

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

// HKDF salt type constants
const (
	CKF_HKDF_SALT_NULL HKDFSaltType = 0x00000001
	CKF_HKDF_SALT_DATA HKDFSaltType = 0x00000002
	CKF_HKDF_SALT_KEY  HKDFSaltType = 0x00000003
)

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

	// MinKeySize is the minimum key size in bits (0 if not applicable).
	MinKeySize uint32

	// MaxKeySize is the maximum key size in bits (0 if not applicable).
	MaxKeySize uint32

	// Flags are the mechanism capability flags.
	Flags MechanismFlag

	// RequiresParams indicates whether the mechanism requires parameters.
	RequiresParams bool

	// ParamsType is the name of the parameter structure type.
	ParamsType string
}

// mechanismRegistry provides O(1) lookup for mechanism descriptors.
var mechanismRegistry = map[MechanismType]*MechanismDescriptor{
	// RSA Mechanisms
	CKM_RSA_PKCS_KEY_PAIR_GEN: {
		Type:       CKM_RSA_PKCS_KEY_PAIR_GEN,
		Name:       "CKM_RSA_PKCS_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		MinKeySize: 512,
		MaxKeySize: 16384,
		Flags:      CKF_GENERATE_KEY_PAIR,
	},
	CKM_RSA_PKCS: {
		Type:       CKM_RSA_PKCS,
		Name:       "CKM_RSA_PKCS",
		Categories: []MechanismCategory{CategorySign, CategoryVerify, CategoryEncrypt, CategoryDecrypt, CategoryWrap, CategoryUnwrap},
		MinKeySize: 512,
		MaxKeySize: 16384,
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
	},
	CKM_RSA_X_509: {
		Type:       CKM_RSA_X_509,
		Name:       "CKM_RSA_X_509",
		Categories: []MechanismCategory{CategorySign, CategoryVerify, CategoryEncrypt, CategoryDecrypt},
		MinKeySize: 512,
		MaxKeySize: 16384,
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT,
	},
	CKM_RSA_PKCS_OAEP: {
		Type:           CKM_RSA_PKCS_OAEP,
		Name:           "CKM_RSA_PKCS_OAEP",
		Categories:     []MechanismCategory{CategoryEncrypt, CategoryDecrypt, CategoryWrap, CategoryUnwrap},
		MinKeySize:     512,
		MaxKeySize:     16384,
		Flags:          CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
		RequiresParams: true,
		ParamsType:     "RSAOAEPParams",
	},
	CKM_RSA_PKCS_PSS: {
		Type:           CKM_RSA_PKCS_PSS,
		Name:           "CKM_RSA_PKCS_PSS",
		Categories:     []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:     512,
		MaxKeySize:     16384,
		Flags:          CKF_SIGN | CKF_VERIFY,
		RequiresParams: true,
		ParamsType:     "RSAPSSParams",
	},
	CKM_SHA1_RSA_PKCS: {
		Type:       CKM_SHA1_RSA_PKCS,
		Name:       "CKM_SHA1_RSA_PKCS",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 512,
		MaxKeySize: 16384,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_SHA256_RSA_PKCS: {
		Type:       CKM_SHA256_RSA_PKCS,
		Name:       "CKM_SHA256_RSA_PKCS",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 512,
		MaxKeySize: 16384,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_SHA384_RSA_PKCS: {
		Type:       CKM_SHA384_RSA_PKCS,
		Name:       "CKM_SHA384_RSA_PKCS",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 512,
		MaxKeySize: 16384,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_SHA512_RSA_PKCS: {
		Type:       CKM_SHA512_RSA_PKCS,
		Name:       "CKM_SHA512_RSA_PKCS",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 512,
		MaxKeySize: 16384,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_SHA256_RSA_PKCS_PSS: {
		Type:           CKM_SHA256_RSA_PKCS_PSS,
		Name:           "CKM_SHA256_RSA_PKCS_PSS",
		Categories:     []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:     512,
		MaxKeySize:     16384,
		Flags:          CKF_SIGN | CKF_VERIFY,
		RequiresParams: true,
		ParamsType:     "RSAPSSParams",
	},
	CKM_SHA384_RSA_PKCS_PSS: {
		Type:           CKM_SHA384_RSA_PKCS_PSS,
		Name:           "CKM_SHA384_RSA_PKCS_PSS",
		Categories:     []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:     512,
		MaxKeySize:     16384,
		Flags:          CKF_SIGN | CKF_VERIFY,
		RequiresParams: true,
		ParamsType:     "RSAPSSParams",
	},
	CKM_SHA512_RSA_PKCS_PSS: {
		Type:           CKM_SHA512_RSA_PKCS_PSS,
		Name:           "CKM_SHA512_RSA_PKCS_PSS",
		Categories:     []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize:     512,
		MaxKeySize:     16384,
		Flags:          CKF_SIGN | CKF_VERIFY,
		RequiresParams: true,
		ParamsType:     "RSAPSSParams",
	},

	// ECDSA Mechanisms
	CKM_EC_KEY_PAIR_GEN: {
		Type:       CKM_EC_KEY_PAIR_GEN,
		Name:       "CKM_EC_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		MinKeySize: 160,
		MaxKeySize: 521,
		Flags:      CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_OID | CKF_EC_UNCOMPRESS,
	},
	CKM_ECDSA: {
		Type:       CKM_ECDSA,
		Name:       "CKM_ECDSA",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 160,
		MaxKeySize: 521,
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_OID,
	},
	CKM_ECDSA_SHA1: {
		Type:       CKM_ECDSA_SHA1,
		Name:       "CKM_ECDSA_SHA1",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 160,
		MaxKeySize: 521,
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_OID,
	},
	CKM_ECDSA_SHA224: {
		Type:       CKM_ECDSA_SHA224,
		Name:       "CKM_ECDSA_SHA224",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 160,
		MaxKeySize: 521,
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_OID,
	},
	CKM_ECDSA_SHA256: {
		Type:       CKM_ECDSA_SHA256,
		Name:       "CKM_ECDSA_SHA256",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 160,
		MaxKeySize: 521,
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_OID,
	},
	CKM_ECDSA_SHA384: {
		Type:       CKM_ECDSA_SHA384,
		Name:       "CKM_ECDSA_SHA384",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 160,
		MaxKeySize: 521,
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_OID,
	},
	CKM_ECDSA_SHA512: {
		Type:       CKM_ECDSA_SHA512,
		Name:       "CKM_ECDSA_SHA512",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 160,
		MaxKeySize: 521,
		Flags:      CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_OID,
	},

	// ECDH Key Derivation
	CKM_ECDH1_DERIVE: {
		Type:           CKM_ECDH1_DERIVE,
		Name:           "CKM_ECDH1_DERIVE",
		Categories:     []MechanismCategory{CategoryDerive},
		MinKeySize:     160,
		MaxKeySize:     521,
		Flags:          CKF_DERIVE | CKF_EC_F_P | CKF_EC_OID,
		RequiresParams: true,
		ParamsType:     "ECDHParams",
	},
	CKM_ECDH1_COFACTOR_DERIVE: {
		Type:           CKM_ECDH1_COFACTOR_DERIVE,
		Name:           "CKM_ECDH1_COFACTOR_DERIVE",
		Categories:     []MechanismCategory{CategoryDerive},
		MinKeySize:     160,
		MaxKeySize:     521,
		Flags:          CKF_DERIVE | CKF_EC_F_P | CKF_EC_OID,
		RequiresParams: true,
		ParamsType:     "ECDHCofactorParams",
	},
	CKM_ECMQV_DERIVE: {
		Type:           CKM_ECMQV_DERIVE,
		Name:           "CKM_ECMQV_DERIVE",
		Categories:     []MechanismCategory{CategoryDerive},
		MinKeySize:     160,
		MaxKeySize:     521,
		Flags:          CKF_DERIVE | CKF_EC_F_P | CKF_EC_OID,
		RequiresParams: true,
		ParamsType:     "ECMQVParams",
	},
	CKM_ECDH_AES_KEY_WRAP: {
		Type:           CKM_ECDH_AES_KEY_WRAP,
		Name:           "CKM_ECDH_AES_KEY_WRAP",
		Categories:     []MechanismCategory{CategoryWrap, CategoryUnwrap},
		MinKeySize:     160,
		MaxKeySize:     521,
		Flags:          CKF_WRAP | CKF_UNWRAP | CKF_EC_F_P | CKF_EC_OID,
		RequiresParams: true,
		ParamsType:     "ECDHAESKeyWrapParams",
	},

	// EdDSA Mechanisms
	CKM_EC_EDWARDS_KEY_PAIR_GEN: {
		Type:       CKM_EC_EDWARDS_KEY_PAIR_GEN,
		Name:       "CKM_EC_EDWARDS_KEY_PAIR_GEN",
		Categories: []MechanismCategory{CategoryKeyPairGen},
		MinKeySize: 255,
		MaxKeySize: 448,
		Flags:      CKF_GENERATE_KEY_PAIR,
	},
	CKM_EDDSA: {
		Type:       CKM_EDDSA,
		Name:       "CKM_EDDSA",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 255,
		MaxKeySize: 448,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},

	// EC Montgomery Curve Mechanisms (X25519/X448)
	CKM_EC_MONTGOMERY_KEY_PAIR_GEN: {
		Type:           CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
		Name:           "CKM_EC_MONTGOMERY_KEY_PAIR_GEN",
		Categories:     []MechanismCategory{CategoryKeyPairGen},
		MinKeySize:     255, // X25519 = 255 bits
		MaxKeySize:     448, // X448 = 448 bits
		Flags:          CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_OID,
		RequiresParams: true,
		ParamsType:     "ECParams",
	},
	CKM_XEDDSA: {
		Type:       CKM_XEDDSA,
		Name:       "CKM_XEDDSA",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 255,
		MaxKeySize: 448,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},

	// AES Mechanisms
	CKM_AES_KEY_GEN: {
		Type:       CKM_AES_KEY_GEN,
		Name:       "CKM_AES_KEY_GEN",
		Categories: []MechanismCategory{CategoryKeyGen},
		MinKeySize: 128,
		MaxKeySize: 256,
		Flags:      CKF_GENERATE,
	},
	CKM_AES_ECB: {
		Type:       CKM_AES_ECB,
		Name:       "CKM_AES_ECB",
		Categories: []MechanismCategory{CategoryEncrypt, CategoryDecrypt},
		MinKeySize: 128,
		MaxKeySize: 256,
		Flags:      CKF_ENCRYPT | CKF_DECRYPT,
	},
	CKM_AES_CBC: {
		Type:           CKM_AES_CBC,
		Name:           "CKM_AES_CBC",
		Categories:     []MechanismCategory{CategoryEncrypt, CategoryDecrypt},
		MinKeySize:     128,
		MaxKeySize:     256,
		Flags:          CKF_ENCRYPT | CKF_DECRYPT,
		RequiresParams: true,
		ParamsType:     "AESCBCParams",
	},
	CKM_AES_CBC_PAD: {
		Type:           CKM_AES_CBC_PAD,
		Name:           "CKM_AES_CBC_PAD",
		Categories:     []MechanismCategory{CategoryEncrypt, CategoryDecrypt},
		MinKeySize:     128,
		MaxKeySize:     256,
		Flags:          CKF_ENCRYPT | CKF_DECRYPT,
		RequiresParams: true,
		ParamsType:     "AESCBCParams",
	},
	CKM_AES_CTR: {
		Type:           CKM_AES_CTR,
		Name:           "CKM_AES_CTR",
		Categories:     []MechanismCategory{CategoryEncrypt, CategoryDecrypt},
		MinKeySize:     128,
		MaxKeySize:     256,
		Flags:          CKF_ENCRYPT | CKF_DECRYPT,
		RequiresParams: true,
		ParamsType:     "AESCTRParams",
	},
	CKM_AES_GCM: {
		Type:           CKM_AES_GCM,
		Name:           "CKM_AES_GCM",
		Categories:     []MechanismCategory{CategoryEncrypt, CategoryDecrypt},
		MinKeySize:     128,
		MaxKeySize:     256,
		Flags:          CKF_ENCRYPT | CKF_DECRYPT,
		RequiresParams: true,
		ParamsType:     "AESGCMParams",
	},
	CKM_AES_CCM: {
		Type:           CKM_AES_CCM,
		Name:           "CKM_AES_CCM",
		Categories:     []MechanismCategory{CategoryEncrypt, CategoryDecrypt},
		MinKeySize:     128,
		MaxKeySize:     256,
		Flags:          CKF_ENCRYPT | CKF_DECRYPT,
		RequiresParams: true,
		ParamsType:     "AESCCMParams",
	},
	CKM_AES_CMAC: {
		Type:       CKM_AES_CMAC,
		Name:       "CKM_AES_CMAC",
		Categories: []MechanismCategory{CategorySign, CategoryVerify},
		MinKeySize: 128,
		MaxKeySize: 256,
		Flags:      CKF_SIGN | CKF_VERIFY,
	},
	CKM_AES_KEY_WRAP: {
		Type:       CKM_AES_KEY_WRAP,
		Name:       "CKM_AES_KEY_WRAP",
		Categories: []MechanismCategory{CategoryWrap, CategoryUnwrap},
		MinKeySize: 128,
		MaxKeySize: 256,
		Flags:      CKF_WRAP | CKF_UNWRAP,
	},
	CKM_AES_KEY_WRAP_PAD: {
		Type:       CKM_AES_KEY_WRAP_PAD,
		Name:       "CKM_AES_KEY_WRAP_PAD",
		Categories: []MechanismCategory{CategoryWrap, CategoryUnwrap},
		MinKeySize: 128,
		MaxKeySize: 256,
		Flags:      CKF_WRAP | CKF_UNWRAP,
	},

	// Digest Mechanisms
	CKM_SHA_1: {
		Type:       CKM_SHA_1,
		Name:       "CKM_SHA_1",
		Categories: []MechanismCategory{CategoryDigest},
		Flags:      CKF_DIGEST,
	},
	CKM_SHA256: {
		Type:       CKM_SHA256,
		Name:       "CKM_SHA256",
		Categories: []MechanismCategory{CategoryDigest},
		Flags:      CKF_DIGEST,
	},
	CKM_SHA384: {
		Type:       CKM_SHA384,
		Name:       "CKM_SHA384",
		Categories: []MechanismCategory{CategoryDigest},
		Flags:      CKF_DIGEST,
	},
	CKM_SHA512: {
		Type:       CKM_SHA512,
		Name:       "CKM_SHA512",
		Categories: []MechanismCategory{CategoryDigest},
		Flags:      CKF_DIGEST,
	},
	CKM_SHA224: {
		Type:       CKM_SHA224,
		Name:       "CKM_SHA224",
		Categories: []MechanismCategory{CategoryDigest},
		Flags:      CKF_DIGEST,
	},
	CKM_SHA3_256: {
		Type:       CKM_SHA3_256,
		Name:       "CKM_SHA3_256",
		Categories: []MechanismCategory{CategoryDigest},
		Flags:      CKF_DIGEST,
	},
	CKM_SHA3_384: {
		Type:       CKM_SHA3_384,
		Name:       "CKM_SHA3_384",
		Categories: []MechanismCategory{CategoryDigest},
		Flags:      CKF_DIGEST,
	},
	CKM_SHA3_512: {
		Type:       CKM_SHA3_512,
		Name:       "CKM_SHA3_512",
		Categories: []MechanismCategory{CategoryDigest},
		Flags:      CKF_DIGEST,
	},

	// HMAC Mechanisms
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
	CKM_HKDF_DERIVE: {
		Type:           CKM_HKDF_DERIVE,
		Name:           "CKM_HKDF_DERIVE",
		Categories:     []MechanismCategory{CategoryDerive},
		Flags:          CKF_DERIVE,
		RequiresParams: true,
		ParamsType:     "HKDFParams",
	},
	CKM_HKDF_DATA: {
		Type:           CKM_HKDF_DATA,
		Name:           "CKM_HKDF_DATA",
		Categories:     []MechanismCategory{CategoryDerive},
		Flags:          CKF_DERIVE,
		RequiresParams: true,
		ParamsType:     "HKDFParams",
	},
	CKM_HKDF_KEY_GEN: {
		Type:       CKM_HKDF_KEY_GEN,
		Name:       "CKM_HKDF_KEY_GEN",
		Categories: []MechanismCategory{CategoryKeyGen},
		MinKeySize: 1,
		MaxKeySize: 0, // No maximum, depends on hash output size
		Flags:      CKF_GENERATE,
	},

	// SP800-108 Key Derivation Functions (NIST SP 800-108)
	CKM_SP800_108_COUNTER_KDF: {
		Type:           CKM_SP800_108_COUNTER_KDF,
		Name:           "CKM_SP800_108_COUNTER_KDF",
		Categories:     []MechanismCategory{CategoryDerive},
		MinKeySize:     1,
		MaxKeySize:     0, // No maximum
		Flags:          CKF_DERIVE,
		RequiresParams: true,
		ParamsType:     "SP800108KDFParams",
	},
	CKM_SP800_108_FEEDBACK_KDF: {
		Type:           CKM_SP800_108_FEEDBACK_KDF,
		Name:           "CKM_SP800_108_FEEDBACK_KDF",
		Categories:     []MechanismCategory{CategoryDerive},
		MinKeySize:     1,
		MaxKeySize:     0, // No maximum
		Flags:          CKF_DERIVE,
		RequiresParams: true,
		ParamsType:     "SP800108KDFParams",
	},
	CKM_SP800_108_DOUBLE_PIPELINE_KDF: {
		Type:           CKM_SP800_108_DOUBLE_PIPELINE_KDF,
		Name:           "CKM_SP800_108_DOUBLE_PIPELINE_KDF",
		Categories:     []MechanismCategory{CategoryDerive},
		MinKeySize:     1,
		MaxKeySize:     0, // No maximum
		Flags:          CKF_DERIVE,
		RequiresParams: true,
		ParamsType:     "SP800108KDFParams",
	},

	// Generic Secret Key
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
	return mechanismRegistry[mechType]
}

// IsMechanismSupported checks if a mechanism is supported by this implementation.
// This provides O(1) lookup time.
func IsMechanismSupported(mechType MechanismType) bool {
	_, ok := mechanismRegistry[mechType]
	return ok
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

// GetMechanismInfo returns the mechanism info for the given mechanism type.
// Returns an error if the mechanism is not supported.
func GetMechanismInfo(mechType MechanismType) (*MechanismInfo, error) {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return nil, ErrMechanismInvalid
	}

	return &MechanismInfo{
		MinKeySize: desc.MinKeySize,
		MaxKeySize: desc.MaxKeySize,
		Flags:      desc.Flags,
	}, nil
}

// MechanismRequiresParams checks if a mechanism requires parameters.
// Returns false if the mechanism is not supported.
func MechanismRequiresParams(mechType MechanismType) bool {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return false
	}
	return desc.RequiresParams
}

// GetMechanismParamsType returns the parameter type name for a mechanism.
// Returns empty string if the mechanism does not require parameters or is not supported.
func GetMechanismParamsType(mechType MechanismType) string {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return ""
	}
	return desc.ParamsType
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

// IsValidKeySize checks if the key size is valid for the given mechanism.
func IsValidKeySize(mechType MechanismType, keySize uint32) bool {
	desc := GetMechanismDescriptor(mechType)
	if desc == nil {
		return false
	}
	// If both min and max are 0, key size is not applicable
	if desc.MinKeySize == 0 && desc.MaxKeySize == 0 {
		return true
	}
	return keySize >= desc.MinKeySize && keySize <= desc.MaxKeySize
}

// ListSupportedMechanisms returns a slice of all supported mechanism types.
func ListSupportedMechanisms() []MechanismType {
	mechanisms := make([]MechanismType, 0, len(mechanismRegistry))
	for mechType := range mechanismRegistry {
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
	case CKD_SHA3_224_KDF:
		return "CKD_SHA3_224_KDF"
	case CKD_SHA3_256_KDF:
		return "CKD_SHA3_256_KDF"
	case CKD_SHA3_384_KDF:
		return "CKD_SHA3_384_KDF"
	case CKD_SHA3_512_KDF:
		return "CKD_SHA3_512_KDF"
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
