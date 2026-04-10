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

// Package module provides PKCS#11 (Cryptoki) v3.0 object definitions and management.
//
// This package implements object classes, key types, attribute types, and object
// management according to the OASIS PKCS#11 v3.0 specification.
//
// Object Categories:
//   - Data Objects (CKO_DATA): Arbitrary application-defined data
//   - Certificate Objects (CKO_CERTIFICATE): X.509 certificates, etc.
//   - Key Objects: Public keys (CKO_PUBLIC_KEY), Private keys (CKO_PRIVATE_KEY),
//     Secret keys (CKO_SECRET_KEY)
//
// References:
//   - OASIS PKCS#11 v3.0: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
package module

import (
	"bytes"
	"encoding/binary"
	"sync"
)

// ObjectClass represents a PKCS#11 object class (CK_OBJECT_CLASS).
// Object classes categorize the types of objects that can be stored in a token.
type ObjectClass uint32

// PKCS#11 v3.0 Object Class Constants (CKO_*)
// Reference: OASIS PKCS#11 Base Specification v3.0, Section 4.3
const (
	// CKO_DATA is a data object that holds arbitrary application-defined data.
	CKO_DATA ObjectClass = 0x00000000

	// CKO_CERTIFICATE is a certificate object (e.g., X.509).
	CKO_CERTIFICATE ObjectClass = 0x00000001

	// CKO_PUBLIC_KEY is a public key object.
	CKO_PUBLIC_KEY ObjectClass = 0x00000002

	// CKO_PRIVATE_KEY is a private key object.
	CKO_PRIVATE_KEY ObjectClass = 0x00000003

	// CKO_SECRET_KEY is a secret (symmetric) key object.
	CKO_SECRET_KEY ObjectClass = 0x00000004

	// CKO_HW_FEATURE is a hardware feature object.
	CKO_HW_FEATURE ObjectClass = 0x00000005

	// CKO_DOMAIN_PARAMETERS is a domain parameters object.
	CKO_DOMAIN_PARAMETERS ObjectClass = 0x00000006

	// CKO_MECHANISM is a mechanism object (PKCS#11 v2.20+).
	CKO_MECHANISM ObjectClass = 0x00000007

	// CKO_OTP_KEY is an OTP key object (PKCS#11 v2.20+).
	CKO_OTP_KEY ObjectClass = 0x00000008

	// CKO_PROFILE is a profile object (PKCS#11 v3.0).
	CKO_PROFILE ObjectClass = 0x00000009

	// CKO_VALIDATION is a validation object (PKCS#11 v3.2).
	// Validation objects hold parameter validation and policy information.
	CKO_VALIDATION ObjectClass = 0x0000000A

	// CKO_TRUST is a trust object (PKCS#11 v3.2).
	// Trust objects bind certificates to trust policies.
	CKO_TRUST ObjectClass = 0x0000000B

	// CKO_VENDOR_DEFINED marks the start of vendor-defined object classes.
	CKO_VENDOR_DEFINED ObjectClass = 0x80000000
)

// objectClassNames maps object class values to their string names.
var objectClassNames = map[ObjectClass]string{
	CKO_DATA:              "CKO_DATA",
	CKO_CERTIFICATE:       "CKO_CERTIFICATE",
	CKO_PUBLIC_KEY:        "CKO_PUBLIC_KEY",
	CKO_PRIVATE_KEY:       "CKO_PRIVATE_KEY",
	CKO_SECRET_KEY:        "CKO_SECRET_KEY",
	CKO_HW_FEATURE:        "CKO_HW_FEATURE",
	CKO_DOMAIN_PARAMETERS: "CKO_DOMAIN_PARAMETERS",
	CKO_MECHANISM:         "CKO_MECHANISM",
	CKO_OTP_KEY:           "CKO_OTP_KEY",
	CKO_PROFILE:           "CKO_PROFILE",
	CKO_VALIDATION:        "CKO_VALIDATION",
	CKO_TRUST:             "CKO_TRUST",
	CKO_VENDOR_DEFINED:    "CKO_VENDOR_DEFINED",
}

// String returns the string representation of the object class.
func (oc ObjectClass) String() string {
	if name, ok := objectClassNames[oc]; ok {
		return name
	}
	if oc >= CKO_VENDOR_DEFINED {
		return "CKO_VENDOR_DEFINED+0x" + uitoaHex(uint32(oc-CKO_VENDOR_DEFINED))
	}
	return "CKO_UNKNOWN(0x" + uitoaHex(uint32(oc)) + ")"
}

// KeyType represents a PKCS#11 key type (CK_KEY_TYPE).
// Key types specify the cryptographic algorithm associated with a key.
type KeyType uint32

// PKCS#11 v3.0 Key Type Constants (CKK_*)
// Reference: OASIS PKCS#11 Base Specification v3.0, Section 4.9
const (
	// CKK_RSA is an RSA key type.
	CKK_RSA KeyType = 0x00000000

	// CKK_DSA is a DSA key type.
	CKK_DSA KeyType = 0x00000001

	// CKK_DH is a Diffie-Hellman key type.
	CKK_DH KeyType = 0x00000002

	// CKK_EC is an elliptic curve (ECDSA/ECDH) key type.
	// Also known as CKK_ECDSA in older specs.
	CKK_EC KeyType = 0x00000003

	// CKK_X9_42_DH is an X9.42 Diffie-Hellman key type.
	CKK_X9_42_DH KeyType = 0x00000004

	// CKK_KEA is a KEA key type.
	CKK_KEA KeyType = 0x00000005

	// CKK_GENERIC_SECRET is a generic secret key type.
	CKK_GENERIC_SECRET KeyType = 0x00000010

	// CKK_RC2 is an RC2 key type.
	CKK_RC2 KeyType = 0x00000011

	// CKK_RC4 is an RC4 key type.
	CKK_RC4 KeyType = 0x00000012

	// CKK_DES is a DES key type.
	CKK_DES KeyType = 0x00000013

	// CKK_DES2 is a double-length DES key type.
	CKK_DES2 KeyType = 0x00000014

	// CKK_DES3 is a triple-DES key type.
	CKK_DES3 KeyType = 0x00000015

	// CKK_CAST is a CAST key type.
	CKK_CAST KeyType = 0x00000016

	// CKK_CAST3 is a CAST3 key type.
	CKK_CAST3 KeyType = 0x00000017

	// CKK_CAST5 is a CAST5 (CAST-128) key type.
	CKK_CAST5    KeyType = 0x00000018
	CKK_CAST128  KeyType = 0x00000018 // Alias for CKK_CAST5
	CKK_RC5      KeyType = 0x00000019
	CKK_IDEA     KeyType = 0x0000001A
	CKK_SKIPJACK KeyType = 0x0000001B
	CKK_BATON    KeyType = 0x0000001C
	CKK_JUNIPER  KeyType = 0x0000001D
	CKK_CDMF     KeyType = 0x0000001E

	// CKK_AES is an AES key type.
	CKK_AES KeyType = 0x0000001F

	// CKK_BLOWFISH is a Blowfish key type.
	CKK_BLOWFISH KeyType = 0x00000020

	// CKK_TWOFISH is a Twofish key type.
	CKK_TWOFISH KeyType = 0x00000021

	// CKK_SECURID is a SecurID key type.
	CKK_SECURID KeyType = 0x00000022

	// CKK_HOTP is an HOTP key type.
	CKK_HOTP KeyType = 0x00000023

	// CKK_ACTI is an ACTI key type.
	CKK_ACTI KeyType = 0x00000024

	// CKK_CAMELLIA is a Camellia key type.
	CKK_CAMELLIA KeyType = 0x00000025

	// CKK_ARIA is an ARIA key type.
	CKK_ARIA KeyType = 0x00000026

	// CKK_MD5_HMAC is an MD5-HMAC key type.
	CKK_MD5_HMAC KeyType = 0x00000027

	// CKK_SHA_1_HMAC is a SHA-1 HMAC key type.
	CKK_SHA_1_HMAC KeyType = 0x00000028

	// CKK_RIPEMD128_HMAC is a RIPEMD-128 HMAC key type.
	CKK_RIPEMD128_HMAC KeyType = 0x00000029

	// CKK_RIPEMD160_HMAC is a RIPEMD-160 HMAC key type.
	CKK_RIPEMD160_HMAC KeyType = 0x0000002A

	// CKK_SHA256_HMAC is a SHA-256 HMAC key type.
	CKK_SHA256_HMAC KeyType = 0x0000002B

	// CKK_SHA384_HMAC is a SHA-384 HMAC key type.
	CKK_SHA384_HMAC KeyType = 0x0000002C

	// CKK_SHA512_HMAC is a SHA-512 HMAC key type.
	CKK_SHA512_HMAC KeyType = 0x0000002D

	// CKK_SHA224_HMAC is a SHA-224 HMAC key type.
	CKK_SHA224_HMAC KeyType = 0x0000002E

	// CKK_SEED is a SEED key type.
	CKK_SEED KeyType = 0x0000002F

	// CKK_GOSTR3410 is a GOST R 34.10-2001 key type.
	CKK_GOSTR3410 KeyType = 0x00000030

	// CKK_GOSTR3411 is a GOST R 34.11-94 key type.
	CKK_GOSTR3411 KeyType = 0x00000031

	// CKK_GOST28147 is a GOST 28147-89 key type.
	CKK_GOST28147 KeyType = 0x00000032

	// CKK_CHACHA20 is a ChaCha20 key type (PKCS#11 v3.0).
	CKK_CHACHA20 KeyType = 0x00000033

	// CKK_POLY1305 is a Poly1305 key type (PKCS#11 v3.0).
	CKK_POLY1305 KeyType = 0x00000034

	// CKK_AES_XTS is an AES-XTS key type (PKCS#11 v3.0).
	CKK_AES_XTS KeyType = 0x00000035

	// CKK_SHA3_224_HMAC is a SHA3-224 HMAC key type (PKCS#11 v3.0).
	CKK_SHA3_224_HMAC KeyType = 0x00000036

	// CKK_SHA3_256_HMAC is a SHA3-256 HMAC key type (PKCS#11 v3.0).
	CKK_SHA3_256_HMAC KeyType = 0x00000037

	// CKK_SHA3_384_HMAC is a SHA3-384 HMAC key type (PKCS#11 v3.0).
	CKK_SHA3_384_HMAC KeyType = 0x00000038

	// CKK_SHA3_512_HMAC is a SHA3-512 HMAC key type (PKCS#11 v3.0).
	CKK_SHA3_512_HMAC KeyType = 0x00000039

	// CKK_BLAKE2B_160_HMAC through CKK_BLAKE2B_512_HMAC for BLAKE2b variants.
	CKK_BLAKE2B_160_HMAC KeyType = 0x0000003A
	CKK_BLAKE2B_256_HMAC KeyType = 0x0000003B
	CKK_BLAKE2B_384_HMAC KeyType = 0x0000003C
	CKK_BLAKE2B_512_HMAC KeyType = 0x0000003D

	// CKK_SALSA20 is a Salsa20 key type (PKCS#11 v3.0).
	CKK_SALSA20 KeyType = 0x0000003E

	// CKK_X2RATCHET is an X2 Ratchet key type (PKCS#11 v3.0).
	CKK_X2RATCHET KeyType = 0x0000003F

	// CKK_EC_EDWARDS is an Edwards curve key type (Ed25519, Ed448).
	CKK_EC_EDWARDS KeyType = 0x00000040

	// CKK_EC_MONTGOMERY is a Montgomery curve key type (X25519, X448).
	CKK_EC_MONTGOMERY KeyType = 0x00000041

	// CKK_HKDF is an HKDF key type (PKCS#11 v3.0).
	CKK_HKDF KeyType = 0x00000042

	// CKK_SHA512_224_HMAC is a SHA-512/224 HMAC key type.
	CKK_SHA512_224_HMAC KeyType = 0x00000043

	// CKK_SHA512_256_HMAC is a SHA-512/256 HMAC key type.
	CKK_SHA512_256_HMAC KeyType = 0x00000044

	// CKK_SHA512_T_HMAC is a SHA-512/t HMAC key type.
	CKK_SHA512_T_HMAC KeyType = 0x00000045

	// PKCS#11 v3.2 Post-Quantum Key Types

	// CKK_HSS is an HSS/LMS (RFC 8554) key type.
	CKK_HSS KeyType = 0x00000046

	// CKK_XMSS is an XMSS (RFC 8391) key type.
	CKK_XMSS KeyType = 0x00000047

	// CKK_XMSSMT is an XMSS^MT (RFC 8391) key type.
	CKK_XMSSMT KeyType = 0x00000048

	// CKK_ML_KEM is an ML-KEM (FIPS 203) key type.
	CKK_ML_KEM KeyType = 0x00000049

	// CKK_ML_DSA is an ML-DSA (FIPS 204) key type.
	CKK_ML_DSA KeyType = 0x0000004A

	// CKK_SLH_DSA is an SLH-DSA (FIPS 205) key type.
	CKK_SLH_DSA KeyType = 0x0000004B

	// CKK_VENDOR_DEFINED marks the start of vendor-defined key types.
	CKK_VENDOR_DEFINED KeyType = 0x80000000
)

// keyTypeNames maps key type values to their string names.
var keyTypeNames = map[KeyType]string{
	CKK_RSA:              "CKK_RSA",
	CKK_DSA:              "CKK_DSA",
	CKK_DH:               "CKK_DH",
	CKK_EC:               "CKK_EC",
	CKK_X9_42_DH:         "CKK_X9_42_DH",
	CKK_KEA:              "CKK_KEA",
	CKK_GENERIC_SECRET:   "CKK_GENERIC_SECRET",
	CKK_RC2:              "CKK_RC2",
	CKK_RC4:              "CKK_RC4",
	CKK_DES:              "CKK_DES",
	CKK_DES2:             "CKK_DES2",
	CKK_DES3:             "CKK_DES3",
	CKK_CAST:             "CKK_CAST",
	CKK_CAST3:            "CKK_CAST3",
	CKK_CAST5:            "CKK_CAST5",
	CKK_RC5:              "CKK_RC5",
	CKK_IDEA:             "CKK_IDEA",
	CKK_SKIPJACK:         "CKK_SKIPJACK",
	CKK_BATON:            "CKK_BATON",
	CKK_JUNIPER:          "CKK_JUNIPER",
	CKK_CDMF:             "CKK_CDMF",
	CKK_AES:              "CKK_AES",
	CKK_BLOWFISH:         "CKK_BLOWFISH",
	CKK_TWOFISH:          "CKK_TWOFISH",
	CKK_SECURID:          "CKK_SECURID",
	CKK_HOTP:             "CKK_HOTP",
	CKK_ACTI:             "CKK_ACTI",
	CKK_CAMELLIA:         "CKK_CAMELLIA",
	CKK_ARIA:             "CKK_ARIA",
	CKK_MD5_HMAC:         "CKK_MD5_HMAC",
	CKK_SHA_1_HMAC:       "CKK_SHA_1_HMAC",
	CKK_RIPEMD128_HMAC:   "CKK_RIPEMD128_HMAC",
	CKK_RIPEMD160_HMAC:   "CKK_RIPEMD160_HMAC",
	CKK_SHA256_HMAC:      "CKK_SHA256_HMAC",
	CKK_SHA384_HMAC:      "CKK_SHA384_HMAC",
	CKK_SHA512_HMAC:      "CKK_SHA512_HMAC",
	CKK_SHA224_HMAC:      "CKK_SHA224_HMAC",
	CKK_SEED:             "CKK_SEED",
	CKK_GOSTR3410:        "CKK_GOSTR3410",
	CKK_GOSTR3411:        "CKK_GOSTR3411",
	CKK_GOST28147:        "CKK_GOST28147",
	CKK_CHACHA20:         "CKK_CHACHA20",
	CKK_POLY1305:         "CKK_POLY1305",
	CKK_AES_XTS:          "CKK_AES_XTS",
	CKK_SHA3_224_HMAC:    "CKK_SHA3_224_HMAC",
	CKK_SHA3_256_HMAC:    "CKK_SHA3_256_HMAC",
	CKK_SHA3_384_HMAC:    "CKK_SHA3_384_HMAC",
	CKK_SHA3_512_HMAC:    "CKK_SHA3_512_HMAC",
	CKK_BLAKE2B_160_HMAC: "CKK_BLAKE2B_160_HMAC",
	CKK_BLAKE2B_256_HMAC: "CKK_BLAKE2B_256_HMAC",
	CKK_BLAKE2B_384_HMAC: "CKK_BLAKE2B_384_HMAC",
	CKK_BLAKE2B_512_HMAC: "CKK_BLAKE2B_512_HMAC",
	CKK_SALSA20:          "CKK_SALSA20",
	CKK_X2RATCHET:        "CKK_X2RATCHET",
	CKK_EC_EDWARDS:       "CKK_EC_EDWARDS",
	CKK_EC_MONTGOMERY:    "CKK_EC_MONTGOMERY",
	CKK_HKDF:             "CKK_HKDF",
	CKK_SHA512_224_HMAC:  "CKK_SHA512_224_HMAC",
	CKK_SHA512_256_HMAC:  "CKK_SHA512_256_HMAC",
	CKK_SHA512_T_HMAC:    "CKK_SHA512_T_HMAC",
	CKK_HSS:              "CKK_HSS",
	CKK_XMSS:             "CKK_XMSS",
	CKK_XMSSMT:           "CKK_XMSSMT",
	CKK_ML_KEM:           "CKK_ML_KEM",
	CKK_ML_DSA:           "CKK_ML_DSA",
	CKK_SLH_DSA:          "CKK_SLH_DSA",
	CKK_VENDOR_DEFINED:   "CKK_VENDOR_DEFINED",
}

// String returns the string representation of the key type.
func (kt KeyType) String() string {
	if name, ok := keyTypeNames[kt]; ok {
		return name
	}
	if kt >= CKK_VENDOR_DEFINED {
		return "CKK_VENDOR_DEFINED+0x" + uitoaHex(uint32(kt-CKK_VENDOR_DEFINED))
	}
	return "CKK_UNKNOWN(0x" + uitoaHex(uint32(kt)) + ")"
}

// AttributeType represents a PKCS#11 attribute type (CK_ATTRIBUTE_TYPE).
// Attributes define the characteristics and capabilities of objects.
type AttributeType uint32

// PKCS#11 v3.0 Attribute Type Constants (CKA_*)
// Reference: OASIS PKCS#11 Base Specification v3.0, Section 4.4
const (
	// Common Object Attributes
	CKA_CLASS                      AttributeType = 0x00000000
	CKA_TOKEN                      AttributeType = 0x00000001
	CKA_PRIVATE                    AttributeType = 0x00000002
	CKA_LABEL                      AttributeType = 0x00000003
	CKA_UNIQUE_ID                  AttributeType = 0x00000004
	CKA_APPLICATION                AttributeType = 0x00000010
	CKA_VALUE                      AttributeType = 0x00000011
	CKA_OBJECT_ID                  AttributeType = 0x00000012
	CKA_CERTIFICATE_TYPE           AttributeType = 0x00000080
	CKA_ISSUER                     AttributeType = 0x00000081
	CKA_SERIAL_NUMBER              AttributeType = 0x00000082
	CKA_AC_ISSUER                  AttributeType = 0x00000083
	CKA_OWNER                      AttributeType = 0x00000084
	CKA_ATTR_TYPES                 AttributeType = 0x00000085
	CKA_TRUSTED                    AttributeType = 0x00000086
	CKA_CERTIFICATE_CATEGORY       AttributeType = 0x00000087
	CKA_JAVA_MIDP_SECURITY_DOMAIN  AttributeType = 0x00000088
	CKA_URL                        AttributeType = 0x00000089
	CKA_HASH_OF_SUBJECT_PUBLIC_KEY AttributeType = 0x0000008A
	CKA_HASH_OF_ISSUER_PUBLIC_KEY  AttributeType = 0x0000008B
	CKA_NAME_HASH_ALGORITHM        AttributeType = 0x0000008C
	CKA_CHECK_VALUE                AttributeType = 0x00000090

	// Key Attributes
	CKA_KEY_TYPE          AttributeType = 0x00000100
	CKA_SUBJECT           AttributeType = 0x00000101
	CKA_ID                AttributeType = 0x00000102
	CKA_SENSITIVE         AttributeType = 0x00000103
	CKA_ENCRYPT           AttributeType = 0x00000104
	CKA_DECRYPT           AttributeType = 0x00000105
	CKA_WRAP              AttributeType = 0x00000106
	CKA_UNWRAP            AttributeType = 0x00000107
	CKA_SIGN              AttributeType = 0x00000108
	CKA_SIGN_RECOVER      AttributeType = 0x00000109
	CKA_VERIFY            AttributeType = 0x0000010A
	CKA_VERIFY_RECOVER    AttributeType = 0x0000010B
	CKA_DERIVE            AttributeType = 0x0000010C
	CKA_START_DATE        AttributeType = 0x00000110
	CKA_END_DATE          AttributeType = 0x00000111
	CKA_MODULUS           AttributeType = 0x00000120
	CKA_MODULUS_BITS      AttributeType = 0x00000121
	CKA_PUBLIC_EXPONENT   AttributeType = 0x00000122
	CKA_PRIVATE_EXPONENT  AttributeType = 0x00000123
	CKA_PRIME_1           AttributeType = 0x00000124
	CKA_PRIME_2           AttributeType = 0x00000125
	CKA_EXPONENT_1        AttributeType = 0x00000126
	CKA_EXPONENT_2        AttributeType = 0x00000127
	CKA_COEFFICIENT       AttributeType = 0x00000128
	CKA_PUBLIC_KEY_INFO   AttributeType = 0x00000129
	CKA_PRIME             AttributeType = 0x00000130
	CKA_SUBPRIME          AttributeType = 0x00000131
	CKA_BASE              AttributeType = 0x00000132
	CKA_PRIME_BITS        AttributeType = 0x00000133
	CKA_SUBPRIME_BITS     AttributeType = 0x00000134
	CKA_VALUE_BITS        AttributeType = 0x00000160
	CKA_VALUE_LEN         AttributeType = 0x00000161
	CKA_EXTRACTABLE       AttributeType = 0x00000162
	CKA_LOCAL             AttributeType = 0x00000163
	CKA_NEVER_EXTRACTABLE AttributeType = 0x00000164
	CKA_ALWAYS_SENSITIVE  AttributeType = 0x00000165
	CKA_KEY_GEN_MECHANISM AttributeType = 0x00000166
	CKA_MODIFIABLE        AttributeType = 0x00000170
	CKA_COPYABLE          AttributeType = 0x00000171
	CKA_DESTROYABLE       AttributeType = 0x00000172

	// EC Key Attributes
	CKA_EC_PARAMS    AttributeType = 0x00000180
	CKA_ECDSA_PARAMS AttributeType = 0x00000180 // Deprecated alias
	CKA_EC_POINT     AttributeType = 0x00000181

	// Secondary Authentication (PKCS#11 v2.20+)
	CKA_SECONDARY_AUTH AttributeType = 0x00000200
	CKA_AUTH_PIN_FLAGS AttributeType = 0x00000201

	// Always Authenticate
	CKA_ALWAYS_AUTHENTICATE AttributeType = 0x00000202

	// Wrap With Trusted
	CKA_WRAP_WITH_TRUSTED AttributeType = 0x00000210

	// Wrap Template / Unwrap Template (CKF_ARRAY_ATTRIBUTE | base)
	CKA_WRAP_TEMPLATE   AttributeType = 0x40000211
	CKA_UNWRAP_TEMPLATE AttributeType = 0x40000212

	// Derive Template (PKCS#11 v3.0) (CKF_ARRAY_ATTRIBUTE | base)
	CKA_DERIVE_TEMPLATE AttributeType = 0x40000213

	// OTP Key Attributes
	CKA_OTP_FORMAT                AttributeType = 0x00000220
	CKA_OTP_LENGTH                AttributeType = 0x00000221
	CKA_OTP_TIME_INTERVAL         AttributeType = 0x00000222
	CKA_OTP_USER_FRIENDLY_MODE    AttributeType = 0x00000223
	CKA_OTP_CHALLENGE_REQUIREMENT AttributeType = 0x00000224
	CKA_OTP_TIME_REQUIREMENT      AttributeType = 0x00000225
	CKA_OTP_COUNTER_REQUIREMENT   AttributeType = 0x00000226
	CKA_OTP_PIN_REQUIREMENT       AttributeType = 0x00000227
	CKA_OTP_COUNTER               AttributeType = 0x0000022E
	CKA_OTP_TIME                  AttributeType = 0x0000022F
	CKA_OTP_USER_IDENTIFIER       AttributeType = 0x0000022A
	CKA_OTP_SERVICE_IDENTIFIER    AttributeType = 0x0000022B
	CKA_OTP_SERVICE_LOGO          AttributeType = 0x0000022C
	CKA_OTP_SERVICE_LOGO_TYPE     AttributeType = 0x0000022D

	// GOSTR Key Attributes
	CKA_GOSTR3410_PARAMS AttributeType = 0x00000250
	CKA_GOSTR3411_PARAMS AttributeType = 0x00000251
	CKA_GOST28147_PARAMS AttributeType = 0x00000252

	// Hardware Feature Attributes
	CKA_HW_FEATURE_TYPE          AttributeType = 0x00000300
	CKA_RESET_ON_INIT            AttributeType = 0x00000301
	CKA_HAS_RESET                AttributeType = 0x00000302
	CKA_PIXEL_X                  AttributeType = 0x00000400
	CKA_PIXEL_Y                  AttributeType = 0x00000401
	CKA_RESOLUTION               AttributeType = 0x00000402
	CKA_CHAR_ROWS                AttributeType = 0x00000403
	CKA_CHAR_COLUMNS             AttributeType = 0x00000404
	CKA_COLOR                    AttributeType = 0x00000405
	CKA_BITS_PER_PIXEL           AttributeType = 0x00000406
	CKA_CHAR_SETS                AttributeType = 0x00000480
	CKA_ENCODING_METHODS         AttributeType = 0x00000481
	CKA_MIME_TYPES               AttributeType = 0x00000482
	CKA_MECHANISM_TYPE           AttributeType = 0x00000500
	CKA_REQUIRED_CMS_ATTRIBUTES  AttributeType = 0x00000501
	CKA_DEFAULT_CMS_ATTRIBUTES   AttributeType = 0x00000502
	CKA_SUPPORTED_CMS_ATTRIBUTES AttributeType = 0x00000503
	CKA_ALLOWED_MECHANISMS       AttributeType = 0x40000600

	// Profile Object Attributes (PKCS#11 v3.0)
	CKA_PROFILE_ID AttributeType = 0x00000601

	// X.942 DH Attributes (PKCS#11 v3.0)
	CKA_X2RATCHET_BAG        AttributeType = 0x00000602
	CKA_X2RATCHET_BAGSIZE    AttributeType = 0x00000603
	CKA_X2RATCHET_BOBS1STMSG AttributeType = 0x00000604
	CKA_X2RATCHET_CKR        AttributeType = 0x00000605
	CKA_X2RATCHET_CKS        AttributeType = 0x00000606
	CKA_X2RATCHET_DHP        AttributeType = 0x00000607
	CKA_X2RATCHET_DHR        AttributeType = 0x00000608
	CKA_X2RATCHET_DHS        AttributeType = 0x00000609
	CKA_X2RATCHET_HKR        AttributeType = 0x0000060A
	CKA_X2RATCHET_HKS        AttributeType = 0x0000060B
	CKA_X2RATCHET_ISALICE    AttributeType = 0x0000060C
	CKA_X2RATCHET_NHKR       AttributeType = 0x0000060D
	CKA_X2RATCHET_NHKS       AttributeType = 0x0000060E
	CKA_X2RATCHET_NR         AttributeType = 0x0000060F
	CKA_X2RATCHET_NS         AttributeType = 0x00000610
	CKA_X2RATCHET_PNS        AttributeType = 0x00000611
	CKA_X2RATCHET_RK         AttributeType = 0x00000612

	// PKCS#11 v3.2 HSS Attributes
	CKA_HSS_LEVELS         AttributeType = 0x00000617
	CKA_HSS_LMS_TYPE       AttributeType = 0x00000618
	CKA_HSS_LMOTS_TYPE     AttributeType = 0x00000619
	CKA_HSS_LMS_TYPES      AttributeType = 0x0000061A
	CKA_HSS_LMOTS_TYPES    AttributeType = 0x0000061B
	CKA_HSS_KEYS_REMAINING AttributeType = 0x0000061C

	// PKCS#11 v3.2 PQC Parameter and Validation Attributes
	CKA_PARAMETER_SET                     AttributeType = 0x0000061D
	CKA_OBJECT_VALIDATION_FLAGS           AttributeType = 0x0000061E
	CKA_VALIDATION_TYPE                   AttributeType = 0x0000061F
	CKA_VALIDATION_VERSION                AttributeType = 0x00000620
	CKA_VALIDATION_LEVEL                  AttributeType = 0x00000621
	CKA_VALIDATION_MODULE_ID              AttributeType = 0x00000622
	CKA_VALIDATION_FLAG                   AttributeType = 0x00000623
	CKA_VALIDATION_AUTHORITY_TYPE         AttributeType = 0x00000624
	CKA_VALIDATION_COUNTRY                AttributeType = 0x00000625
	CKA_VALIDATION_CERTIFICATE_IDENTIFIER AttributeType = 0x00000626
	CKA_VALIDATION_CERTIFICATE_URI        AttributeType = 0x00000627
	CKA_VALIDATION_VENDOR_URI             AttributeType = 0x00000628
	CKA_VALIDATION_PROFILE                AttributeType = 0x00000629

	// PKCS#11 v3.2 KEM Template Attributes
	CKA_ENCAPSULATE_TEMPLATE AttributeType = 0x4000062A
	CKA_DECAPSULATE_TEMPLATE AttributeType = 0x4000062B

	// PKCS#11 v3.2 Trust Attributes
	CKA_TRUST_SERVER_AUTH      AttributeType = 0x0000062C
	CKA_TRUST_CLIENT_AUTH      AttributeType = 0x0000062D
	CKA_TRUST_CODE_SIGNING     AttributeType = 0x0000062E
	CKA_TRUST_EMAIL_PROTECTION AttributeType = 0x0000062F
	CKA_TRUST_IPSEC_IKE        AttributeType = 0x00000630
	CKA_TRUST_TIME_STAMPING    AttributeType = 0x00000631
	CKA_TRUST_OCSP_SIGNING     AttributeType = 0x00000632

	// PKCS#11 v3.2 KEM and PQC Attributes

	// CKA_ENCAPSULATE indicates the key supports encapsulation operations.
	CKA_ENCAPSULATE AttributeType = 0x00000633

	// CKA_DECAPSULATE indicates the key supports decapsulation operations.
	CKA_DECAPSULATE AttributeType = 0x00000634

	// CKA_HASH_OF_CERTIFICATE stores a hash of the certificate.
	CKA_HASH_OF_CERTIFICATE AttributeType = 0x00000635

	// CKA_PUBLIC_CRC64_VALUE stores the CRC64 value of a public key.
	CKA_PUBLIC_CRC64_VALUE AttributeType = 0x00000636

	// CKA_SEED provides a seed for deterministic key generation.
	CKA_SEED AttributeType = 0x00000637

	// Vendor-defined attributes start at this value
	CKA_VENDOR_DEFINED AttributeType = 0x80000000
)

// attributeTypeNames maps attribute type values to their string names.
var attributeTypeNames = map[AttributeType]string{
	CKA_CLASS:                             "CKA_CLASS",
	CKA_TOKEN:                             "CKA_TOKEN",
	CKA_PRIVATE:                           "CKA_PRIVATE",
	CKA_LABEL:                             "CKA_LABEL",
	CKA_UNIQUE_ID:                         "CKA_UNIQUE_ID",
	CKA_APPLICATION:                       "CKA_APPLICATION",
	CKA_VALUE:                             "CKA_VALUE",
	CKA_OBJECT_ID:                         "CKA_OBJECT_ID",
	CKA_CERTIFICATE_TYPE:                  "CKA_CERTIFICATE_TYPE",
	CKA_ISSUER:                            "CKA_ISSUER",
	CKA_SERIAL_NUMBER:                     "CKA_SERIAL_NUMBER",
	CKA_TRUSTED:                           "CKA_TRUSTED",
	CKA_CHECK_VALUE:                       "CKA_CHECK_VALUE",
	CKA_KEY_TYPE:                          "CKA_KEY_TYPE",
	CKA_SUBJECT:                           "CKA_SUBJECT",
	CKA_ID:                                "CKA_ID",
	CKA_SENSITIVE:                         "CKA_SENSITIVE",
	CKA_ENCRYPT:                           "CKA_ENCRYPT",
	CKA_DECRYPT:                           "CKA_DECRYPT",
	CKA_WRAP:                              "CKA_WRAP",
	CKA_UNWRAP:                            "CKA_UNWRAP",
	CKA_SIGN:                              "CKA_SIGN",
	CKA_SIGN_RECOVER:                      "CKA_SIGN_RECOVER",
	CKA_VERIFY:                            "CKA_VERIFY",
	CKA_VERIFY_RECOVER:                    "CKA_VERIFY_RECOVER",
	CKA_DERIVE:                            "CKA_DERIVE",
	CKA_START_DATE:                        "CKA_START_DATE",
	CKA_END_DATE:                          "CKA_END_DATE",
	CKA_MODULUS:                           "CKA_MODULUS",
	CKA_MODULUS_BITS:                      "CKA_MODULUS_BITS",
	CKA_PUBLIC_EXPONENT:                   "CKA_PUBLIC_EXPONENT",
	CKA_PRIVATE_EXPONENT:                  "CKA_PRIVATE_EXPONENT",
	CKA_PRIME_1:                           "CKA_PRIME_1",
	CKA_PRIME_2:                           "CKA_PRIME_2",
	CKA_EXPONENT_1:                        "CKA_EXPONENT_1",
	CKA_EXPONENT_2:                        "CKA_EXPONENT_2",
	CKA_COEFFICIENT:                       "CKA_COEFFICIENT",
	CKA_PUBLIC_KEY_INFO:                   "CKA_PUBLIC_KEY_INFO",
	CKA_PRIME:                             "CKA_PRIME",
	CKA_SUBPRIME:                          "CKA_SUBPRIME",
	CKA_BASE:                              "CKA_BASE",
	CKA_PRIME_BITS:                        "CKA_PRIME_BITS",
	CKA_SUBPRIME_BITS:                     "CKA_SUBPRIME_BITS",
	CKA_VALUE_BITS:                        "CKA_VALUE_BITS",
	CKA_VALUE_LEN:                         "CKA_VALUE_LEN",
	CKA_EXTRACTABLE:                       "CKA_EXTRACTABLE",
	CKA_LOCAL:                             "CKA_LOCAL",
	CKA_NEVER_EXTRACTABLE:                 "CKA_NEVER_EXTRACTABLE",
	CKA_ALWAYS_SENSITIVE:                  "CKA_ALWAYS_SENSITIVE",
	CKA_KEY_GEN_MECHANISM:                 "CKA_KEY_GEN_MECHANISM",
	CKA_MODIFIABLE:                        "CKA_MODIFIABLE",
	CKA_COPYABLE:                          "CKA_COPYABLE",
	CKA_DESTROYABLE:                       "CKA_DESTROYABLE",
	CKA_EC_PARAMS:                         "CKA_EC_PARAMS",
	CKA_EC_POINT:                          "CKA_EC_POINT",
	CKA_ALWAYS_AUTHENTICATE:               "CKA_ALWAYS_AUTHENTICATE",
	CKA_WRAP_WITH_TRUSTED:                 "CKA_WRAP_WITH_TRUSTED",
	CKA_WRAP_TEMPLATE:                     "CKA_WRAP_TEMPLATE",
	CKA_UNWRAP_TEMPLATE:                   "CKA_UNWRAP_TEMPLATE",
	CKA_DERIVE_TEMPLATE:                   "CKA_DERIVE_TEMPLATE",
	CKA_ALLOWED_MECHANISMS:                "CKA_ALLOWED_MECHANISMS",
	CKA_PROFILE_ID:                        "CKA_PROFILE_ID",
	CKA_HSS_LEVELS:                        "CKA_HSS_LEVELS",
	CKA_HSS_LMS_TYPE:                      "CKA_HSS_LMS_TYPE",
	CKA_HSS_LMOTS_TYPE:                    "CKA_HSS_LMOTS_TYPE",
	CKA_HSS_LMS_TYPES:                     "CKA_HSS_LMS_TYPES",
	CKA_HSS_LMOTS_TYPES:                   "CKA_HSS_LMOTS_TYPES",
	CKA_HSS_KEYS_REMAINING:                "CKA_HSS_KEYS_REMAINING",
	CKA_PARAMETER_SET:                     "CKA_PARAMETER_SET",
	CKA_OBJECT_VALIDATION_FLAGS:           "CKA_OBJECT_VALIDATION_FLAGS",
	CKA_VALIDATION_TYPE:                   "CKA_VALIDATION_TYPE",
	CKA_VALIDATION_VERSION:                "CKA_VALIDATION_VERSION",
	CKA_VALIDATION_LEVEL:                  "CKA_VALIDATION_LEVEL",
	CKA_VALIDATION_MODULE_ID:              "CKA_VALIDATION_MODULE_ID",
	CKA_VALIDATION_FLAG:                   "CKA_VALIDATION_FLAG",
	CKA_VALIDATION_AUTHORITY_TYPE:         "CKA_VALIDATION_AUTHORITY_TYPE",
	CKA_VALIDATION_COUNTRY:                "CKA_VALIDATION_COUNTRY",
	CKA_VALIDATION_CERTIFICATE_IDENTIFIER: "CKA_VALIDATION_CERTIFICATE_IDENTIFIER",
	CKA_VALIDATION_CERTIFICATE_URI:        "CKA_VALIDATION_CERTIFICATE_URI",
	CKA_VALIDATION_VENDOR_URI:             "CKA_VALIDATION_VENDOR_URI",
	CKA_VALIDATION_PROFILE:                "CKA_VALIDATION_PROFILE",
	CKA_ENCAPSULATE_TEMPLATE:              "CKA_ENCAPSULATE_TEMPLATE",
	CKA_DECAPSULATE_TEMPLATE:              "CKA_DECAPSULATE_TEMPLATE",
	CKA_TRUST_SERVER_AUTH:                 "CKA_TRUST_SERVER_AUTH",
	CKA_TRUST_CLIENT_AUTH:                 "CKA_TRUST_CLIENT_AUTH",
	CKA_TRUST_CODE_SIGNING:                "CKA_TRUST_CODE_SIGNING",
	CKA_TRUST_EMAIL_PROTECTION:            "CKA_TRUST_EMAIL_PROTECTION",
	CKA_TRUST_IPSEC_IKE:                   "CKA_TRUST_IPSEC_IKE",
	CKA_TRUST_TIME_STAMPING:               "CKA_TRUST_TIME_STAMPING",
	CKA_TRUST_OCSP_SIGNING:                "CKA_TRUST_OCSP_SIGNING",
	CKA_ENCAPSULATE:                       "CKA_ENCAPSULATE",
	CKA_DECAPSULATE:                       "CKA_DECAPSULATE",
	CKA_HASH_OF_CERTIFICATE:               "CKA_HASH_OF_CERTIFICATE",
	CKA_PUBLIC_CRC64_VALUE:                "CKA_PUBLIC_CRC64_VALUE",
	CKA_SEED:                              "CKA_SEED",
	CKA_VENDOR_DEFINED:                    "CKA_VENDOR_DEFINED",
}

// String returns the string representation of the attribute type.
func (at AttributeType) String() string {
	if name, ok := attributeTypeNames[at]; ok {
		return name
	}
	if at >= CKA_VENDOR_DEFINED {
		return "CKA_VENDOR_DEFINED+0x" + uitoaHex(uint32(at-CKA_VENDOR_DEFINED))
	}
	return "CKA_UNKNOWN(0x" + uitoaHex(uint32(at)) + ")"
}

// ParameterSetType represents a PKCS#11 v3.2 parameter set identifier (CK_PARAMETER_SET_TYPE).
// Parameter set values are scoped per algorithm — different algorithms may reuse the same
// numeric values (e.g., ML-DSA-44 and ML-KEM-512 both use 0x00000001).
type ParameterSetType uint32

// PKCS#11 v3.2 ML-DSA parameter sets (CKP_ML_DSA_*)
// Reference: OASIS PKCS#11 v3.2, Section 2.3
const (
	CKP_ML_DSA_44 ParameterSetType = 0x00000001
	CKP_ML_DSA_65 ParameterSetType = 0x00000002
	CKP_ML_DSA_87 ParameterSetType = 0x00000003
)

// PKCS#11 v3.2 ML-KEM parameter sets (CKP_ML_KEM_*)
// Reference: OASIS PKCS#11 v3.2, Section 2.3
const (
	CKP_ML_KEM_512  ParameterSetType = 0x00000001
	CKP_ML_KEM_768  ParameterSetType = 0x00000002
	CKP_ML_KEM_1024 ParameterSetType = 0x00000003
)

// PKCS#11 v3.2 SLH-DSA parameter sets (CKP_SLH_DSA_*)
// Reference: OASIS PKCS#11 v3.2, Section 2.3
const (
	CKP_SLH_DSA_SHA2_128S  ParameterSetType = 0x00000001
	CKP_SLH_DSA_SHA2_128F  ParameterSetType = 0x00000002
	CKP_SLH_DSA_SHA2_192S  ParameterSetType = 0x00000003
	CKP_SLH_DSA_SHA2_192F  ParameterSetType = 0x00000004
	CKP_SLH_DSA_SHA2_256S  ParameterSetType = 0x00000005
	CKP_SLH_DSA_SHA2_256F  ParameterSetType = 0x00000006
	CKP_SLH_DSA_SHAKE_128S ParameterSetType = 0x00000007
	CKP_SLH_DSA_SHAKE_128F ParameterSetType = 0x00000008
	CKP_SLH_DSA_SHAKE_192S ParameterSetType = 0x00000009
	CKP_SLH_DSA_SHAKE_192F ParameterSetType = 0x0000000A
	CKP_SLH_DSA_SHAKE_256S ParameterSetType = 0x0000000B
	CKP_SLH_DSA_SHAKE_256F ParameterSetType = 0x0000000C
)

// parameterSetNames maps parameter set values to human-readable names.
// Note: since values are scoped per algorithm, names include the algorithm prefix.
var parameterSetNames = map[string]ParameterSetType{
	"ML-DSA-44":          CKP_ML_DSA_44,
	"ML-DSA-65":          CKP_ML_DSA_65,
	"ML-DSA-87":          CKP_ML_DSA_87,
	"ML-KEM-512":         CKP_ML_KEM_512,
	"ML-KEM-768":         CKP_ML_KEM_768,
	"ML-KEM-1024":        CKP_ML_KEM_1024,
	"SLH-DSA-SHA2-128S":  CKP_SLH_DSA_SHA2_128S,
	"SLH-DSA-SHA2-128F":  CKP_SLH_DSA_SHA2_128F,
	"SLH-DSA-SHA2-192S":  CKP_SLH_DSA_SHA2_192S,
	"SLH-DSA-SHA2-192F":  CKP_SLH_DSA_SHA2_192F,
	"SLH-DSA-SHA2-256S":  CKP_SLH_DSA_SHA2_256S,
	"SLH-DSA-SHA2-256F":  CKP_SLH_DSA_SHA2_256F,
	"SLH-DSA-SHAKE-128S": CKP_SLH_DSA_SHAKE_128S,
	"SLH-DSA-SHAKE-128F": CKP_SLH_DSA_SHAKE_128F,
	"SLH-DSA-SHAKE-192S": CKP_SLH_DSA_SHAKE_192S,
	"SLH-DSA-SHAKE-192F": CKP_SLH_DSA_SHAKE_192F,
	"SLH-DSA-SHAKE-256S": CKP_SLH_DSA_SHAKE_256S,
	"SLH-DSA-SHAKE-256F": CKP_SLH_DSA_SHAKE_256F,
}

// sensitiveAttributes lists attributes that should not be revealed.
var sensitiveAttributes = map[AttributeType]bool{
	CKA_VALUE:            true,
	CKA_PRIVATE_EXPONENT: true,
	CKA_PRIME_1:          true,
	CKA_PRIME_2:          true,
	CKA_EXPONENT_1:       true,
	CKA_EXPONENT_2:       true,
	CKA_COEFFICIENT:      true,
}

// IsSensitiveAttribute returns true if the attribute type is sensitive.
func IsSensitiveAttribute(attrType AttributeType) bool {
	return sensitiveAttributes[attrType]
}

// readOnlyAttributes lists attributes that cannot be modified after creation.
var readOnlyAttributes = map[AttributeType]bool{
	CKA_CLASS:             true,
	CKA_KEY_TYPE:          true,
	CKA_LOCAL:             true,
	CKA_NEVER_EXTRACTABLE: true,
	CKA_ALWAYS_SENSITIVE:  true,
	CKA_KEY_GEN_MECHANISM: true,
	CKA_MODULUS:           true,
	CKA_PUBLIC_EXPONENT:   true,
	CKA_EC_PARAMS:         true,
	CKA_EC_POINT:          true,
	CKA_UNIQUE_ID:         true,
}

// IsReadOnlyAttribute returns true if the attribute type is read-only.
func IsReadOnlyAttribute(attrType AttributeType) bool {
	return readOnlyAttributes[attrType]
}

// uitoaHex converts a uint32 to a hex string without importing strconv.
func uitoaHex(val uint32) string {
	if val == 0 {
		return "0"
	}
	const hexDigits = "0123456789ABCDEF"
	var buf [8]byte
	i := len(buf) - 1
	for val > 0 {
		buf[i] = hexDigits[val&0xF]
		val >>= 4
		i--
	}
	return string(buf[i+1:])
}

// Attribute represents a single PKCS#11 attribute (CK_ATTRIBUTE).
type Attribute struct {
	Type  AttributeType
	Value []byte
}

// NewAttribute creates a new attribute with the given type and value.
func NewAttribute(attrType AttributeType, value []byte) Attribute {
	return Attribute{
		Type:  attrType,
		Value: copyBytes(value),
	}
}

// NewBoolAttribute creates a new boolean attribute.
// PKCS#11 represents booleans as a single CK_BBOOL byte (0 = false, 1 = true).
func NewBoolAttribute(attrType AttributeType, value bool) Attribute {
	var v byte
	if value {
		v = 1
	}
	return Attribute{Type: attrType, Value: []byte{v}}
}

// NewUint32Attribute creates a new uint32 attribute.
// Uses little-endian encoding as per PKCS#11 specification.
func NewUint32Attribute(attrType AttributeType, value uint32) Attribute {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, value)
	return Attribute{Type: attrType, Value: buf}
}

// NewUint64Attribute creates a new uint64 attribute.
func NewUint64Attribute(attrType AttributeType, value uint64) Attribute {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, value)
	return Attribute{Type: attrType, Value: buf}
}

// NewStringAttribute creates a new string attribute.
func NewStringAttribute(attrType AttributeType, value string) Attribute {
	return Attribute{Type: attrType, Value: []byte(value)}
}

// GetBool returns the boolean value of the attribute.
func (a Attribute) GetBool() (bool, error) {
	if len(a.Value) != 1 {
		return false, NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
	}
	return a.Value[0] != 0, nil
}

// GetUint32 returns the uint32 value of the attribute.
func (a Attribute) GetUint32() (uint32, error) {
	if len(a.Value) < 4 {
		return 0, NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
	}
	return binary.LittleEndian.Uint32(a.Value[:4]), nil
}

// GetUint64 returns the uint64 value of the attribute.
func (a Attribute) GetUint64() (uint64, error) {
	if len(a.Value) < 8 {
		return 0, NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
	}
	return binary.LittleEndian.Uint64(a.Value[:8]), nil
}

// GetString returns the string value of the attribute.
func (a Attribute) GetString() string {
	return string(a.Value)
}

// copyBytes creates a copy of the byte slice.
func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// Object represents a PKCS#11 object with its attributes.
// Objects are the basic storage unit in PKCS#11 tokens.
type Object struct {
	// Handle is the unique identifier for this object within a session.
	Handle ObjectHandle

	// Class specifies the type of object (data, key, certificate, etc.).
	Class ObjectClass

	// KeyType specifies the key algorithm (only valid for key objects).
	KeyType KeyType

	// Attributes stores the object's attribute values.
	// Keys are AttributeType values.
	Attributes map[AttributeType][]byte

	// KeyID is an optional reference to a backend key identifier.
	// This allows mapping PKCS#11 objects to keys stored in external backends.
	KeyID string

	// BackendName identifies which key backend manages this object.
	BackendName string

	// IsToken indicates if this is a token object (persistent) vs session object.
	IsToken bool

	// IsPrivate indicates if this object requires user authentication to access.
	IsPrivate bool

	// IsSensitive indicates if this object contains sensitive data.
	IsSensitive bool

	// IsExtractable indicates if the key material can be extracted.
	IsExtractable bool

	// IsModifiable indicates if the object can be modified.
	IsModifiable bool

	// IsCopyable indicates if the object can be copied.
	IsCopyable bool

	// IsDestroyable indicates if the object can be destroyed.
	IsDestroyable bool
}

// NewObject creates a new object with the specified class.
func NewObject(class ObjectClass) *Object {
	obj := &Object{
		Class:         class,
		Attributes:    make(map[AttributeType][]byte),
		IsModifiable:  true,
		IsCopyable:    true,
		IsDestroyable: true,
	}
	// Set CKA_CLASS attribute for template matching compatibility
	obj.Attributes[CKA_CLASS] = NewUint32Attribute(CKA_CLASS, uint32(class)).Value
	return obj
}

// NewKeyObject creates a new key object with the specified class and type.
func NewKeyObject(class ObjectClass, keyType KeyType) *Object {
	obj := NewObject(class)
	obj.KeyType = keyType
	obj.SetAttribute(CKA_KEY_TYPE, NewUint32Attribute(CKA_KEY_TYPE, uint32(keyType)).Value)
	return obj
}

// SetAttribute sets an attribute value on the object.
func (o *Object) SetAttribute(attrType AttributeType, value []byte) {
	o.Attributes[attrType] = copyBytes(value)

	// Update convenience fields based on attribute
	switch attrType {
	case CKA_CLASS:
		if len(value) >= 4 {
			o.Class = ObjectClass(binary.LittleEndian.Uint32(value))
		}
	case CKA_KEY_TYPE:
		if len(value) >= 4 {
			o.KeyType = KeyType(binary.LittleEndian.Uint32(value))
		}
	case CKA_TOKEN:
		if len(value) >= 1 {
			o.IsToken = value[0] != 0
		}
	case CKA_PRIVATE:
		if len(value) >= 1 {
			o.IsPrivate = value[0] != 0
		}
	case CKA_SENSITIVE:
		if len(value) >= 1 {
			o.IsSensitive = value[0] != 0
		}
	case CKA_EXTRACTABLE:
		if len(value) >= 1 {
			o.IsExtractable = value[0] != 0
		}
	case CKA_MODIFIABLE:
		if len(value) >= 1 {
			o.IsModifiable = value[0] != 0
		}
	case CKA_COPYABLE:
		if len(value) >= 1 {
			o.IsCopyable = value[0] != 0
		}
	case CKA_DESTROYABLE:
		if len(value) >= 1 {
			o.IsDestroyable = value[0] != 0
		}
	}
}

// GetAttribute retrieves an attribute value from the object.
// Returns nil if the attribute is not set.
func (o *Object) GetAttribute(attrType AttributeType) []byte {
	return o.Attributes[attrType]
}

// HasAttribute checks if the object has the specified attribute.
func (o *Object) HasAttribute(attrType AttributeType) bool {
	_, exists := o.Attributes[attrType]
	return exists
}

// GetLabel returns the object's label attribute as a string.
func (o *Object) GetLabel() string {
	if label, ok := o.Attributes[CKA_LABEL]; ok {
		return string(label)
	}
	return ""
}

// GetID returns the object's ID attribute.
func (o *Object) GetID() []byte {
	return o.Attributes[CKA_ID]
}

// MatchesTemplate checks if the object matches all attributes in the template.
// Returns true if all template attributes match the object's attributes.
func (o *Object) MatchesTemplate(template []Attribute) bool {
	for _, attr := range template {
		objValue, exists := o.Attributes[attr.Type]
		if !exists {
			return false
		}
		if !bytes.Equal(objValue, attr.Value) {
			return false
		}
	}
	return true
}

// Clone creates a deep copy of the object.
func (o *Object) Clone() *Object {
	clone := &Object{
		Handle:        0, // New handle will be assigned
		Class:         o.Class,
		KeyType:       o.KeyType,
		Attributes:    make(map[AttributeType][]byte, len(o.Attributes)),
		KeyID:         o.KeyID,
		BackendName:   o.BackendName,
		IsToken:       o.IsToken,
		IsPrivate:     o.IsPrivate,
		IsSensitive:   o.IsSensitive,
		IsExtractable: o.IsExtractable,
		IsModifiable:  o.IsModifiable,
		IsCopyable:    o.IsCopyable,
		IsDestroyable: o.IsDestroyable,
	}
	for k, v := range o.Attributes {
		clone.Attributes[k] = copyBytes(v)
	}
	return clone
}

// FindObjectsState holds the state for an active FindObjects operation.
type FindObjectsState struct {
	// Template is the search template.
	Template []Attribute

	// Matches contains handles of objects that match the template.
	Matches []ObjectHandle

	// Position is the current position in the matches slice.
	Position int
}

// ObjectManager provides thread-safe object management for a PKCS#11 session.
// It handles object creation, lookup, search operations, and lifecycle management.
type ObjectManager struct {
	mu sync.RWMutex

	// objects stores all objects by their handle.
	objects *HandleTable[*Object]

	// sessionObjects tracks session objects (destroyed when session closes).
	sessionObjects map[ObjectHandle]bool

	// findState holds the current FindObjects operation state per session.
	findState map[SessionHandle]*FindObjectsState
}

// NewObjectManager creates a new object manager.
func NewObjectManager() *ObjectManager {
	return &ObjectManager{
		objects:        NewHandleTable[*Object](),
		sessionObjects: make(map[ObjectHandle]bool),
		findState:      make(map[SessionHandle]*FindObjectsState),
	}
}

// CreateObject creates a new object from the provided template.
// Returns the object handle or an error if creation fails.
func (om *ObjectManager) CreateObject(session SessionHandle, template []Attribute) (ObjectHandle, error) {
	om.mu.Lock()
	defer om.mu.Unlock()

	// Extract class from template
	var class ObjectClass
	var hasClass bool
	for _, attr := range template {
		if attr.Type == CKA_CLASS {
			if len(attr.Value) < 4 {
				return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
			}
			class = ObjectClass(binary.LittleEndian.Uint32(attr.Value))
			hasClass = true
			break
		}
	}

	if !hasClass {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_TEMPLATE_INCOMPLETE)
	}

	// Create object with appropriate class
	obj := NewObject(class)

	// Extract key type if this is a key object
	if class == CKO_PUBLIC_KEY || class == CKO_PRIVATE_KEY || class == CKO_SECRET_KEY {
		for _, attr := range template {
			if attr.Type == CKA_KEY_TYPE {
				if len(attr.Value) < 4 {
					return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
				}
				obj.KeyType = KeyType(binary.LittleEndian.Uint32(attr.Value))
				break
			}
		}
	}

	// Apply template attributes
	for _, attr := range template {
		obj.SetAttribute(attr.Type, attr.Value)
	}

	// Allocate handle
	handle, err := om.objects.Allocate(obj)
	if err != nil {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithCause(CKR_DEVICE_MEMORY, err)
	}
	obj.Handle = ObjectHandle(handle)

	// Track session objects
	if !obj.IsToken {
		om.sessionObjects[ObjectHandle(handle)] = true
	}

	return ObjectHandle(handle), nil
}

// CopyObject creates a copy of an existing object with optional attribute modifications.
func (om *ObjectManager) CopyObject(session SessionHandle, handle ObjectHandle, template []Attribute) (ObjectHandle, error) {
	om.mu.Lock()
	defer om.mu.Unlock()

	// Lookup source object
	srcObj, ok := om.objects.Lookup(uint64(handle))
	if !ok {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}

	// Check if object is copyable
	if !srcObj.IsCopyable {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_ACTION_PROHIBITED)
	}

	// Clone the object
	newObj := srcObj.Clone()

	// Apply template modifications
	for _, attr := range template {
		// Check for read-only attributes
		if IsReadOnlyAttribute(attr.Type) {
			return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_ATTRIBUTE_READ_ONLY)
		}
		newObj.SetAttribute(attr.Type, attr.Value)
	}

	// Allocate new handle
	newHandle, err := om.objects.Allocate(newObj)
	if err != nil {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithCause(CKR_DEVICE_MEMORY, err)
	}
	newObj.Handle = ObjectHandle(newHandle)

	// Track session objects
	if !newObj.IsToken {
		om.sessionObjects[ObjectHandle(newHandle)] = true
	}

	return ObjectHandle(newHandle), nil
}

// DestroyObject removes an object from the manager.
func (om *ObjectManager) DestroyObject(session SessionHandle, handle ObjectHandle) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	// Lookup object
	obj, ok := om.objects.Lookup(uint64(handle))
	if !ok {
		return NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}

	// Check if object is destroyable
	if !obj.IsDestroyable {
		return NewPKCS11Error(CKR_ACTION_PROHIBITED)
	}

	// Release handle
	_, ok = om.objects.Release(uint64(handle))
	if !ok {
		return NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}

	// Remove from session objects tracking
	delete(om.sessionObjects, handle)

	return nil
}

// GetAttributeValue retrieves attribute values for an object.
// Per PKCS#11 spec:
//   - If template value is nil, returns required buffer size
//   - If template value is too small, returns CKR_BUFFER_TOO_SMALL
//   - Sensitive attributes on sensitive objects return CKR_ATTRIBUTE_SENSITIVE
func (om *ObjectManager) GetAttributeValue(session SessionHandle, handle ObjectHandle, template []Attribute) ([]Attribute, error) {
	om.mu.RLock()
	defer om.mu.RUnlock()

	obj, ok := om.objects.Lookup(uint64(handle))
	if !ok {
		return nil, NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}

	result := make([]Attribute, len(template))
	var hasError error

	for i, attr := range template {
		result[i].Type = attr.Type

		// Check for sensitive attributes
		if obj.IsSensitive && IsSensitiveAttribute(attr.Type) {
			result[i].Value = nil
			if hasError == nil {
				hasError = NewPKCS11Error(CKR_ATTRIBUTE_SENSITIVE)
			}
			continue
		}

		// Get attribute value
		value, exists := obj.Attributes[attr.Type]
		if !exists {
			result[i].Value = nil
			if hasError == nil {
				hasError = NewPKCS11Error(CKR_ATTRIBUTE_TYPE_INVALID)
			}
			continue
		}

		// Copy value
		result[i].Value = copyBytes(value)
	}

	return result, hasError
}

// SetAttributeValue modifies attribute values for an object.
func (om *ObjectManager) SetAttributeValue(session SessionHandle, handle ObjectHandle, template []Attribute) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	obj, ok := om.objects.Lookup(uint64(handle))
	if !ok {
		return NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}

	// Check if object is modifiable
	if !obj.IsModifiable {
		return NewPKCS11Error(CKR_ACTION_PROHIBITED)
	}

	// Validate all attributes before applying
	for _, attr := range template {
		// Check for read-only attributes
		if IsReadOnlyAttribute(attr.Type) {
			return NewPKCS11Error(CKR_ATTRIBUTE_READ_ONLY)
		}
	}

	// Apply modifications
	for _, attr := range template {
		obj.SetAttribute(attr.Type, attr.Value)
	}

	return nil
}

// FindObjectsInit initializes a search for objects that match the template.
func (om *ObjectManager) FindObjectsInit(session SessionHandle, template []Attribute) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	// Check for existing find operation
	if _, exists := om.findState[session]; exists {
		return NewPKCS11Error(CKR_OPERATION_ACTIVE)
	}

	// Find matching objects
	var matches []ObjectHandle
	om.objects.ForEach(func(handle uint64, obj *Object) bool {
		if obj.MatchesTemplate(template) {
			matches = append(matches, ObjectHandle(handle))
		}
		return true
	})

	// Create find state
	om.findState[session] = &FindObjectsState{
		Template: template,
		Matches:  matches,
		Position: 0,
	}

	return nil
}

// FindObjects returns the next batch of matching object handles.
func (om *ObjectManager) FindObjects(session SessionHandle, maxCount int) ([]ObjectHandle, error) {
	om.mu.Lock()
	defer om.mu.Unlock()

	state, exists := om.findState[session]
	if !exists {
		return nil, NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	// Calculate how many objects to return
	remaining := len(state.Matches) - state.Position
	count := maxCount
	if count > remaining {
		count = remaining
	}

	// Get handles
	handles := make([]ObjectHandle, count)
	copy(handles, state.Matches[state.Position:state.Position+count])
	state.Position += count

	return handles, nil
}

// FindObjectsFinal terminates a search operation.
func (om *ObjectManager) FindObjectsFinal(session SessionHandle) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if _, exists := om.findState[session]; !exists {
		return NewPKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
	}

	delete(om.findState, session)
	return nil
}

// GetObject retrieves an object by its handle.
func (om *ObjectManager) GetObject(handle ObjectHandle) (*Object, error) {
	om.mu.RLock()
	defer om.mu.RUnlock()

	obj, ok := om.objects.Lookup(uint64(handle))
	if !ok {
		return nil, NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}

	return obj, nil
}

// DestroySessionObjects removes all session objects for the given session.
// This should be called when a session is closed.
func (om *ObjectManager) DestroySessionObjects(session SessionHandle) {
	om.mu.Lock()
	defer om.mu.Unlock()

	// Remove all session objects
	for handle := range om.sessionObjects {
		om.objects.Release(uint64(handle))
		delete(om.sessionObjects, handle)
	}

	// Clean up any find state for this session
	delete(om.findState, session)
}

// Size returns the total number of objects.
func (om *ObjectManager) Size() int {
	return om.objects.Size()
}

// SessionObjectCount returns the number of session objects.
func (om *ObjectManager) SessionObjectCount() int {
	om.mu.RLock()
	defer om.mu.RUnlock()
	return len(om.sessionObjects)
}

// HasFindOperation checks if a find operation is active for the session.
func (om *ObjectManager) HasFindOperation(session SessionHandle) bool {
	om.mu.RLock()
	defer om.mu.RUnlock()
	_, exists := om.findState[session]
	return exists
}

// AddObject adds a pre-constructed object to the manager.
// Used primarily for restoring objects from persistent storage.
func (om *ObjectManager) AddObject(obj *Object) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	// If object has a specific handle (e.g., from restoration), insert at that handle
	if obj.Handle != ObjectHandle(InvalidHandle) {
		// Try to update if it exists, otherwise insert at specific handle
		if err := om.objects.Update(uint64(obj.Handle), obj); err != nil {
			// Handle doesn't exist, insert at the specific handle (for restoration)
			if insertErr := om.objects.Insert(uint64(obj.Handle), obj); insertErr != nil {
				return insertErr
			}
		}
	} else {
		// No handle set, allocate a new one
		handle, allocErr := om.objects.Allocate(obj)
		if allocErr != nil {
			return allocErr
		}
		obj.Handle = ObjectHandle(handle)
	}

	// Track session objects
	if !obj.IsToken {
		om.sessionObjects[obj.Handle] = true
	}

	return nil
}

// SetNextHandle sets the next handle to allocate.
// Used to ensure handle counter is greater than restored objects.
func (om *ObjectManager) SetNextHandle(handle ObjectHandle) {
	om.mu.Lock()
	defer om.mu.Unlock()

	// Find the current maximum handle in use
	currentMax := uint64(0)
	om.objects.ForEach(func(h uint64, _ *Object) bool {
		if h > currentMax {
			currentMax = h
		}
		return true
	})

	// Use the higher of the requested handle or the current max
	targetHandle := uint64(handle)
	if currentMax >= targetHandle {
		targetHandle = currentMax + 1
	}

	// Set the HandleTable's atomic counter to ensure new allocations
	// start at or above the target handle
	om.objects.SetCounter(targetHandle)
}
