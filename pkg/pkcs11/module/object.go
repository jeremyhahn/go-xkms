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
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/jeremyhahn/go-enclave"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
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

	// PKCS#11 v3.2 KEM Template Attributes.
	//
	// Unlike every other *_TEMPLATE attribute, OASIS defines these two
	// without the CKF_ARRAY_ATTRIBUTE bit: the normative v3.2 header gives
	// them the plain values 0x62A and 0x62B. The values below follow the
	// header, because a C application compiles against it and would send
	// the plain values regardless of what this module considers tidier.
	CKA_ENCAPSULATE_TEMPLATE AttributeType = 0x0000062A
	CKA_DECAPSULATE_TEMPLATE AttributeType = 0x0000062B

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

// PKCS#11 v3.2 SLH-DSA parameter sets (CKP_SLH_DSA_*).
//
// OASIS interleaves the two hash families rather than listing all six SHA2
// sets before all six SHAKE sets: each security level contributes SHA2 then
// SHAKE, small signature ("S") before fast signature ("F"). The constants are
// listed below in that numeric order. Only the first and last entries survive
// the grouped-by-hash-family layout unchanged, so, for example,
// CKP_SLH_DSA_SHAKE_128S is 0x02 and NOT 0x07, and CKP_SLH_DSA_SHA2_256F is
// 0x0B and NOT 0x06.
//
// Reference: OASIS PKCS#11 v3.2, Section 2.3
const (
	CKP_SLH_DSA_SHA2_128S  ParameterSetType = 0x00000001
	CKP_SLH_DSA_SHAKE_128S ParameterSetType = 0x00000002
	CKP_SLH_DSA_SHA2_128F  ParameterSetType = 0x00000003
	CKP_SLH_DSA_SHAKE_128F ParameterSetType = 0x00000004
	CKP_SLH_DSA_SHA2_192S  ParameterSetType = 0x00000005
	CKP_SLH_DSA_SHAKE_192S ParameterSetType = 0x00000006
	CKP_SLH_DSA_SHA2_192F  ParameterSetType = 0x00000007
	CKP_SLH_DSA_SHAKE_192F ParameterSetType = 0x00000008
	CKP_SLH_DSA_SHA2_256S  ParameterSetType = 0x00000009
	CKP_SLH_DSA_SHAKE_256S ParameterSetType = 0x0000000A
	CKP_SLH_DSA_SHA2_256F  ParameterSetType = 0x0000000B
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
//
// CKA_TOKEN, CKA_PRIVATE and CKA_MODIFIABLE appear here because PKCS#11 v3.2
// §4.1.1 permits changing them only while copying an object, never in place
// through C_SetAttributeValue.
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
	CKA_TOKEN:             true,
	CKA_PRIVATE:           true,
	CKA_MODIFIABLE:        true,
	CKA_DESTROYABLE:       true,
}

// keyMaterialAttributes name the attributes that carry a key's actual secret or
// public value. Per PKCS#11 v3.2 §4.1.1 they may be supplied once in a creation
// template but are never modifiable afterwards — their object-table footnotes
// are 1,4,6,7, never the "modifiable" footnote 8. This is kept separate from
// readOnlyAttributes because CKA_VALUE is class-dependent: a CKO_DATA object's
// CKA_VALUE is freely modifiable, so the rule is scoped to key classes through
// isImmutableKeyMaterial rather than applied unconditionally.
var keyMaterialAttributes = map[AttributeType]bool{
	CKA_VALUE:            true, // secret keys; EC / EdDSA private scalar
	CKA_PRIVATE_EXPONENT: true,
	CKA_PRIME_1:          true,
	CKA_PRIME_2:          true,
	CKA_EXPONENT_1:       true,
	CKA_EXPONENT_2:       true,
	CKA_COEFFICIENT:      true,
}

// isImmutableKeyMaterial reports whether attrType carries key material that an
// object of the given class may not have modified after creation. It scopes the
// class-independent keyMaterialAttributes set to key classes, so a CKO_DATA
// object's modifiable CKA_VALUE is left untouched while a secret or private
// key's value cannot be rewritten in place or through a copy template.
func isImmutableKeyMaterial(class ObjectClass, attrType AttributeType) bool {
	return isKeyClass(class) && keyMaterialAttributes[attrType]
}

// computedAttributes lists attributes the token derives itself. A caller may
// never supply them in a creation template; doing so would let an application
// forge provenance claims such as "this key was generated on the token".
var computedAttributes = map[AttributeType]bool{
	CKA_LOCAL:             true,
	CKA_ALWAYS_SENSITIVE:  true,
	CKA_NEVER_EXTRACTABLE: true,
	CKA_KEY_GEN_MECHANISM: true,
	CKA_UNIQUE_ID:         true,
}

// requiredAttributes lists the attributes a creation template must carry for
// each object class, per the object definitions in PKCS#11 v3.2 §4.
var requiredAttributes = map[ObjectClass][]AttributeType{
	CKO_DATA:        {},
	CKO_CERTIFICATE: {CKA_CERTIFICATE_TYPE, CKA_VALUE},
	CKO_PUBLIC_KEY:  {CKA_KEY_TYPE},
	CKO_PRIVATE_KEY: {CKA_KEY_TYPE},
	CKO_SECRET_KEY:  {CKA_KEY_TYPE},
}

// copyModifiableAttributes lists the otherwise read-only attributes that
// PKCS#11 v3.2 §4.1.1 permits a C_CopyObject template to change, because the
// copy is a new object rather than a mutation of the original.
var copyModifiableAttributes = map[AttributeType]bool{
	CKA_TOKEN:       true,
	CKA_PRIVATE:     true,
	CKA_MODIFIABLE:  true,
	CKA_DESTROYABLE: true,
}

// oneWayBoolAttributes lists boolean attributes that may only ever transition
// in a single direction, mapping each to the value it may be changed *to*.
// Allowing any of them to be reversed would let a caller strip a protection
// from live key material, which is why each is one-way in the first place.
//
// PKCS#11 v3.2 Table 13 states the rules as attribute footnotes:
//
//	footnote 11  "Attribute cannot be changed once set to CK_TRUE. It becomes
//	             a read only attribute."  -- CKA_SENSITIVE, CKA_WRAP_WITH_TRUSTED
//	footnote 12  "Attribute cannot be changed once set to CK_FALSE. It becomes
//	             a read only attribute."  -- CKA_EXTRACTABLE
//
// and Table 17 states CKA_COPYABLE inline: "Can't be set to TRUE once it is set
// to FALSE."
//
// CKA_WRAP_WITH_TRUSTED is here for the same reason CKA_TRUSTED is SO-gated in
// checkTrustedAssertion, and neither guard is sufficient alone: CKA_TRUSTED on
// the wrapping key and CKA_WRAP_WITH_TRUSTED on the target key are the two
// halves of one restriction, so a caller able to clear either one can wrap a
// key the partition was drawn to protect.
var oneWayBoolAttributes = map[AttributeType]bool{
	CKA_SENSITIVE:         true,
	CKA_EXTRACTABLE:       false,
	CKA_COPYABLE:          false,
	CKA_WRAP_WITH_TRUSTED: true,
}

// IsReadOnlyAttribute returns true if the attribute type is read-only.
func IsReadOnlyAttribute(attrType AttributeType) bool {
	return readOnlyAttributes[attrType]
}

// checkOneWayTransition rejects a change that would reverse a one-way boolean
// attribute. It returns nil for attributes that have no direction constraint.
func checkOneWayTransition(obj *Object, attr Attribute) error {
	allowed, constrained := oneWayBoolAttributes[attr.Type]
	if !constrained {
		return nil
	}
	if len(attr.Value) < 1 {
		return NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
	}

	current := obj.GetAttribute(attr.Type)
	if len(current) < 1 {
		return nil
	}

	// Only a transition to the allowed target value may change the attribute.
	requested := attr.Value[0] != 0
	if (current[0] != 0) != requested && requested != allowed {
		return NewPKCS11Error(CKR_ATTRIBUTE_READ_ONLY)
	}
	return nil
}

// checkTrustedAssertion refuses a template that claims CKA_TRUSTED without the
// authority to do so, and refuses to retract one that is already asserted.
//
// PKCS#11 v3.2 Table 13 footnote 10 says of CKA_TRUSTED "Can only be set to
// CK_TRUE by the SO user", §4.6.2 repeats it for certificates ("cannot be set
// to CK_TRUE by an application... MUST be set by a token initialization
// application or by the token's SO"), and footnote 11 makes it read-only
// thereafter.
//
// The rule is load-bearing rather than ceremonial. CKA_TRUSTED on the wrapping
// key is the only thing CKA_WRAP_WITH_TRUSTED consults, so a caller who can
// mark a key of their own trusted can wrap every key that restriction was drawn
// to protect. obj is the object the template is being applied to, and nil for a
// creation, which has no prior value to preserve.
func checkTrustedAssertion(ctx AccessContext, obj *Object, template []Attribute) error {
	// A trusted certificate cannot be modified (v3.2 §4.6: a certificate with
	// CKA_TRUSTED = CK_TRUE is immutable). The guard covers every attribute in
	// the template, not only CKA_TRUSTED: the subject, value or usage of an
	// SO-vouched certificate must be as fixed as the trust bit, or an attacker
	// able to rewrite them would defeat the trust anchor while leaving the bit
	// set. Applies to C_SetAttributeValue and to a modifying C_CopyObject alike.
	if obj != nil && obj.Class == CKO_CERTIFICATE && len(template) > 0 &&
		boolAttributeIsTrue(obj.GetAttribute(CKA_TRUSTED)) {
		return NewPKCS11Error(CKR_ATTRIBUTE_READ_ONLY)
	}

	for _, attr := range template {
		if attr.Type != CKA_TRUSTED {
			continue
		}
		if len(attr.Value) < 1 {
			return NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
		}

		requested := attr.Value[0] != 0
		if requested && !ctx.SecurityOfficer {
			return NewPKCS11Error(CKR_ATTRIBUTE_READ_ONLY)
		}
		if !requested && obj != nil && boolAttributeIsTrue(obj.GetAttribute(CKA_TRUSTED)) {
			return NewPKCS11Error(CKR_ATTRIBUTE_READ_ONLY)
		}
	}
	return nil
}

// attributePolicy classifies what this token actually does with an attribute
// type.
//
// The classification exists because an ignored attribute and an enforced one
// are indistinguishable from the wire: both round-trip unchanged through
// C_SetAttributeValue and C_GetAttributeValue, so an application that sets a
// restriction the token never reads cannot tell that it bought nothing. An
// attribute whose entire meaning is a promise this module cannot keep must
// therefore be refused rather than stored. PKCS#11 v3.2 §5.7.5 lists
// CKR_ATTRIBUTE_TYPE_INVALID for the case where "an invalid attribute type was
// specified in a template", which is what an attribute the token does not
// support is.
type attributePolicy uint8

const (
	// attrStored marks a descriptive attribute. It records something about the
	// object without constraining any later operation, so storing it verbatim
	// and handing it back on request is the complete implementation.
	attrStored attributePolicy = iota

	// attrEnforced marks an attribute that constrains what the token will do,
	// and that some code path actually reads. The boolean usage flags and the
	// structural attributes are enforced by the object and operation entry
	// points; CKA_ALLOWED_MECHANISMS by Object.CheckAllowedMechanism;
	// CKA_START_DATE and CKA_END_DATE by Object.CheckValidityPeriod; and the
	// *_TEMPLATE attributes by Object.CheckWrapTemplate and
	// Object.ApplyAttributeTemplate.
	attrEnforced

	// attrUnsupported marks an attribute whose whole meaning is an enforcement
	// promise this module cannot keep: one-time-signature exhaustion counters
	// with no HSS/LMS implementation behind them, EKU trust bindings with no
	// CKO_TRUST interpretation, and validation-state claims with no validation
	// objects. Accepting one would sell the caller a guarantee that does not
	// exist, so a template carrying one is rejected.
	attrUnsupported
)

// attributeHandler describes the token's treatment of a single attribute type.
type attributeHandler struct {
	// policy says whether the token stores, enforces or refuses the attribute.
	policy attributePolicy

	// validate rejects a value the token could not act on. It is set only for
	// attributes whose value this module parses; a nil validate accepts any
	// value, which is the correct treatment of an opaque byte-array attribute.
	validate func(value []byte) error
}

// attributeHandlers is the allowlist of attribute types a caller may put in a
// creation, copy or modification template. It names every CKA_ constant this
// module defines, which is every attribute the shipped pkcs11t.h header can
// produce, so an attribute is accounted for by name rather than by having
// escaped a deny-list.
//
// An attribute type absent from this table is one the module has never heard
// of and is refused. The sole exception is the vendor-defined range, which
// PKCS#11 v3.2 §4.4 reserves for attributes a token defines for itself;
// checkAttributeSupported admits that range before consulting the table.
var attributeHandlers = map[AttributeType]attributeHandler{
	CKA_CLASS:                             {policy: attrEnforced},
	CKA_TOKEN:                             {policy: attrEnforced},
	CKA_PRIVATE:                           {policy: attrEnforced},
	CKA_LABEL:                             {policy: attrStored},
	CKA_UNIQUE_ID:                         {policy: attrEnforced},
	CKA_APPLICATION:                       {policy: attrStored},
	CKA_VALUE:                             {policy: attrStored},
	CKA_OBJECT_ID:                         {policy: attrStored},
	CKA_CERTIFICATE_TYPE:                  {policy: attrStored},
	CKA_ISSUER:                            {policy: attrStored},
	CKA_SERIAL_NUMBER:                     {policy: attrStored},
	CKA_AC_ISSUER:                         {policy: attrStored},
	CKA_OWNER:                             {policy: attrStored},
	CKA_ATTR_TYPES:                        {policy: attrStored},
	CKA_TRUSTED:                           {policy: attrEnforced},
	CKA_CERTIFICATE_CATEGORY:              {policy: attrStored},
	CKA_JAVA_MIDP_SECURITY_DOMAIN:         {policy: attrStored},
	CKA_URL:                               {policy: attrStored},
	CKA_HASH_OF_SUBJECT_PUBLIC_KEY:        {policy: attrStored},
	CKA_HASH_OF_ISSUER_PUBLIC_KEY:         {policy: attrStored},
	CKA_NAME_HASH_ALGORITHM:               {policy: attrStored},
	CKA_CHECK_VALUE:                       {policy: attrStored},
	CKA_KEY_TYPE:                          {policy: attrEnforced},
	CKA_SUBJECT:                           {policy: attrStored},
	CKA_ID:                                {policy: attrStored},
	CKA_SENSITIVE:                         {policy: attrEnforced},
	CKA_ENCRYPT:                           {policy: attrEnforced},
	CKA_DECRYPT:                           {policy: attrEnforced},
	CKA_WRAP:                              {policy: attrEnforced},
	CKA_UNWRAP:                            {policy: attrEnforced},
	CKA_SIGN:                              {policy: attrEnforced},
	CKA_SIGN_RECOVER:                      {policy: attrEnforced},
	CKA_VERIFY:                            {policy: attrEnforced},
	CKA_VERIFY_RECOVER:                    {policy: attrEnforced},
	CKA_DERIVE:                            {policy: attrEnforced},
	CKA_START_DATE:                        {policy: attrEnforced, validate: validateDateValue},
	CKA_END_DATE:                          {policy: attrEnforced, validate: validateDateValue},
	CKA_MODULUS:                           {policy: attrStored},
	CKA_MODULUS_BITS:                      {policy: attrStored},
	CKA_PUBLIC_EXPONENT:                   {policy: attrStored},
	CKA_PRIVATE_EXPONENT:                  {policy: attrStored},
	CKA_PRIME_1:                           {policy: attrStored},
	CKA_PRIME_2:                           {policy: attrStored},
	CKA_EXPONENT_1:                        {policy: attrStored},
	CKA_EXPONENT_2:                        {policy: attrStored},
	CKA_COEFFICIENT:                       {policy: attrStored},
	CKA_PUBLIC_KEY_INFO:                   {policy: attrStored},
	CKA_PRIME:                             {policy: attrStored},
	CKA_SUBPRIME:                          {policy: attrStored},
	CKA_BASE:                              {policy: attrStored},
	CKA_PRIME_BITS:                        {policy: attrStored},
	CKA_SUBPRIME_BITS:                     {policy: attrStored},
	CKA_VALUE_BITS:                        {policy: attrStored},
	CKA_VALUE_LEN:                         {policy: attrStored},
	CKA_EXTRACTABLE:                       {policy: attrEnforced},
	CKA_LOCAL:                             {policy: attrEnforced},
	CKA_NEVER_EXTRACTABLE:                 {policy: attrEnforced},
	CKA_ALWAYS_SENSITIVE:                  {policy: attrEnforced},
	CKA_KEY_GEN_MECHANISM:                 {policy: attrEnforced},
	CKA_MODIFIABLE:                        {policy: attrEnforced},
	CKA_COPYABLE:                          {policy: attrEnforced},
	CKA_DESTROYABLE:                       {policy: attrEnforced},
	CKA_EC_PARAMS:                         {policy: attrStored},
	CKA_EC_POINT:                          {policy: attrStored},
	CKA_SECONDARY_AUTH:                    {policy: attrStored},
	CKA_AUTH_PIN_FLAGS:                    {policy: attrStored},
	CKA_ALWAYS_AUTHENTICATE:               {policy: attrEnforced},
	CKA_WRAP_WITH_TRUSTED:                 {policy: attrEnforced},
	CKA_WRAP_TEMPLATE:                     {policy: attrEnforced, validate: validateAttributeArrayValue},
	CKA_UNWRAP_TEMPLATE:                   {policy: attrEnforced, validate: validateAttributeArrayValue},
	CKA_DERIVE_TEMPLATE:                   {policy: attrEnforced, validate: validateAttributeArrayValue},
	CKA_OTP_FORMAT:                        {policy: attrStored},
	CKA_OTP_LENGTH:                        {policy: attrStored},
	CKA_OTP_TIME_INTERVAL:                 {policy: attrStored},
	CKA_OTP_USER_FRIENDLY_MODE:            {policy: attrStored},
	CKA_OTP_CHALLENGE_REQUIREMENT:         {policy: attrStored},
	CKA_OTP_TIME_REQUIREMENT:              {policy: attrStored},
	CKA_OTP_COUNTER_REQUIREMENT:           {policy: attrStored},
	CKA_OTP_PIN_REQUIREMENT:               {policy: attrStored},
	CKA_OTP_COUNTER:                       {policy: attrStored},
	CKA_OTP_TIME:                          {policy: attrStored},
	CKA_OTP_USER_IDENTIFIER:               {policy: attrStored},
	CKA_OTP_SERVICE_IDENTIFIER:            {policy: attrStored},
	CKA_OTP_SERVICE_LOGO:                  {policy: attrStored},
	CKA_OTP_SERVICE_LOGO_TYPE:             {policy: attrStored},
	CKA_GOSTR3410_PARAMS:                  {policy: attrStored},
	CKA_GOSTR3411_PARAMS:                  {policy: attrStored},
	CKA_GOST28147_PARAMS:                  {policy: attrStored},
	CKA_HW_FEATURE_TYPE:                   {policy: attrStored},
	CKA_RESET_ON_INIT:                     {policy: attrStored},
	CKA_HAS_RESET:                         {policy: attrStored},
	CKA_PIXEL_X:                           {policy: attrStored},
	CKA_PIXEL_Y:                           {policy: attrStored},
	CKA_RESOLUTION:                        {policy: attrStored},
	CKA_CHAR_ROWS:                         {policy: attrStored},
	CKA_CHAR_COLUMNS:                      {policy: attrStored},
	CKA_COLOR:                             {policy: attrStored},
	CKA_BITS_PER_PIXEL:                    {policy: attrStored},
	CKA_CHAR_SETS:                         {policy: attrStored},
	CKA_ENCODING_METHODS:                  {policy: attrStored},
	CKA_MIME_TYPES:                        {policy: attrStored},
	CKA_MECHANISM_TYPE:                    {policy: attrStored},
	CKA_REQUIRED_CMS_ATTRIBUTES:           {policy: attrStored},
	CKA_DEFAULT_CMS_ATTRIBUTES:            {policy: attrStored},
	CKA_SUPPORTED_CMS_ATTRIBUTES:          {policy: attrStored},
	CKA_ALLOWED_MECHANISMS:                {policy: attrEnforced, validate: validateMechanismListValue},
	CKA_PROFILE_ID:                        {policy: attrStored},
	CKA_X2RATCHET_BAG:                     {policy: attrStored},
	CKA_X2RATCHET_BAGSIZE:                 {policy: attrStored},
	CKA_X2RATCHET_BOBS1STMSG:              {policy: attrStored},
	CKA_X2RATCHET_CKR:                     {policy: attrStored},
	CKA_X2RATCHET_CKS:                     {policy: attrStored},
	CKA_X2RATCHET_DHP:                     {policy: attrStored},
	CKA_X2RATCHET_DHR:                     {policy: attrStored},
	CKA_X2RATCHET_DHS:                     {policy: attrStored},
	CKA_X2RATCHET_HKR:                     {policy: attrStored},
	CKA_X2RATCHET_HKS:                     {policy: attrStored},
	CKA_X2RATCHET_ISALICE:                 {policy: attrStored},
	CKA_X2RATCHET_NHKR:                    {policy: attrStored},
	CKA_X2RATCHET_NHKS:                    {policy: attrStored},
	CKA_X2RATCHET_NR:                      {policy: attrStored},
	CKA_X2RATCHET_NS:                      {policy: attrStored},
	CKA_X2RATCHET_PNS:                     {policy: attrStored},
	CKA_X2RATCHET_RK:                      {policy: attrStored},
	CKA_HSS_LEVELS:                        {policy: attrStored},
	CKA_HSS_LMS_TYPE:                      {policy: attrStored},
	CKA_HSS_LMOTS_TYPE:                    {policy: attrStored},
	CKA_HSS_LMS_TYPES:                     {policy: attrStored},
	CKA_HSS_LMOTS_TYPES:                   {policy: attrStored},
	CKA_HSS_KEYS_REMAINING:                {policy: attrUnsupported},
	CKA_PARAMETER_SET:                     {policy: attrStored},
	CKA_OBJECT_VALIDATION_FLAGS:           {policy: attrUnsupported},
	CKA_VALIDATION_TYPE:                   {policy: attrUnsupported},
	CKA_VALIDATION_VERSION:                {policy: attrUnsupported},
	CKA_VALIDATION_LEVEL:                  {policy: attrUnsupported},
	CKA_VALIDATION_MODULE_ID:              {policy: attrUnsupported},
	CKA_VALIDATION_FLAG:                   {policy: attrUnsupported},
	CKA_VALIDATION_AUTHORITY_TYPE:         {policy: attrUnsupported},
	CKA_VALIDATION_COUNTRY:                {policy: attrUnsupported},
	CKA_VALIDATION_CERTIFICATE_IDENTIFIER: {policy: attrUnsupported},
	CKA_VALIDATION_CERTIFICATE_URI:        {policy: attrUnsupported},
	CKA_VALIDATION_VENDOR_URI:             {policy: attrUnsupported},
	CKA_VALIDATION_PROFILE:                {policy: attrUnsupported},
	CKA_ENCAPSULATE_TEMPLATE:              {policy: attrEnforced, validate: validateAttributeArrayValue},
	CKA_DECAPSULATE_TEMPLATE:              {policy: attrEnforced, validate: validateAttributeArrayValue},
	CKA_TRUST_SERVER_AUTH:                 {policy: attrUnsupported},
	CKA_TRUST_CLIENT_AUTH:                 {policy: attrUnsupported},
	CKA_TRUST_CODE_SIGNING:                {policy: attrUnsupported},
	CKA_TRUST_EMAIL_PROTECTION:            {policy: attrUnsupported},
	CKA_TRUST_IPSEC_IKE:                   {policy: attrUnsupported},
	CKA_TRUST_TIME_STAMPING:               {policy: attrUnsupported},
	CKA_TRUST_OCSP_SIGNING:                {policy: attrUnsupported},
	CKA_ENCAPSULATE:                       {policy: attrEnforced},
	CKA_DECAPSULATE:                       {policy: attrEnforced},
	CKA_HASH_OF_CERTIFICATE:               {policy: attrStored},
	CKA_PUBLIC_CRC64_VALUE:                {policy: attrStored},
	CKA_SEED:                              {policy: attrStored},
	CKA_VENDOR_DEFINED:                    {policy: attrStored},
}

// checkAttributeSupported reports whether the token can honour an attribute a
// caller supplied in a creation, copy or modification template.
//
// An attribute type the module does not define, or one whose enforcement it
// cannot perform, is refused with CKR_ATTRIBUTE_TYPE_INVALID (PKCS#11 v3.2
// §5.7.5). A value the token would have to parse but cannot is refused with
// CKR_ATTRIBUTE_VALUE_INVALID: a restriction the token cannot read is a
// restriction it cannot apply.
func checkAttributeSupported(attr Attribute) error {
	// The vendor-defined range is reserved for a token's own attributes
	// (v3.2 §4.4), so it is admitted without a table entry.
	if attr.Type >= CKA_VENDOR_DEFINED {
		return nil
	}

	handler, known := attributeHandlers[attr.Type]
	if !known || handler.policy == attrUnsupported {
		return NewPKCS11Error(CKR_ATTRIBUTE_TYPE_INVALID)
	}
	if handler.validate != nil {
		if err := handler.validate(attr.Value); err != nil {
			return err
		}
	}

	return checkNestedTemplateSupported(attr)
}

// attributeArrayTypes lists the attributes whose value is a nested template
// rather than a scalar or an opaque byte string.
var attributeArrayTypes = map[AttributeType]bool{
	CKA_WRAP_TEMPLATE:        true,
	CKA_UNWRAP_TEMPLATE:      true,
	CKA_DERIVE_TEMPLATE:      true,
	CKA_ENCAPSULATE_TEMPLATE: true,
	CKA_DECAPSULATE_TEMPLATE: true,
}

// checkNestedTemplateSupported refuses a constraint template that itself
// contains an attribute the token does not support, so a caller cannot smuggle
// an unenforceable restriction inside an enforceable one.
//
// Only the policy of each contained attribute is checked, not its value: the
// nested value is data the token compares byte for byte, and recursing into it
// would let a caller choose this module's recursion depth.
func checkNestedTemplateSupported(attr Attribute) error {
	if !attributeArrayTypes[attr.Type] {
		return nil
	}

	contained, err := decodeConstraintTemplate(attr.Value)
	if err != nil {
		return err
	}
	for _, nested := range contained {
		if !isAttributeSupported(nested.Type) {
			return NewPKCS11Error(CKR_ATTRIBUTE_TYPE_INVALID)
		}
	}

	return nil
}

// isAttributeSupported reports whether the token accepts the attribute type in
// a template at all. It is the predicate behind the CKR_ATTRIBUTE_TYPE_INVALID
// that C_CreateObject, C_CopyObject and C_SetAttributeValue return.
func isAttributeSupported(attrType AttributeType) bool {
	if attrType >= CKA_VENDOR_DEFINED {
		return true
	}
	handler, known := attributeHandlers[attrType]
	return known && handler.policy != attrUnsupported
}

// ckDateLayout is the CK_DATE wire format: four ASCII digits of year, two of
// month and two of day, per the CK_DATE definition in PKCS#11 v3.2 §3.1.
const ckDateLayout = "20060102"

// ckDateLength is the length in bytes of a populated CK_DATE.
const ckDateLength = 8

// validateDateValue rejects a CKA_START_DATE or CKA_END_DATE value that is not
// a CK_DATE.
//
// The empty value is legal and means "no date": PKCS#11 v3.2 §4.8.2 gives both
// date attributes the default "empty". Anything else must be eight digits
// naming a real calendar day, because a token that cannot read the date cannot
// compare against it.
func validateDateValue(value []byte) error {
	if len(value) == 0 {
		return nil
	}
	if len(value) != ckDateLength {
		return NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
	}
	if _, err := time.Parse(ckDateLayout, string(value)); err != nil {
		return NewPKCS11ErrorWithCause(CKR_ATTRIBUTE_VALUE_INVALID, err)
	}
	return nil
}

// ckULongSize is the width of a CK_ULONG on every platform this module targets.
const ckULongSize = 8

// validateMechanismListValue rejects a CKA_ALLOWED_MECHANISMS value that is not
// an array of CK_MECHANISM_TYPE.
//
// PKCS#11 v3.2 §4.8.2 defines the attribute as "a pointer to a
// CK_MECHANISM_TYPE array" whose element count "is the ulValueLen component of
// the attribute divided by the size of CK_MECHANISM_TYPE", so a length that is
// not a whole number of elements is not a mechanism list. The element width is
// fixed at the native CK_ULONG rather than accepted at either width, because a
// sixteen-byte value would otherwise be two mechanisms or four, and guessing
// which would decide whether a key may perform an operation.
func validateMechanismListValue(value []byte) error {
	if len(value)%ckULongSize != 0 {
		return NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
	}
	return nil
}

// validateAttributeArrayValue rejects a *_TEMPLATE value this token could not
// interpret. An empty value is the empty template, which constrains nothing
// and is the default PKCS#11 v3.2 §6.43 gives CKA_WRAP_TEMPLATE.
//
// It reads the value through decodeConstraintTemplate, the same function the
// enforcement paths use, so a value accepted here is one they can act on.
func validateAttributeArrayValue(value []byte) error {
	if _, err := decodeConstraintTemplate(value); err != nil {
		return err
	}
	return nil
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

	// Unavailable reports that the token could not reveal this attribute, either
	// because the object is sensitive or unextractable or because the attribute
	// is invalid for the object. Callers marshalling back into a CK_ATTRIBUTE
	// must set ulValueLen to CK_UNAVAILABLE_INFORMATION and copy no value.
	// See PKCS#11 v3.2 §5.7.5.
	Unavailable bool

	// Secret holds a value the module keeps sealed until the C boundary,
	// instead of Value: a backend-held secret key's CKA_VALUE. At most one of
	// Value and Secret is set. The holder owns it and must call Release once
	// the value has been copied out.
	Secret *secure.Buffer
}

// ValueLen returns the length of the attribute's value, whichever field
// holds it.
func (a *Attribute) ValueLen() int {
	if a.Secret != nil {
		return a.Secret.Size()
	}
	return len(a.Value)
}

// WithValue calls fn with the attribute's value, whichever field holds it.
// A Secret is borrowed for the duration of fn; fn must not retain the slice.
func (a *Attribute) WithValue(fn func(value []byte) error) error {
	if a.Secret != nil {
		return a.Secret.WithBytes(fn)
	}
	return fn(a.Value)
}

// Release wipes the attribute's value and destroys its Secret. It is safe to
// call more than once.
func (a *Attribute) Release() {
	enclave.Wipe(a.Value)
	a.Value = nil
	if a.Secret != nil {
		a.Secret.Destroy()
		a.Secret = nil
	}
}

// ReleaseAttributes releases every attribute in attrs.
func ReleaseAttributes(attrs []Attribute) {
	for i := range attrs {
		attrs[i].Release()
	}
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

// encodeULong writes a CK_ULONG at the width a C application sees, in the
// little-endian byte order of every platform this module targets.
func encodeULong(value uint64) []byte {
	buf := make([]byte, ckULongSize)
	binary.LittleEndian.PutUint64(buf, value)
	return buf
}

// NewULongAttribute creates an attribute whose value is a CK_ULONG, or one of
// the types PKCS#11 v3.2 §4.4 defines as a CK_ULONG: CK_OBJECT_CLASS,
// CK_KEY_TYPE, CK_CERTIFICATE_TYPE, CK_MECHANISM_TYPE and the rest of the set
// named by ulongAttributes. It is the canonical constructor for those
// attributes, because it is the only one that cannot encode them at the wrong
// width.
func NewULongAttribute(attrType AttributeType, value uint64) Attribute {
	return Attribute{Type: attrType, Value: encodeULong(value)}
}

// NewUint32Attribute creates an attribute from a 32-bit value, little-endian as
// PKCS#11 values are on every platform this module targets.
//
// A CK_ULONG-typed attribute is encoded at the full CK_ULONG width whatever the
// width of the Go argument, because four bytes is not a CK_ULONG here and a
// caller has no way to ask for a narrower one. An application allocates
// sizeof(CK_ULONG) for such an attribute and C_GetAttributeValue reports back
// however many bytes the token stored, so a four-byte value leaves the upper
// half of the caller's buffer holding whatever was already there:
// pkcs11-provider read a four-byte CKA_CLASS that way and decoded
// CKO_PUBLIC_KEY as 0xFFFFFFFF00000002, then abandoned the object rather than
// use a key of an unknown class.
//
// Every other attribute is encoded exactly as given, four bytes wide. Those are
// byte arrays whose length is their content -- a caller's CKA_ID, for one --
// and widening them would change what they say.
func NewUint32Attribute(attrType AttributeType, value uint32) Attribute {
	if ulongAttributes[attrType] {
		return NewULongAttribute(attrType, uint64(value))
	}
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

	// SlotID identifies the token this object belongs to. PKCS#11 objects are
	// owned by exactly one token, and this is what keeps a session on one slot
	// from finding or using another token's objects.
	SlotID SlotID

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
	obj.Attributes[CKA_CLASS] = NewULongAttribute(CKA_CLASS, uint64(class)).Value
	return obj
}

// NewKeyObject creates a new key object with the specified class and type.
func NewKeyObject(class ObjectClass, keyType KeyType) *Object {
	obj := NewObject(class)
	obj.KeyType = keyType
	obj.SetAttribute(CKA_KEY_TYPE, NewULongAttribute(CKA_KEY_TYPE, uint64(keyType)).Value)
	return obj
}

// SetAttribute sets an attribute value on the object.
//
// The attribute map is created on demand so that an Object built as a bare
// composite literal — which several callers do, since the zero value is
// otherwise usable — accepts an attribute instead of panicking on a nil map.
//
// A CK_ULONG-typed value is stored at the native CK_ULONG width whatever width
// it arrives in, so that C_GetAttributeValue hands the application back a whole
// CK_ULONG. This is the single point every attribute a token object holds
// passes through — buildObjectFromTemplate applies each template entry here, as
// do the paths that set an attribute the token computed itself — so the width
// is decided once rather than at each of the callers that build a value.
func (o *Object) SetAttribute(attrType AttributeType, value []byte) {
	if o.Attributes == nil {
		o.Attributes = make(map[AttributeType][]byte)
	}
	o.Attributes[attrType] = copyBytes(normalizeULongWidth(attrType, value))

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
// Returns nil if the attribute is not set. The returned slice is a copy, so a
// caller that zeroizes key material after use cannot corrupt the stored object.
func (o *Object) GetAttribute(attrType AttributeType) []byte {
	return copyBytes(o.Attributes[attrType])
}

// Zeroize overwrites every attribute value held by the object before it is
// discarded, so key material does not linger in memory after destruction.
func (o *Object) Zeroize() {
	for attrType, value := range o.Attributes {
		enclave.Wipe(value)
		delete(o.Attributes, attrType)
	}
}

// protectsSensitiveAttributes reports whether the object's protected
// attributes (CKA_VALUE and the RSA private components) must be withheld.
// CKA_SENSITIVE and CKA_EXTRACTABLE are defined only for private, secret
// and OTP key objects; certificates, data and public-key objects carry no
// extractability semantics and always reveal their CKA_VALUE.
func (o *Object) protectsSensitiveAttributes() bool {
	switch o.Class {
	case CKO_PRIVATE_KEY, CKO_SECRET_KEY, CKO_OTP_KEY:
		return o.IsSensitive || !o.IsExtractable
	default:
		return false
	}
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
//
// The returned slice is a copy, as GetAttribute's is: a caller must not be able
// to rewrite a stored attribute by writing through a value it merely read, which
// would bypass every gate in SetAttributeValue.
func (o *Object) GetID() []byte {
	return copyBytes(o.Attributes[CKA_ID])
}

// ulongAttributes are the attributes whose value is a CK_ULONG (or a type
// defined as one: CK_OBJECT_CLASS, CK_KEY_TYPE, CK_MECHANISM_TYPE and friends).
//
// It is the authority on which attributes carry a CK_ULONG, and is read for two
// purposes. normalizeULongWidth reads it to decide what the token stores, so
// that every such attribute is held and returned at the native CK_ULONG width
// no matter how wide the value arrived. attributeValuesEqual reads it to
// compare numerically rather than byte for byte, because a search template
// still arrives at either width: a C application sends a native 8-byte
// CK_ULONG, while a Go caller may send 4, and neither is wrong to.
var ulongAttributes = map[AttributeType]bool{
	CKA_CLASS:                     true,
	CKA_CERTIFICATE_TYPE:          true,
	CKA_KEY_TYPE:                  true,
	CKA_MODULUS_BITS:              true,
	CKA_VALUE_LEN:                 true,
	CKA_KEY_GEN_MECHANISM:         true,
	CKA_HW_FEATURE_TYPE:           true,
	CKA_MECHANISM_TYPE:            true,
	CKA_PRIME_BITS:                true,
	CKA_SUBPRIME_BITS:             true,
	CKA_CERTIFICATE_CATEGORY:      true,
	CKA_JAVA_MIDP_SECURITY_DOMAIN: true,

	// CKA_PARAMETER_SET holds a CK_PARAMETER_SET_TYPE, which PKCS#11 v3.2 §4.10
	// defines as a CK_ULONG. The module writes it itself onto both halves of
	// every ML-DSA and ML-KEM key pair it generates (§6.67.3, §6.68.3), so it is
	// an attribute an application reads back from an object it never supplied a
	// template value for -- the same position CKA_CLASS is in.
	CKA_PARAMETER_SET: true,
}

// ulongValue decodes a CK_ULONG-valued attribute, tolerating either width.
//
// It reads little-endian, which is the byte order of every platform this
// module targets. Both widths are accepted because an application may send
// either in a template; what the token stores is always the native width, which
// normalizeULongWidth is responsible for.
func ulongValue(value []byte) (uint64, bool) {
	switch len(value) {
	case ckULongSize:
		return binary.LittleEndian.Uint64(value), true
	case 4:
		return uint64(binary.LittleEndian.Uint32(value)), true
	default:
		return 0, false
	}
}

// normalizeULongWidth re-encodes a CK_ULONG-typed attribute value at the native
// CK_ULONG width, and returns any other value unchanged.
//
// PKCS#11 v3.2 §3.2 types CK_OBJECT_CLASS, CK_KEY_TYPE and their relatives as
// CK_ULONG, and §5.7.5 has C_GetAttributeValue report the stored length in
// ulValueLen. An application therefore allocates sizeof(CK_ULONG) for such an
// attribute and reads back whatever width the token wrote: a four-byte value
// leaves the upper half of its buffer holding whatever was there before, which
// is how pkcs11-provider came to decode a generated key's CKA_CLASS as
// 0xFFFFFFFF00000002 and abandon the object. The token must therefore store the
// native width even when the value reached it as four bytes, which is what
// every value the module builds for itself out of a Go constant does.
//
// A value that is neither width is left exactly as it arrived. Such a value is
// not a CK_ULONG this module wrote, and inventing the missing bytes would put a
// number the caller never supplied into the object; the attribute validators
// and the operations that read the value reject it on its own terms instead.
func normalizeULongWidth(attrType AttributeType, value []byte) []byte {
	if !ulongAttributes[attrType] || len(value) == ckULongSize {
		return value
	}
	number, ok := ulongValue(value)
	if !ok {
		return value
	}
	return encodeULong(number)
}

// attributeValuesEqual reports whether a stored attribute value and a template
// value denote the same thing.
//
// Byte-array and string attributes compare exactly. CK_ULONG-valued attributes
// compare numerically, because the same value legitimately arrives in two
// widths: a C application sends a native 8-byte CK_ULONG through the cgo
// boundary, while an object created through the Go API holds 4 bytes. A raw
// byte comparison made those mismatch, so C_FindObjects could not find any
// Go-created key by CKA_CLASS or CKA_KEY_TYPE -- pkcs11-tool listed such a key
// happily and then reported "Private key not found" the moment it searched for
// one to sign with.
func attributeValuesEqual(attrType AttributeType, objValue, templateValue []byte) bool {
	if ulongAttributes[attrType] {
		objNum, objOK := ulongValue(objValue)
		tmplNum, tmplOK := ulongValue(templateValue)
		if objOK && tmplOK {
			return objNum == tmplNum
		}
		// A width neither 4 nor 8 is not a CK_ULONG the module wrote, so fall
		// through to an exact comparison rather than guessing at its meaning.
	}
	return bytes.Equal(objValue, templateValue)
}

// MatchesTemplate checks if the object matches all attributes in the template.
// Returns true if all template attributes match the object's attributes.
func (o *Object) MatchesTemplate(template []Attribute) bool {
	for _, attr := range template {
		objValue, exists := o.Attributes[attr.Type]
		if !exists {
			return false
		}
		if !attributeValuesEqual(attr.Type, objValue, attr.Value) {
			return false
		}
	}
	return true
}

// attributeArrayHeaderSize is the size of the element count that prefixes a
// flattened attribute array.
const attributeArrayHeaderSize = 4

// attributeArrayEntrySize is the size of one flattened entry's fixed part: the
// attribute type followed by the length of its value.
const attributeArrayEntrySize = 8

// EncodeAttributeArray flattens a nested template into the value of an
// attribute-array attribute (CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE,
// CKA_DERIVE_TEMPLATE, CKA_ENCAPSULATE_TEMPLATE, CKA_DECAPSULATE_TEMPLATE).
//
// In C such a value is an array of CK_ATTRIBUTE, each element of which points
// at its own value. This module cannot store that representation: an object
// lives in the token, which is on the far side of the transport from the
// application, where a caller's pointer addresses nothing and its buffer no
// longer exists once the call returns. The nested template is therefore
// carried flattened:
//
//	count   uint32          number of attributes in the array
//	repeated count times:
//	  type   uint32          CK_ATTRIBUTE_TYPE
//	  length uint32          length in bytes of the value that follows
//	  value  length bytes    the value itself
//
// Integers are little-endian, matching NewUint32Attribute and every platform
// this module targets.
func EncodeAttributeArray(attrs []Attribute) []byte {
	size := attributeArrayHeaderSize
	for _, attr := range attrs {
		size += attributeArrayEntrySize + len(attr.Value)
	}

	encoded := make([]byte, attributeArrayHeaderSize, size)
	binary.LittleEndian.PutUint32(encoded, uint32(len(attrs)))

	var entry [attributeArrayEntrySize]byte
	for _, attr := range attrs {
		binary.LittleEndian.PutUint32(entry[0:4], uint32(attr.Type))
		binary.LittleEndian.PutUint32(entry[4:8], uint32(len(attr.Value)))
		encoded = append(encoded, entry[:]...)
		encoded = append(encoded, attr.Value...)
	}

	return encoded
}

// DecodeAttributeArray parses a flattened attribute array as written by
// EncodeAttributeArray. A value that is truncated, that declares a length past
// the end of the buffer, or that carries trailing bytes is refused with
// CKR_ATTRIBUTE_VALUE_INVALID: a constraint the token cannot read is a
// constraint it cannot apply, and storing it unread is exactly the silent
// acceptance this encoding exists to prevent.
func DecodeAttributeArray(value []byte) ([]Attribute, error) {
	if len(value) < attributeArrayHeaderSize {
		return nil, NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
	}

	count := binary.LittleEndian.Uint32(value[:attributeArrayHeaderSize])
	// Every entry costs at least its fixed part, so a count that could not fit
	// in the remaining bytes is rejected before any allocation.
	remaining := value[attributeArrayHeaderSize:]
	if uint64(count)*attributeArrayEntrySize > uint64(len(remaining)) {
		return nil, NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
	}

	attrs := make([]Attribute, 0, count)
	for i := uint32(0); i < count; i++ {
		if len(remaining) < attributeArrayEntrySize {
			return nil, NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
		}
		attrType := AttributeType(binary.LittleEndian.Uint32(remaining[0:4]))
		length := binary.LittleEndian.Uint32(remaining[4:8])
		remaining = remaining[attributeArrayEntrySize:]

		if uint64(length) > uint64(len(remaining)) {
			return nil, NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
		}
		attrs = append(attrs, NewAttribute(attrType, remaining[:length]))
		remaining = remaining[length:]
	}

	if len(remaining) != 0 {
		return nil, NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
	}

	return attrs, nil
}

// decodeConstraintTemplate reads a stored *_TEMPLATE value as the constraint it
// expresses, treating an empty value as the empty template.
//
// It exists because the two representations of "constrains nothing" did not
// agree. validateAttributeArrayValue accepts a zero-length value on the way in,
// which PKCS#11 v3.2 §6.43 makes the default for CKA_WRAP_TEMPLATE, while
// DecodeAttributeArray refuses anything shorter than the four-byte element
// count. A C application never produced the mismatch -- the cgo boundary
// flattens an empty CK_ATTRIBUTE array into the canonical count of zero -- but a
// Go caller passing NewAttribute(CKA_WRAP_TEMPLATE, nil) stored a constraint
// that every later C_WrapKey then rejected with CKR_ATTRIBUTE_VALUE_INVALID.
// The key was not restricted to a subset of targets; it could wrap nothing at
// all.
//
// The empty value is resolved here, where constraints are read, rather than
// normalized when the attribute is stored: an object recovered from token
// storage is rebuilt from its serialized attribute map and never passes back
// through the write path, so normalizing on write would leave any already
// persisted empty template still bricking the key. DecodeAttributeArray itself
// stays strict, because a truncated array arriving from an application is a
// constraint the token genuinely cannot read.
//
// A zero-length value and the canonical zero-count encoding therefore produce
// the identical empty constraint, which is what makes the two paths agree.
func decodeConstraintTemplate(value []byte) ([]Attribute, error) {
	if len(value) == 0 {
		return nil, nil
	}
	return DecodeAttributeArray(value)
}

// EncodeMechanismList builds a CKA_ALLOWED_MECHANISMS value: the array of
// CK_MECHANISM_TYPE described in PKCS#11 v3.2 §4.8.2, written at the native
// CK_ULONG width so a C application and the Go API agree on the element count.
func EncodeMechanismList(mechanisms []MechanismType) []byte {
	encoded := make([]byte, len(mechanisms)*ckULongSize)
	for i, mechanism := range mechanisms {
		binary.LittleEndian.PutUint64(encoded[i*ckULongSize:], uint64(mechanism))
	}
	return encoded
}

// DecodeMechanismList parses a CKA_ALLOWED_MECHANISMS value. A length that is
// not a whole number of CK_MECHANISM_TYPE elements is refused with
// CKR_ATTRIBUTE_VALUE_INVALID.
func DecodeMechanismList(value []byte) ([]MechanismType, error) {
	if err := validateMechanismListValue(value); err != nil {
		return nil, err
	}

	mechanisms := make([]MechanismType, 0, len(value)/ckULongSize)
	for offset := 0; offset < len(value); offset += ckULongSize {
		mechanisms = append(mechanisms, MechanismType(binary.LittleEndian.Uint64(value[offset:])))
	}
	return mechanisms, nil
}

// CheckAllowedMechanism enforces CKA_ALLOWED_MECHANISMS, which PKCS#11 v3.2
// §4.8.2 defines as "a list of mechanisms allowed to be used with this key".
//
// A key without the attribute is unrestricted, which is why the attribute's
// absence and an empty list are not the same thing: an empty list is a list
// that permits nothing, and a key carrying one may perform no operation at
// all. The mechanism-wide checks an operation initializer already performs are
// not a substitute for this one — they ask whether the token supports the
// mechanism, never whether this key may be used with it.
//
// A mechanism outside the list is reported as CKR_MECHANISM_INVALID, which is
// how the return tables of C_SignInit, C_EncryptInit and their siblings name a
// mechanism that may not be used for the requested operation.
func (o *Object) CheckAllowedMechanism(mechanism MechanismType) error {
	if !o.HasAttribute(CKA_ALLOWED_MECHANISMS) {
		return nil
	}

	allowed, err := DecodeMechanismList(o.Attributes[CKA_ALLOWED_MECHANISMS])
	if err != nil {
		return err
	}
	for _, candidate := range allowed {
		if candidate == mechanism {
			return nil
		}
	}

	return NewPKCS11Error(CKR_MECHANISM_INVALID)
}

// CheckValidityPeriod reports whether the object is inside the validity window
// its CKA_START_DATE and CKA_END_DATE describe, treating an absent or empty
// date as unbounded in that direction. A key used outside its window is
// reported as CKR_KEY_FUNCTION_NOT_PERMITTED.
//
// This is a token policy, not a specification requirement, and the doc comment
// says so because the difference decides whether a caller may rely on it:
// PKCS#11 v3.2 §4.8.2 states that "the CKA_START_DATE and CKA_END_DATE
// attributes are for reference only; Cryptoki does not attach any special
// meaning to them. In particular, it does not restrict usage of a key
// according to the dates; doing this is up to the application." A token is
// free to be stricter than that, and many hardware tokens are, but an
// application that needs the window enforced must not assume any Cryptoki
// implementation enforces it.
//
// The comparison is on the CK_DATE text itself, which is ordered because
// YYYYMMDD sorts chronologically, so no time zone is imputed to a date the
// specification gives none.
func (o *Object) CheckValidityPeriod(now time.Time) error {
	today := now.Format(ckDateLayout)

	start := o.Attributes[CKA_START_DATE]
	if len(start) == ckDateLength && today < string(start) {
		return NewPKCS11Error(CKR_KEY_FUNCTION_NOT_PERMITTED)
	}

	end := o.Attributes[CKA_END_DATE]
	if len(end) == ckDateLength && today > string(end) {
		return NewPKCS11Error(CKR_KEY_FUNCTION_NOT_PERMITTED)
	}

	return nil
}

// CheckWrapTemplate enforces the CKA_WRAP_TEMPLATE of a wrapping key against
// the key it has been asked to wrap.
//
// PKCS#11 v3.2 §5.14.3: "To partition the wrapping keys so they can only wrap
// a subset of extractable keys the attribute CKA_WRAP_TEMPLATE can be used on
// the wrapping key to specify an attribute set that will be compared against
// the attributes of the key to be wrapped. If all attributes match according
// to the C_FindObject rules of attribute matching then the wrap will proceed
// [...] If any attribute mismatch occurs on an attempt to wrap a key then the
// function SHALL return CKR_KEY_HANDLE_INVALID."
//
// Matching follows the C_FindObjects rules the sentence above names, so an
// attribute the target key does not carry at all is a mismatch. The same
// paragraph adds that "if an attribute is not present, it will not be
// checked", which reads the other way; the C_FindObjects rule is the one the
// normative sentence defers to, and it is also the safe reading, since the
// alternative lets a key escape a constraint by omitting the attribute it
// constrains.
func (o *Object) CheckWrapTemplate(target *Object) error {
	if !o.HasAttribute(CKA_WRAP_TEMPLATE) {
		return nil
	}

	constraint, err := decodeConstraintTemplate(o.Attributes[CKA_WRAP_TEMPLATE])
	if err != nil {
		return err
	}
	if target == nil || !target.MatchesTemplate(constraint) {
		return NewPKCS11Error(CKR_KEY_HANDLE_INVALID)
	}

	return nil
}

// ApplyAttributeTemplate merges the constraint template a key carries into the
// template an application supplied for the key about to be created from it,
// and returns the template the new object must actually be built from.
//
// It implements the CKA_UNWRAP_TEMPLATE, CKA_DERIVE_TEMPLATE,
// CKA_ENCAPSULATE_TEMPLATE and CKA_DECAPSULATE_TEMPLATE rule, stated for
// C_UnwrapKey in PKCS#11 v3.2 §5.14.4 and for C_DeriveKey in §5.15.1: the
// attribute "can be used on the unwrapping key to specify an attribute set
// that will be added to attributes of the key to be unwrapped. If the
// attributes do not conflict with the user supplied attribute template [...]
// then the unwrap will proceed. [...] If any attribute conflict occurs on an
// attempt to unwrap a key then the function SHALL return
// CKR_TEMPLATE_INCONSISTENT."
//
// A key without the named attribute adds nothing and the caller's template is
// returned unchanged, per "if this attribute is not present on the unwrapping
// key then no additional attributes will be added".
func (o *Object) ApplyAttributeTemplate(attrType AttributeType, template []Attribute) ([]Attribute, error) {
	if !o.HasAttribute(attrType) {
		return template, nil
	}

	constraint, err := decodeConstraintTemplate(o.Attributes[attrType])
	if err != nil {
		return nil, err
	}

	supplied := make(map[AttributeType][]byte, len(template))
	for _, attr := range template {
		supplied[attr.Type] = attr.Value
	}

	merged := make([]Attribute, len(template), len(template)+len(constraint))
	copy(merged, template)

	for _, attr := range constraint {
		existing, present := supplied[attr.Type]
		if !present {
			merged = append(merged, attr)
			continue
		}
		// The caller asked for the same attribute. Agreeing with the
		// constraint is not a conflict; contradicting it is.
		if !attributeValuesEqual(attr.Type, existing, attr.Value) {
			return nil, NewPKCS11Error(CKR_TEMPLATE_INCONSISTENT)
		}
	}

	return merged, nil
}

// Clone creates a deep copy of the object.
func (o *Object) Clone() *Object {
	clone := &Object{
		Handle:        0, // New handle will be assigned
		SlotID:        o.SlotID,
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

// AccessContext carries the authorization state of the session performing an
// object operation. The object layer consults it to enforce the two access
// rules PKCS#11 places on every object operation: private objects require an
// authenticated normal user (v3.2 §4.2), and token objects may only be created,
// modified or destroyed from a read/write session (v3.2 §5.7.1–§5.7.4).
type AccessContext struct {
	// Session identifies the session performing the operation. It scopes
	// session-object ownership and FindObjects cursor state.
	Session SessionHandle

	// Slot identifies the token the session is connected to. Objects belong to
	// exactly one token, so this scopes every object operation: a session on
	// one slot must never observe or use another token's objects.
	Slot SlotID

	// LoggedIn reports whether the normal user is authenticated to the token.
	LoggedIn bool

	// ReadWrite reports whether the session was opened with CKF_RW_SESSION.
	ReadWrite bool

	// SecurityOfficer reports whether the Security Officer is authenticated to
	// the token. It is the authority CKA_TRUSTED requires and nothing else:
	// PKCS#11 v3.2 Table 13 footnote 10 says of that attribute "Can only be set
	// to CK_TRUE by the SO user", and §4.6.2 repeats it for certificates.
	//
	// This flag never widens CanAccess. The SO administers the token but is not
	// the normal user, so it must not reach private objects (v3.2 §4.2); that
	// decision stays with LoggedIn alone.
	SecurityOfficer bool
}

// NewAccessContext builds an AccessContext from a live session. The slot is
// taken from the session itself, so every caller is automatically scoped to the
// token it opened.
func NewAccessContext(handle SessionHandle, session *Session) AccessContext {
	if session == nil {
		return AccessContext{Session: handle}
	}
	return AccessContext{
		Session:         handle,
		Slot:            SlotID(session.SlotID),
		LoggedIn:        session.IsUserLoggedIn(),
		ReadWrite:       session.IsReadWrite(),
		SecurityOfficer: session.IsSOLoggedIn(),
	}
}

// CanAccess reports whether the session may observe or use the object at all.
// The object must belong to the session's token, and a private object is
// invisible until the normal user has authenticated.
//
// Session-object ownership is deliberately not part of this decision. A session
// object is scoped to the application, not to the one session that created it:
// PKCS#11 v3.0 §5.6 says of C_CloseSession that "when a session is closed, any
// session objects which were created in that session are destroyed", and that
// this holds "even if other sessions are using those objects" -- wording that
// only makes sense if the other sessions of the same application could reach
// them in the first place. One Cryptoki instance serves one application, so
// every session this manager knows about belongs to that same application and
// there is no second application to hide anything from.
func (a AccessContext) CanAccess(obj *Object) bool {
	if obj == nil || obj.SlotID != a.Slot {
		return false
	}
	return !obj.IsPrivate || a.LoggedIn
}

// ObjectManager provides thread-safe object management for a PKCS#11 session.
// It handles object creation, lookup, search operations, and lifecycle management.
type ObjectManager struct {
	mu sync.RWMutex

	// objects stores all objects by their handle.
	objects *HandleTable[*Object]

	// sessionObjects tracks session objects by owning session. Session objects
	// live only as long as the session that created them (v3.2 §4.1.3), so
	// ownership must be recorded to destroy exactly the right ones on close.
	sessionObjects map[SessionHandle]map[ObjectHandle]bool

	// objectOwner is the reverse of sessionObjects: it answers "which session
	// owns this handle" in constant time, so destroying one object releases it
	// without scanning every per-session set. This index governs lifetime only,
	// never visibility -- see AccessContext.CanAccess for why. The two maps are
	// always mutated together, through trackSessionObject and
	// untrackSessionObject, and a handle absent from this map is by definition
	// owned by no session.
	objectOwner map[ObjectHandle]SessionHandle

	// findState holds the current FindObjects operation state per session.
	findState map[SessionHandle]*FindObjectsState

	// uniqueIDPrefix is the random half of every CKA_UNIQUE_ID this manager
	// generates. It is drawn once, lazily, so that a failure of the system
	// entropy source is reported to the caller that provoked it rather than
	// swallowed by a constructor that cannot return an error.
	uniqueIDPrefix [uniqueIDPrefixSize]byte

	// uniqueIDPrefixReady reports whether uniqueIDPrefix has been drawn.
	uniqueIDPrefixReady bool

	// uniqueIDCounter is the sequential half of every generated
	// CKA_UNIQUE_ID. It only ever increases, including across the destruction
	// of the objects that consumed earlier values, which is what keeps a
	// destroyed object's identifier from being handed to a later one.
	uniqueIDCounter uint64
}

// uniqueIDPrefixSize is the number of random bytes shared by every
// CKA_UNIQUE_ID one manager generates.
const uniqueIDPrefixSize = 8

// uniqueIDCounterSize is the number of bytes of the sequential half of a
// generated CKA_UNIQUE_ID.
const uniqueIDCounterSize = 8

// generateUniqueIDLocked returns a fresh CKA_UNIQUE_ID value. The caller must
// hold the write lock.
//
// PKCS#11 v3.2 §4.4.1: "Any time a new object is created, a value for
// CKA_UNIQUE_ID MUST be generated by the token and stored with the object. The
// specific algorithm used to generate unique ID values for objects is
// token-specific, but values generated MUST be unique across all objects
// visible to any particular session, and SHOULD be unique across all objects
// created by the token."
//
// The value is the hex text of a random per-manager prefix followed by a
// counter, which makes both properties structural rather than probabilistic.
// Within one manager the counter guarantees distinctness, and because it never
// goes backwards no value is reused after the object holding it is destroyed —
// the specification permits reuse only after the token is reinitialized. The
// random prefix separates the values of one manager from those of any other,
// including the values restored from storage after a restart, which were
// generated under a previous prefix.
func (om *ObjectManager) generateUniqueIDLocked() ([]byte, error) {
	if !om.uniqueIDPrefixReady {
		if _, err := rand.Read(om.uniqueIDPrefix[:]); err != nil {
			return nil, NewPKCS11ErrorWithCause(CKR_DEVICE_ERROR, err)
		}
		om.uniqueIDPrefixReady = true
	}

	om.uniqueIDCounter++

	var raw [uniqueIDPrefixSize + uniqueIDCounterSize]byte
	copy(raw[:uniqueIDPrefixSize], om.uniqueIDPrefix[:])
	binary.BigEndian.PutUint64(raw[uniqueIDPrefixSize:], om.uniqueIDCounter)

	// CKA_UNIQUE_ID is an RFC 2279 string, so the bytes are rendered as text
	// rather than stored raw.
	encoded := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(encoded, raw[:])

	return encoded, nil
}

// NewObjectManager creates a new object manager.
func NewObjectManager() *ObjectManager {
	return &ObjectManager{
		objects:        NewHandleTable[*Object](),
		sessionObjects: make(map[SessionHandle]map[ObjectHandle]bool),
		objectOwner:    make(map[ObjectHandle]SessionHandle),
		findState:      make(map[SessionHandle]*FindObjectsState),
	}
}

// trackSessionObject records session-object ownership in both the forward and
// the reverse index. The caller must hold the write lock.
func (om *ObjectManager) trackSessionObject(session SessionHandle, handle ObjectHandle) {
	owned, ok := om.sessionObjects[session]
	if !ok {
		owned = make(map[ObjectHandle]bool)
		om.sessionObjects[session] = owned
	}
	owned[handle] = true
	om.objectOwner[handle] = session
}

// untrackSessionObject drops ownership of a destroyed session object. The
// reverse index locates the owning session directly, so releasing an object
// costs the same whether one session or a thousand are open. The caller must
// hold the write lock.
func (om *ObjectManager) untrackSessionObject(handle ObjectHandle) {
	session, ok := om.objectOwner[handle]
	if !ok {
		return
	}
	delete(om.objectOwner, handle)

	owned := om.sessionObjects[session]
	delete(owned, handle)
	if len(owned) == 0 {
		delete(om.sessionObjects, session)
	}
}

// authorizeLocked returns the error a caller must surface when the session may
// not touch the object. An object the session may not see is reported as
// CKR_OBJECT_HANDLE_INVALID: a caller must not be able to tell an object on
// another token from a handle that was never allocated. The caller must hold at
// least the read lock.
func (om *ObjectManager) authorizeLocked(ctx AccessContext, obj *Object) error {
	if !ctx.CanAccess(obj) {
		return NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}
	return nil
}

// authorizeWriteLocked reports whether the session may modify or destroy the
// object, layering the read/write-session rule for token objects on top of
// authorizeLocked. The caller must hold the write lock.
func (om *ObjectManager) authorizeWriteLocked(ctx AccessContext, obj *Object) error {
	if err := om.authorizeLocked(ctx, obj); err != nil {
		return err
	}
	if obj.IsToken && !ctx.ReadWrite {
		return NewPKCS11Error(CKR_SESSION_READ_ONLY)
	}
	return nil
}

// CreateObject creates a new object from the provided template.
// Returns the object handle or an error if creation fails.
//
// Per PKCS#11 v3.2 §5.7.1 only session objects may be created during a
// read-only session, and only public objects may be created unless the normal
// user is logged in.
func (om *ObjectManager) CreateObject(ctx AccessContext, template []Attribute) (ObjectHandle, error) {
	// The per-subtype creation requirements apply here and not in
	// buildObjectFromTemplate, which the generate and derive paths also use;
	// see requiredSubtypeAttributes.
	class, hasClass, classErr := templateClass(template)
	if classErr != nil {
		return ObjectHandle(InvalidHandle), classErr
	}
	if hasClass {
		present := make(map[AttributeType]bool, len(template))
		for _, attr := range template {
			present[attr.Type] = true
		}
		if err := checkRequiredSubtypeAttributes(class, template, present); err != nil {
			return ObjectHandle(InvalidHandle), err
		}
	}

	obj, err := buildObjectFromTemplate(template)
	if err != nil {
		return ObjectHandle(InvalidHandle), err
	}

	return om.createPolicyChecked(ctx, obj)
}

// CreateGeneratedObject creates an object holding key material the token itself
// produced, for C_GenerateKey and C_GenerateKeyPair. The class and key type are
// supplied by the caller because the mechanism implies them when the template
// omits them. Provenance is recorded by the token, not the caller: CKA_LOCAL is
// CK_TRUE, and CKA_ALWAYS_SENSITIVE / CKA_NEVER_EXTRACTABLE follow the key's
// effective protection (PKCS#11 v3.2 §4.9).
func (om *ObjectManager) CreateGeneratedObject(ctx AccessContext, class ObjectClass, keyType KeyType, template []Attribute) (ObjectHandle, error) {
	obj, err := buildObjectFromTemplate(completeKeyTemplate(class, keyType, template))
	if err != nil {
		return ObjectHandle(InvalidHandle), err
	}

	obj.SetAttribute(CKA_LOCAL, boolAttributeValue(true))
	obj.SetAttribute(CKA_ALWAYS_SENSITIVE, boolAttributeValue(obj.IsSensitive))
	obj.SetAttribute(CKA_NEVER_EXTRACTABLE, boolAttributeValue(!obj.IsExtractable))

	return om.createPolicyChecked(ctx, obj)
}

// CreateDerivedObject creates an object holding key material produced from an
// existing key, for C_DeriveKey, C_UnwrapKey and the KEM operations. CKA_LOCAL
// is CK_FALSE because the key was not generated on the token, and the two
// history attributes may only remain CK_TRUE if they were also true of the base
// key — otherwise deriving from an exposed key would launder its history
// (PKCS#11 v3.2 §4.9).
func (om *ObjectManager) CreateDerivedObject(ctx AccessContext, base *Object, class ObjectClass, keyType KeyType, template []Attribute) (ObjectHandle, error) {
	obj, err := buildObjectFromTemplate(completeKeyTemplate(class, keyType, template))
	if err != nil {
		return ObjectHandle(InvalidHandle), err
	}

	alwaysSensitive := obj.IsSensitive
	neverExtractable := !obj.IsExtractable
	if base != nil {
		alwaysSensitive = alwaysSensitive && boolAttributeIsTrue(base.GetAttribute(CKA_ALWAYS_SENSITIVE))
		neverExtractable = neverExtractable && boolAttributeIsTrue(base.GetAttribute(CKA_NEVER_EXTRACTABLE))
	}

	obj.SetAttribute(CKA_LOCAL, boolAttributeValue(false))
	obj.SetAttribute(CKA_ALWAYS_SENSITIVE, boolAttributeValue(alwaysSensitive))
	obj.SetAttribute(CKA_NEVER_EXTRACTABLE, boolAttributeValue(neverExtractable))

	return om.createPolicyChecked(ctx, obj)
}

// createPolicyChecked applies the session access rules to a fully-built object
// and inserts it.
func (om *ObjectManager) createPolicyChecked(ctx AccessContext, obj *Object) (ObjectHandle, error) {
	if obj.IsToken && !ctx.ReadWrite {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_SESSION_READ_ONLY)
	}
	if obj.IsPrivate && !ctx.LoggedIn {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_USER_NOT_LOGGED_IN)
	}
	// CKA_TRUSTED is checked on the built object rather than on the template so
	// that every creation path is covered by one rule: C_CreateObject,
	// C_GenerateKey(Pair), C_DeriveKey, C_UnwrapKey and the KEM operations all
	// arrive here, and each of them accepts a caller-supplied template.
	// v3.2 Table 13 footnote 10: only the SO may set it to CK_TRUE.
	if boolAttributeIsTrue(obj.GetAttribute(CKA_TRUSTED)) && !ctx.SecurityOfficer {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_ATTRIBUTE_READ_ONLY)
	}

	om.mu.Lock()
	defer om.mu.Unlock()

	return om.insertLocked(ctx, obj)
}

// completeKeyTemplate returns the template with CKA_CLASS and CKA_KEY_TYPE
// filled in from the mechanism when the caller omitted them, and with any
// token-computed attributes stripped so a caller cannot forge provenance.
func completeKeyTemplate(class ObjectClass, keyType KeyType, template []Attribute) []Attribute {
	completed := make([]Attribute, 0, len(template)+2)
	var hasClass, hasKeyType bool

	for _, attr := range template {
		if computedAttributes[attr.Type] {
			continue
		}
		switch attr.Type {
		case CKA_CLASS:
			hasClass = true
		case CKA_KEY_TYPE:
			hasKeyType = true
		}
		completed = append(completed, attr)
	}

	// The completed values are CK_ULONGs the token supplied rather than the
	// caller, and are the ones an application reads back from a key it asked
	// C_GenerateKeyPair to make without naming a class or a type. They are
	// written at the native CK_ULONG width for the reason normalizeULongWidth
	// gives: a caller that allocated sizeof(CK_ULONG) must get a whole one back.
	if !hasClass {
		completed = append(completed, NewULongAttribute(CKA_CLASS, uint64(class)))
	}
	if !hasKeyType {
		completed = append(completed, NewULongAttribute(CKA_KEY_TYPE, uint64(keyType)))
	}

	return completed
}

// boolAttributeIsTrue decodes a CK_BBOOL attribute value, treating an absent
// value as false.
func boolAttributeIsTrue(value []byte) bool {
	return len(value) > 0 && value[0] != 0
}

// insertLocked allocates a handle for a fully-built object and records session
// ownership. The caller must hold the write lock.
func (om *ObjectManager) insertLocked(ctx AccessContext, obj *Object) (ObjectHandle, error) {
	// The object belongs to the token the creating session is connected to.
	obj.SlotID = ctx.Slot

	// PKCS#11 v3.2 §4.4.1: "Any time a new object is created, a value for
	// CKA_UNIQUE_ID MUST be generated by the token and stored with the
	// object." Every path that creates an object -- C_CreateObject,
	// C_GenerateKey, C_GenerateKeyPair, C_DeriveKey, C_UnwrapKey, the KEM
	// operations and C_CopyObject -- reaches the token through this function,
	// so the identifier is assigned here and nowhere else. The assignment is
	// unconditional: a copy carries its source's identifier in the cloned
	// attribute map, and §5.7.2 requires that "whenever an object is copied, a
	// new value for CKA_UNIQUE_ID is generated and assigned to the new
	// object".
	uniqueID, err := om.generateUniqueIDLocked()
	if err != nil {
		return ObjectHandle(InvalidHandle), err
	}
	obj.SetAttribute(CKA_UNIQUE_ID, uniqueID)

	handle, err := om.objects.Allocate(obj)
	if err != nil {
		return ObjectHandle(InvalidHandle), NewPKCS11ErrorWithCause(CKR_DEVICE_MEMORY, err)
	}
	obj.Handle = ObjectHandle(handle)

	if !obj.IsToken {
		om.trackSessionObject(ctx.Session, ObjectHandle(handle))
	}

	return ObjectHandle(handle), nil
}

// buildObjectFromTemplate validates a creation template and materialises the
// object it describes, applying the attribute defaults PKCS#11 v3.2 §4.x
// specifies for each object class.
func buildObjectFromTemplate(template []Attribute) (*Object, error) {
	class, ok, err := templateClass(template)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, NewPKCS11Error(CKR_TEMPLATE_INCOMPLETE)
	}

	if err := validateCreateTemplate(class, template); err != nil {
		return nil, err
	}

	obj := NewObject(class)
	applyClassDefaults(obj, class)

	for _, attr := range template {
		obj.SetAttribute(attr.Type, attr.Value)
	}

	// CKA_LOCAL, CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE describe how the
	// token itself produced the key. An object supplied through C_CreateObject
	// was not generated on the token, so all three are CK_FALSE regardless of
	// what the caller asked for.
	if isKeyClass(class) {
		obj.SetAttribute(CKA_LOCAL, boolAttributeValue(false))
		obj.SetAttribute(CKA_ALWAYS_SENSITIVE, boolAttributeValue(false))
		obj.SetAttribute(CKA_NEVER_EXTRACTABLE, boolAttributeValue(false))
	}

	applyTrustedPrivacyDefault(obj, template)

	return obj, nil
}

// applyTrustedPrivacyDefault resolves this token's CKA_PRIVATE default for an
// object the caller marked CKA_TRUSTED.
//
// Only the SO may set CKA_TRUSTED (v3.2 Table 13 footnote 10), and the SO is not
// the normal user, so it cannot reach private objects (§4.2). Left at the class
// default of CK_TRUE, the two rules would deadlock: the only role permitted to
// create a trusted key would be the one role forbidden to create it.
//
// Table 17 resolves this by making the default the token's to choose -- of
// CKA_PRIVATE it says "Default value is token-specific, and may depend on the
// values of other attributes of the object." So this token makes a trusted
// object public by default, which is also what the attribute is for: a trusted
// wrapping key or trust anchor exists to be readable. An explicit CKA_PRIVATE in
// the template always wins; this only supplies the default the caller omitted.
func applyTrustedPrivacyDefault(obj *Object, template []Attribute) {
	if !boolAttributeIsTrue(obj.GetAttribute(CKA_TRUSTED)) {
		return
	}
	for _, attr := range template {
		if attr.Type == CKA_PRIVATE {
			return
		}
	}
	obj.SetAttribute(CKA_PRIVATE, boolAttributeValue(false))
}

// templateClass extracts CKA_CLASS from a template.
func templateClass(template []Attribute) (ObjectClass, bool, error) {
	for _, attr := range template {
		if attr.Type != CKA_CLASS {
			continue
		}
		if len(attr.Value) < 4 {
			return 0, false, NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
		}
		class := ObjectClass(binary.LittleEndian.Uint32(attr.Value))
		// A class outside the defined set names an object this token cannot
		// describe: it has no attribute table, no defaults and no required
		// attributes, so applyClassDefaults falls to its default arm and
		// isKeyClass returns false -- which skips the CKA_LOCAL /
		// CKA_ALWAYS_SENSITIVE / CKA_NEVER_EXTRACTABLE reset. The object was
		// created anyway and appeared in every C_FindObjects with an empty
		// template. The vendor range is admitted for the reason v3.2 §4.4 gives,
		// as checkAttributeSupported admits vendor attributes.
		if class < CKO_VENDOR_DEFINED && !definedObjectClasses[class] {
			return 0, false, NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
		}
		return class, true, nil
	}
	return 0, false, nil
}

// validateCreateTemplate enforces the per-class required attributes and rejects
// attributes the token alone may set.
func validateCreateTemplate(class ObjectClass, template []Attribute) error {
	present := make(map[AttributeType]bool, len(template))
	for _, attr := range template {
		if computedAttributes[attr.Type] {
			return NewPKCS11Error(CKR_ATTRIBUTE_READ_ONLY)
		}
		if err := checkAttributeSupported(attr); err != nil {
			return err
		}
		if present[attr.Type] {
			return NewPKCS11Error(CKR_TEMPLATE_INCONSISTENT)
		}
		present[attr.Type] = true
	}

	if err := checkValidityPeriodConsistent(template); err != nil {
		return err
	}

	for _, required := range requiredAttributes[class] {
		if !present[required] {
			return NewPKCS11Error(CKR_TEMPLATE_INCOMPLETE)
		}
	}

	return nil
}

// requiredSubtypeAttributes lists the attributes a creation template must carry
// for a particular key type or certificate type, on top of the class-wide set
// in requiredAttributes.
//
// PKCS#11 v3.2 Table 13 footnote 1 marks these "MUST be specified when object is
// created with C_CreateObject" in the per-type tables of §4.6.3 and §6, which a
// class-keyed table cannot express: an RSA public key needs a modulus and a DSA
// one does not.
//
// The scope is C_CreateObject ALONE. Footnote 4 is the opposite rule for the
// generate path -- CKA_VALUE must NOT be specified when the token generates the
// key -- so applying these in the shared template validator refuses every
// C_GenerateKey and C_GenerateKeyPair. checkRequiredSubtypeAttributes is called
// from ObjectManager.CreateObject and nowhere else for that reason.
var requiredSubtypeAttributes = map[ObjectClass]map[uint64][]AttributeType{
	CKO_CERTIFICATE: {
		uint64(CKC_X_509): {CKA_SUBJECT},
	},
	CKO_PUBLIC_KEY: {
		uint64(CKK_RSA): {CKA_MODULUS, CKA_PUBLIC_EXPONENT},
		uint64(CKK_EC):  {CKA_EC_PARAMS, CKA_EC_POINT},
	},
	CKO_SECRET_KEY: {
		uint64(CKK_AES):            {CKA_VALUE},
		uint64(CKK_GENERIC_SECRET): {CKA_VALUE},
	},
}

// subtypeDiscriminator names the attribute whose value selects the per-type
// requirement set for an object class.
var subtypeDiscriminator = map[ObjectClass]AttributeType{
	CKO_CERTIFICATE: CKA_CERTIFICATE_TYPE,
	CKO_PUBLIC_KEY:  CKA_KEY_TYPE,
	CKO_SECRET_KEY:  CKA_KEY_TYPE,
}

// checkRequiredSubtypeAttributes applies the per-key-type and
// per-certificate-type creation requirements. A subtype the table does not name
// carries no extra requirement, which is the correct treatment of a type this
// module does not model.
func checkRequiredSubtypeAttributes(class ObjectClass, template []Attribute, present map[AttributeType]bool) error {
	discriminator, ok := subtypeDiscriminator[class]
	if !ok {
		return nil
	}

	var subtype uint64
	for _, attr := range template {
		if attr.Type != discriminator {
			continue
		}
		value, decoded := ulongValue(attr.Value)
		if !decoded {
			return NewPKCS11Error(CKR_ATTRIBUTE_VALUE_INVALID)
		}
		subtype = value
	}

	for _, required := range requiredSubtypeAttributes[class][subtype] {
		if !present[required] {
			return NewPKCS11Error(CKR_TEMPLATE_INCOMPLETE)
		}
	}
	return nil
}

// definedObjectClasses is the set of CK_OBJECT_CLASS values PKCS#11 v3.2 §4.4
// defines. A template naming anything else, below the vendor range, is refused
// rather than materialised as an object whose behaviour no table describes.
var definedObjectClasses = map[ObjectClass]bool{
	CKO_DATA:              true,
	CKO_CERTIFICATE:       true,
	CKO_PUBLIC_KEY:        true,
	CKO_PRIVATE_KEY:       true,
	CKO_SECRET_KEY:        true,
	CKO_HW_FEATURE:        true,
	CKO_DOMAIN_PARAMETERS: true,
	CKO_MECHANISM:         true,
	CKO_OTP_KEY:           true,
	CKO_PROFILE:           true,
	CKO_VALIDATION:        true,
	CKO_TRUST:             true,
}

// checkValidityPeriodConsistent rejects a template whose CKA_START_DATE falls
// after its CKA_END_DATE. Such a template describes a window that can never be
// open, so it is inconsistent in the sense PKCS#11 v3.2 §5.7.1 gives
// CKR_TEMPLATE_INCONSISTENT: an attribute value incompatible with another
// attribute of the same object.
func checkValidityPeriodConsistent(template []Attribute) error {
	var start, end []byte
	for _, attr := range template {
		switch attr.Type {
		case CKA_START_DATE:
			start = attr.Value
		case CKA_END_DATE:
			end = attr.Value
		}
	}

	if len(start) == ckDateLength && len(end) == ckDateLength && string(start) > string(end) {
		return NewPKCS11Error(CKR_TEMPLATE_INCONSISTENT)
	}
	return nil
}

// applyClassDefaults seeds the attribute defaults for an object class before
// the caller's template is applied on top.
func applyClassDefaults(obj *Object, class ObjectClass) {
	obj.SetAttribute(CKA_TOKEN, boolAttributeValue(false))
	obj.SetAttribute(CKA_MODIFIABLE, boolAttributeValue(true))
	obj.SetAttribute(CKA_COPYABLE, boolAttributeValue(true))
	obj.SetAttribute(CKA_DESTROYABLE, boolAttributeValue(true))

	switch class {
	case CKO_PRIVATE_KEY:
		// Private keys default to private and sensitive: CKA_PRIVATE and
		// CKA_SENSITIVE are token-specific defaults, and a token that protects
		// key material must choose the protective value.
		obj.SetAttribute(CKA_PRIVATE, boolAttributeValue(true))
		obj.SetAttribute(CKA_SENSITIVE, boolAttributeValue(true))
		obj.SetAttribute(CKA_EXTRACTABLE, boolAttributeValue(true))
		applyKeyUsageDefaults(obj)
	case CKO_SECRET_KEY:
		obj.SetAttribute(CKA_PRIVATE, boolAttributeValue(true))
		obj.SetAttribute(CKA_SENSITIVE, boolAttributeValue(false))
		obj.SetAttribute(CKA_EXTRACTABLE, boolAttributeValue(true))
		applyKeyUsageDefaults(obj)
	case CKO_PUBLIC_KEY:
		obj.SetAttribute(CKA_PRIVATE, boolAttributeValue(false))
		applyKeyUsageDefaults(obj)
	default:
		obj.SetAttribute(CKA_PRIVATE, boolAttributeValue(false))
	}
}

// keyUsageAttributes are the boolean capability attributes every key object
// carries (PKCS#11 v3.2 §4.9).
var keyUsageAttributes = []AttributeType{
	CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY,
	CKA_SIGN_RECOVER, CKA_VERIFY_RECOVER,
	CKA_WRAP, CKA_UNWRAP, CKA_DERIVE,
	CKA_ALWAYS_AUTHENTICATE, CKA_WRAP_WITH_TRUSTED, CKA_TRUSTED,
}

// applyKeyUsageDefaults gives a key object every capability attribute with the
// value CK_FALSE.
//
// They must be present rather than absent even when unset. C_GetAttributeValue
// answers CKR_ATTRIBUTE_TYPE_INVALID for an attribute an object does not have
// (v3.2 §5.7.5), and real Cryptoki consumers treat that as a hard error rather
// than "capability not granted" — libp11 refuses to load a key at all, and
// pkcs11-tool warns on every listing. CK_FALSE says the same thing the absence
// was meant to say, so the token's deny-by-default posture is unchanged while
// the object becomes readable by an ordinary client.
func applyKeyUsageDefaults(obj *Object) {
	for _, attr := range keyUsageAttributes {
		obj.SetAttribute(attr, boolAttributeValue(false))
	}
}

// isKeyClass reports whether the object class holds key material.
// isKeyClass reports whether the object class holds key material.
//
// It must name the same classes protectsSensitiveAttributes does. CKO_OTP_KEY
// was in that function's set and not this one, so an OTP key was withheld from
// C_GetAttributeValue as a key while never having its provenance attributes
// reset as one: CKA_LOCAL, CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE stayed
// whatever the caller's template asked for.
func isKeyClass(class ObjectClass) bool {
	switch class {
	case CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_SECRET_KEY, CKO_OTP_KEY:
		return true
	default:
		return false
	}
}

// boolAttributeValue encodes a CK_BBOOL attribute value.
func boolAttributeValue(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}

// CopyObject creates a copy of an existing object with optional attribute modifications.
//
// Per PKCS#11 v3.2 §5.7.2 the copy is subject to the same read-only-session and
// login restrictions as any other object creation. CKA_TOKEN, CKA_PRIVATE and
// CKA_MODIFIABLE may be changed here — this is the only place the specification
// allows it — but the one-way rules on CKA_SENSITIVE and CKA_EXTRACTABLE still
// apply, so a copy cannot be used to launder protection off a key.
func (om *ObjectManager) CopyObject(ctx AccessContext, handle ObjectHandle, template []Attribute) (ObjectHandle, error) {
	om.mu.Lock()
	defer om.mu.Unlock()

	srcObj, ok := om.objects.Lookup(uint64(handle))
	if !ok {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}
	if err := om.authorizeLocked(ctx, srcObj); err != nil {
		return ObjectHandle(InvalidHandle), err
	}
	if !srcObj.IsCopyable {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_ACTION_PROHIBITED)
	}

	newObj := srcObj.Clone()

	if err := checkTrustedAssertion(ctx, srcObj, template); err != nil {
		return ObjectHandle(InvalidHandle), err
	}

	for _, attr := range template {
		if computedAttributes[attr.Type] {
			return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_ATTRIBUTE_READ_ONLY)
		}
		if !copyModifiableAttributes[attr.Type] && IsReadOnlyAttribute(attr.Type) {
			return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_ATTRIBUTE_READ_ONLY)
		}
		if isImmutableKeyMaterial(newObj.Class, attr.Type) {
			return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_ATTRIBUTE_READ_ONLY)
		}
		if err := checkAttributeSupported(attr); err != nil {
			return ObjectHandle(InvalidHandle), err
		}
		if err := checkOneWayTransition(newObj, attr); err != nil {
			return ObjectHandle(InvalidHandle), err
		}
		newObj.SetAttribute(attr.Type, attr.Value)
	}

	if newObj.IsToken && !ctx.ReadWrite {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_SESSION_READ_ONLY)
	}
	if newObj.IsPrivate && !ctx.LoggedIn {
		return ObjectHandle(InvalidHandle), NewPKCS11Error(CKR_USER_NOT_LOGGED_IN)
	}

	return om.insertLocked(ctx, newObj)
}

// DestroyObject removes an object from the manager.
//
// Per PKCS#11 v3.2 §5.7.3 only session objects may be destroyed during a
// read-only session and only public objects unless the normal user is logged in.
func (om *ObjectManager) DestroyObject(ctx AccessContext, handle ObjectHandle) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	obj, ok := om.objects.Lookup(uint64(handle))
	if !ok {
		return NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}
	if err := om.authorizeWriteLocked(ctx, obj); err != nil {
		return err
	}
	if !obj.IsDestroyable {
		return NewPKCS11Error(CKR_ACTION_PROHIBITED)
	}

	if _, ok := om.objects.Release(uint64(handle)); !ok {
		return NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}
	obj.Zeroize()
	om.untrackSessionObject(handle)

	return nil
}

// GetAttributeValue retrieves attribute values for an object.
// Per PKCS#11 spec:
//   - If template value is nil, returns required buffer size
//   - If template value is too small, returns CKR_BUFFER_TOO_SMALL
//   - Sensitive attributes on sensitive objects return CKR_ATTRIBUTE_SENSITIVE
func (om *ObjectManager) GetAttributeValue(ctx AccessContext, handle ObjectHandle, template []Attribute) ([]Attribute, error) {
	om.mu.RLock()
	defer om.mu.RUnlock()

	obj, ok := om.objects.Lookup(uint64(handle))
	if !ok {
		return nil, NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}
	if err := om.authorizeLocked(ctx, obj); err != nil {
		return nil, err
	}

	// Every entry in the template must be processed even after one of them
	// fails, and the caller receives the whole result alongside the error so it
	// can write back the values it is entitled to. See v3.2 §5.7.5.
	result := make([]Attribute, len(template))
	var hasError error
	fail := func(i int, rv CK_RV) {
		result[i].Value = nil
		result[i].Unavailable = true
		if hasError == nil {
			hasError = NewPKCS11Error(rv)
		}
	}

	for i, attr := range template {
		result[i].Type = attr.Type

		// A sensitive or unextractable key never reveals its protected
		// attributes. Both conditions must be checked: an unextractable key is
		// protected even when CKA_SENSITIVE is CK_FALSE. Non-key classes
		// (certificates, data objects) always reveal their CKA_VALUE.
		if obj.protectsSensitiveAttributes() && IsSensitiveAttribute(attr.Type) {
			fail(i, CKR_ATTRIBUTE_SENSITIVE)
			continue
		}

		value, exists := obj.Attributes[attr.Type]
		if !exists {
			fail(i, CKR_ATTRIBUTE_TYPE_INVALID)
			continue
		}

		result[i].Value = copyBytes(value)
	}

	return result, hasError
}

// SetAttributeValue modifies attribute values for an object.
//
// Per PKCS#11 v3.2 §5.7.4 only session objects may be modified during a
// read-only session, and the one-way rules on CKA_SENSITIVE and
// CKA_EXTRACTABLE are enforced so protection can never be removed in place.
func (om *ObjectManager) SetAttributeValue(ctx AccessContext, handle ObjectHandle, template []Attribute) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	obj, ok := om.objects.Lookup(uint64(handle))
	if !ok {
		return NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}
	if err := om.authorizeWriteLocked(ctx, obj); err != nil {
		return err
	}
	if !obj.IsModifiable {
		return NewPKCS11Error(CKR_ACTION_PROHIBITED)
	}

	// Validate the whole template before applying any of it, so a rejected
	// attribute cannot leave the object partially modified.
	if err := checkTrustedAssertion(ctx, obj, template); err != nil {
		return err
	}
	for _, attr := range template {
		if IsReadOnlyAttribute(attr.Type) || computedAttributes[attr.Type] ||
			isImmutableKeyMaterial(obj.Class, attr.Type) {
			return NewPKCS11Error(CKR_ATTRIBUTE_READ_ONLY)
		}
		if err := checkAttributeSupported(attr); err != nil {
			return err
		}
		if err := checkOneWayTransition(obj, attr); err != nil {
			return err
		}
	}

	// The validity window is a property of the pair, so a modification that
	// changes only one end must be judged against the value the other end will
	// still hold afterwards.
	effective := []Attribute{
		NewAttribute(CKA_START_DATE, obj.Attributes[CKA_START_DATE]),
		NewAttribute(CKA_END_DATE, obj.Attributes[CKA_END_DATE]),
	}
	effective = append(effective, template...)
	if err := checkValidityPeriodConsistent(effective); err != nil {
		return err
	}

	for _, attr := range template {
		obj.SetAttribute(attr.Type, attr.Value)
	}

	return nil
}

// FindObjectsInit initializes a search for objects that match the template.
//
// The search only ever returns objects the session may view: per PKCS#11 v3.2
// §5.7.7 a search from a public session must not find private objects, and a
// session must not find objects belonging to another token.
func (om *ObjectManager) FindObjectsInit(ctx AccessContext, template []Attribute) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if _, exists := om.findState[ctx.Session]; exists {
		return NewPKCS11Error(CKR_OPERATION_ACTIVE)
	}

	var matches []ObjectHandle
	om.objects.ForEach(func(handle uint64, obj *Object) bool {
		if ctx.CanAccess(obj) && obj.MatchesTemplate(template) {
			matches = append(matches, ObjectHandle(handle))
		}
		return true
	})

	// Return matches in a stable order. ForEach walks a Go map, whose iteration
	// order is deliberately randomised per range, so the same search returned
	// the same objects in a different order on every call. PKCS#11 does not
	// mandate an order, but real callers depend on one: OpenSC's pkcs11-tool
	// takes the first object of the requested class for --encrypt/--decrypt, so
	// an unstable order made it encrypt and decrypt under different keys on a
	// multi-key token -- intermittently, which is the worst way to find out.
	// SoftHSM, the reference implementation, is stable here.
	sort.Slice(matches, func(i, j int) bool { return matches[i] < matches[j] })

	om.findState[ctx.Session] = &FindObjectsState{
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

// getObjectUnchecked retrieves an object by its handle without applying any
// access policy.
//
// It is unexported and deliberately named so that its use is conspicuous: it is
// only for callers that genuinely have no session context — restoring persisted
// objects at startup, mirroring PIV slot contents, or re-reading a handle the
// same call just created through a validated AccessContext. Any path serving an
// application request must use GetObjectFor instead, or it will bypass the
// private-object and slot-isolation rules.
func (om *ObjectManager) getObjectUnchecked(handle ObjectHandle) (*Object, error) {
	om.mu.RLock()
	defer om.mu.RUnlock()

	obj, ok := om.objects.Lookup(uint64(handle))
	if !ok {
		return nil, NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}

	return obj, nil
}

// GetObjectFor retrieves an object on behalf of a session, enforcing the
// private-object and session-object visibility rules. Every application-driven
// path — key lookup for a cryptographic operation, attribute access, wrapping —
// must resolve handles through this method so a session can neither use nor
// probe for private objects it has not authenticated to, nor for session
// objects belonging to another session.
func (om *ObjectManager) GetObjectFor(ctx AccessContext, handle ObjectHandle) (*Object, error) {
	om.mu.RLock()
	defer om.mu.RUnlock()

	obj, ok := om.objects.Lookup(uint64(handle))
	if !ok {
		return nil, NewPKCS11Error(CKR_OBJECT_HANDLE_INVALID)
	}
	if err := om.authorizeLocked(ctx, obj); err != nil {
		return nil, err
	}

	return obj, nil
}

// DestroySessionObjects destroys the session objects owned by the given session
// and clears its search state. Objects belonging to other sessions are left
// untouched: PKCS#11 v3.2 §5.6.2 scopes this cleanup to the session being
// closed, and destroying another session's live objects would break it.
func (om *ObjectManager) DestroySessionObjects(session SessionHandle) {
	om.mu.Lock()
	defer om.mu.Unlock()

	for handle := range om.sessionObjects[session] {
		if obj, ok := om.objects.Release(uint64(handle)); ok {
			obj.Zeroize()
		}
		delete(om.objectOwner, handle)
	}
	delete(om.sessionObjects, session)

	delete(om.findState, session)
}

// Zeroize destroys every object the manager holds and overwrites its attribute
// values.
//
// It is what C_Finalize needs. PKCS#11 v3.2 §5.4.2 ends the application's use of
// the library, and the material the token was holding on its behalf must not
// outlive that in this process's heap: an application that finalizes precisely
// to shed key material before forking, dropping privilege or dumping core gets
// no such guarantee if the objects are merely released to the garbage collector.
func (om *ObjectManager) Zeroize() {
	om.mu.Lock()
	defer om.mu.Unlock()

	om.objects.ForEach(func(_ uint64, obj *Object) bool {
		obj.Zeroize()
		return true
	})

	om.objects.Clear()
	om.sessionObjects = make(map[SessionHandle]map[ObjectHandle]bool)
	om.objectOwner = make(map[ObjectHandle]SessionHandle)
	om.findState = make(map[SessionHandle]*FindObjectsState)
}

// DestroyPrivateSessionObjects destroys the private session objects owned by
// the given session, as C_Logout requires (PKCS#11 v3.2 §5.6.10). Public
// session objects survive the logout.
func (om *ObjectManager) DestroyPrivateSessionObjects(session SessionHandle) {
	om.mu.Lock()
	defer om.mu.Unlock()

	owned := om.sessionObjects[session]
	for handle := range owned {
		obj, ok := om.objects.Lookup(uint64(handle))
		if !ok || !obj.IsPrivate {
			continue
		}
		if released, ok := om.objects.Release(uint64(handle)); ok {
			released.Zeroize()
		}
		delete(owned, handle)
		delete(om.objectOwner, handle)
	}
	if len(owned) == 0 {
		delete(om.sessionObjects, session)
	}
}

// DestroyAllDestroyableObjects destroys every object on the given token that
// the token is permitted to destroy, as C_InitToken requires (PKCS#11 v3.2
// §5.5.7). Objects belonging to another slot, and objects whose
// CKA_DESTROYABLE is CK_FALSE, are left in place. The handles of the destroyed
// objects are returned so the caller can clear them from persistent storage.
func (om *ObjectManager) DestroyAllDestroyableObjects(slotID SlotID) []ObjectHandle {
	om.mu.Lock()
	defer om.mu.Unlock()

	var destroyable []ObjectHandle
	om.objects.ForEach(func(handle uint64, obj *Object) bool {
		if obj.SlotID == slotID && obj.IsDestroyable {
			destroyable = append(destroyable, ObjectHandle(handle))
		}
		return true
	})

	for _, handle := range destroyable {
		if obj, ok := om.objects.Release(uint64(handle)); ok {
			obj.Zeroize()
		}
		om.untrackSessionObject(handle)
	}

	return destroyable
}

// DestroyObjectsForKey destroys every object holding the given backend key,
// returning the handles it removed.
//
// It exists for the PIV mirror, where the certificate, public key and private
// key of one card slot share a KeyID. A slot's contents are replaced rather than
// accumulated: the card holds one certificate and one key per slot, so a second
// trio for the same slot gives C_FindObjects two answers to a question that has
// one, and OpenSSH -- which pairs a certificate to its key by CKA_ID -- binds
// whichever the handle order happens to surface first.
func (om *ObjectManager) DestroyObjectsForKey(backendName, keyID string) []ObjectHandle {
	om.mu.Lock()
	defer om.mu.Unlock()

	var stale []ObjectHandle
	om.objects.ForEach(func(handle uint64, obj *Object) bool {
		if obj.KeyID == keyID && obj.BackendName == backendName {
			stale = append(stale, ObjectHandle(handle))
		}
		return true
	})

	for _, handle := range stale {
		if obj, ok := om.objects.Release(uint64(handle)); ok {
			obj.Zeroize()
		}
		om.untrackSessionObject(handle)
	}

	return stale
}

// Size returns the total number of objects.
func (om *ObjectManager) Size() int {
	return om.objects.Size()
}

// SessionObjectCount returns the number of session objects across all sessions.
func (om *ObjectManager) SessionObjectCount() int {
	om.mu.RLock()
	defer om.mu.RUnlock()

	count := 0
	for _, owned := range om.sessionObjects {
		count += len(owned)
	}
	return count
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

	// An object restored from storage already carries the CKA_UNIQUE_ID it was
	// created with, and keeping it is what makes the identifier stable across
	// a restart. An object mirrored from hardware, such as a PIV slot, has
	// never been through a creation path and has none, so it is given one here
	// -- §4.4.1 requires every object to have one, however it came to exist.
	if !obj.HasAttribute(CKA_UNIQUE_ID) {
		uniqueID, err := om.generateUniqueIDLocked()
		if err != nil {
			return err
		}
		obj.SetAttribute(CKA_UNIQUE_ID, uniqueID)
	}

	// A restored or mirrored object names the handle it must keep, and that
	// handle is either free or already holds this same object. Anything else is
	// two objects claiming one handle, and HandleTable.Update succeeds precisely
	// when the handle is TAKEN -- so the previous code silently overwrote whoever
	// was there. A corrupt handle counter or a mislabelled record could therefore
	// replace a live private key, and an application holding a handle to it would
	// find different key material under the same number, with no error anywhere.
	if obj.Handle != ObjectHandle(InvalidHandle) {
		if existing, taken := om.objects.Lookup(uint64(obj.Handle)); taken && existing != obj {
			return NewPKCS11ErrorWithMessage(CKR_DEVICE_ERROR,
				"object handle "+strconv.FormatUint(uint64(obj.Handle), 10)+
					" is already in use by another object")
		}
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

	// Objects added this way have no owning session: they are restored token
	// objects or objects that mirror hardware slot state. They are therefore
	// module-scoped and are not destroyed when any particular session closes.

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
