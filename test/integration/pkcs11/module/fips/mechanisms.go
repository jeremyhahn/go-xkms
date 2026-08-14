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

//go:build integration && fips

package fips

import "fmt"

// Mechanism types the module implements that github.com/miekg/pkcs11 v1.1.2
// does not define. The values are the ones in pkg/pkcs11/module/mechanism.go,
// which are in turn the OASIS PKCS#11 v3.2 assignments; they are restated here
// rather than imported so this suite reaches the module only through the C
// interface, exactly as a foreign application would.
const (
	ckmECEdwardsKeyPairGen    uint = 0x00001055
	ckmECMontgomeryKeyPairGen uint = 0x00001056
	ckmEdDSA                  uint = 0x00001057
	ckmXEdDSA                 uint = 0x00001058
	ckmHKDFDerive             uint = 0x0000402C
	ckmHKDFData               uint = 0x0000402D
	ckmHKDFKeyGen             uint = 0x0000402E
	ckmSP800108CounterKDF     uint = 0x000003AC
	ckmSHA384HMAC             uint = 0x00000261
	ckmSHA512HMAC             uint = 0x00000271

	// The truncated SHA-512 digests of FIPS 180-4 §6.6-6.7 and the current
	// RFC 5649 key-wrap identifier. All three are advertised by the module and
	// FIPS-approved, so the enforcement suite needs a probe for each.
	ckmSHA512224     uint = 0x00000048
	ckmSHA512256     uint = 0x0000004C
	ckmAESKeyWrapKWP uint = 0x0000210B
)

// mechanismNames maps a mechanism type to its OASIS name, so a failure names
// the mechanism a reader can look up rather than a bare hex value.
var mechanismNames = map[uint]string{
	0x00000000: "CKM_RSA_PKCS_KEY_PAIR_GEN",
	0x00000001: "CKM_RSA_PKCS",
	0x00000003: "CKM_RSA_X_509",
	0x00000006: "CKM_SHA1_RSA_PKCS",
	0x00000009: "CKM_RSA_PKCS_OAEP",
	0x0000000D: "CKM_RSA_PKCS_PSS",
	0x00000040: "CKM_SHA256_RSA_PKCS",
	0x00000041: "CKM_SHA384_RSA_PKCS",
	0x00000042: "CKM_SHA512_RSA_PKCS",
	0x00000043: "CKM_SHA256_RSA_PKCS_PSS",
	0x00000044: "CKM_SHA384_RSA_PKCS_PSS",
	0x00000045: "CKM_SHA512_RSA_PKCS_PSS",
	0x00000220: "CKM_SHA_1",
	0x00000250: "CKM_SHA256",
	0x00000251: "CKM_SHA256_HMAC",
	0x00000255: "CKM_SHA224",
	0x00000260: "CKM_SHA384",
	0x00000261: "CKM_SHA384_HMAC",
	0x00000270: "CKM_SHA512",
	0x00000271: "CKM_SHA512_HMAC",
	0x000002B0: "CKM_SHA3_256",
	0x000002D0: "CKM_SHA3_512",
	0x00000350: "CKM_GENERIC_SECRET_KEY_GEN",
	0x000003AC: "CKM_SP800_108_COUNTER_KDF",
	0x0000402C: "CKM_HKDF_DERIVE",
	0x0000402D: "CKM_HKDF_DATA",
	0x0000402E: "CKM_HKDF_KEY_GEN",
	0x00001040: "CKM_EC_KEY_PAIR_GEN",
	0x00001041: "CKM_ECDSA",
	0x00001042: "CKM_ECDSA_SHA1",
	0x00001043: "CKM_ECDSA_SHA224",
	0x00001044: "CKM_ECDSA_SHA256",
	0x00001045: "CKM_ECDSA_SHA384",
	0x00001046: "CKM_ECDSA_SHA512",
	0x00001050: "CKM_ECDH1_DERIVE",
	0x00001051: "CKM_ECDH1_COFACTOR_DERIVE",
	0x00001052: "CKM_ECMQV_DERIVE",
	0x00001053: "CKM_ECDH_AES_KEY_WRAP",
	0x00001055: "CKM_EC_EDWARDS_KEY_PAIR_GEN",
	0x00001056: "CKM_EC_MONTGOMERY_KEY_PAIR_GEN",
	0x00001057: "CKM_EDDSA",
	0x00001058: "CKM_XEDDSA",
	0x00001080: "CKM_AES_KEY_GEN",
	0x00001081: "CKM_AES_ECB",
	0x00001082: "CKM_AES_CBC",
	0x00001085: "CKM_AES_CBC_PAD",
	0x00001086: "CKM_AES_CTR",
	0x00001087: "CKM_AES_GCM",
	0x00001088: "CKM_AES_CCM",
	0x0000108A: "CKM_AES_CMAC",
	0x00002109: "CKM_AES_KEY_WRAP",
	0x0000210A: "CKM_AES_KEY_WRAP_PAD",
	0x0000210B: "CKM_AES_KEY_WRAP_KWP",
	0x00000048: "CKM_SHA512_224",
	0x0000004C: "CKM_SHA512_256",
}

// mechName returns a readable name for a mechanism type.
func mechName(mech uint) string {
	if name, ok := mechanismNames[mech]; ok {
		return name
	}
	return fmt.Sprintf("CKM_UNKNOWN(0x%08X)", mech)
}

// mechNames renders a set of mechanism types as a sorted, readable list.
func mechNames(mechs []uint) []string {
	out := make([]string, 0, len(mechs))
	for _, m := range mechs {
		out = append(out, fmt.Sprintf("%s (0x%08X)", mechName(m), m))
	}
	return out
}
