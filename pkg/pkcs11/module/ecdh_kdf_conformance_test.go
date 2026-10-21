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

package module

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ecdhConformanceSecret stands in for an ECDH shared secret. The derivations
// below are compared against each other, so a fixed value is sufficient.
var ecdhConformanceSecret = []byte("pkcs11 ecdh conformance shared secret")

// validECDHPeerPoint returns a genuine uncompressed P-256 point to stand in for
// CK_ECDH1_DERIVE_PARAMS.pPublicData.
//
// A fixture cannot use 0x04 followed by zeroes: that is the right shape but not
// a point on the curve, and ValidateECDHPeerPoint refuses it precisely so an
// off-curve point cannot reach a backend. Generating a real key is the cheapest
// way to get a point that is on the curve by construction.
func validECDHPeerPoint(t *testing.T) []byte {
	t.Helper()

	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a peer key for the ECDH fixture: %v", err)
	}
	return key.PublicKey().Bytes()
}

// TestSupportedECDHKDFs_EveryAdvertisedKDFDerives is the conformance assertion
// for the CK_EC_KDF_TYPE advertisement, and the one that would have caught the
// defect it replaces. C_DeriveKey accepted CKD_SHA1_KDF, CKD_SHA224_KDF and
// CKD_SHA3_224_KDF and forwarded "SHA-1" / "SHA-224" / "SHA3-224" to the KDF
// layer, whose allowlist held only SHA-2 and SHA-3 at 256 bits and above — so
// three advertised mechanisms failed at derivation time, every time.
//
// It drives the (algorithm, hash) pair straight out of the module's own
// advertisement and runs it through types.KDFParams, which is the single
// derivation entry point every backend shares. A KDF type added to ecdhKDFs
// therefore cannot be advertised without being proven to derive.
func TestSupportedECDHKDFs_EveryAdvertisedKDFDerives(t *testing.T) {
	advertised := SupportedECDHKDFs()
	if len(advertised) == 0 {
		t.Fatal("SupportedECDHKDFs returned nothing")
	}

	seen := make(map[string][]byte, len(advertised))
	for _, kdfType := range advertised {
		t.Run(kdfType.String(), func(t *testing.T) {
			algorithm, hash, ok := ECDHKDF(kdfType)
			if !ok {
				t.Fatalf("%s is advertised by SupportedECDHKDFs but does not resolve", kdfType)
			}

			params := &types.KDFParams{
				Algorithm: types.KDFAlgorithm(algorithm),
				Hash:      hash,
				KeyLength: 32,
			}
			err := params.Validate()
			if hash == "SHA-1" && !types.HashUsable(crypto.SHA1) {
				// fips140=only refuses crypto/sha1 for every use, so the KDF
				// must refuse it with a typed error (go-xkms#292).
				if !errors.Is(err, types.ErrUnsupportedKDFHash) {
					t.Fatalf("%s under fips140=only: Validate returned %v, want ErrUnsupportedKDFHash",
						kdfType, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s resolves to (%s, %s), which types.KDFParams.Validate rejects: %v",
					kdfType, algorithm, hash, err)
			}

			derived, err := params.Derive(ecdhConformanceSecret)
			if err != nil {
				t.Fatalf("%s resolves to (%s, %s), which fails at derivation time: %v",
					kdfType, algorithm, hash, err)
			}
			if len(derived) != 32 {
				t.Fatalf("%s derived %d bytes, want 32", kdfType, len(derived))
			}
			if bytes.Equal(derived, make([]byte, 32)) {
				t.Fatalf("%s derived all zero bytes", kdfType)
			}

			// Distinct KDF types must produce distinct keying material,
			// otherwise the CK_EC_KDF_TYPE the caller chose did not reach the
			// derivation. The three SHA-1 X9.63 aliases are the documented
			// exception: CKD_SHA1_KDF, CKD_SHA1_KDF_ASN1 and
			// CKD_SHA1_KDF_CONCATENATE differ only in how the caller encodes
			// SharedData, not in the derivation.
			key := algorithm + "/" + hash
			if prior, ok := seen[key]; ok {
				if !bytes.Equal(prior, derived) {
					t.Fatalf("%s is a %s alias but derived different bytes", kdfType, key)
				}
				return
			}
			for otherKey, other := range seen {
				if bytes.Equal(other, derived) {
					t.Fatalf("%s (%s) derived the same bytes as %s; the requested KDF did not run",
						kdfType, key, otherKey)
				}
			}
			seen[key] = derived
		})
	}

	// The advertisement must cover both concatenation KDFs and the full hash
	// range, otherwise the loop above could pass over a single entry.
	if len(seen) < 8 {
		t.Errorf("only %d distinct (algorithm, hash) pairs are advertised: %d expected at minimum", len(seen), 8)
	}
}

// TestECDHKDF_AdvertisementMatchesResolver asserts the two halves of the
// advertisement agree: everything SupportedECDHKDFs enumerates resolves, and
// everything ECDHKDF resolves is enumerated. A drift between them would let a
// KDF type be reachable without being advertised, or advertised without being
// reachable.
func TestECDHKDF_AdvertisementMatchesResolver(t *testing.T) {
	advertised := make(map[KDFType]bool)
	for _, kdfType := range SupportedECDHKDFs() {
		advertised[kdfType] = true
		if _, _, ok := ECDHKDF(kdfType); !ok {
			t.Errorf("%s is advertised but does not resolve", kdfType)
		}
	}

	// Every CK_EC_KDF_TYPE value PKCS#11 v3.0 defines, so the sweep covers the
	// unadvertised ones too rather than only the ones already in the table.
	allDefined := []KDFType{
		CKD_NULL, CKD_SHA1_KDF, CKD_SHA1_KDF_ASN1, CKD_SHA1_KDF_CONCATENATE,
		CKD_SHA224_KDF, CKD_SHA256_KDF, CKD_SHA384_KDF, CKD_SHA512_KDF,
		CKD_CPDIVERSIFY_KDF,
		CKD_SHA3_224_KDF, CKD_SHA3_256_KDF, CKD_SHA3_384_KDF, CKD_SHA3_512_KDF,
		CKD_SHA1_KDF_SP800, CKD_SHA224_KDF_SP800, CKD_SHA256_KDF_SP800,
		CKD_SHA384_KDF_SP800, CKD_SHA512_KDF_SP800,
		CKD_BLAKE2B_160_KDF, CKD_BLAKE2B_256_KDF, CKD_BLAKE2B_384_KDF, CKD_BLAKE2B_512_KDF,
	}
	for _, kdfType := range allDefined {
		_, _, ok := ECDHKDF(kdfType)
		if ok != advertised[kdfType] {
			t.Errorf("%s: ECDHKDF resolves=%v but SupportedECDHKDFs advertises=%v",
				kdfType, ok, advertised[kdfType])
		}
	}

	// SupportedECDHKDFs must be sorted so callers and C_GetMechanismInfo-style
	// enumerations see a stable order rather than Go's randomized map order.
	sorted := SupportedECDHKDFs()
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1] >= sorted[i] {
			t.Fatalf("SupportedECDHKDFs is not sorted ascending: %v", sorted)
		}
	}
}

// TestDeriveKeyECDH_RefusesUnadvertisedKDFType asserts the reject side at the
// PKCS#11 boundary. The mapping this replaces answered every unlisted
// CK_EC_KDF_TYPE — the four BLAKE2b types among them — with HKDF-SHA-256 and
// returned CKR_OK, so a caller received key material derived by a function it
// never named and had no way to detect the substitution. The correct answer is
// CKR_MECHANISM_PARAM_INVALID: the KDF is a mechanism parameter
// (CK_ECDH1_DERIVE_PARAMS.kdf), not a mechanism.
//
// CKD_NULL is deliberately absent from this list. It used to be refused here
// for want of a "no KDF" representation on the wire, but refusing it made the
// token unusable for TLS key exchange and for OpenSSL's pkcs11-provider, which
// both ask for the raw shared secret. It now resolves to the raw KDF and is
// covered by TestDeriveKeyECDH_AcceptsEveryAdvertisedKDFType.
func TestDeriveKeyECDH_RefusesUnadvertisedKDFType(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// The token sets CKF_LOGIN_REQUIRED, so key derivation is refused until the
	// normal user has authenticated.
	session := loginAsNormalUser(t, m)

	// A real P-256 point, so the refusal under test is the KDF type and not the
	// peer point: deriveKeyECDH validates the point first, and an off-curve one
	// would answer CKR_MECHANISM_PARAM_INVALID for a different reason than the
	// one this test means to pin.
	peerPoint := validECDHPeerPoint(t)

	unsupported := []KDFType{
		CKD_CPDIVERSIFY_KDF,
		CKD_BLAKE2B_160_KDF,
		CKD_BLAKE2B_256_KDF,
		CKD_BLAKE2B_384_KDF,
		CKD_BLAKE2B_512_KDF,
		KDFType(0),
		KDFType(0xFFFFFFFF),
	}
	for _, kdfType := range unsupported {
		t.Run(kdfType.String(), func(t *testing.T) {
			mechanism := &Mechanism{
				Type:           CKM_ECDH1_DERIVE,
				TypedParameter: NewECDHParams(kdfType, peerPoint),
			}
			handle, rv := m.deriveKeyECDH(session, mechanism, &Object{KeyID: "ecdh-base"}, nil, nil)
			if rv != CKR_MECHANISM_PARAM_INVALID {
				t.Errorf("deriveKeyECDH returned %v, want CKR_MECHANISM_PARAM_INVALID", rv)
			}
			if handle != ObjectHandle(InvalidHandle) {
				t.Errorf("deriveKeyECDH returned object handle %v for a refused KDF type", handle)
			}
		})
	}
}

// TestDeriveKeyECDH_AcceptsEveryAdvertisedKDFType is the accept side at the
// same boundary: no advertised CK_EC_KDF_TYPE may be turned away as an invalid
// mechanism parameter. It is driven from the advertisement so a newly listed
// KDF type is covered automatically.
func TestDeriveKeyECDH_AcceptsEveryAdvertisedKDFType(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	// The token sets CKF_LOGIN_REQUIRED, so key derivation is refused until the
	// normal user has authenticated.
	session := loginAsNormalUser(t, m)

	peerPoint := validECDHPeerPoint(t)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewUint32Attribute(CKA_VALUE_LEN, 32),
	}

	for _, kdfType := range SupportedECDHKDFs() {
		t.Run(kdfType.String(), func(t *testing.T) {
			mechanism := &Mechanism{
				Type:           CKM_ECDH1_DERIVE,
				TypedParameter: NewECDHParams(kdfType, peerPoint),
			}
			handle, rv := m.deriveKeyECDH(session, mechanism, &Object{KeyID: "ecdh-base"}, template, nil)
			if rv != CKR_OK {
				t.Fatalf("deriveKeyECDH returned %v for advertised KDF type, want CKR_OK", rv)
			}
			if handle == ObjectHandle(InvalidHandle) {
				t.Fatal("deriveKeyECDH returned CKR_OK with an invalid object handle")
			}
		})
	}
}
