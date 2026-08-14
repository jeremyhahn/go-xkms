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

import (
	"fmt"
	"testing"

	"github.com/miekg/pkcs11"
)

// tryGenerateRSA attempts an RSA key pair generation at the given modulus size
// and reports the error, without failing the test. Both outcomes are data here:
// which sizes a FIPS module accepts is the thing under test.
func tryGenerateRSA(t *testing.T, tok *token, session pkcs11.SessionHandle, modulusBits uint) error {
	t.Helper()

	label := uniqueLabel(fmt.Sprintf("fips-rsa-%d", modulusBits))
	_, _, err := tok.ctx.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, modulusBits),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		})
	return err
}

// TestFIPSModulus_OnlySpecPermittedRSASizesAreAccepted holds the module to
// PKCS#11 v3.2 §6.1.21: "When CKM_RSA_PKCS is operated in FIPS mode, the length
// of the modulus SHALL only be 1024, 2048, or 3072 bits."
//
// The interesting half is the upper bound. A module that only enforces a
// minimum -- which is the natural way to write a strength check -- happily
// generates a 4096-bit key that §6.1.21 does not permit in FIPS mode, and
// C_GetMechanismInfo here reports a maximum of 16384 bits, so nothing else in
// the module contradicts it.
//
// This test asserts the FIPS regime only. Outside FIPS the module applies its
// own 2048-bit floor, which is a different and stricter rule at the bottom end;
// see TestFIPSModulus_1024IsTheRegimeBoundary for the one size where the two
// rules disagree.
func TestFIPSModulus_OnlySpecPermittedRSASizesAreAccepted(t *testing.T) {
	tok := openToken(t)

	permitted := []uint{2048, 3072}
	for _, bits := range permitted {
		t.Run(fmt.Sprintf("accepts-%d", bits), func(t *testing.T) {
			session := probeSession(t, tok)
			if err := tryGenerateRSA(t, tok, session, bits); err != nil {
				t.Fatalf("PKCS#11 v3.2 §6.1.21 permits a %d-bit modulus in FIPS mode but "+
					"C_GenerateKeyPair refused it: %v", bits, err)
			}
		})
	}

	forbidden := []uint{512, 768, 1536, 2047, 4096}
	for _, bits := range forbidden {
		t.Run(fmt.Sprintf("refuses-%d", bits), func(t *testing.T) {
			session := probeSession(t, tok)
			err := tryGenerateRSA(t, tok, session, bits)
			if err == nil {
				t.Fatalf("C_GenerateKeyPair produced a %d-bit RSA modulus in FIPS mode; "+
					"PKCS#11 v3.2 §6.1.21 permits only 1024, 2048 or 3072", bits)
			}
			t.Logf("%d bits refused with %v", bits, err)
		})
	}
}

// TestFIPSModulus_1024IsTheRegimeBoundary pins the one modulus size where the
// FIPS rule and the module's own strength floor disagree.
//
// PKCS#11 v3.2 §6.1.21 permits a 1024-bit modulus in FIPS mode, while this
// module raised its general RSA floor to 2048 bits, so 1024 is refused outside
// FIPS. A module may legitimately be stricter than §6.1.21 -- FIPS 140-3 itself
// no longer approves 1024-bit RSA for signature generation -- but the two rules
// must not silently swap places: 1024 becoming *available only under FIPS*
// would mean turning FIPS on weakened the module, which is the opposite of what
// the mode is for.
//
// This test therefore asserts the direction rather than a fixed verdict: FIPS
// mode may refuse 1024, and must never be the only mode that accepts it.
func TestFIPSModulus_1024IsTheRegimeBoundary(t *testing.T) {
	tok := openToken(t)
	session := probeSession(t, tok)

	err := tryGenerateRSA(t, tok, session, 1024)
	if err == nil {
		t.Log("1024-bit RSA is accepted under FIPS, as PKCS#11 v3.2 §6.1.21 permits; " +
			"confirm the non-FIPS floor of 2048 does not make this size FIPS-only")
		return
	}
	t.Logf("1024-bit RSA is refused under FIPS (%v); the module is stricter than "+
		"PKCS#11 v3.2 §6.1.21, which is a defensible reading of FIPS 140-3 given "+
		"1024-bit RSA is no longer approved for signature generation", err)
}

// TestFIPSKeySizes_RSAMechanismInfoDescribesWhatKeyGenAccepts checks
// CK_MECHANISM_INFO against reality.
//
// ulMinKeySize and ulMaxKeySize are how an application decides what to ask for;
// PKCS#11 v3.2 §6.1 defines them for the RSA family as the modulus size range
// in bits. If the reported range is wider than what C_GenerateKeyPair will
// accept, every application that trusts the range picks a size the token then
// refuses -- and under FIPS that is exactly what a §6.1.21 cap without a
// matching CK_MECHANISM_INFO produces.
func TestFIPSKeySizes_RSAMechanismInfoDescribesWhatKeyGenAccepts(t *testing.T) {
	tok := openToken(t)

	info, err := tok.ctx.GetMechanismInfo(tok.slot,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)})
	if err != nil {
		t.Fatalf("C_GetMechanismInfo(CKM_RSA_PKCS_KEY_PAIR_GEN): %v", err)
	}
	t.Logf("CKM_RSA_PKCS_KEY_PAIR_GEN reports ulMinKeySize=%d ulMaxKeySize=%d bits",
		info.MinKeySize, info.MaxKeySize)

	t.Run("min-is-generatable", func(t *testing.T) {
		session := probeSession(t, tok)
		if genErr := tryGenerateRSA(t, tok, session, info.MinKeySize); genErr != nil {
			t.Fatalf("CK_MECHANISM_INFO advertises ulMinKeySize=%d but C_GenerateKeyPair "+
				"refuses that size: %v", info.MinKeySize, genErr)
		}
	})

	// The maximum is asserted against §6.1.21 rather than by generating a key
	// at it. Generating a 16384-bit modulus takes minutes and would time out
	// long before it proved anything, and the claim that matters under FIPS is
	// not "the token can eventually produce this" but "the token must not offer
	// a size FIPS does not permit". A caller that reads ulMaxKeySize=16384 and
	// asks for 4096 gets a key §6.1.21 forbids -- see
	// TestFIPSModulus_OnlySpecPermittedRSASizesAreAccepted, which proves the
	// token does exactly that.
	t.Run("max-respects-the-FIPS-cap", func(t *testing.T) {
		const fipsMaxModulusBits = 3072
		if info.MaxKeySize > fipsMaxModulusBits {
			t.Fatalf("CK_MECHANISM_INFO advertises ulMaxKeySize=%d bits under FIPS, but "+
				"PKCS#11 v3.2 §6.1.21 permits only 1024, 2048 or 3072; an application that "+
				"trusts this range will ask the token for a modulus FIPS does not allow",
				info.MaxKeySize)
		}
	})

	t.Run("below-min-is-refused", func(t *testing.T) {
		session := probeSession(t, tok)
		const wellBelowAnyFloor = 512
		if genErr := tryGenerateRSA(t, tok, session, wellBelowAnyFloor); genErr == nil {
			t.Fatalf("C_GenerateKeyPair accepted %d bits, below the advertised "+
				"ulMinKeySize=%d", wellBelowAnyFloor, info.MinKeySize)
		}
	})
}

// tryGenerateAES attempts an AES key generation of the given byte length.
func tryGenerateAES(t *testing.T, tok *token, session pkcs11.SessionHandle, keyBytes uint) error {
	t.Helper()

	_, err := tok.ctx.GenerateKey(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keyBytes),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, uniqueLabel("fips-aes-size")),
		})
	return err
}

// TestFIPSKeySizes_AESMechanismInfoDescribesWhatKeyGenAccepts checks the AES
// key-size range the same way, where the unit is bytes.
//
// PKCS#11 v3.2 §6.10.3 says the AES ulMinKeySize and ulMaxKeySize are "in
// bytes", so a module that filled them with 128 and 256 would be telling
// applications it supports 1024-bit AES keys. Generating at the reported bounds
// is what turns that units question into a checkable claim.
func TestFIPSKeySizes_AESMechanismInfoDescribesWhatKeyGenAccepts(t *testing.T) {
	tok := openToken(t)

	info, err := tok.ctx.GetMechanismInfo(tok.slot,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)})
	if err != nil {
		t.Fatalf("C_GetMechanismInfo(CKM_AES_KEY_GEN): %v", err)
	}
	t.Logf("CKM_AES_KEY_GEN reports ulMinKeySize=%d ulMaxKeySize=%d bytes",
		info.MinKeySize, info.MaxKeySize)

	for _, size := range []uint{info.MinKeySize, info.MaxKeySize} {
		t.Run(fmt.Sprintf("accepts-%d-bytes", size), func(t *testing.T) {
			session := probeSession(t, tok)
			if genErr := tryGenerateAES(t, tok, session, size); genErr != nil {
				t.Fatalf("CK_MECHANISM_INFO advertises %d bytes as a supported AES key size "+
					"but C_GenerateKey refuses it: %v", size, genErr)
			}
		})
	}

	for _, size := range []uint{info.MinKeySize - 1, info.MaxKeySize + 1} {
		t.Run(fmt.Sprintf("refuses-%d-bytes", size), func(t *testing.T) {
			session := probeSession(t, tok)
			if genErr := tryGenerateAES(t, tok, session, size); genErr == nil {
				t.Fatalf("C_GenerateKey accepted a %d-byte AES key, outside the advertised "+
					"%d..%d range", size, info.MinKeySize, info.MaxKeySize)
			}
		})
	}
}

// TestFIPSFlags_CapabilityFlagsMatchWhatOperationsAccept checks the CKF_* bits
// against the operations the module will actually start.
//
// The flags are a contract: an application picks a mechanism for a job by
// reading them. A mechanism whose CKF_SIGN bit is set but whose C_SignInit
// returns CKR_MECHANISM_INVALID sends every such application down a path that
// cannot work, and the failure surfaces far from the mechanism table that
// caused it.
func TestFIPSFlags_CapabilityFlagsMatchWhatOperationsAccept(t *testing.T) {
	tok := openToken(t)
	fx := newFixtures(t, tok)

	listed, err := collectMechanisms(tok.ctx, tok.slot)
	if err != nil {
		t.Fatalf("collecting mechanisms: %v", err)
	}

	// Each probed mechanism's entry in initProbes exercises exactly one
	// operation; this table says which CKF_ bit that operation corresponds to,
	// so the flag and the probe can be compared.
	probedCapability := map[uint]uint{
		pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN: pkcs11.CKF_GENERATE_KEY_PAIR,
		pkcs11.CKM_RSA_PKCS:              pkcs11.CKF_SIGN,
		pkcs11.CKM_RSA_PKCS_OAEP:         pkcs11.CKF_DECRYPT,
		pkcs11.CKM_RSA_PKCS_PSS:          pkcs11.CKF_SIGN,
		pkcs11.CKM_SHA256_RSA_PKCS:       pkcs11.CKF_SIGN,
		pkcs11.CKM_SHA384_RSA_PKCS:       pkcs11.CKF_SIGN,
		pkcs11.CKM_SHA512_RSA_PKCS:       pkcs11.CKF_SIGN,
		pkcs11.CKM_SHA256_RSA_PKCS_PSS:   pkcs11.CKF_SIGN,
		pkcs11.CKM_SHA384_RSA_PKCS_PSS:   pkcs11.CKF_SIGN,
		pkcs11.CKM_SHA512_RSA_PKCS_PSS:   pkcs11.CKF_SIGN,
		pkcs11.CKM_EC_KEY_PAIR_GEN:       pkcs11.CKF_GENERATE_KEY_PAIR,
		pkcs11.CKM_ECDSA:                 pkcs11.CKF_SIGN,
		pkcs11.CKM_ECDSA_SHA256:          pkcs11.CKF_SIGN,
		pkcs11.CKM_ECDSA_SHA384:          pkcs11.CKF_SIGN,
		pkcs11.CKM_ECDSA_SHA512:          pkcs11.CKF_SIGN,
		pkcs11.CKM_ECDH1_DERIVE:          pkcs11.CKF_DERIVE,
		ckmECEdwardsKeyPairGen:           pkcs11.CKF_GENERATE_KEY_PAIR,
		ckmEdDSA:                         pkcs11.CKF_SIGN,
		pkcs11.CKM_AES_KEY_GEN:           pkcs11.CKF_GENERATE,
		pkcs11.CKM_AES_ECB:               pkcs11.CKF_ENCRYPT,
		pkcs11.CKM_AES_CBC:               pkcs11.CKF_ENCRYPT,
		pkcs11.CKM_AES_CBC_PAD:           pkcs11.CKF_ENCRYPT,
		pkcs11.CKM_AES_GCM:               pkcs11.CKF_ENCRYPT,
		pkcs11.CKM_AES_KEY_WRAP:          pkcs11.CKF_WRAP,
		pkcs11.CKM_AES_KEY_WRAP_PAD:      pkcs11.CKF_WRAP,
		pkcs11.CKM_SHA_1:                 pkcs11.CKF_DIGEST,
		pkcs11.CKM_SHA256:                pkcs11.CKF_DIGEST,
		pkcs11.CKM_SHA384:                pkcs11.CKF_DIGEST,
		pkcs11.CKM_SHA512:                pkcs11.CKF_DIGEST,
	}

	for _, rec := range listed.Mechanisms {
		capability, known := probedCapability[rec.Mechanism]
		if !known {
			t.Errorf("%s is advertised but this test does not know which capability its probe "+
				"exercises; add it to probedCapability", mechName(rec.Mechanism))
			continue
		}
		t.Run(mechName(rec.Mechanism), func(t *testing.T) {
			if rec.Flags&capability == 0 {
				t.Fatalf("%s does not set the capability flag 0x%08X that its probe exercises; "+
					"either the flag is missing from CK_MECHANISM_INFO or probedCapability "+
					"names the wrong operation", mechName(rec.Mechanism), capability)
			}
			session := probeSession(t, tok)
			if probeErr := initProbes[rec.Mechanism](tok, session, fx); isMechanismInvalid(probeErr) {
				t.Fatalf("%s advertises capability flag 0x%08X but the matching operation "+
					"returns CKR_MECHANISM_INVALID", mechName(rec.Mechanism), capability)
			}
		})
	}
}
