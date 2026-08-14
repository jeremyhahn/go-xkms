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
	"crypto/rand"
	"sort"
	"testing"

	"github.com/miekg/pkcs11"
)

// initProbe performs only the C_*Init half of an operation, which is where the
// module resolves the mechanism and therefore where an advertising/enforcement
// disagreement shows up.
type initProbe func(tok *token, session pkcs11.SessionHandle, fx *fixtures) error

// probeSession opens an extra session for a probe, so an Init that succeeds
// does not leave an active operation on the session the rest of the suite uses.
// Login state is a property of the token, not of the session, so the new
// session inherits it.
func probeSession(t *testing.T, tok *token) pkcs11.SessionHandle {
	t.Helper()

	session, err := tok.ctx.OpenSession(tok.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("C_OpenSession for a probe: %v", err)
	}
	t.Cleanup(func() {
		if cerr := tok.ctx.CloseSession(session); cerr != nil {
			t.Errorf("C_CloseSession for a probe: %v", cerr)
		}
	})
	return session
}

// signProbe returns a probe that runs C_SignInit with the given key.
func signProbe(mech uint, params any, key func(fx *fixtures) pkcs11.ObjectHandle) initProbe {
	return func(tok *token, session pkcs11.SessionHandle, fx *fixtures) error {
		return tok.ctx.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, params)}, key(fx))
	}
}

// encryptProbe returns a probe that runs C_EncryptInit with the given key.
func encryptProbe(mech uint, params any, key func(fx *fixtures) pkcs11.ObjectHandle) initProbe {
	return func(tok *token, session pkcs11.SessionHandle, fx *fixtures) error {
		return tok.ctx.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, params)}, key(fx))
	}
}

// digestProbe returns a probe that runs C_DigestInit.
func digestProbe(mech uint) initProbe {
	return func(tok *token, session pkcs11.SessionHandle, fx *fixtures) error {
		return tok.ctx.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)})
	}
}

// wrapProbe returns a probe that runs C_WrapKey, which has no separate Init.
func wrapProbe(mech uint) initProbe {
	return func(tok *token, session pkcs11.SessionHandle, fx *fixtures) error {
		_, err := tok.ctx.WrapKey(session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}, fx.aesKey, fx.aesKey)
		return err
	}
}

// deriveProbe returns a probe that runs C_DeriveKey.
func deriveProbe(mech uint, params any, base func(fx *fixtures) pkcs11.ObjectHandle) initProbe {
	return func(tok *token, session pkcs11.SessionHandle, fx *fixtures) error {
		_, err := tok.ctx.DeriveKey(session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(mech, params)}, base(fx),
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
				pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, uint(32)),
			})
		return err
	}
}

// keyGenProbe returns a probe that runs C_GenerateKey.
func keyGenProbe(mech uint) initProbe {
	return func(tok *token, session pkcs11.SessionHandle, fx *fixtures) error {
		_, err := tok.ctx.GenerateKey(session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)},
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
				pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, uint(32)),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, uniqueLabel("fips-probe")),
			})
		return err
	}
}

// keyPairGenProbe returns a probe that runs C_GenerateKeyPair.
func keyPairGenProbe(mech uint, pubExtra []*pkcs11.Attribute) initProbe {
	return func(tok *token, session pkcs11.SessionHandle, fx *fixtures) error {
		label := uniqueLabel("fips-probe")
		pub := append([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		}, pubExtra...)
		_, _, err := tok.ctx.GenerateKeyPair(session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}, pub,
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			})
		return err
	}
}

func rsaKey(fx *fixtures) pkcs11.ObjectHandle { return fx.rsa.priv }
func ecKey(fx *fixtures) pkcs11.ObjectHandle  { return fx.ec.priv }
func edKey(fx *fixtures) pkcs11.ObjectHandle  { return fx.ed.priv }
func aesKey(fx *fixtures) pkcs11.ObjectHandle { return fx.aesKey }

// pssSHA256Params are valid CKM_RSA_PKCS_PSS parameters, supplied so that a
// probe reaches the mechanism check rather than stopping at parameter
// validation.
var pssSHA256Params = pkcs11.NewPSSParams(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32)

// aesIV is a valid 16-byte CBC initialisation vector for probing.
var aesIV = make([]byte, 16)

// aesCTRParams is a valid CK_AES_CTR_PARAMS: a 32-bit counter width followed by
// the 16-byte counter block.
var aesCTRParams = append([]byte{0x00, 0x00, 0x00, 0x20}, make([]byte, 16)...)

// initProbes maps a mechanism to the smallest operation that forces the module
// to decide whether it will perform that mechanism.
//
// It covers every mechanism the module advertises outside FIPS mode plus the
// implemented-but-unadvertised ones, because the interesting bypass is a
// mechanism that FIPS withholds from the list yet still performs when asked
// directly. An application never has to read the list.
var initProbes = map[uint]initProbe{
	pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN: keyPairGenProbe(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, uint(2048)),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
	}),
	pkcs11.CKM_RSA_PKCS:            signProbe(pkcs11.CKM_RSA_PKCS, nil, rsaKey),
	pkcs11.CKM_RSA_X_509:           signProbe(pkcs11.CKM_RSA_X_509, nil, rsaKey),
	pkcs11.CKM_SHA1_RSA_PKCS:       signProbe(pkcs11.CKM_SHA1_RSA_PKCS, nil, rsaKey),
	pkcs11.CKM_RSA_PKCS_PSS:        signProbe(pkcs11.CKM_RSA_PKCS_PSS, pssSHA256Params, rsaKey),
	pkcs11.CKM_SHA256_RSA_PKCS:     signProbe(pkcs11.CKM_SHA256_RSA_PKCS, nil, rsaKey),
	pkcs11.CKM_SHA384_RSA_PKCS:     signProbe(pkcs11.CKM_SHA384_RSA_PKCS, nil, rsaKey),
	pkcs11.CKM_SHA512_RSA_PKCS:     signProbe(pkcs11.CKM_SHA512_RSA_PKCS, nil, rsaKey),
	pkcs11.CKM_SHA256_RSA_PKCS_PSS: signProbe(pkcs11.CKM_SHA256_RSA_PKCS_PSS, pssSHA256Params, rsaKey),
	pkcs11.CKM_SHA384_RSA_PKCS_PSS: signProbe(pkcs11.CKM_SHA384_RSA_PKCS_PSS, pkcs11.NewPSSParams(pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, 48), rsaKey),
	pkcs11.CKM_SHA512_RSA_PKCS_PSS: signProbe(pkcs11.CKM_SHA512_RSA_PKCS_PSS, pkcs11.NewPSSParams(pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, 64), rsaKey),
	pkcs11.CKM_RSA_PKCS_OAEP: func(tok *token, session pkcs11.SessionHandle, fx *fixtures) error {
		params := pkcs11.NewOAEPParams(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, pkcs11.CKZ_DATA_SPECIFIED, nil)
		return tok.ctx.DecryptInit(session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}, fx.rsa.priv)
	},

	pkcs11.CKM_EC_KEY_PAIR_GEN: keyPairGenProbe(pkcs11.CKM_EC_KEY_PAIR_GEN, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParamsP256),
	}),
	pkcs11.CKM_ECDSA:                 signProbe(pkcs11.CKM_ECDSA, nil, ecKey),
	pkcs11.CKM_ECDSA_SHA1:            signProbe(pkcs11.CKM_ECDSA_SHA1, nil, ecKey),
	pkcs11.CKM_ECDSA_SHA224:          signProbe(pkcs11.CKM_ECDSA_SHA224, nil, ecKey),
	pkcs11.CKM_ECDSA_SHA256:          signProbe(pkcs11.CKM_ECDSA_SHA256, nil, ecKey),
	pkcs11.CKM_ECDSA_SHA384:          signProbe(pkcs11.CKM_ECDSA_SHA384, nil, ecKey),
	pkcs11.CKM_ECDSA_SHA512:          signProbe(pkcs11.CKM_ECDSA_SHA512, nil, ecKey),
	pkcs11.CKM_ECDH1_DERIVE:          deriveProbe(pkcs11.CKM_ECDH1_DERIVE, ecdhProbeParams(), ecKey),
	pkcs11.CKM_ECDH1_COFACTOR_DERIVE: deriveProbe(pkcs11.CKM_ECDH1_COFACTOR_DERIVE, ecdhProbeParams(), ecKey),
	pkcs11.CKM_ECMQV_DERIVE:          deriveProbe(pkcs11.CKM_ECMQV_DERIVE, ecdhProbeParams(), ecKey),
	pkcs11.CKM_ECDH_AES_KEY_WRAP:     wrapProbe(pkcs11.CKM_ECDH_AES_KEY_WRAP),

	ckmECEdwardsKeyPairGen: keyPairGenProbe(ckmECEdwardsKeyPairGen, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParamsEd25519),
	}),
	ckmEdDSA:  signProbe(ckmEdDSA, nil, edKey),
	ckmXEdDSA: signProbe(ckmXEdDSA, nil, edKey),
	ckmECMontgomeryKeyPairGen: keyPairGenProbe(ckmECMontgomeryKeyPairGen, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{0x06, 0x03, 0x2b, 0x65, 0x6e}),
	}),

	pkcs11.CKM_AES_KEY_GEN:      keyGenProbe(pkcs11.CKM_AES_KEY_GEN),
	pkcs11.CKM_AES_ECB:          encryptProbe(pkcs11.CKM_AES_ECB, nil, aesKey),
	pkcs11.CKM_AES_CBC:          encryptProbe(pkcs11.CKM_AES_CBC, aesIV, aesKey),
	pkcs11.CKM_AES_CBC_PAD:      encryptProbe(pkcs11.CKM_AES_CBC_PAD, aesIV, aesKey),
	pkcs11.CKM_AES_CTR:          encryptProbe(pkcs11.CKM_AES_CTR, aesCTRParams, aesKey),
	pkcs11.CKM_AES_CMAC:         signProbe(pkcs11.CKM_AES_CMAC, nil, aesKey),
	pkcs11.CKM_AES_KEY_WRAP:     wrapProbe(pkcs11.CKM_AES_KEY_WRAP),
	pkcs11.CKM_AES_KEY_WRAP_PAD: wrapProbe(pkcs11.CKM_AES_KEY_WRAP_PAD),
	// CKM_AES_KEY_WRAP_KWP is the current RFC 5649 identifier for the same
	// construction CKM_AES_KEY_WRAP_PAD names; both are advertised, so both
	// need a probe here.
	ckmAESKeyWrapKWP: wrapProbe(ckmAESKeyWrapKWP),
	pkcs11.CKM_AES_GCM: func(tok *token, session pkcs11.SessionHandle, fx *fixtures) error {
		params := pkcs11.NewGCMParams(make([]byte, 12), nil, 128)
		defer params.Free()
		return tok.ctx.EncryptInit(session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, fx.aesKey)
	},

	pkcs11.CKM_SHA_1:    digestProbe(pkcs11.CKM_SHA_1),
	pkcs11.CKM_SHA224:   digestProbe(pkcs11.CKM_SHA224),
	pkcs11.CKM_SHA256:   digestProbe(pkcs11.CKM_SHA256),
	pkcs11.CKM_SHA384:   digestProbe(pkcs11.CKM_SHA384),
	pkcs11.CKM_SHA512:   digestProbe(pkcs11.CKM_SHA512),
	pkcs11.CKM_SHA3_256: digestProbe(pkcs11.CKM_SHA3_256),
	pkcs11.CKM_SHA3_512: digestProbe(pkcs11.CKM_SHA3_512),
	ckmSHA512224:        digestProbe(ckmSHA512224),
	ckmSHA512256:        digestProbe(ckmSHA512256),

	pkcs11.CKM_SHA256_HMAC: signProbe(pkcs11.CKM_SHA256_HMAC, nil, aesKey),
	ckmSHA384HMAC:          signProbe(ckmSHA384HMAC, nil, aesKey),
	ckmSHA512HMAC:          signProbe(ckmSHA512HMAC, nil, aesKey),

	pkcs11.CKM_GENERIC_SECRET_KEY_GEN: keyGenProbe(pkcs11.CKM_GENERIC_SECRET_KEY_GEN),
	ckmHKDFKeyGen:                     keyGenProbe(ckmHKDFKeyGen),
	ckmHKDFDerive:                     deriveProbe(ckmHKDFDerive, nil, aesKey),
	ckmHKDFData:                       deriveProbe(ckmHKDFData, nil, aesKey),
	ckmSP800108CounterKDF:             deriveProbe(ckmSP800108CounterKDF, nil, aesKey),
}

// ecdhProbeParams builds throwaway but structurally valid ECDH1 parameters, so
// that a probe of an ECDH mechanism is stopped by the mechanism policy rather
// than by parameter validation. The KDF is one the module implements, for the
// same reason: a probe that trips over an unsupported CK_EC_KDF_TYPE would let
// a missing FIPS check hide behind CKR_MECHANISM_PARAM_INVALID.
func ecdhProbeParams() any {
	point := make([]byte, 65)
	point[0] = 0x04
	if _, err := rand.Read(point[1:]); err != nil {
		// The point does not have to be on the curve for an Init probe; a
		// deterministic fallback keeps the table usable without entropy.
		for i := range point[1:] {
			point[i+1] = byte(i)
		}
	}
	return pkcs11.NewECDH1DeriveParams(ckdSHA256KDF, nil, point)
}

// TestFIPSEnforcement_ListedMechanismsAreNotRefused checks the direction that a
// FIPS build most easily gets wrong in the other direction: promising a
// mechanism and then refusing it.
//
// C_GetMechanismList and the mechanism resolution inside C_*Init are answered
// from different code in this module, so a mechanism can be advertised and
// still be unreachable. That is a broken promise an application discovers only
// when it tries to use the token.
func TestFIPSEnforcement_ListedMechanismsAreNotRefused(t *testing.T) {
	tok := openToken(t)
	fx := newFixtures(t, tok)

	listed, err := collectMechanisms(tok.ctx, tok.slot)
	if err != nil {
		t.Fatalf("collecting mechanisms: %v", err)
	}
	mechs := listed.types()
	sort.Slice(mechs, func(i, j int) bool { return mechs[i] < mechs[j] })

	for _, mech := range mechs {
		probe, ok := initProbes[mech]
		if !ok {
			t.Errorf("%s (0x%08X) is advertised under FIPS but no probe exists for it in initProbes",
				mechName(mech), mech)
			continue
		}
		t.Run(mechName(mech), func(t *testing.T) {
			session := probeSession(t, tok)
			if err := probe(tok, session, fx); isMechanismInvalid(err) {
				t.Fatalf("C_GetMechanismList offers %s under FIPS but the operation returns "+
					"CKR_MECHANISM_INVALID: the module advertises a mechanism it will not perform",
					mechName(mech))
			}
		})
	}
}

// TestFIPSEnforcement_WithheldMechanismsAreRefused checks the bypass direction:
// a mechanism FIPS keeps out of the list must also be impossible to use.
//
// Nothing forces an application to read C_GetMechanismList first, so a filter
// that only edits the list leaves every withheld algorithm reachable by name.
// That would be a FIPS mode in appearance only.
func TestFIPSEnforcement_WithheldMechanismsAreRefused(t *testing.T) {
	tok := openToken(t)
	fx := newFixtures(t, tok)

	listed, err := collectMechanisms(tok.ctx, tok.slot)
	if err != nil {
		t.Fatalf("collecting mechanisms: %v", err)
	}
	listedSet := listed.set()

	var withheld []uint
	for mech := range initProbes {
		if _, ok := listedSet[mech]; !ok {
			withheld = append(withheld, mech)
		}
	}
	sort.Slice(withheld, func(i, j int) bool { return withheld[i] < withheld[j] })

	if len(withheld) == 0 {
		t.Fatal("every probed mechanism is advertised under FIPS, so this test proves nothing; " +
			"either the FIPS filter is not running or initProbes has lost its non-approved entries")
	}
	t.Logf("probing %d mechanisms the FIPS list withholds", len(withheld))

	for _, mech := range withheld {
		probe := initProbes[mech]
		t.Run(mechName(mech), func(t *testing.T) {
			session := probeSession(t, tok)
			err := probe(tok, session, fx)
			if err == nil {
				t.Fatalf("%s is withheld from C_GetMechanismList under FIPS but the operation "+
					"succeeded: the mechanism is still usable by name, which makes the FIPS "+
					"filter cosmetic", mechName(mech))
			}
			if !isMechanismInvalid(err) {
				ckr, ok := ckrOf(err)
				if !ok {
					t.Fatalf("%s was refused with a non-PKCS#11 error %v; a caller cannot tell "+
						"an unapproved mechanism from a transport failure", mechName(mech), err)
				}
				t.Errorf("%s was refused with CKR 0x%08X, want CKR_MECHANISM_INVALID (0x%08X): "+
					"the refusal is right but the code does not tell the caller the mechanism "+
					"is unavailable", mechName(mech), uint(ckr), pkcs11.CKR_MECHANISM_INVALID)
			}
		})
	}
}

// TestFIPSEnforcement_SHA1RSASigningIsRefused states the motivating case as its
// own assertion rather than leaving it inside a table.
//
// CKM_SHA1_RSA_PKCS is the mechanism that forced FIPS filtering to exist: OASIS
// conformance requires the module to offer it and FIPS forbids using it, so
// signing with it under FIPS must fail with CKR_MECHANISM_INVALID -- not with a
// signature, and not with some other error that an application might retry.
func TestFIPSEnforcement_SHA1RSASigningIsRefused(t *testing.T) {
	tok := openToken(t)
	fx := newFixtures(t, tok)
	session := probeSession(t, tok)

	err := tok.ctx.SignInit(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA1_RSA_PKCS, nil)}, fx.rsa.priv)
	if err == nil {
		sig, signErr := tok.ctx.Sign(session, []byte("sha-1 rsa signature under FIPS"))
		if signErr == nil {
			t.Fatalf("the module produced a %d-byte CKM_SHA1_RSA_PKCS signature under FIPS; "+
				"FIPS 140-3 does not approve SHA-1 for signature generation", len(sig))
		}
		t.Fatalf("C_SignInit(CKM_SHA1_RSA_PKCS) succeeded under FIPS and only C_Sign refused "+
			"(%v); the mechanism must be rejected at Init so a caller learns before it commits "+
			"to the operation", signErr)
	}
	if !isMechanismInvalid(err) {
		ckr, ok := ckrOf(err)
		if !ok {
			t.Fatalf("C_SignInit(CKM_SHA1_RSA_PKCS) failed with a non-PKCS#11 error: %v", err)
		}
		t.Fatalf("C_SignInit(CKM_SHA1_RSA_PKCS) returned CKR 0x%08X, want CKR_MECHANISM_INVALID (0x%08X)",
			uint(ckr), pkcs11.CKR_MECHANISM_INVALID)
	}
}
