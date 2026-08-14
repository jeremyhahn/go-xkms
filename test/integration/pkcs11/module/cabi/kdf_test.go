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

//go:build integration && pkcs11_cabi

package cabi

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// deriveSecret runs C_DeriveKey for a KDF mechanism and returns the derived
// key's handle.
func deriveSecret(t *testing.T, f *Fixture, mechType uint, params MechParams, baseKey uint, valueLen uint) (uint, error) {
	t.Helper()

	template := []Attr{
		AttrULong(CKA_CLASS, CKO_SECRET_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
		AttrBool(CKA_TOKEN, false),
		AttrULong(CKA_VALUE_LEN, valueLen),
		AttrBool(CKA_SENSITIVE, false),
		AttrBool(CKA_EXTRACTABLE, true),
		AttrString(CKA_LABEL, UniqueLabel(t, "cabi-kdf-derived")),
	}

	key, err := f.Session.DeriveKey(mechType, params, baseKey, template)
	if err != nil {
		return 0, err
	}
	return f.Track(key), nil
}

// newHKDFBaseKey creates the derivable secret an HKDF derivation starts from,
// returning its handle and its raw bytes for the oracle.
func newHKDFBaseKey(t *testing.T, f *Fixture) (uint, []byte) {
	t.Helper()

	key, err := generateDerivableSecret(t, f, CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, 32)
	if err != nil {
		t.Fatalf("C_GenerateKey for the HKDF base key: %v", err)
	}
	return key, readSecretValue(t, f, key)
}

// TestHKDFIsEitherAdvertisedAndWorkingOrRefused holds the module to the one
// invariant that must be true of any mechanism.
//
// C_GetMechanismList is how an application discovers what a token can do
// (PKCS#11 v3.2 section 5.5). Either a mechanism is advertised and the
// operations that name it work, or it is not advertised and those operations
// return CKR_MECHANISM_INVALID. A mechanism that is implemented but not
// advertised is unreachable to every application that enumerates before it
// calls, which includes p11-kit and OpenSSL's pkcs11-provider; a mechanism
// that is advertised but not implemented is worse.
//
// This is asserted instead of skipping when HKDF is absent, because "the token
// does not offer it" is a claim that must itself be checked rather than
// assumed.
func TestHKDFIsEitherAdvertisedAndWorkingOrRefused(t *testing.T) {
	f := NewFixture(t)
	advertised := f.SupportsMechanism(CKM_HKDF_DERIVE)

	base, _ := newHKDFBaseKey(t, f)
	params := HKDFParams{
		Extract:     true,
		Expand:      true,
		PRFHashMech: CKM_SHA256,
		SaltType:    CKF_HKDF_SALT_DATA,
		Salt:        []byte("advertise-probe-salt"),
		Info:        []byte("advertise-probe-info"),
	}

	_, err := deriveSecret(t, f, CKM_HKDF_DERIVE, params, base, 32)

	switch {
	case advertised && err == nil:
		return
	case advertised && err != nil:
		t.Fatalf("CKM_HKDF_DERIVE is advertised by C_GetMechanismList but C_DeriveKey returned %s (0x%08X)",
			rvName(RV(err)), RV(err))
	case !advertised && err == nil:
		t.Fatal("CKM_HKDF_DERIVE is not listed by C_GetMechanismList, yet C_DeriveKey performed the derivation. " +
			"An application that enumerates mechanisms before using them, as p11-kit and OpenSSL's pkcs11-provider do, " +
			"can never discover this mechanism, so the implementation is unreachable through the documented discovery path.")
	default:
		if got := RV(err); got != CKR_MECHANISM_INVALID {
			t.Fatalf("CKM_HKDF_DERIVE is not advertised, so C_DeriveKey must refuse it with CKR_MECHANISM_INVALID, but it returned %s (0x%08X)",
				rvName(got), got)
		}
	}
}

// TestHKDFMatchesTheGolangOracle proves the salt, info and PRF hash in
// CK_HKDF_PARAMS all reach the derivation.
//
// The comparison is against golang.org/x/crypto/hkdf over the same base key.
// This is the test that catches a fabricating parser: before the boundary read
// CK_HKDF_PARAMS it returned hardcoded defaults regardless of its input, so
// every derivation used no salt, no info and SHA-256. The output was
// well-formed and repeatable, which is why nothing noticed.
func TestHKDFMatchesTheGolangOracle(t *testing.T) {
	f := NewFixture(t)
	base, baseBytes := newHKDFBaseKey(t, f)

	salt := []byte("go-xkms/cabi/hkdf/salt")
	info := []byte("go-xkms/cabi/hkdf/info")

	params := HKDFParams{
		Extract:     true,
		Expand:      true,
		PRFHashMech: CKM_SHA256,
		SaltType:    CKF_HKDF_SALT_DATA,
		Salt:        salt,
		Info:        info,
	}
	derived, err := deriveSecret(t, f, CKM_HKDF_DERIVE, params, base, 32)
	if err != nil {
		t.Fatalf("C_DeriveKey with CKM_HKDF_DERIVE: %v", err)
	}
	got := readSecretValue(t, f, derived)

	want := make([]byte, 32)
	if _, err := hkdf.New(sha256.New, baseBytes, salt, info).Read(want); err != nil {
		t.Fatalf("computing the HKDF oracle: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("the derived key does not match RFC 5869 HKDF-SHA256 over the same inputs:\n  module %x\n  oracle %x",
			got, want)
	}
}

// TestHKDFInfoCrossesTheABI proves pInfo reaches the derivation, by changing
// nothing else.
//
// This is the assertion that survives even if the oracle comparison cannot be
// made. Two derivations that differ only in the info string must differ in
// output; a parser that discarded the caller's info and substituted a constant
// returns the same key for both, and every application relying on the info
// string to separate purposes would silently share one key across all of them.
func TestHKDFInfoCrossesTheABI(t *testing.T) {
	f := NewFixture(t)
	base, _ := newHKDFBaseKey(t, f)
	salt := []byte("constant-salt")

	derive := func(info []byte) []byte {
		t.Helper()
		params := HKDFParams{
			Extract:     true,
			Expand:      true,
			PRFHashMech: CKM_SHA256,
			SaltType:    CKF_HKDF_SALT_DATA,
			Salt:        salt,
			Info:        info,
		}
		key, err := deriveSecret(t, f, CKM_HKDF_DERIVE, params, base, 32)
		if err != nil {
			t.Fatalf("C_DeriveKey with info %q: %v", info, err)
		}
		return readSecretValue(t, f, key)
	}

	first := derive([]byte("purpose-encryption"))
	second := derive([]byte("purpose-authentication"))

	if bytes.Equal(first, second) {
		t.Fatalf("changing only pInfo produced the same derived key (%x): the info string was accepted and discarded, "+
			"so every purpose an application separates with it shares one key", first)
	}
}

// TestHKDFSaltCrossesTheABI proves pSalt reaches the extract step.
//
// Two derivations differ only in the salt. A parser that dropped it would
// return the same key for both, which means the salt contributes nothing to
// the extraction and a caller rotating salts is not rotating keys.
func TestHKDFSaltCrossesTheABI(t *testing.T) {
	f := NewFixture(t)
	base, _ := newHKDFBaseKey(t, f)
	info := []byte("constant-info")

	derive := func(salt []byte) []byte {
		t.Helper()
		params := HKDFParams{
			Extract:     true,
			Expand:      true,
			PRFHashMech: CKM_SHA256,
			SaltType:    CKF_HKDF_SALT_DATA,
			Salt:        salt,
			Info:        info,
		}
		key, err := deriveSecret(t, f, CKM_HKDF_DERIVE, params, base, 32)
		if err != nil {
			t.Fatalf("C_DeriveKey with salt %q: %v", salt, err)
		}
		return readSecretValue(t, f, key)
	}

	if first, second := derive([]byte("salt-one")), derive([]byte("salt-two")); bytes.Equal(first, second) {
		t.Fatalf("changing only pSalt produced the same derived key (%x): the salt was accepted and discarded", first)
	}
}

// TestSP800108IsEitherAdvertisedAndWorkingOrRefused applies the same
// discoverability invariant to the SP800-108 counter-mode KDF.
//
// The module's own C headers do not even declare CKM_SP800_108_COUNTER_KDF,
// although they declare its parameter structs and the boundary parses them,
// which is why this suite has to name the mechanism by its numeric value.
func TestSP800108IsEitherAdvertisedAndWorkingOrRefused(t *testing.T) {
	f := NewFixture(t)
	advertised := f.SupportsMechanism(CKM_SP800_108_COUNTER_KDF)

	base, err := generateDerivableSecret(t, f, CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, 32)
	if err != nil {
		t.Fatalf("C_GenerateKey for the SP800-108 base key: %v", err)
	}

	params := SP800108Params{
		PRF: CKM_SHA256_HMAC,
		DataParams: []PRFDataParam{
			{Type: CK_SP800_108_ITERATION_VARIABLE},
			{Type: CK_SP800_108_BYTE_ARRAY, Value: []byte("label")},
			{Type: CK_SP800_108_BYTE_ARRAY, Value: []byte("context")},
		},
	}

	_, derr := deriveSecret(t, f, CKM_SP800_108_COUNTER_KDF, params, base, 32)

	switch {
	case advertised && derr == nil:
		return
	case advertised && derr != nil:
		t.Fatalf("CKM_SP800_108_COUNTER_KDF is advertised by C_GetMechanismList but C_DeriveKey returned %s (0x%08X)",
			rvName(RV(derr)), RV(derr))
	case !advertised && derr == nil:
		t.Fatal("CKM_SP800_108_COUNTER_KDF is not listed by C_GetMechanismList, yet C_DeriveKey performed the derivation. " +
			"The mechanism is unreachable to any application that enumerates before it calls.")
	default:
		if got := RV(derr); got != CKR_MECHANISM_INVALID {
			t.Fatalf("CKM_SP800_108_COUNTER_KDF is not advertised, so C_DeriveKey must refuse it with CKR_MECHANISM_INVALID, but it returned %s (0x%08X)",
				rvName(got), got)
		}
	}
}

// TestSP800108ContextCrossesTheABI proves the CK_PRF_DATA_PARAM array reaches
// the derivation.
//
// The label and context segments are the caller's domain separation. Before
// the boundary read them, the parser returned fabricated defaults and every
// derivation ignored the caller's segments entirely. Two derivations differing
// only in the context segment must differ in output.
func TestSP800108ContextCrossesTheABI(t *testing.T) {
	f := NewFixture(t)
	base, err := generateDerivableSecret(t, f, CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, 32)
	if err != nil {
		t.Fatalf("C_GenerateKey for the SP800-108 base key: %v", err)
	}

	derive := func(context []byte) []byte {
		t.Helper()
		params := SP800108Params{
			PRF: CKM_SHA256_HMAC,
			DataParams: []PRFDataParam{
				{Type: CK_SP800_108_ITERATION_VARIABLE},
				{Type: CK_SP800_108_BYTE_ARRAY, Value: []byte("label")},
				{Type: CK_SP800_108_BYTE_ARRAY, Value: context},
			},
		}
		key, derr := deriveSecret(t, f, CKM_SP800_108_COUNTER_KDF, params, base, 32)
		if derr != nil {
			t.Fatalf("C_DeriveKey with context %q: %v", context, derr)
		}
		return readSecretValue(t, f, key)
	}

	if first, second := derive([]byte("context-A")), derive([]byte("context-B")); bytes.Equal(first, second) {
		t.Fatalf("changing only the CK_SP800_108_BYTE_ARRAY context segment produced the same derived key (%x): "+
			"the PRF data parameters were accepted and discarded", first)
	}
}
