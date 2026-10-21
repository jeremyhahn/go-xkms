// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package main

// FIPS 140-3 regime tests for the cgo boundary (go-xkms #23).
//
// Several round trips in this package drive constructions the FIPS module
// refuses: CKM_AES_GCM over a caller-supplied IV (Go's crypto/cipher refuses
// arbitrary-IV GCM under GODEBUG=fips140=only), CKM_HKDF_DERIVE over an
// arbitrary base key (withheld in FIPS mode, see pkg/pkcs11/module's
// mechanism registry) and CKM_RSA_PKCS sign-recover over raw data (PKCS#1
// v1.5 with no digest). Those tests re-run themselves under
// GODEBUG=fips140=off through runsOutsideFIPSMode, and
// TestFIPSOnlyRefusesNonApprovedConstructions proves the refusals in a
// fips140=only child.

import (
	"crypto/fips140"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// runsOutsideFIPSMode reports whether the calling top-level test runs its body
// in this process. In FIPS mode crypto/fips140.Enabled is fixed for the life
// of the process, so the test is re-run in a child under GODEBUG=fips140=off,
// t fails if the child does, and the caller returns.
func runsOutsideFIPSMode(t *testing.T) bool {
	t.Helper()
	if !fips140.Enabled() {
		return true
	}
	rerunUnderGODEBUG(t, "fips140=off")
	return false
}

// rerunUnderGODEBUG re-executes the running top-level test in a child test
// binary with GODEBUG set to godebug, and fails t unless the child reports
// that test as passed.
func rerunUnderGODEBUG(t *testing.T, godebug string) {
	t.Helper()
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GODEBUG=") {
			env = append(env, kv)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v")
	cmd.Env = append(env, "GODEBUG="+godebug)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s under GODEBUG=%s failed: %v\n%s", t.Name(), godebug, err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()+" ") {
		t.Fatalf("%s did not run under GODEBUG=%s:\n%s", t.Name(), godebug, out)
	}
}

// TestFIPSOnlyRefusesNonApprovedConstructions proves, in a fips140=only
// child, that every construction the runsOutsideFIPSMode tests move out of
// FIPS mode is refused through the C ABI rather than performed.
func TestFIPSOnlyRefusesNonApprovedConstructions(t *testing.T) {
	if !fips140.Enforced() {
		rerunUnderGODEBUG(t, "fips140=only")
		return
	}

	t.Run("C_Encrypt CKM_AES_GCM over a caller IV", func(t *testing.T) {
		_, session := newCryptoFixture(t)
		key := generateAESKeyViaC(t, session, "fips-only-aes-gcm")
		mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, gcmRoundTripIV, 96, nil, 128))
		if rv := encryptInitViaC(t, session, key, mechBuf); rv != module.CKR_OK {
			t.Fatalf("C_EncryptInit = %s, want CKR_OK", rv)
		}

		fn := reflect.ValueOf(C_Encrypt)
		ft := fn.Type()
		plaintext := []byte("plaintext the FIPS module must not encrypt")
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(session)),
			setBufferPtr(plaintext, ft, 1),
			scalarOf(ft, 2, uint64(len(plaintext))),
			reflect.Zero(ft.In(3)),
			allocOf(ft, 4),
		})
		runtime.KeepAlive(plaintext)
		if rv := module.CK_RV(out[0].Uint()); rv == module.CKR_OK {
			t.Fatal("C_Encrypt(CKM_AES_GCM, caller IV) = CKR_OK under fips140=only, want a refusal")
		}
	})

	// CKM_AES_GCM stays a supported wrapping mechanism under fips140=only: a
	// token-generated IV still seals. Only the caller-supplied IV is refused,
	// so the refusal is CKR_MECHANISM_PARAM_INVALID ("invalid parameters were
	// supplied to the mechanism", PKCS#11 v3.2 section 5.1.6), not
	// CKR_MECHANISM_INVALID. The parameters are otherwise well formed (12-byte
	// IV, full tag), so the FIPS gate is the check that refuses them.
	t.Run("C_WrapKeyAuthenticated CKM_AES_GCM over a caller IV", func(t *testing.T) {
		f := newTestFixture(t)
		mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMMessageParams(t, gcmRoundTripIV, 0, module.CKG_NO_GENERATE, make([]byte, 16), 128))
		fn := reflect.ValueOf(C_WrapKeyAuthenticated)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			scalarOf(ft, 2, 0xDEADBEEF),
			scalarOf(ft, 3, uint64(f.privKey)),
			reflect.Zero(ft.In(4)),
			scalarOf(ft, 5, 0),
			reflect.Zero(ft.In(6)),
			allocOf(ft, 7),
		})
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
			t.Fatalf("C_WrapKeyAuthenticated(caller IV) under fips140=only = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
		}
	})

	t.Run("C_DeriveKey CKM_HKDF_DERIVE", func(t *testing.T) {
		_, session := newCryptoFixture(t)
		baseKey := createSecretKeyObjectViaC(t, session, []byte("0123456789ABCDEF0123456789ABCDEF"))
		hkdfParams := buildHKDFParams(t, true, true, module.CKM_SHA256, module.CKF_HKDF_SALT_DATA, []byte("fips-only-hkdf-salt"), 0, nil)
		mechBuf := buildCMechanismWithParam(t, module.CKM_HKDF_DERIVE, hkdfParams)
		template := buildCAttributeArray(t, []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 16),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		})

		fn := reflect.ValueOf(C_DeriveKey)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(session)),
			cMechanismPtr(mechBuf, ft, 1),
			scalarOf(ft, 2, uint64(baseKey)),
			cAttributePtr(template, ft, 3),
			scalarOf(ft, 4, attrCount(template)),
			allocOf(ft, 5),
		})
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_INVALID {
			t.Fatalf("C_DeriveKey(CKM_HKDF_DERIVE) under fips140=only = %s, want CKR_MECHANISM_INVALID", rv)
		}
	})

	t.Run("C_SignRecover CKM_RSA_PKCS over raw data", func(t *testing.T) {
		m, session := newCryptoFixture(t)
		pub, priv := generateRSAKeyPairViaC(t, session)
		enableRecoverAttributes(t, m, session, pub, priv)
		if rv := signRecoverInitViaC(t, session, priv, module.CKM_RSA_PKCS); rv != module.CKR_OK {
			t.Fatalf("C_SignRecoverInit = %s, want CKR_OK", rv)
		}
		if _, rv := signRecoverViaC(t, session, []byte("recoverable data")); rv == module.CKR_OK {
			t.Fatal("C_SignRecover(CKM_RSA_PKCS, raw data) = CKR_OK under fips140=only, want a refusal")
		}
	})
}
