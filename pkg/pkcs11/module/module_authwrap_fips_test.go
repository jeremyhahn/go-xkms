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
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/stretchr/testify/require"
)

// TestAuthWrapVerbs_UnderFIPSOnly is the regression test for the
// pkg/pkcs11/module instance of go-xkms#292.
//
// Under GODEBUG=fips140=only, Go's crypto/cipher refuses arbitrary-IV GCM and
// seals only through cipher.NewGCMWithRandomNonce. Before #292 the refusal
// surfaced from inside the wrap as CKR_FUNCTION_FAILED -- a regime restriction
// reported as an internal fault. The verbs now seal a token-generated IV under
// the full tag through the stdlib's random-nonce construction, so that form
// round-trips, and refuse a caller-supplied IV or a truncated tag at the
// mechanism check with CKR_MECHANISM_PARAM_INVALID. All three verbs -- wrap,
// size query and unwrap -- answer with the same code, per the module's rule
// that a size query answers with the code the wrap itself would.
//
// The FIPS posture is fixed when the process starts, so the only-mode branch
// runs in a re-exec'd child, the pattern of certstore.TestToString_UnderFIPSOnly.
func TestAuthWrapVerbs_UnderFIPSOnly(t *testing.T) {
	if os.Getenv("XKMS_FIPS_AUTHWRAP_SUBPROCESS") == "1" {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		aad := []byte("fips140-only-authwrap")

		// A token-generated IV under the full tag is the construction
		// fips140=only seals with, so the verbs round-trip.
		mechanism := NewMechanism(CKM_AES_GCM)
		size, err := m.WrapKeyAuthenticatedSize(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle)
		require.NoError(t, err, "size query must succeed for a token-generated IV")
		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, aad)
		require.NoError(t, err, "authenticated wrap must succeed for a token-generated IV")
		require.Equal(t, size, uint64(len(wrappedKey)))

		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		newHandle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle,
			wrappedKey, unwrapTemplate, aad)
		require.NoError(t, err, "authenticated unwrap must open a token-generated IV")
		require.NotEqual(t, ObjectHandle(InvalidHandle), newHandle)

		// A caller-supplied IV and a truncated tag are refused as parameters
		// this process cannot honour.
		callerIV := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(make([]byte, GCMNonceSize), 128))
		_, err = m.WrapKeyAuthenticated(sessionHandle, callerIV, wrappingKeyHandle, targetKeyHandle, aad)
		requireCode(t, err, CKR_MECHANISM_PARAM_INVALID, "caller IV under fips140=only")
		_, err = m.WrapKeyAuthenticatedSize(sessionHandle, callerIV, wrappingKeyHandle, targetKeyHandle)
		requireCode(t, err, CKR_MECHANISM_PARAM_INVALID, "caller IV size query under fips140=only")

		truncated := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(nil, 96))
		_, err = m.WrapKeyAuthenticated(sessionHandle, truncated, wrappingKeyHandle, targetKeyHandle, aad)
		requireCode(t, err, CKR_MECHANISM_PARAM_INVALID, "truncated tag under fips140=only")
		_, err = m.UnwrapKeyAuthenticated(sessionHandle, truncated, wrappingKeyHandle,
			wrappedKey, unwrapTemplate, aad)
		requireCode(t, err, CKR_MECHANISM_PARAM_INVALID, "truncated tag unwrap under fips140=only")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestAuthWrapVerbs_UnderFIPSOnly$", "-test.v")
	cmd.Env = append(os.Environ(),
		"XKMS_FIPS_AUTHWRAP_SUBPROCESS=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=only subprocess failed: %v\n%s", err, out)
	}
	require.Contains(t, string(out), "PASS",
		"fips140=only subprocess did not pass:\n%s", out)
	require.NotContains(t, string(out), "panic:",
		"fips140=only subprocess panicked:\n%s", out)
}

// TestAuthWrapVerbs_UnderFIPSOn pins the other half of the #292 gate: the
// arbitrary-IV GCM construction WORKS under GODEBUG=fips140=on — only the
// only mode refuses it — so the gate must not fire there. A predicate-based
// gate on fips140.Enabled(), which is true under both settings, would have
// withdrawn a working mechanism; this test is what fails if anyone
// reintroduces one. The full wrap/size/unwrap round trip must succeed.
func TestAuthWrapVerbs_UnderFIPSOn(t *testing.T) {
	if os.Getenv("XKMS_FIPS_AUTHWRAP_ON_SUBPROCESS") == "1" {
		m, sessionHandle, wrappingKeyHandle, targetKeyHandle := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		aad := []byte("fips140-on-authwrap")

		size, err := m.WrapKeyAuthenticatedSize(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle)
		require.NoError(t, err, "size query must succeed under fips140=on")

		wrappedKey, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle, targetKeyHandle, aad)
		require.NoError(t, err, "authenticated wrap must succeed under fips140=on")
		require.Equal(t, size, uint64(len(wrappedKey)),
			"size query must report the length the wrap produces")

		unwrapTemplate := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
		}
		newHandle, err := m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKeyHandle,
			wrappedKey, unwrapTemplate, aad)
		require.NoError(t, err, "authenticated unwrap must succeed under fips140=on")
		require.NotEqual(t, ObjectHandle(InvalidHandle), newHandle)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestAuthWrapVerbs_UnderFIPSOn$", "-test.v")
	cmd.Env = append(os.Environ(),
		"XKMS_FIPS_AUTHWRAP_ON_SUBPROCESS=1", "GODEBUG=fips140=on")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=on subprocess failed: %v\n%s", err, out)
	}
	require.Contains(t, string(out), "PASS",
		"fips140=on subprocess did not pass:\n%s", out)
	require.NotContains(t, string(out), "panic:",
		"fips140=on subprocess panicked:\n%s", out)
}

// TestAuthWrapVerbs_GateRefusesBeforeTouchingHandles pins the gate's
// position: it sits at the mechanism check, before any object resolution, so
// under fips140=only a caller with garbage handles still learns its
// caller-supplied IV is unavailable rather than a misleading handle error. In every other mode
// the same call reports the handle problem, proving the gate itself is what
// answered. Runs in the only-mode child via the parent above; here it guards
// the non-FIPS ordering so the two answers stay distinguishable.
func TestAuthWrapVerbs_GateRefusesBeforeTouchingHandles(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	sessionHandle := loginAsNormalUser(t, m)
	callerIV := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(make([]byte, GCMNonceSize), 128))

	_, err := m.WrapKeyAuthenticated(sessionHandle, callerIV,
		ObjectHandle(0xdeadbeef), ObjectHandle(0xfeedface), nil)
	if strings.Contains(os.Getenv("GODEBUG"), "fips140=only") {
		// When the whole suite is run under fips140=only, the gate answers
		// first; the rest of that behaviour is asserted by the subprocess
		// test above.
		requireCode(t, err, CKR_MECHANISM_PARAM_INVALID, "authwrap fips gate")
		return
	}
	requireCode(t, err, CKR_WRAPPING_KEY_HANDLE_INVALID, "non-FIPS ordering")
}

// authWrapRefusedUnderFIPS reports whether this process runs fips140=only
// and the authenticated wrap under test is one the module refuses there: a
// truncated tag, or a caller-supplied IV when sealing (SP 800-38D section
// 8.2). In that case it asserts that call answered
// CKR_MECHANISM_PARAM_INVALID. Otherwise it does not call call.
func authWrapRefusedUnderFIPS(t *testing.T, tagSize int, callerIV bool, call func() error) bool {
	t.Helper()
	if aead.ArbitraryIVGCMUsable() || (tagSize == aead.GCMFullTagSize && !callerIV) {
		return false
	}
	requireCode(t, call(), CKR_MECHANISM_PARAM_INVALID, "authenticated wrap under fips140=only")
	return true
}
