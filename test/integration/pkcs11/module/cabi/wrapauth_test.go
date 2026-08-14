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
	"crypto/rand"
	"sync"
	"testing"
	"time"
)

// gcmNonceSize and gcmTagSize are the AES-GCM framing the module's
// authenticated wrap uses: a 12-byte nonce prefix when the caller supplies no
// IV, and a 16-byte tag suffix.
const (
	gcmNonceSize = 12
	gcmTagSize   = 16
)

// authWrapKeys creates the two AES keys C_WrapKeyAuthenticated needs: a
// 32-byte wrapping key marked CKA_WRAP, and an extractable target key holding
// targetValue as its material.
//
// The keys are created with C_CreateObject rather than generated, because the
// wrapped output length is a function of the target's CKA_VALUE and the tests
// below assert on that length exactly. Both are session objects, and the target
// is deliberately non-sensitive: CKA_VALUE is not a read-only attribute, so an
// application may change a secret key's material through C_SetAttributeValue,
// and the race test depends on being able to.
func authWrapKeys(t *testing.T, f *Fixture, targetValue []byte) (uint, uint) {
	t.Helper()

	wrappingValue := make([]byte, 32)
	for i := range wrappingValue {
		wrappingValue[i] = byte(0x40 + i)
	}

	wrappingTemplate := []Attr{
		AttrULong(CKA_CLASS, CKO_SECRET_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_AES),
		AttrBool(CKA_TOKEN, false),
		AttrBool(CKA_WRAP, true),
		AttrBool(CKA_UNWRAP, true),
		AttrBytes(CKA_VALUE, wrappingValue),
		AttrString(CKA_LABEL, UniqueLabel(t, "cabi-authwrap-wk")),
	}
	wrappingKey, err := f.Session.CreateObject(wrappingTemplate)
	if err != nil {
		t.Fatalf("C_CreateObject for the wrapping key: %v", err)
	}

	targetTemplate := []Attr{
		AttrULong(CKA_CLASS, CKO_SECRET_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_AES),
		AttrBool(CKA_TOKEN, false),
		AttrBool(CKA_EXTRACTABLE, true),
		AttrBool(CKA_SENSITIVE, false),
		AttrBytes(CKA_VALUE, targetValue),
		AttrString(CKA_LABEL, UniqueLabel(t, "cabi-authwrap-target")),
	}
	targetKey, err := f.Session.CreateObject(targetTemplate)
	if err != nil {
		t.Fatalf("C_CreateObject for the target key: %v", err)
	}

	return f.Track(wrappingKey), f.Track(targetKey)
}

// TestWrapKeyAuthenticatedTwoCall asserts the ordinary two-call contract of
// C_WrapKeyAuthenticated: a NULL pWrappedKey reports the required length, an
// undersized buffer is refused with CKR_BUFFER_TOO_SMALL and the required
// length, and a correctly sized buffer succeeds.
//
// The undersized call is made through a guarded buffer, so a module that
// refused the call but wrote the bytes anyway would still be caught.
func TestWrapKeyAuthenticatedTwoCall(t *testing.T) {
	f := NewFixture(t)
	wrappingKey, targetKey := authWrapKeys(t, f, make([]byte, 16))

	required, err := f.Session.WrapKeyAuthenticatedProbe(wrappingKey, targetKey, nil)
	if err != nil {
		t.Fatalf("C_WrapKeyAuthenticated with a NULL pWrappedKey must report the required length, but returned %s (0x%08X)",
			rvName(RV(err)), RV(err))
	}
	want := uint(gcmNonceSize + 16 + gcmTagSize)
	if required != want {
		t.Fatalf("the size query reported %d bytes for a 16-byte AES key, want %d (%d-byte nonce + 16-byte ciphertext + %d-byte tag)",
			required, want, gcmNonceSize, gcmTagSize)
	}

	short := f.Session.WrapKeyAuthenticatedGuarded(wrappingKey, targetKey, nil, required-1, 64)
	if short.RV != CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_WrapKeyAuthenticated with a %d-byte buffer for a %d-byte output returned %s (0x%08X), want CKR_BUFFER_TOO_SMALL",
			required-1, required, rvName(short.RV), short.RV)
	}
	if short.Reported != required {
		t.Fatalf("the refused call reported %d bytes, want %d; the caller cannot size its retry", short.Reported, required)
	}
	if at := short.RedZoneClobbered(); at >= 0 {
		t.Fatalf("C_WrapKeyAuthenticated returned CKR_BUFFER_TOO_SMALL but still wrote %d bytes past the %d-byte buffer",
			at+1, required-1)
	}

	exact := f.Session.WrapKeyAuthenticatedGuarded(wrappingKey, targetKey, nil, required, 64)
	if exact.RV != CKR_OK {
		t.Fatalf("C_WrapKeyAuthenticated with the reported %d-byte buffer returned %s (0x%08X)",
			required, rvName(exact.RV), exact.RV)
	}
	if exact.Reported != required || uint(len(exact.Output)) != required {
		t.Fatalf("the wrap reported %d bytes and wrote %d, want %d", exact.Reported, len(exact.Output), required)
	}
	if at := exact.RedZoneClobbered(); at >= 0 {
		t.Fatalf("C_WrapKeyAuthenticated wrote %d bytes past the %d-byte buffer it was given", at+1, required)
	}
}

// TestWrapKeyAuthenticatedNeverWritesPastTheDeclaredLength drives the race
// between C_WrapKeyAuthenticated's internal size query and the wrap itself.
//
// The cgo entry point sizes the output by calling WrapKeyAuthenticatedSize and
// then calls WrapKeyAuthenticated. Each takes the module lock separately, and
// both read the target key's CKA_VALUE, which is not a read-only attribute. A
// C_SetAttributeValue that lengthens that value lands between the two, so the
// wrap returns more bytes than the size query predicted. Copying the predicted
// length into the caller's buffer is a heap overflow in the application's
// address space, not a wrong return code, which is why this test asserts on
// memory rather than on a CK_RV: the buffer carries a red zone past the length
// declared to the module, and no byte of it may ever change.
//
// The declared length is fixed at the 16-byte key's output size, so the
// overflow window is exactly the interleaving where the size query observes 16
// bytes of key material and the wrap observes 32.
//
// Driving the module from several goroutines at once is legitimate even though
// the harness passes NULL_PTR to C_Initialize: this module declares itself
// natively thread-safe and serializes internally regardless of pInitArgs
// (cmd/pkcs11-module/exports.go, C_Initialize), so the locking permission
// PKCS#11 v3.2 section 5.6.1 negotiates has no bearing on whether the calls
// below are safe to make. What is under test is the buffer arithmetic at the
// cgo boundary, which those internal locks do not cover: the size query and
// the wrap take them separately.
func TestWrapKeyAuthenticatedNeverWritesPastTheDeclaredLength(t *testing.T) {
	const (
		shortValueLen = 16
		longValueLen  = 32
		redZoneLen    = 128
		iterations    = 4000
	)
	declared := uint(gcmNonceSize + shortValueLen + gcmTagSize)

	short := make([]byte, shortValueLen)
	long := make([]byte, longValueLen)
	for i := range long {
		long[i] = byte(i + 1)
	}
	for i := range short {
		short[i] = byte(i + 1)
	}

	f := NewFixture(t)
	wrappingKey, targetKey := authWrapKeys(t, f, short)

	// Confirm the premise before racing on it: if the token refuses to change
	// CKA_VALUE at all, this test would pass without ever opening the window.
	if err := f.Session.SetAttributeValue(targetKey, []Attr{AttrBytes(CKA_VALUE, long)}); err != nil {
		t.Fatalf("C_SetAttributeValue on CKA_VALUE: %v; the race this test drives depends on the attribute being modifiable", err)
	}
	grown, err := f.Session.WrapKeyAuthenticatedProbe(wrappingKey, targetKey, nil)
	if err != nil {
		t.Fatalf("the size query after growing CKA_VALUE: %v", err)
	}
	if grown <= declared {
		t.Fatalf("growing CKA_VALUE from %d to %d bytes did not grow the wrap output past %d bytes (got %d); the overflow window does not exist and this test proves nothing",
			shortValueLen, longValueLen, declared, grown)
	}
	if err := f.Session.SetAttributeValue(targetKey, []Attr{AttrBytes(CKA_VALUE, short)}); err != nil {
		t.Fatalf("C_SetAttributeValue restoring the short CKA_VALUE: %v", err)
	}

	stop := make(chan struct{})
	var mutators sync.WaitGroup
	var mutateErr error
	var mutateOnce sync.Once

	for i := 0; i < 2; i++ {
		mutators.Add(1)
		go func() {
			defer mutators.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, value := range [][]byte{long, short} {
					if err := f.Session.SetAttributeValue(targetKey, []Attr{AttrBytes(CKA_VALUE, value)}); err != nil {
						mutateOnce.Do(func() { mutateErr = err })
						return
					}
				}
			}
		}()
	}

	var sawShortBuffer, sawSuccess int
	deadline := time.Now().Add(30 * time.Second)
	for i := 0; i < iterations && time.Now().Before(deadline); i++ {
		result := f.Session.WrapKeyAuthenticatedGuarded(wrappingKey, targetKey, nil, declared, redZoneLen)

		if at := result.RedZoneClobbered(); at >= 0 {
			close(stop)
			mutators.Wait()
			t.Fatalf("iteration %d: C_WrapKeyAuthenticated returned %s (0x%08X) reporting %d bytes, and overwrote the red zone %d bytes past the end of the %d-byte buffer it was given. "+
				"The size query and the wrap read CKA_VALUE under separate locks, so the memcpy must be guarded by the length actually produced, not the length predicted",
				i, rvName(result.RV), result.RV, result.Reported, at, declared)
		}

		switch result.RV {
		case CKR_OK:
			if result.Reported > declared {
				close(stop)
				mutators.Wait()
				t.Fatalf("iteration %d: C_WrapKeyAuthenticated returned CKR_OK reporting %d bytes written into a %d-byte buffer",
					i, result.Reported, declared)
			}
			sawSuccess++
		case CKR_BUFFER_TOO_SMALL:
			if result.Reported <= declared {
				close(stop)
				mutators.Wait()
				t.Fatalf("iteration %d: CKR_BUFFER_TOO_SMALL reported %d bytes, which fits in the %d-byte buffer", i, result.Reported, declared)
			}
			sawShortBuffer++
		default:
			close(stop)
			mutators.Wait()
			t.Fatalf("iteration %d: C_WrapKeyAuthenticated returned %s (0x%08X), want CKR_OK or CKR_BUFFER_TOO_SMALL",
				i, rvName(result.RV), result.RV)
		}
	}

	close(stop)
	mutators.Wait()

	if mutateErr != nil {
		t.Fatalf("the CKA_VALUE mutator failed: %v", mutateErr)
	}
	if sawShortBuffer == 0 {
		t.Fatalf("no iteration observed the grown key (%d successes, 0 CKR_BUFFER_TOO_SMALL); the race never interleaved and the guard was never exercised",
			sawSuccess)
	}
	if sawSuccess == 0 {
		t.Fatalf("no iteration observed the short key (0 successes, %d CKR_BUFFER_TOO_SMALL); the mutator starved the wrap and the test proves nothing",
			sawShortBuffer)
	}
}

// authWrapKeysWith creates the C_WrapKeyAuthenticated key pair the way
// authWrapKeys does, adding the attributes the caller names to each template
// and making both objects CKA_PRIVATE=CK_FALSE.
//
// The objects are public so a test may log out and still name them. A gate
// proved against private objects would look enforced even if it were deleted,
// because C_Logout invalidates handles to private objects on its own
// (PKCS#11 v3.2 section 5.6.10) and the call would fail for that reason
// instead.
func authWrapKeysWith(t *testing.T, f *Fixture, targetValue []byte, wrapExtra, targetExtra []Attr) (uint, uint) {
	t.Helper()

	wrappingValue := make([]byte, 32)
	for i := range wrappingValue {
		wrappingValue[i] = byte(0x40 + i)
	}

	wrappingTemplate := append([]Attr{
		AttrULong(CKA_CLASS, CKO_SECRET_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_AES),
		AttrBool(CKA_TOKEN, false),
		AttrBool(CKA_PRIVATE, false),
		AttrBool(CKA_WRAP, true),
		AttrBool(CKA_UNWRAP, true),
		AttrBytes(CKA_VALUE, wrappingValue),
		AttrString(CKA_LABEL, UniqueLabel(t, "cabi-authwrap-wk")),
	}, wrapExtra...)
	wrappingKey, err := f.Session.CreateObject(wrappingTemplate)
	if err != nil {
		t.Fatalf("C_CreateObject for the wrapping key: %v", err)
	}

	targetTemplate := append([]Attr{
		AttrULong(CKA_CLASS, CKO_SECRET_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_AES),
		AttrBool(CKA_TOKEN, false),
		AttrBool(CKA_PRIVATE, false),
		AttrBool(CKA_EXTRACTABLE, true),
		AttrBool(CKA_SENSITIVE, false),
		AttrBytes(CKA_VALUE, targetValue),
		AttrString(CKA_LABEL, UniqueLabel(t, "cabi-authwrap-target")),
	}, targetExtra...)
	targetKey, err := f.Session.CreateObject(targetTemplate)
	if err != nil {
		t.Fatalf("C_CreateObject for the target key: %v", err)
	}

	return f.Track(wrappingKey), f.Track(targetKey)
}

// TestWrapKeyAuthenticatedHonoursWrapWithTrusted proves CKA_WRAP_WITH_TRUSTED
// is enforced by the exported C_WrapKeyAuthenticated, not merely by some
// internal path.
//
// PKCS#11 v3.2 section 4.9 makes the attribute the only way to say that a key
// may leave the token solely under a wrapping key the token itself marked
// CKA_TRUSTED. C_WrapKey applies it; the authenticated form is reachable by
// name through the same v3.2 function list, so an application that meant to
// restrict a key gets no restriction at all if the two verbs disagree. The test
// asserts on the wrapped bytes as well as the return code: a module that
// refused with the right code but still filled the buffer would have released
// the material regardless.
func TestWrapKeyAuthenticatedHonoursWrapWithTrusted(t *testing.T) {
	targetValue := make([]byte, 16)
	for i := range targetValue {
		targetValue[i] = byte(0x11 * (i + 1))
	}

	t.Run("refuses an untrusted wrapping key", func(t *testing.T) {
		f := NewFixture(t)
		wrappingKey, targetKey := authWrapKeysWith(t, f, targetValue,
			nil, []Attr{AttrBool(CKA_WRAP_WITH_TRUSTED, true)})

		if _, err := f.Session.WrapKeyAuthenticatedProbe(wrappingKey, targetKey, nil); err == nil {
			t.Fatal("the size query answered CKR_OK for a wrap CKA_WRAP_WITH_TRUSTED forbids")
		} else if got := RV(err); got != CKR_KEY_NOT_WRAPPABLE {
			t.Fatalf("the size query returned %s (0x%08X), want CKR_KEY_NOT_WRAPPABLE", rvName(got), got)
		}

		declared := uint(gcmNonceSize + len(targetValue) + gcmTagSize)
		result := f.Session.WrapKeyAuthenticatedGuarded(wrappingKey, targetKey, nil, declared, 64)
		if result.RV != CKR_KEY_NOT_WRAPPABLE {
			t.Fatalf("C_WrapKeyAuthenticated returned %s (0x%08X) for a CKA_WRAP_WITH_TRUSTED key wrapped by a key the token does not trust, want CKR_KEY_NOT_WRAPPABLE. "+
				"The material left the token under a wrapping key section 4.9 excludes",
				rvName(result.RV), result.RV)
		}
		if len(result.Output) != 0 {
			t.Fatalf("the refused wrap still produced %d bytes of output", len(result.Output))
		}
		if at := result.RedZoneClobbered(); at >= 0 {
			t.Fatalf("the refused wrap wrote %d bytes past the declared buffer", at+1)
		}
	})

	t.Run("accepts a CKA_TRUSTED wrapping key", func(t *testing.T) {
		f := NewFixture(t)
		wrappingKey, targetKey := authWrapKeysWith(t, f, targetValue,
			[]Attr{AttrBool(CKA_TRUSTED, true)}, []Attr{AttrBool(CKA_WRAP_WITH_TRUSTED, true)})

		required, err := f.Session.WrapKeyAuthenticatedProbe(wrappingKey, targetKey, nil)
		if err != nil {
			t.Fatalf("the size query refused the wrapping key the token trusts: %s (0x%08X)", rvName(RV(err)), RV(err))
		}
		want := uint(gcmNonceSize + len(targetValue) + gcmTagSize)
		if required != want {
			t.Fatalf("the size query reported %d bytes, want %d", required, want)
		}

		result := f.Session.WrapKeyAuthenticatedGuarded(wrappingKey, targetKey, nil, required, 64)
		if result.RV != CKR_OK {
			t.Fatalf("C_WrapKeyAuthenticated refused the CKA_TRUSTED wrapping key with %s (0x%08X); the gate refuses unconditionally",
				rvName(result.RV), result.RV)
		}
		if uint(len(result.Output)) != required {
			t.Fatalf("the wrap wrote %d bytes after reporting %d", len(result.Output), required)
		}
		if at := result.RedZoneClobbered(); at >= 0 {
			t.Fatalf("the wrap wrote %d bytes past the %d-byte buffer", at+1, required)
		}
	})
}

// TestWrapKeyAuthenticatedRequiresLogin proves the token's CKF_LOGIN_REQUIRED
// policy reaches the exported C_WrapKeyAuthenticated.
//
// Wrapping is an export path for key material, and C_WrapKey refuses an
// unauthenticated session with CKR_USER_NOT_LOGGED_IN. An application reaches
// the authenticated form by name from the same v3.2 function list, so if it
// answers differently the policy is decided by which verb the caller happened
// to pick. Both objects are public, so nothing but the login gate can refuse
// the call — which is what makes the assertion meaningful.
func TestWrapKeyAuthenticatedRequiresLogin(t *testing.T) {
	f := NewFixture(t)
	targetValue := make([]byte, 16)
	wrappingKey, targetKey := authWrapKeysWith(t, f, targetValue, nil, nil)

	required, err := f.Session.WrapKeyAuthenticatedProbe(wrappingKey, targetKey, nil)
	if err != nil {
		t.Fatalf("the size query failed while the session was authenticated: %v", err)
	}

	if err := f.Session.Logout(); err != nil {
		t.Fatalf("C_Logout: %v", err)
	}
	// The fixture's teardown logs out and destroys the tracked objects, so the
	// session is authenticated again before this test returns however it ends.
	defer func() {
		if err := f.Session.Login(CKU_USER, UserPIN()); err != nil {
			t.Fatalf("C_Login restoring the session for teardown: %v", err)
		}
	}()

	if _, err := f.Session.WrapKeyAuthenticatedProbe(wrappingKey, targetKey, nil); err == nil {
		t.Fatal("the size query told a logged-out session the length of a wrapped key")
	} else if got := RV(err); got != CKR_USER_NOT_LOGGED_IN {
		t.Fatalf("the size query on a logged-out session returned %s (0x%08X), want CKR_USER_NOT_LOGGED_IN", rvName(got), got)
	}

	result := f.Session.WrapKeyAuthenticatedGuarded(wrappingKey, targetKey, nil, required, 64)
	if result.RV != CKR_USER_NOT_LOGGED_IN {
		t.Fatalf("C_WrapKeyAuthenticated on a logged-out session returned %s (0x%08X) and %d bytes of output, want CKR_USER_NOT_LOGGED_IN. "+
			"C_WrapKey refuses the same session, so the authenticated form is the one that skips authentication",
			rvName(result.RV), result.RV, len(result.Output))
	}
	if len(result.Output) != 0 {
		t.Fatalf("the refused wrap still produced %d bytes of key material", len(result.Output))
	}
	if at := result.RedZoneClobbered(); at >= 0 {
		t.Fatalf("the refused wrap wrote %d bytes past the declared buffer", at+1)
	}
}

// freshIV returns a 12-byte IV no earlier call has used.
//
// Every fixture in this file wraps under the same 32-byte wrapping key value,
// and the module refuses to seal twice under one (key, IV) pair, so a test
// that is not about reuse has to bring its own IV.
func freshIV(t *testing.T) []byte {
	t.Helper()
	iv := make([]byte, gcmNonceSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("reading a random IV: %v", err)
	}
	return iv
}

// TestWrapKeyAuthenticatedAcceptsGCMMessageParams is the C-ABI proof for the
// parameter structure PKCS#11 v3.2 section 5.18.6 defines.
//
// The verbs used to route their mechanism through the CKM_AES_GCM decoder the
// table registers for C_EncryptInit, which reads CK_GCM_PARAMS. Both structs
// are 48 bytes here, so the length gate passed and the fields transposed from
// offset 16: ivGenerator -- a value of 0 to 3 -- was read as the pAAD pointer
// and pTag as ulAADLen, so the boundary ended up asking for ulAADLen bytes at
// address 0x1 and refused the call. Every spec-conforming application got
// CKR_MECHANISM_PARAM_INVALID, which is to say the verbs could not be used at
// all.
//
// This test drives them exactly as such an application would: it lets the
// token generate the IV, reads it back out of pIv, and unwraps with it.
func TestWrapKeyAuthenticatedAcceptsGCMMessageParams(t *testing.T) {
	f := NewFixture(t)

	targetValue := make([]byte, 16)
	for i := range targetValue {
		targetValue[i] = byte(0x11 * (i%15 + 1))
	}
	wrappingKey, targetKey := authWrapKeys(t, f, targetValue)

	aad := []byte("cabi-message-params-aad")
	wrapParams := &GCMMessageParams{
		IV:          make([]byte, gcmNonceSize),
		IVGenerator: CKG_GENERATE_RANDOM,
		TagBits:     8 * gcmTagSize,
	}

	blob, err := f.Session.WrapKeyAuthenticatedMessage(wrapParams, wrappingKey, targetKey, aad)
	if err != nil {
		t.Fatalf("C_WrapKeyAuthenticated with a CK_GCM_MESSAGE_PARAMS returned %s (0x%08X); section 5.18.6 defines these verbs in terms of that structure",
			rvName(RV(err)), RV(err))
	}

	if want := len(targetValue) + gcmTagSize; len(blob) != want {
		t.Fatalf("the wrapped blob is %d bytes, want %d: with CK_GCM_MESSAGE_PARAMS the IV comes back through pIv, so it is not prepended to the blob",
			len(blob), want)
	}
	if len(wrapParams.IV) != gcmNonceSize {
		t.Fatalf("the token wrote a %d-byte IV back into pIv, want %d", len(wrapParams.IV), gcmNonceSize)
	}
	if bytes.Equal(wrapParams.IV, make([]byte, gcmNonceSize)) {
		t.Fatal("pIv still holds the zeroes it went in with; a generated IV that is never written back leaves a blob nobody can unwrap")
	}

	unwrapParams := &GCMMessageParams{
		IV:          wrapParams.IV,
		IVGenerator: CKG_NO_GENERATE,
		TagBits:     8 * gcmTagSize,
	}
	template := []Attr{
		AttrULong(CKA_CLASS, CKO_SECRET_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_AES),
		AttrBool(CKA_TOKEN, false),
		AttrBool(CKA_SENSITIVE, false),
		AttrBool(CKA_EXTRACTABLE, true),
		AttrString(CKA_LABEL, UniqueLabel(t, "cabi-authwrap-unwrapped")),
	}

	unwrapped, err := f.Session.UnwrapKeyAuthenticatedMessage(unwrapParams, wrappingKey, blob, template, aad)
	if err != nil {
		t.Fatalf("C_UnwrapKeyAuthenticated with the IV the wrap returned failed: %s (0x%08X)", rvName(RV(err)), RV(err))
	}
	f.Track(unwrapped)

	value, err := f.Session.Attribute(unwrapped, CKA_VALUE)
	if err != nil {
		t.Fatalf("reading CKA_VALUE of the unwrapped key: %v", err)
	}
	if !bytes.Equal(value, targetValue) {
		t.Fatalf("the unwrapped key holds %x, want %x", value, targetValue)
	}
}

// TestWrapKeyAuthenticatedRefusesAReusedIVThroughTheCABI drives the reuse probe
// through the shared library: one wrapping key, one caller-supplied IV, two
// wraps.
//
// The module performs this AES-GCM in process, so the reuse check that covers
// C_Encrypt never saw these nonces. Two seals under one (key, IV) leak the XOR
// of their plaintexts, and the plaintext of a key wrap is key material, so the
// second call must be refused.
func TestWrapKeyAuthenticatedRefusesAReusedIVThroughTheCABI(t *testing.T) {
	f := NewFixture(t)
	wrappingKey, targetKey := authWrapKeys(t, f, make([]byte, 16))

	iv := freshIV(t)
	params := &GCMMessageParams{
		IV:          iv,
		IVGenerator: CKG_NO_GENERATE,
		TagBits:     8 * gcmTagSize,
	}

	if _, err := f.Session.WrapKeyAuthenticatedMessage(params, wrappingKey, targetKey, nil); err != nil {
		t.Fatalf("the first use of an IV under a key is legitimate: %s (0x%08X)", rvName(RV(err)), RV(err))
	}

	repeat := &GCMMessageParams{
		IV:          iv,
		IVGenerator: CKG_NO_GENERATE,
		TagBits:     8 * gcmTagSize,
	}
	_, err := f.Session.WrapKeyAuthenticatedMessage(repeat, wrappingKey, targetKey, nil)
	if err == nil {
		t.Fatal("C_WrapKeyAuthenticated sealed twice under one (key, IV); XORing the two blobs recovers both wrapped keys")
	}
	if RV(err) != CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("the repeated (key, IV) returned %s (0x%08X), want CKR_MECHANISM_PARAM_INVALID: the caller has to change pIv",
			rvName(RV(err)), RV(err))
	}

	// A different IV under the same key must still work, so the guard is
	// refusing repeats rather than refusing everything.
	fresh := &GCMMessageParams{
		IV:          freshIV(t),
		IVGenerator: CKG_NO_GENERATE,
		TagBits:     8 * gcmTagSize,
	}
	if _, err := f.Session.WrapKeyAuthenticatedMessage(fresh, wrappingKey, targetKey, nil); err != nil {
		t.Fatalf("a fresh IV under the same key must be accepted: %s (0x%08X)", rvName(RV(err)), RV(err))
	}
}

// TestWrapKeyAuthenticatedRefusesAGeneratedIVWithNowhereToPutIt is the
// bad-input half of the CK_GCM_MESSAGE_PARAMS path. An application that asks
// the token to generate the IV but leaves pIv NULL could never learn it, so
// the wrap would produce a key blob nobody can ever unwrap. Refusing is the
// only answer that does not silently destroy the key.
func TestWrapKeyAuthenticatedRefusesAGeneratedIVWithNowhereToPutIt(t *testing.T) {
	f := NewFixture(t)
	wrappingKey, targetKey := authWrapKeys(t, f, make([]byte, 16))

	params := &GCMMessageParams{
		IVGenerator: CKG_GENERATE_RANDOM,
		TagBits:     8 * gcmTagSize,
	}

	_, err := f.Session.WrapKeyAuthenticatedMessage(params, wrappingKey, targetKey, nil)
	if err == nil {
		t.Fatal("C_WrapKeyAuthenticated generated an IV it had no way to return, producing an unusable wrapped key")
	}
	if RV(err) != CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("returned %s (0x%08X), want CKR_MECHANISM_PARAM_INVALID", rvName(RV(err)), RV(err))
	}
}
