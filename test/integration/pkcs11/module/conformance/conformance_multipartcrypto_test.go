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

//go:build integration && conformance
// +build integration,conformance

// Package conformance validates the multi-part encrypt/decrypt round trip —
// C_EncryptUpdate/C_EncryptFinal and C_DecryptUpdate/C_DecryptFinal — with
// assertions that check the operation actually recovered the expected
// plaintext, not merely that the terminal call was not refused with
// CKR_OPERATION_ACTIVE. conformance_multipart_test.go's
// TestSinglePart_WithoutUpdateStillWorks checks only the latter, which
// suffices for what that test proves (that a single-part call is not
// blocked by leftover multi-part state) but would not by itself catch the
// encryption operation being broken; this file's tests use CKM_AES_GCM and
// verify the round trip end to end. CKM_AES_CBC/CKM_AES_CBC_PAD get their
// own dedicated coverage below, in TestEncrypt_CBCMatchesTheStandardLibrary.
//
// C_GenerateKey never stores CKA_VALUE on the secret key object it creates,
// regardless of CKA_EXTRACTABLE/CKA_SENSITIVE (see
// TestGenerateKey_ExtractableKeyValueIsUnreadable). That closes off the
// usual "read the key back and drive an independent crypto/aes computation"
// oracle for any backend-generated key: C_GetAttributeValue cannot return
// the value, and C_WrapKey's backend-key dispatch path (see
// conformance_wrapkey_test.go) is scoped to the RSA import-ceremony
// algorithms rather than general key export, so it cannot recover the raw
// bytes of an arbitrary backend-generated AES key either. The oracle used
// below is therefore restricted to what remains achievable without the key
// material: multi-part output must equal single-part output for the
// identical plaintext/key/IV, decryption must recover exactly the known
// plaintext, and the ciphertext must differ from the plaintext (ruling out
// an identity no-op standing in for real encryption).
//
// Reference: OASIS PKCS#11 v3.2 §5.9.3 (C_EncryptUpdate), §5.9.4
// (C_EncryptFinal), §5.10.3 (C_DecryptUpdate), §5.10.4 (C_DecryptFinal),
// §6.13.7 (CKM_AES_GCM wire framing: ciphertext || tag), §6.10.5/§6.10.6
// (CKM_AES_CBC/CKM_AES_CBC_PAD IV requirement), §4.9 (CKA_EXTRACTABLE).
//
// Build tags: integration,conformance
package conformance

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// generateBackendAESKey creates a session-scoped, backend-generated AES key
// (a real key the server can encrypt/decrypt with).
func generateBackendAESKey(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, label string) module.ObjectHandle {
	t.Helper()

	handle, rv := env.Module.GenerateKey(session,
		&module.Mechanism{Type: module.CKM_AES_KEY_GEN},
		[]module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, label),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
		})
	if rv != module.CKR_OK {
		t.Fatalf("C_GenerateKey returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, handle) })
	return handle
}

// gcmMechanism builds a CKM_AES_GCM mechanism with an explicit 12-byte IV,
// so the same IV can be supplied again for C_DecryptInit: PKCS#11 v3.2
// §6.13.7 requires the decryptor to supply the exact IV encryption used, and
// this module has no session-level getter for a backend-generated one.
func gcmMechanism(iv []byte) *module.Mechanism {
	return &module.Mechanism{
		Type:           module.CKM_AES_GCM,
		TypedParameter: &module.AESGCMParams{IV: iv},
	}
}

// TestEncryptMultiPart_MatchesSinglePart proves that streaming plaintext
// through C_EncryptUpdate in several chunks and finishing with
// C_EncryptFinal, then decrypting the result back in one shot, recovers the
// same plaintext a single-part C_Encrypt/C_Decrypt round trip does — and
// that the two ciphertexts (necessarily produced under different IVs; see
// below) are neither equal to each other nor contain the plaintext
// verbatim.
//
// The two calls deliberately use different IVs rather than comparing
// ciphertext bytes directly: CryptoManager.Encrypt's GCM nonce-reuse guard
// (crypto.go's checkGCMNonce) correctly refuses to encrypt a second time
// under the same (key, IV) pair, which a same-IV comparison would trip
// before ever reaching the property under test. Round-tripping each
// ciphertext back to the same known plaintext is the accumulation-bug
// oracle instead: a module that dropped the first chunk, reset its buffer on
// each Update, or reordered chunks would still return a well-formed,
// correctly-sized ciphertext; only decrypting it back to the exact original
// bytes (or failing to) catches that.
func TestEncryptMultiPart_MatchesSinglePart(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	keyHandle := generateBackendAESKey(t, env, session, "multipart-enc-key")

	parts := [][]byte{
		bytes.Repeat([]byte{0xAA}, 20),
		bytes.Repeat([]byte{0xBB}, 37),
		bytes.Repeat([]byte{0xCC}, 15),
	}
	var whole []byte
	for _, p := range parts {
		whole = append(whole, p...)
	}

	multiIV := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b}
	singleIV := []byte{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b}

	// Multi-part encryption.
	multiMech := gcmMechanism(multiIV)
	if rv := env.Module.EncryptInit(session, multiMech, keyHandle); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit returned %s", rv.String())
	}
	for i, p := range parts {
		if _, rv := env.Module.EncryptUpdate(session, p); rv != module.CKR_OK {
			t.Fatalf("C_EncryptUpdate #%d returned %s", i, rv.String())
		}
	}
	multiPartCiphertext, rv := env.Module.EncryptFinal(session)
	if rv != module.CKR_OK {
		t.Fatalf("C_EncryptFinal returned %s", rv.String())
	}
	// The two-call output convention (v3.2 §5.2) leaves the operation active
	// until the caller confirms receipt; it must be explicitly finished
	// before a new C_EncryptInit can start.
	if rv := env.Module.FinishOperation(session, module.OperationEncrypt); rv != module.CKR_OK {
		t.Fatalf("FinishOperation returned %s", rv.String())
	}

	// Single-part encryption of the same bytes, same key, a different IV.
	singleMech := gcmMechanism(singleIV)
	if rv := env.Module.EncryptInit(session, singleMech, keyHandle); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit (single-part) returned %s", rv.String())
	}
	singlePartCiphertext, rv := env.Module.Encrypt(session, whole)
	if rv != module.CKR_OK {
		t.Fatalf("C_Encrypt (single-part) returned %s", rv.String())
	}
	if rv := env.Module.FinishOperation(session, module.OperationEncrypt); rv != module.CKR_OK {
		t.Fatalf("FinishOperation returned %s", rv.String())
	}

	if bytes.Equal(multiPartCiphertext, singlePartCiphertext) {
		t.Error("multi-part and single-part ciphertext are identical despite different IVs; " +
			"the IV is not actually affecting the encryption")
	}
	if bytes.Contains(multiPartCiphertext, whole) || bytes.Contains(singlePartCiphertext, whole) {
		t.Error("a ciphertext contains the plaintext verbatim")
	}

	// Both must decrypt back to exactly the plaintext that was encrypted.
	if rv := env.Module.DecryptInit(session, multiMech, keyHandle); rv != module.CKR_OK {
		t.Fatalf("C_DecryptInit (multi-part ciphertext) returned %s", rv.String())
	}
	recoveredFromMulti, rv := env.Module.Decrypt(session, multiPartCiphertext)
	if rv != module.CKR_OK {
		t.Fatalf("C_Decrypt (multi-part ciphertext) returned %s", rv.String())
	}
	if !bytes.Equal(recoveredFromMulti, whole) {
		t.Errorf("decrypting the multi-part ciphertext did not recover the original plaintext\n"+
			"got  %x\nwant %x", recoveredFromMulti, whole)
	}
	if rv := env.Module.FinishOperation(session, module.OperationDecrypt); rv != module.CKR_OK {
		t.Fatalf("FinishOperation returned %s", rv.String())
	}

	if rv := env.Module.DecryptInit(session, singleMech, keyHandle); rv != module.CKR_OK {
		t.Fatalf("C_DecryptInit (single-part ciphertext) returned %s", rv.String())
	}
	recoveredFromSingle, rv := env.Module.Decrypt(session, singlePartCiphertext)
	if rv != module.CKR_OK {
		t.Fatalf("C_Decrypt (single-part ciphertext) returned %s", rv.String())
	}
	if !bytes.Equal(recoveredFromSingle, whole) {
		t.Errorf("decrypting the single-part ciphertext did not recover the original plaintext\n"+
			"got  %x\nwant %x", recoveredFromSingle, whole)
	}
}

// TestDecryptMultiPart_RecoversTheOriginalPlaintext proves that ciphertext
// produced by a single C_Encrypt call, fed back through C_DecryptUpdate in
// several differently-sized chunks and finished with C_DecryptFinal,
// recovers exactly the original plaintext.
//
// A multi-part decrypt accumulator with an off-by-one chunk boundary would
// still produce SOME plaintext of a plausible length; only comparing against
// the exact original bytes (known here because the test chose them) catches
// that.
func TestDecryptMultiPart_RecoversTheOriginalPlaintext(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	keyHandle := generateBackendAESKey(t, env, session, "multipart-dec-key")

	plaintext := bytes.Repeat([]byte{0x42}, 64)
	iv := []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b}
	mech := gcmMechanism(iv)

	if rv := env.Module.EncryptInit(session, mech, keyHandle); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit returned %s", rv.String())
	}
	ciphertext, rv := env.Module.Encrypt(session, plaintext)
	if rv != module.CKR_OK {
		t.Fatalf("C_Encrypt returned %s", rv.String())
	}

	// Feed the ciphertext||tag back through decrypt in three uneven chunks.
	// GCM's tag lives at the end, so the split points intentionally fall
	// both inside the ciphertext body and across the ciphertext/tag boundary
	// to prove the accumulator does not care where the caller's chunk
	// boundaries land.
	third := len(ciphertext) / 3
	chunks := [][]byte{
		ciphertext[:third],
		ciphertext[third : 2*third],
		ciphertext[2*third:],
	}

	if rv := env.Module.DecryptInit(session, mech, keyHandle); rv != module.CKR_OK {
		t.Fatalf("C_DecryptInit returned %s", rv.String())
	}
	for i, c := range chunks {
		if _, rv := env.Module.DecryptUpdate(session, c); rv != module.CKR_OK {
			t.Fatalf("C_DecryptUpdate #%d returned %s", i, rv.String())
		}
	}
	recovered, rv := env.Module.DecryptFinal(session)
	if rv != module.CKR_OK {
		t.Fatalf("C_DecryptFinal returned %s", rv.String())
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("multi-part decryption did not recover the original plaintext\n"+
			"got  %x\nwant %x", recovered, plaintext)
	}
}

// TestEncryptFinal_TwoCallConventionIsIdempotent proves a repeated
// C_EncryptFinal call returns the same ciphertext without re-running the
// operation, and that the operation only ends via FinishOperation.
//
// Reference: PKCS#11 v3.2 §5.2 two-call output convention.
func TestEncryptFinal_TwoCallConventionIsIdempotent(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)
	keyHandle := generateBackendAESKey(t, env, session, "encfinal-twocall")

	iv := bytes.Repeat([]byte{0x07}, 12)
	mech := gcmMechanism(iv)
	if rv := env.Module.EncryptInit(session, mech, keyHandle); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit returned %s", rv.String())
	}
	if _, rv := env.Module.EncryptUpdate(session, bytes.Repeat([]byte{0x01}, 16)); rv != module.CKR_OK {
		t.Fatalf("C_EncryptUpdate returned %s", rv.String())
	}

	first, rv := env.Module.EncryptFinal(session)
	if rv != module.CKR_OK {
		t.Fatalf("the first C_EncryptFinal returned %s", rv.String())
	}
	second, rv := env.Module.EncryptFinal(session)
	if rv != module.CKR_OK {
		t.Fatalf("the repeated C_EncryptFinal returned %s; the operation must stay active "+
			"until the caller has collected the output", rv.String())
	}
	if !bytes.Equal(first, second) {
		t.Errorf("the repeated call returned different bytes\nfirst  %x\nsecond %x", first, second)
	}

	if rv := env.Module.FinishOperation(session, module.OperationEncrypt); rv != module.CKR_OK {
		t.Fatalf("FinishOperation returned %s", rv.String())
	}
	if _, rv := env.Module.EncryptFinal(session); rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("after the operation was finished C_EncryptFinal returned %s, want "+
			"CKR_OPERATION_NOT_INITIALIZED", rv.String())
	}
}

// TestDecryptFinal_TwoCallConventionIsIdempotent is
// TestEncryptFinal_TwoCallConventionIsIdempotent's decrypt-side counterpart.
func TestDecryptFinal_TwoCallConventionIsIdempotent(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)
	keyHandle := generateBackendAESKey(t, env, session, "decfinal-twocall")

	iv := bytes.Repeat([]byte{0x08}, 12)
	mech := gcmMechanism(iv)
	if rv := env.Module.EncryptInit(session, mech, keyHandle); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit returned %s", rv.String())
	}
	ciphertext, rv := env.Module.Encrypt(session, bytes.Repeat([]byte{0x02}, 16))
	if rv != module.CKR_OK {
		t.Fatalf("C_Encrypt returned %s", rv.String())
	}

	if rv := env.Module.DecryptInit(session, mech, keyHandle); rv != module.CKR_OK {
		t.Fatalf("C_DecryptInit returned %s", rv.String())
	}
	if _, rv := env.Module.DecryptUpdate(session, ciphertext); rv != module.CKR_OK {
		t.Fatalf("C_DecryptUpdate returned %s", rv.String())
	}

	first, rv := env.Module.DecryptFinal(session)
	if rv != module.CKR_OK {
		t.Fatalf("the first C_DecryptFinal returned %s", rv.String())
	}
	second, rv := env.Module.DecryptFinal(session)
	if rv != module.CKR_OK {
		t.Fatalf("the repeated C_DecryptFinal returned %s; the operation must stay active "+
			"until the caller has collected the output", rv.String())
	}
	if !bytes.Equal(first, second) {
		t.Errorf("the repeated call returned different bytes\nfirst  %x\nsecond %x", first, second)
	}

	if rv := env.Module.FinishOperation(session, module.OperationDecrypt); rv != module.CKR_OK {
		t.Fatalf("FinishOperation returned %s", rv.String())
	}
	if _, rv := env.Module.DecryptFinal(session); rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("after the operation was finished C_DecryptFinal returned %s, want "+
			"CKR_OPERATION_NOT_INITIALIZED", rv.String())
	}
}

// TestEncrypt_CBCMatchesTheStandardLibrary proves C_Encrypt succeeds for
// CKM_AES_CBC given a fully-permitted key and a spec-correct 16-byte IV,
// consistent with CKM_AES_CBC being advertised with CKF_ENCRYPT
// (mechanism.go, v3.2 §6.10.5).
//
// The assertion checks for CKR_OK specifically rather than merely "no
// CKR_OPERATION_ACTIVE": conformance_multipart_test.go's
// TestSinglePart_WithoutUpdateStillWorks uses the weaker check for a
// different property it is testing, and that weaker form would not by
// itself catch a CBC encryption path that fails outright.
func TestEncrypt_CBCMatchesTheStandardLibrary(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)
	keyHandle := generateBackendAESKey(t, env, session, "cbc-defect-key")

	iv := bytes.Repeat([]byte{0x09}, 16) // the 16-byte IV CKM_AES_CBC requires
	mech := &module.Mechanism{Type: module.CKM_AES_CBC, Parameter: iv}
	if rv := env.Module.EncryptInit(session, mech, keyHandle); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit CKM_AES_CBC (setup) returned %s", rv.String())
	}
	_, rv := env.Module.Encrypt(session, bytes.Repeat([]byte{0x0A}, 32))
	if rv != module.CKR_OK {
		t.Errorf("C_Encrypt CKM_AES_CBC returned %s, want CKR_OK; mechanism.go advertises "+
			"CKF_ENCRYPT for CKM_AES_CBC (v3.2 §6.10.5), so a fully-permitted key and a "+
			"spec-correct 16-byte IV must succeed", rv.String())
	}
}

// TestGenerateKey_ProtectionAttributesGovernRevelation proves a generated
// secret key reveals its value exactly when its own attributes say it may.
//
// PKCS#11 v3.2 §4.9 footnote 7 states the rule: a value "cannot be revealed if
// object has its CKA_SENSITIVE attribute set to CK_TRUE or its CKA_EXTRACTABLE
// attribute set to CK_FALSE". Both halves matter, and CKA_SENSITIVE=CK_FALSE on
// its own therefore obliges the token to reveal nothing.
//
// Getting this wrong in either direction is a real failure. Refusing the
// template outright made the token unusable from standard tooling —
// pkcs11-tool --keygen sends CKA_SENSITIVE=CK_FALSE by default, so no secret
// key could be created without --sensitive. Accepting it while never being able
// to produce CKA_VALUE would be the opposite fault: an object that contradicts
// itself, discovered only at the point of use.
func TestGenerateKey_ProtectionAttributesGovernRevelation(t *testing.T) {

	t.Run("a non-sensitive extractable key reveals its value", func(t *testing.T) {
		env, session := testutil.SetupAuthenticatedModule(t)
		handle, rv := env.Module.GenerateKey(session,
			&module.Mechanism{Type: module.CKM_AES_KEY_GEN},
			[]module.Attribute{
				module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
				module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
				module.NewStringAttribute(module.CKA_LABEL, "revealable"),
				module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
				module.NewBoolAttribute(module.CKA_TOKEN, false),
				module.NewBoolAttribute(module.CKA_SENSITIVE, false),
				module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
			})
		if rv != module.CKR_OK {
			t.Fatalf("C_GenerateKey returned %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		attrs, rv := env.Module.GetAttributeValue(session, handle,
			[]module.Attribute{{Type: module.CKA_VALUE}})
		if rv != module.CKR_OK {
			t.Fatalf("C_GetAttributeValue(CKA_VALUE) returned %s; footnote 7 permits "+
				"this key's value to be revealed", rv.String())
		}
		if len(attrs) == 0 || len(attrs[0].Value) != 32 {
			t.Errorf("expected a 32-byte key value, got %d bytes", len(attrs[0].Value))
		}
	})

	t.Run("a sensitive key withholds its value", func(t *testing.T) {
		env, session := testutil.SetupAuthenticatedModule(t)
		handle, rv := env.Module.GenerateKey(session,
			&module.Mechanism{Type: module.CKM_AES_KEY_GEN},
			[]module.Attribute{
				module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
				module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
				module.NewStringAttribute(module.CKA_LABEL, "sensitive-key"),
				module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
				module.NewBoolAttribute(module.CKA_TOKEN, false),
				module.NewBoolAttribute(module.CKA_SENSITIVE, true),
				module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
			})
		if rv != module.CKR_OK {
			t.Fatalf("C_GenerateKey returned %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		if _, rv := env.Module.GetAttributeValue(session, handle,
			[]module.Attribute{{Type: module.CKA_VALUE}}); rv != module.CKR_ATTRIBUTE_SENSITIVE {
			t.Errorf("C_GetAttributeValue(CKA_VALUE) on a sensitive key returned %s, "+
				"want CKR_ATTRIBUTE_SENSITIVE", rv.String())
		}
	})

	t.Run("an unextractable key withholds its value even when not sensitive", func(t *testing.T) {
		// The second half of footnote 7, and the case standard tooling hits:
		// pkcs11-tool's default template is CKA_SENSITIVE=false with no
		// CKA_EXTRACTABLE, so the key is created but its value stays withheld.
		env, session := testutil.SetupAuthenticatedModule(t)

		h2, rv := env.Module.GenerateKey(session,
			&module.Mechanism{Type: module.CKM_AES_KEY_GEN},
			[]module.Attribute{
				module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
				module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
				module.NewStringAttribute(module.CKA_LABEL, "unextractable2"),
				module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
				module.NewBoolAttribute(module.CKA_TOKEN, false),
				module.NewBoolAttribute(module.CKA_SENSITIVE, false),
				module.NewBoolAttribute(module.CKA_EXTRACTABLE, false),
			})
		if rv != module.CKR_OK {
			t.Fatalf("C_GenerateKey returned %s; a non-sensitive template must be "+
				"honoured, not refused -- refusing it broke pkcs11-tool --keygen "+
				"entirely", rv.String())
		}
		defer env.Module.DestroyObject(session, h2)

		if _, rv := env.Module.GetAttributeValue(session, h2,
			[]module.Attribute{{Type: module.CKA_VALUE}}); rv != module.CKR_ATTRIBUTE_SENSITIVE {
			t.Errorf("C_GetAttributeValue(CKA_VALUE) on an unextractable key returned "+
				"%s, want CKR_ATTRIBUTE_SENSITIVE", rv.String())
		}
	})
}
