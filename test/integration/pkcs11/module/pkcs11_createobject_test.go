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

//go:build integration
// +build integration

package module

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// C_CreateObject key import, driven against a real xkmsd.
//
// These tests exist because the module-level suite cannot reach the daemon:
// pkg/xkms depends on pkg/pkcs11/module, so a unit test that imported the real
// service would be an import cycle, and every in-package fixture is therefore a
// double. A double is exactly what hid this defect the first time it was
// attempted -- the module-side change passed against a fake that ignored the
// key id while the real service rejected the same call for the field it was
// missing. Nothing here may substitute for the service.

// importAESKEK creates an AES key-encryption key from caller-supplied material
// with C_CreateObject and returns its handle and plaintext.
//
// The key is never bound to a backend by the test. C_CreateObject imports the
// material itself, and that import is the subject: a fixture that assigned the
// backend key id by hand would pass whether or not the import worked.
func importAESKEK(t *testing.T, env *TestEnvironment, session module.SessionHandle, label string) (module.ObjectHandle, []byte) {
	t.Helper()

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatalf("generating KEK material failed: %v", err)
	}

	handle, rv := env.Module.CreateObject(session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_WRAP, true),
		module.NewBoolAttribute(module.CKA_UNWRAP, true),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewAttribute(module.CKA_VALUE, keyBytes),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_CreateObject for the KEK returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, handle) })

	return handle, keyBytes
}

// TestCreateObjectImportedKEKWrapsAndUnwrapsAgainstTheDaemon is the decisive
// test for the change: a KEK an application supplied with C_CreateObject wraps
// a target, unwraps it back, and the recovered material is verified against
// crypto/cipher outside the module.
//
// Every step crosses the real transport to a real xkmsd. C_WrapKey and
// C_UnwrapKey resolve the KEK server-side by (backend, key id), so before
// C_CreateObject imported the material these calls could not be made at all:
// they returned CKR_WRAPPING_KEY_HANDLE_INVALID and
// CKR_UNWRAPPING_KEY_HANDLE_INVALID, and the daemon refused independently
// because XKMSService.WrapKeyByID rejects an empty wrapping key id.
//
// The independent check matters as much as the round trip. Two halves of one
// implementation agreeing proves only that they agree; AES key wrap is defined
// by RFC 3394, so decrypting the blob with crypto/cipher's own KWP-free
// primitive -- or, for AES-GCM below, opening it with crypto/cipher directly --
// is what says the module and the service produced the real construction.
func TestCreateObjectImportedKEKWrapsAndUnwrapsAgainstTheDaemon(t *testing.T) {
	env, session := SetupAuthenticatedModule(t)
	defer env.Teardown(t)

	kek, kekBytes := importAESKEK(t, env, session, "imported-kek-roundtrip")

	targetBytes := make([]byte, 32)
	if _, err := rand.Read(targetBytes); err != nil {
		t.Fatalf("generating target material failed: %v", err)
	}

	target, rv := env.Module.CreateObject(session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, "imported-kek-roundtrip-target"),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewAttribute(module.CKA_VALUE, targetBytes),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_CreateObject for the target key returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, target) })

	// CKM_AES_GCM rather than CKM_AES_KEY_WRAP, because its blob is
	// nonce||ciphertext||tag and can be opened by crypto/cipher below with no
	// dependence on this repository's own wrapping code.
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("generating the GCM nonce failed: %v", err)
	}

	wrapped, rv := env.Module.WrapKey(session,
		module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(iv, 128)),
		kek, target)
	if rv != module.CKR_OK {
		t.Fatalf("C_WrapKey under an imported KEK returned %s; "+
			"before C_CreateObject imported the KEK this was CKR_WRAPPING_KEY_HANDLE_INVALID", rv.String())
	}
	if len(wrapped) == 0 {
		t.Fatal("C_WrapKey returned CKR_OK with an empty blob")
	}
	if bytes.Contains(wrapped, targetBytes) {
		t.Error("the wrapped blob contains the target key bytes verbatim")
	}

	// The independent oracle: open the blob with crypto/cipher under the KEK
	// bytes this test supplied to C_CreateObject. This is what proves the
	// service wrapped under the key the application imported, and not under
	// some other key it happened to have.
	block, err := aes.NewCipher(kekBytes)
	if err != nil {
		t.Fatalf("building the AES cipher for the independent check failed: %v", err)
	}
	gcm, err := cipher.NewGCMWithTagSize(block, 16)
	if err != nil {
		t.Fatalf("building GCM for the independent check failed: %v", err)
	}
	if len(wrapped) < gcm.NonceSize() {
		t.Fatalf("the wrapped blob is shorter than a GCM nonce: %d bytes", len(wrapped))
	}
	recovered, err := gcm.Open(nil, wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():], nil)
	if err != nil {
		t.Fatalf("the wrapped blob did not open under the imported KEK: %v; "+
			"the service wrapped under a different key than the one C_CreateObject imported", err)
	}
	if !bytes.Equal(recovered, targetBytes) {
		t.Errorf("the blob decrypts to the wrong key\n got: %x\nwant: %x", recovered, targetBytes)
	}

	// The other direction, through the same KEK.
	unwrapped, rv := env.Module.UnwrapKey(session,
		module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(iv, 128)),
		kek, wrapped, []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "imported-kek-roundtrip-unwrapped"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
			module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		})
	if rv != module.CKR_OK {
		t.Fatalf("C_UnwrapKey under an imported KEK returned %s; "+
			"before this change it was CKR_UNWRAPPING_KEY_HANDLE_INVALID", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, unwrapped) })

	// The unwrapped key is created in the backend, and the daemon releases the
	// material of an extractable secret key. Reading it back is what closes the
	// loop: the bytes that went into C_WrapKey came out of C_UnwrapKey.
	attrs, rv := env.Module.GetAttributeValue(session, unwrapped,
		[]module.Attribute{{Type: module.CKA_VALUE}})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetAttributeValue(CKA_VALUE) on the unwrapped key returned %s", rv.String())
	}
	if !bytes.Equal(attrs[0].Value, targetBytes) {
		t.Errorf("the unwrapped key is not the key that was wrapped\n got: %x\nwant: %x",
			attrs[0].Value, targetBytes)
	}
}

// TestCreateObjectImportedKeyIsUsableForEncryptAgainstTheDaemon proves the
// import fixes more than wrapping.
//
// C_Encrypt resolves its key by (backend, key id) through
// XKMSService.Encrypt's findKeyAttrs, so an imported key with no id failed
// there too -- the same defect wearing a different verb. Decrypting the
// ciphertext with crypto/cipher under the material this test supplied shows the
// daemon encrypted under the imported key and not merely under something.
func TestCreateObjectImportedKeyIsUsableForEncryptAgainstTheDaemon(t *testing.T) {
	env, session := SetupAuthenticatedModule(t)
	defer env.Teardown(t)

	key, keyBytes := importAESKEK(t, env, session, "imported-key-encrypt")

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("generating the GCM nonce failed: %v", err)
	}
	plaintext := []byte("data encrypted under a key the application imported")

	if rv := env.Module.EncryptInit(session,
		module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(iv, 128)),
		key); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit under an imported key returned %s", rv.String())
	}
	ciphertext, rv := env.Module.Encrypt(session, plaintext)
	if rv != module.CKR_OK {
		t.Fatalf("C_Encrypt under an imported key returned %s; "+
			"an imported key with no backend key id could not be resolved by the service at all", rv.String())
	}
	env.Module.FinishOperation(session, module.OperationEncrypt)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		t.Fatalf("building the AES cipher for the independent check failed: %v", err)
	}
	gcm, err := cipher.NewGCMWithTagSize(block, 16)
	if err != nil {
		t.Fatalf("building GCM for the independent check failed: %v", err)
	}
	// C_Encrypt emits ciphertext||tag and does NOT prefix the nonce: the IV is
	// the one the caller put in CK_GCM_PARAMS, so it is supplied here rather
	// than read off the front of the blob. That differs from C_WrapKey's
	// framing above, which the service builds as nonce||ciphertext||tag so
	// C_UnwrapKey can reverse it without being told the nonce again.
	recovered, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		t.Fatalf("the ciphertext did not open under the imported key: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("the ciphertext decrypts to the wrong plaintext\n got: %q\nwant: %q", recovered, plaintext)
	}
}

// TestCreateObjectUnextractableKeyIsNotImportedAgainstTheDaemon is the
// bad-input half against the real service.
//
// A key the application marks CKA_EXTRACTABLE=CK_FALSE is deliberately NOT
// imported: the ceremony carries no exportability field, so the backend copy
// would be created extractable and the module would have silently widened the
// protection the caller asked for. The object is still created, and it still
// cannot serve as a KEK -- which is what every imported key could not do before
// this change, and is the documented cost of keeping the request honest.
func TestCreateObjectUnextractableKeyIsNotImportedAgainstTheDaemon(t *testing.T) {
	env, session := SetupAuthenticatedModule(t)
	defer env.Teardown(t)

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatalf("generating KEK material failed: %v", err)
	}

	kek, rv := env.Module.CreateObject(session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, "unextractable-kek"),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_WRAP, true),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, false),
		module.NewAttribute(module.CKA_VALUE, keyBytes),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_CreateObject for an unextractable key returned %s; "+
			"refusing to import must not refuse to create", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, kek) })

	target, targetBytes := importAESKEK(t, env, session, "unextractable-kek-target")
	_ = targetBytes

	wrapped, rv := env.Module.WrapKey(session,
		module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(nil, 128)),
		kek, target)
	if rv != module.CKR_WRAPPING_KEY_HANDLE_INVALID {
		t.Errorf("C_WrapKey under a key that was deliberately not imported returned %s, want %s",
			rv.String(), module.CKR_WRAPPING_KEY_HANDLE_INVALID.String())
	}
	if len(wrapped) != 0 {
		t.Error("a refused wrap must return no blob")
	}
}
