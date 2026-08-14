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
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestApplyCipherMode_AESECBNamesItsMode is the unit-level statement of the
// defect: CKM_AES_ECB must resolve to the "ecb" wire mode.
//
// A mechanism absent from symmetricCipherModes takes the default branch, which
// sends no mode at all and so selects the backend's native AEAD. That is what
// CKM_AES_ECB did: the token answered a request for ECB with AES-GCM.
func TestApplyCipherMode_AESECBNamesItsMode(t *testing.T) {
	mode, nonce, iv := applyCipherMode(CKM_AES_ECB, nil)

	if mode != "ecb" {
		t.Fatalf("applyCipherMode(CKM_AES_ECB) = %q, want %q; an empty mode selects the backend's default AEAD", mode, "ecb")
	}
	if len(nonce) != 0 {
		t.Errorf("ECB carries no AEAD nonce, got %x", nonce)
	}
	if len(iv) != 0 {
		t.Errorf("ECB carries no IV, got %x", iv)
	}
}

// TestCryptoManager_Encrypt_ECB_NamesModeOnTheWire proves C_Encrypt under
// CKM_AES_ECB reaches the backend as an ECB request, carrying neither an IV
// nor a nonce.
//
// Every symptom of the original defect follows from the mode being absent
// here: the backend built AES-GCM, so identical plaintext blocks produced
// different ciphertext blocks, and the generated nonce and authentication tag
// were both dropped on the way back (Encrypt reassembles those only for
// CKM_AES_GCM), leaving output the token could not decrypt.
func TestCryptoManager_Encrypt_ECB_NamesModeOnTheWire(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_ECB}

	op, err := cm.EncryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("EncryptInit failed: %v", err)
	}

	plaintext := bytes.Repeat([]byte{0xa5}, 32)
	if _, err := cm.Encrypt(context.Background(), op, plaintext); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if client.lastEncryptReq.Mode != "ecb" {
		t.Errorf("expected Mode %q, got %q", "ecb", client.lastEncryptReq.Mode)
	}
	if len(client.lastEncryptReq.IV) != 0 {
		t.Errorf("ECB has no IV, but one was sent: %x", client.lastEncryptReq.IV)
	}
	if len(client.lastEncryptReq.Nonce) != 0 {
		t.Errorf("ECB has no AEAD nonce, but one was sent: %x", client.lastEncryptReq.Nonce)
	}
	if client.lastEncryptReq.TagSize != 0 {
		t.Errorf("ECB produces no authentication tag, but a tag size of %d was sent",
			client.lastEncryptReq.TagSize)
	}
}

// TestCryptoManager_Decrypt_ECB_NamesModeOnTheWire is the decrypt half. The
// two must agree: a decrypt that named no mode would be served by the default
// AEAD and could never reverse an ECB encryption.
func TestCryptoManager_Decrypt_ECB_NamesModeOnTheWire(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_ECB}

	op, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}

	ciphertext := bytes.Repeat([]byte{0x5a}, 32)
	if _, err := cm.Decrypt(context.Background(), op, ciphertext); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if client.lastDecryptReq.Mode != "ecb" {
		t.Errorf("expected Mode %q, got %q", "ecb", client.lastDecryptReq.Mode)
	}
	if len(client.lastDecryptReq.IV) != 0 {
		t.Errorf("ECB has no IV, but one was sent: %x", client.lastDecryptReq.IV)
	}
	if len(client.lastDecryptReq.Nonce) != 0 {
		t.Errorf("ECB has no AEAD nonce, but one was sent: %x", client.lastDecryptReq.Nonce)
	}
	// No AEAD tag may be split off a non-GCM ciphertext: the whole input is
	// ciphertext.
	if len(client.lastDecryptReq.Tag) != 0 {
		t.Errorf("ECB ciphertext carries no tag, but %x was split off", client.lastDecryptReq.Tag)
	}
	if !bytes.Equal(client.lastDecryptReq.Ciphertext, ciphertext) {
		t.Errorf("ciphertext was altered on the way to the backend: sent %x, forwarded %x",
			ciphertext, client.lastDecryptReq.Ciphertext)
	}
}

// TestCryptoManager_ECB_ModeIsDistinctFromCBC guards the routing against the
// other way it can be wrong. Mapping CKM_AES_ECB onto the CBC mode string
// would make it decryptable by the token and defeat a round-trip test, while
// still being the wrong cipher for every peer.
func TestCryptoManager_ECB_ModeIsDistinctFromCBC(t *testing.T) {
	ecbMode, _, _ := applyCipherMode(CKM_AES_ECB, nil)
	cbcMode, _, _ := applyCipherMode(CKM_AES_CBC, bytes.Repeat([]byte{0x01}, 16))
	cbcPadMode, _, _ := applyCipherMode(CKM_AES_CBC_PAD, bytes.Repeat([]byte{0x01}, 16))

	if ecbMode == cbcMode || ecbMode == cbcPadMode {
		t.Fatalf("CKM_AES_ECB resolves to %q, the same mode as a CBC mechanism", ecbMode)
	}
}

// TestCryptoManager_Encrypt_ECB_ClientError proves a backend rejection of an
// ECB encryption surfaces as a PKCS#11 error rather than being swallowed --
// the bad-input counterpart to the success path above. A backend that does not
// implement ECB for the key in question must produce a failure the caller can
// see.
func TestCryptoManager_Encrypt_ECB_ClientError(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.encryptError = errAESECBUnsupported
	mech := &Mechanism{Type: CKM_AES_ECB}

	op, err := cm.EncryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("EncryptInit failed: %v", err)
	}

	_, err = cm.Encrypt(context.Background(), op, bytes.Repeat([]byte{0x01}, 16))
	if err == nil {
		t.Fatal("expected the backend's rejection to reach the caller")
	}
	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_FUNCTION_FAILED {
		t.Errorf("expected CKR_FUNCTION_FAILED for an unclassifiable backend error, got %s",
			pkcsErr.Code.String())
	}
}

// errAESECBUnsupported stands in for a backend that refuses the mode. It
// deliberately carries no PKCS#11 code, so it exercises backendCKRV's
// fallback.
var errAESECBUnsupported = &transportRejection{msg: "backend does not support cipher mode ecb"}

// transportRejection is a plain error type with no CK_RV of its own.
type transportRejection struct{ msg string }

func (e *transportRejection) Error() string { return e.msg }

// Compile-time assurance that the request types this file inspects are the
// ones the transport actually carries.
var (
	_ = (*transport.EncryptRequest)(nil)
	_ = (*transport.DecryptRequest)(nil)
)
