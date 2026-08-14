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

// Package conformance validates the PKCS#11 v3.2 "signature-first"
// verification family — C_VerifySignatureInit, C_VerifySignature,
// C_VerifySignatureUpdate, C_VerifySignatureFinal — which previously had
// zero integration coverage. Unlike C_VerifyInit/C_Verify, this family takes
// the signature at initialization time rather than at the terminal call,
// which is why v3.2 §5.15 introduced it: PQC signature schemes need the
// signature available before streaming data through the verification state
// machine.
//
// This module implements the family only for ML-DSA (crypto_quantum.go's
// verifySigInit type-asserts to *QuantumCryptoManager and requires
// IsMLDSAMechanism). ML-DSA verification runs entirely inside this process
// against the raw CKA_VALUE public key bytes (pkg/quantum/dilithium2), with
// no backend round trip, so a key pair generated with the reference
// dilithium2 package and imported via C_CreateObject is a real key the
// module can verify against — not a mock. Signing that same message with the
// dilithium2 private key and having the module verify it independently
// through C_VerifySignature is the oracle: a plumbing defect (wrong operand
// order between the stored signature and the streamed data, a multi-part
// accumulator that drops a chunk, a key handle that resolves to the wrong
// object) surfaces as a verification failure or a wrong success, not merely
// a non-CKR_OK return.
//
// Reference: OASIS PKCS#11 v3.2 §5.15.7 (C_VerifySignatureInit), §5.15.8
// (C_VerifySignature), §5.15.9 (C_VerifySignatureUpdate), §5.15.10
// (C_VerifySignatureFinal), §6.67 (ML-DSA mechanisms).
//
// Build tags: integration,conformance
package conformance

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/pkg/quantum/dilithium2"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// mlDSA44KeyPair holds a reference-implementation ML-DSA-44 key pair used to
// produce signatures the module never helped create.
type mlDSA44KeyPair struct {
	signer    *dilithium2.Dilithium2
	publicKey []byte
}

// generateMLDSA44Oracle generates an ML-DSA-44 key pair with the reference
// dilithium2 implementation, independent of the module under test.
func generateMLDSA44Oracle(t *testing.T) *mlDSA44KeyPair {
	t.Helper()
	signer, err := dilithium2.New()
	if err != nil {
		t.Fatalf("dilithium2.New failed: %v", err)
	}
	pub, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("dilithium2 GenerateKeyPair failed: %v", err)
	}
	t.Cleanup(signer.Clean)
	return &mlDSA44KeyPair{signer: signer, publicKey: pub}
}

// importMLDSA44PublicKey imports the oracle's public key bytes into the
// module as a verification key.
func importMLDSA44PublicKey(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, kp *mlDSA44KeyPair, label string) module.ObjectHandle {
	t.Helper()
	handle, rv := env.Module.CreateObject(session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_ML_DSA)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_VERIFY, true),
		module.NewAttribute(module.CKA_VALUE, kp.publicKey),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_CreateObject for the imported ML-DSA-44 public key returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, handle) })
	return handle
}

// TestVerifySignature_AcceptsAnIndependentlyProducedSignature proves
// C_VerifySignatureInit/C_VerifySignature accept a signature the reference
// ML-DSA-44 implementation produced over the same message, using a public
// key imported from that same reference implementation.
func TestVerifySignature_AcceptsAnIndependentlyProducedSignature(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	kp := generateMLDSA44Oracle(t)
	pubHandle := importMLDSA44PublicKey(t, env, session, kp, "verifysig-accept")

	message := []byte("conformance VerifySignature payload")
	signature, err := kp.signer.Sign(message)
	if err != nil {
		t.Fatalf("dilithium2 Sign failed: %v", err)
	}

	mech := &module.Mechanism{Type: module.CKM_VENDOR_ML_DSA_44}
	if err := env.Module.VerifySignatureInit(session, mech, pubHandle, signature); err != nil {
		t.Fatalf("C_VerifySignatureInit returned %v", err)
	}
	if err := env.Module.VerifySignature(session, message); err != nil {
		t.Errorf("C_VerifySignature rejected a signature the reference ML-DSA-44 "+
			"implementation produced over the same message and key: %v", err)
	}
}

// TestVerifySignature_RejectsTamperedMessage proves a message that was
// altered after signing is rejected with CKR_SIGNATURE_INVALID, not merely
// "an error".
func TestVerifySignature_RejectsTamperedMessage(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	kp := generateMLDSA44Oracle(t)
	pubHandle := importMLDSA44PublicKey(t, env, session, kp, "verifysig-tamper")

	message := []byte("original message that will be tampered with")
	signature, err := kp.signer.Sign(message)
	if err != nil {
		t.Fatalf("dilithium2 Sign failed: %v", err)
	}
	tampered := append([]byte(nil), message...)
	tampered[0] ^= 0xff

	mech := &module.Mechanism{Type: module.CKM_VENDOR_ML_DSA_44}
	if err := env.Module.VerifySignatureInit(session, mech, pubHandle, signature); err != nil {
		t.Fatalf("C_VerifySignatureInit returned %v", err)
	}
	err = env.Module.VerifySignature(session, tampered)
	if err == nil {
		t.Fatal("C_VerifySignature accepted a signature over a different message than was signed")
	}
	pkcsErr, ok := err.(*module.PKCS11Error)
	if !ok {
		t.Fatalf("expected a *module.PKCS11Error, got %T: %v", err, err)
	}
	if pkcsErr.Code != module.CKR_SIGNATURE_INVALID {
		t.Errorf("C_VerifySignature of a tampered message returned %s, want CKR_SIGNATURE_INVALID",
			pkcsErr.Code.String())
	}
}

// TestVerifySignatureMultiPart_MatchesSinglePart proves that streaming the
// same message through C_VerifySignatureUpdate in several chunks accepts the
// same signature C_VerifySignature accepts for the whole message at once.
//
// This is where an accumulation bug would surface: a module that reset its
// buffer on each Update call, or dropped the first chunk, would still return
// a definite CKR_OK/CKR_SIGNATURE_INVALID either way — just the wrong one —
// so the only way to catch it is to compare the multi-part outcome against
// the known-good single-part outcome for the identical bytes.
func TestVerifySignatureMultiPart_MatchesSinglePart(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	kp := generateMLDSA44Oracle(t)
	pubHandle := importMLDSA44PublicKey(t, env, session, kp, "verifysig-multipart")

	parts := [][]byte{
		[]byte("first chunk of the multi-part message "),
		[]byte("second chunk "),
		[]byte("third and final chunk"),
	}
	var whole []byte
	for _, p := range parts {
		whole = append(whole, p...)
	}

	signature, err := kp.signer.Sign(whole)
	if err != nil {
		t.Fatalf("dilithium2 Sign failed: %v", err)
	}

	mech := &module.Mechanism{Type: module.CKM_VENDOR_ML_DSA_44}
	if err := env.Module.VerifySignatureInit(session, mech, pubHandle, signature); err != nil {
		t.Fatalf("C_VerifySignatureInit returned %v", err)
	}
	for i, p := range parts {
		if err := env.Module.VerifySignatureUpdate(session, p); err != nil {
			t.Errorf("C_VerifySignatureUpdate #%d returned %v, want nil; multi-part "+
				"signature-first verification must accept each chunk of a message whose "+
				"signature was supplied at C_VerifySignatureInit", i, err)
			return
		}
	}
	if err := env.Module.VerifySignatureFinal(session); err != nil {
		t.Errorf("C_VerifySignatureFinal rejected a signature valid over the concatenation "+
			"of the fed parts: %v", err)
	}
}

// TestVerifySignature_CannotTerminateAMultiPartOperation proves
// C_VerifySignature is refused once C_VerifySignatureUpdate has fed a part,
// matching the same rule the legacy C_Verify family observes (v3.2 §5.15.8).
//
// A module that allowed it would run C_VerifySignature only over its own
// (empty-context) argument, silently discarding the buffered parts and
// verifying against the wrong data.
func TestVerifySignature_CannotTerminateAMultiPartOperation(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	kp := generateMLDSA44Oracle(t)
	pubHandle := importMLDSA44PublicKey(t, env, session, kp, "verifysig-noterm")

	message := []byte("message fed through Update before a terminal call")
	signature, err := kp.signer.Sign(message)
	if err != nil {
		t.Fatalf("dilithium2 Sign failed: %v", err)
	}

	mech := &module.Mechanism{Type: module.CKM_VENDOR_ML_DSA_44}
	if err := env.Module.VerifySignatureInit(session, mech, pubHandle, signature); err != nil {
		t.Fatalf("C_VerifySignatureInit returned %v", err)
	}
	if err := env.Module.VerifySignatureUpdate(session, message); err != nil {
		t.Fatalf("C_VerifySignatureUpdate returned %v, want nil; this test cannot exercise "+
			"the intervening-Update rule without a successful Update call first", err)
	}

	err = env.Module.VerifySignature(session, message)
	if err == nil {
		t.Fatal("C_VerifySignature succeeded after an intervening C_VerifySignatureUpdate call")
	}
	pkcsErr, ok := err.(*module.PKCS11Error)
	if !ok {
		t.Fatalf("expected a *module.PKCS11Error, got %T: %v", err, err)
	}
	if pkcsErr.Code != module.CKR_OPERATION_ACTIVE {
		t.Errorf("C_VerifySignature after an Update call returned %s, want CKR_OPERATION_ACTIVE",
			pkcsErr.Code.String())
	}
}

// TestVerifySignatureInit_RejectsMissingSignature proves C_VerifySignatureInit
// requires the signature at initialization time — the entire point of the
// signature-first family — rather than accepting an empty one and deferring
// the check.
//
// Reference: v3.2 §5.15.7 CK_DECLARE_FUNCTION signature requires pSignature/
// ulSignatureLen; CKR_ARGUMENTS_BAD covers a missing required argument.
func TestVerifySignatureInit_RejectsMissingSignature(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	kp := generateMLDSA44Oracle(t)
	pubHandle := importMLDSA44PublicKey(t, env, session, kp, "verifysig-missingsig")

	mech := &module.Mechanism{Type: module.CKM_VENDOR_ML_DSA_44}
	err := env.Module.VerifySignatureInit(session, mech, pubHandle, nil)
	if err == nil {
		t.Fatal("C_VerifySignatureInit succeeded with no signature bytes")
	}
	pkcsErr, ok := err.(*module.PKCS11Error)
	if !ok {
		t.Fatalf("expected a *module.PKCS11Error, got %T: %v", err, err)
	}
	if pkcsErr.Code != module.CKR_ARGUMENTS_BAD {
		t.Errorf("C_VerifySignatureInit with no signature returned %s, want CKR_ARGUMENTS_BAD",
			pkcsErr.Code.String())
	}
}

// TestVerifySignatureInit_RejectsKeyWithoutVerifyAttribute proves the
// signature-first family observes the same CKA_VERIFY gate as C_VerifyInit.
//
// Reference: v3.2 §5.15.7: "the CKA_VERIFY attribute of the verification key
// ... MUST be CK_TRUE".
func TestVerifySignatureInit_RejectsKeyWithoutVerifyAttribute(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	kp := generateMLDSA44Oracle(t)
	handle, rv := env.Module.CreateObject(session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_ML_DSA)),
		module.NewStringAttribute(module.CKA_LABEL, "verifysig-noverify"),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_VERIFY, false),
		module.NewAttribute(module.CKA_VALUE, kp.publicKey),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_CreateObject returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, handle) })

	message := []byte("message")
	signature, err := kp.signer.Sign(message)
	if err != nil {
		t.Fatalf("dilithium2 Sign failed: %v", err)
	}

	mech := &module.Mechanism{Type: module.CKM_VENDOR_ML_DSA_44}
	err = env.Module.VerifySignatureInit(session, mech, handle, signature)
	if err == nil {
		t.Fatal("C_VerifySignatureInit succeeded with a CKA_VERIFY=false key")
	}
	pkcsErr, ok := err.(*module.PKCS11Error)
	if !ok {
		t.Fatalf("expected a *module.PKCS11Error, got %T: %v", err, err)
	}
	if pkcsErr.Code != module.CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Errorf("C_VerifySignatureInit with a non-CKA_VERIFY key returned %s, want CKR_KEY_FUNCTION_NOT_PERMITTED",
			pkcsErr.Code.String())
	}
}

// TestVerifySignature_WithoutInitIsRefused proves the terminal calls refuse
// to run outside an active signature-first operation.
//
// Reference: CKR_OPERATION_NOT_INITIALIZED for an operation function called
// without its matching Init.
func TestVerifySignature_WithoutInitIsRefused(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	t.Run("verify_signature", func(t *testing.T) {
		err := env.Module.VerifySignature(session, []byte("x"))
		requireOperationNotInitialized(t, err)
	})
	t.Run("verify_signature_update", func(t *testing.T) {
		err := env.Module.VerifySignatureUpdate(session, []byte("x"))
		requireOperationNotInitialized(t, err)
	})
	t.Run("verify_signature_final", func(t *testing.T) {
		err := env.Module.VerifySignatureFinal(session)
		requireOperationNotInitialized(t, err)
	})
}

// requireOperationNotInitialized fails the test unless err is a
// *module.PKCS11Error carrying CKR_OPERATION_NOT_INITIALIZED.
func requireOperationNotInitialized(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	pkcsErr, ok := err.(*module.PKCS11Error)
	if !ok {
		t.Fatalf("expected a *module.PKCS11Error, got %T: %v", err, err)
	}
	if pkcsErr.Code != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("returned %s, want CKR_OPERATION_NOT_INITIALIZED", pkcsErr.Code.String())
	}
}
