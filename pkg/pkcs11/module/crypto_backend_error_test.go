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
	"context"
	"errors"
	"fmt"
	"testing"
)

// requireCKRV asserts err is a *PKCS11Error carrying want.
func requireCKRV(t *testing.T, err error, want CK_RV, context string) {
	t.Helper()

	if err == nil {
		t.Fatalf("%s: expected an error, got nil", context)
	}
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) {
		t.Fatalf("%s: expected *PKCS11Error, got %T (%v)", context, err, err)
	}
	if pkcsErr.Code != want {
		t.Fatalf("%s: got %s, want %s", context, pkcsErr.Code.String(), want.String())
	}
}

// backendErrorCases are the rejections a daemon can return mid-operation,
// paired with the CK_RV a caller must see.
//
// CKR_USER_NOT_LOGGED_IN and CKR_SESSION_HANDLE_INVALID are the two that
// matter operationally, and both appear in C_Sign's return table (PKCS#11 v3.2
// §5.13.2) as well as C_Encrypt's and C_Decrypt's. They arise for real when
// another session calls C_Logout while this one is signing: login state is
// token-wide, so the authentication under the operation is revoked and handles
// to private objects are invalidated at that moment (§5.6.10).
var backendErrorCases = []struct {
	name string
	err  error
	want CK_RV
}{
	{
		name: "not logged in, as a PKCS11Error",
		err:  NewPKCS11Error(CKR_USER_NOT_LOGGED_IN),
		want: CKR_USER_NOT_LOGGED_IN,
	},
	{
		name: "not logged in, as a wrapped sentinel",
		err:  fmt.Errorf("transport: %w", ErrUserNotLoggedIn),
		want: CKR_USER_NOT_LOGGED_IN,
	},
	{
		name: "invalidated session, as a PKCS11Error",
		err:  NewPKCS11Error(CKR_SESSION_HANDLE_INVALID),
		want: CKR_SESSION_HANDLE_INVALID,
	},
	{
		name: "invalidated session, as a wrapped sentinel",
		err:  fmt.Errorf("transport: %w", ErrSessionHandleInvalid),
		want: CKR_SESSION_HANDLE_INVALID,
	},
	{
		name: "invalidated key handle",
		err:  NewPKCS11Error(CKR_KEY_HANDLE_INVALID),
		want: CKR_KEY_HANDLE_INVALID,
	},
}

// TestCryptoManager_Sign_PreservesBackendCKRV proves C_Sign reports the
// condition the backend actually named.
//
// Collapsing every rejection into CKR_FUNCTION_FAILED left a caller unable to
// tell "log in again" from "the token crashed" -- and CKR_FUNCTION_FAILED is
// specifically the value the C ABI substitutes when a panic escapes an entry
// point, so a routine authentication failure was indistinguishable from a
// module defect. That ambiguity is what made
// TestConcurrentCABILoginLogoutDuringOperations flaky: the suite rejects
// CKR_FUNCTION_FAILED outright for exactly this reason.
func TestCryptoManager_Sign_PreservesBackendCKRV(t *testing.T) {
	for _, tc := range backendErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			cm, client := newTestCryptoManager()
			client.signError = tc.err

			op, err := cm.SignInit(&Mechanism{Type: CKM_RSA_PKCS}, 1, "test-key", "backend1")
			if err != nil {
				t.Fatalf("SignInit failed: %v", err)
			}

			_, err = cm.Sign(context.Background(), op, []byte("data"))
			requireCKRV(t, err, tc.want, "C_Sign")
		})
	}
}

// TestCryptoManager_Sign_UnclassifiableErrorFallsBack is the bad-input
// counterpart: an error naming no PKCS#11 condition must still become
// CKR_FUNCTION_FAILED, so preserving determinate codes does not turn every
// unknown failure into CKR_GENERAL_ERROR.
func TestCryptoManager_Sign_UnclassifiableErrorFallsBack(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.signError = errors.New("connection reset by peer")

	op, err := cm.SignInit(&Mechanism{Type: CKM_RSA_PKCS}, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("SignInit failed: %v", err)
	}

	_, err = cm.Sign(context.Background(), op, []byte("data"))
	requireCKRV(t, err, CKR_FUNCTION_FAILED, "C_Sign with an unclassifiable error")
}

// TestCryptoManager_Verify_PreservesBackendCKRV covers the sibling terminal
// operation, which hardcoded the same value.
func TestCryptoManager_Verify_PreservesBackendCKRV(t *testing.T) {
	for _, tc := range backendErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			cm, client := newTestCryptoManager()
			client.verifyError = tc.err

			op, err := cm.VerifyInit(&Mechanism{Type: CKM_RSA_PKCS}, 1, "test-key", "backend1")
			if err != nil {
				t.Fatalf("VerifyInit failed: %v", err)
			}

			err = cm.Verify(context.Background(), op, []byte("data"), []byte("sig"))
			requireCKRV(t, err, tc.want, "C_Verify")
		})
	}
}

// TestCryptoManager_Encrypt_PreservesBackendCKRV covers C_Encrypt.
func TestCryptoManager_Encrypt_PreservesBackendCKRV(t *testing.T) {
	for _, tc := range backendErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			cm, client := newTestCryptoManager()
			client.encryptError = tc.err

			op, err := cm.EncryptInit(&Mechanism{Type: CKM_AES_ECB}, 1, "test-key", "backend1")
			if err != nil {
				t.Fatalf("EncryptInit failed: %v", err)
			}

			_, err = cm.Encrypt(context.Background(), op, []byte("0123456789abcdef"))
			requireCKRV(t, err, tc.want, "C_Encrypt")
		})
	}
}

// TestCryptoManager_Decrypt_PreservesBackendCKRV covers C_Decrypt, whose
// fallback is CKR_ENCRYPTED_DATA_INVALID rather than CKR_FUNCTION_FAILED.
//
// The fallback is the right answer for a rejection that really is about the
// ciphertext, but it was applied to every rejection, including a session torn
// down underneath the operation. Telling a caller its ciphertext is invalid
// when the answer is "log in again" sends it looking for an attack that is not
// there.
func TestCryptoManager_Decrypt_PreservesBackendCKRV(t *testing.T) {
	for _, tc := range backendErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			cm, client := newTestCryptoManager()
			client.decryptError = tc.err

			op, err := cm.DecryptInit(&Mechanism{Type: CKM_AES_ECB}, 1, "test-key", "backend1")
			if err != nil {
				t.Fatalf("DecryptInit failed: %v", err)
			}

			_, err = cm.Decrypt(context.Background(), op, []byte("0123456789abcdef"))
			requireCKRV(t, err, tc.want, "C_Decrypt")
		})
	}
}

// TestCryptoManager_Decrypt_UnclassifiableErrorStaysEncryptedDataInvalid
// proves the decrypt fallback is unchanged for the case it was written for: a
// rejection that names nothing is still reported as invalid ciphertext, not as
// a generic failure.
func TestCryptoManager_Decrypt_UnclassifiableErrorStaysEncryptedDataInvalid(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.decryptError = errors.New("tag mismatch")

	op, err := cm.DecryptInit(&Mechanism{Type: CKM_AES_ECB}, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}

	_, err = cm.Decrypt(context.Background(), op, []byte("0123456789abcdef"))
	requireCKRV(t, err, CKR_ENCRYPTED_DATA_INVALID, "C_Decrypt with an unclassifiable error")
}

// TestBackendCKRV_Classification exercises the helper directly, including the
// case FromError alone cannot express: an error that genuinely carries
// CKR_GENERAL_ERROR must keep it rather than being rewritten to the fallback.
func TestBackendCKRV_Classification(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		fallback CK_RV
		want     CK_RV
	}{
		{"nil is CKR_OK", nil, CKR_FUNCTION_FAILED, CKR_OK},
		{"determinate code wins", NewPKCS11Error(CKR_DEVICE_ERROR), CKR_FUNCTION_FAILED, CKR_DEVICE_ERROR},
		{"wrapped sentinel wins", fmt.Errorf("rpc: %w", ErrTokenNotPresent), CKR_FUNCTION_FAILED, CKR_TOKEN_NOT_PRESENT},
		{"genuine general error is kept", NewPKCS11Error(CKR_GENERAL_ERROR), CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR},
		{"general-error sentinel is kept", fmt.Errorf("rpc: %w", ErrGeneralError), CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR},
		{"unclassifiable takes the fallback", errors.New("i/o timeout"), CKR_FUNCTION_FAILED, CKR_FUNCTION_FAILED},
		{"fallback is the caller's choice", errors.New("i/o timeout"), CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_INVALID},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := backendCKRV(tc.err, tc.fallback); got != tc.want {
				t.Fatalf("backendCKRV = %s, want %s", got.String(), tc.want.String())
			}
		})
	}
}
