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
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// wrappedStatus carries a gRPC status behind another error, which is how a
// status reaches this layer once a transport has added context to it.
type wrappedStatus struct {
	err error
}

func (w *wrappedStatus) Error() string { return "transport: " + w.err.Error() }
func (w *wrappedStatus) Unwrap() error { return w.err }

// TestFromError_TranslatesDaemonStatusCodes covers the classifications the
// xkms daemon makes on the wire and this module used to discard. Each case
// names the service-layer condition that produces the code, because the
// mapping is only correct with respect to that condition.
func TestFromError_TranslatesDaemonStatusCodes(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		code      codes.Code
		want      CK_RV
	}{
		{
			name:      "capability refusal",
			condition: "xkms.ErrOperationNotSupported: the backend cannot derive from a stored key",
			code:      codes.Unimplemented,
			want:      CKR_FUNCTION_NOT_SUPPORTED,
		},
		{
			name:      "export refusal",
			condition: "xkms.ErrExportKeyMaterialFailed: the key will not release its material",
			code:      codes.FailedPrecondition,
			want:      CKR_ATTRIBUTE_SENSITIVE,
		},
		{
			name:      "request validation",
			condition: "xkms.ErrValidation: a field the operation cannot accept",
			code:      codes.InvalidArgument,
			want:      CKR_ARGUMENTS_BAD,
		},
		{
			name:      "authentication",
			condition: "the daemon rejected the client's credentials",
			code:      codes.Unauthenticated,
			want:      CKR_USER_NOT_LOGGED_IN,
		},
		{
			name:      "service unreachable",
			condition: "xkms.ErrNotInitialized, a sealed tenant barrier, or a dead connection",
			code:      codes.Unavailable,
			want:      CKR_DEVICE_ERROR,
		},
		{
			name:      "caller cancelled",
			condition: "the caller's context was cancelled",
			code:      codes.Canceled,
			want:      CKR_FUNCTION_CANCELED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := status.Error(tc.code, tc.condition)
			if got := FromError(err); got != tc.want {
				t.Errorf("FromError(%s) = %s, want %s", tc.code, got.String(), tc.want.String())
			}
			if got := FromError(&wrappedStatus{err: err}); got != tc.want {
				t.Errorf("FromError(wrapped %s) = %s, want %s", tc.code, got.String(), tc.want.String())
			}
		})
	}
}

// TestBackendCKRV_UsesDaemonStatusOverTheFallback proves the translation
// actually reaches the operation call sites, which are what an application
// sees. Before the mapping, every one of these came back as the fallback and
// "this token does not do that" was indistinguishable from "something broke".
func TestBackendCKRV_UsesDaemonStatusOverTheFallback(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		fallback CK_RV
		want     CK_RV
	}{
		{
			name:     "C_DeriveKey against a backend with no KDF",
			err:      status.Error(codes.Unimplemented, "backend awskms cannot derive from a stored symmetric key"),
			fallback: CKR_FUNCTION_FAILED,
			want:     CKR_FUNCTION_NOT_SUPPORTED,
		},
		{
			name:     "C_Sign against a backend that cannot sign",
			err:      status.Error(codes.Unimplemented, "backend phone does not support signing"),
			fallback: CKR_FUNCTION_FAILED,
			want:     CKR_FUNCTION_NOT_SUPPORTED,
		},
		{
			name:     "C_GetAttributeValue on a key that will not export",
			err:      status.Error(codes.FailedPrecondition, "key material export failed"),
			fallback: CKR_FUNCTION_FAILED,
			want:     CKR_ATTRIBUTE_SENSITIVE,
		},
		{
			name:     "C_Decrypt while the daemon is unreachable",
			err:      status.Error(codes.Unavailable, "connection refused"),
			fallback: CKR_ENCRYPTED_DATA_INVALID,
			want:     CKR_DEVICE_ERROR,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := backendCKRV(tc.err, tc.fallback); got != tc.want {
				t.Errorf("backendCKRV() = %s, want %s", got.String(), tc.want.String())
			}
		})
	}
}

// TestFromError_LeavesUntranslatableStatusCodesToTheCallSite covers the codes
// deliberately left unmapped. Each must reach CKR_GENERAL_ERROR from FromError
// so backendCKRV falls back to the code the call site chose, which knows which
// operation was in flight.
func TestFromError_LeavesUntranslatableStatusCodesToTheCallSite(t *testing.T) {
	tests := []struct {
		code   codes.Code
		reason string
	}{
		{codes.NotFound, "a missing backend, key and role are all NotFound but map to different CK_RVs"},
		{codes.PermissionDenied, "Cryptoki has no authorized-but-forbidden code"},
		{codes.Internal, "means something broke, which is what the fallback already says"},
		{codes.DeadlineExceeded, "the operation may still be running on the token"},
		{codes.ResourceExhausted, "usually a gRPC message limit, not a token resource limit"},
		{codes.Unknown, "unclassified"},
	}

	for _, tc := range tests {
		t.Run(tc.code.String(), func(t *testing.T) {
			err := status.Error(tc.code, tc.reason)
			if got := FromError(err); got != CKR_GENERAL_ERROR {
				t.Errorf("FromError(%s) = %s, want CKR_GENERAL_ERROR so the call site's fallback applies", tc.code, got.String())
			}
			if got := backendCKRV(err, CKR_KEY_HANDLE_INVALID); got != CKR_KEY_HANDLE_INVALID {
				t.Errorf("backendCKRV(%s) = %s, want the call site's fallback", tc.code, got.String())
			}
		})
	}
}

// TestFromError_StatusTranslationDoesNotOutrankExplicitCodes covers the
// precedence a translated status must not take. A PKCS11Error carries a code
// the module already determined, and a module sentinel maps to a specific
// CK_RV; a gRPC status arriving alongside either must not overwrite it.
func TestFromError_StatusTranslationDoesNotOutrankExplicitCodes(t *testing.T) {
	t.Run("PKCS11Error wins", func(t *testing.T) {
		err := NewPKCS11ErrorFull(CKR_KEY_HANDLE_INVALID, "key derivation failed",
			status.Error(codes.Unimplemented, "backend cannot derive"))
		if got := FromError(err); got != CKR_KEY_HANDLE_INVALID {
			t.Errorf("FromError() = %s, want CKR_KEY_HANDLE_INVALID", got.String())
		}
	})

	t.Run("module sentinel wins", func(t *testing.T) {
		err := errors.Join(ErrUserNotLoggedIn, status.Error(codes.Unimplemented, "backend cannot derive"))
		if got := FromError(err); got != CKR_USER_NOT_LOGGED_IN {
			t.Errorf("FromError() = %s, want CKR_USER_NOT_LOGGED_IN", got.String())
		}
	})
}

// TestFromError_LegacyKeyWrapRefusalIsNotAModuleFault pins the CK_RV an
// application sees when it asks C_WrapKey or C_UnwrapKey for one of the
// unauthenticated constructions the deployment has switched off —
// CKM_RSA_PKCS, CKM_AES_CBC_PAD or unpadded CKM_AES_CBC without
// crypto.allow_legacy_key_wrap.
//
// The status below is the one the daemon actually sends. The refusal is
// pkg/xkms's ErrLegacyWrapDisabled wrapped in an *xkms.ErrValidation
// (resolveWrapMechanism), and pkg/api/grpc/errors_keyops.go's mapKeyOpError
// tests errors.As for *xkms.ErrValidation before it consults its sentinel
// table, so the whole gate arrives as codes.InvalidArgument with the gate's
// own message and no surviving sentinel identity.
//
// The property that matters is the second assertion: the refusal must not read
// as CKR_GENERAL_ERROR or CKR_FUNCTION_FAILED, which are what the module says
// when it has broken or has no idea. An application that gets those goes
// looking for a fault; this one is answered by a configuration setting.
//
// CKR_MECHANISM_INVALID would be the more precise answer and is deliberately
// not given here — see grpcStatusCKR for why it cannot be told apart from the
// other InvalidArgument conditions until the daemon sends a distinguishing
// detail. If it ever does, this test is where the sharper code lands.
func TestFromError_LegacyKeyWrapRefusalIsNotAModuleFault(t *testing.T) {
	const gateMessage = "AES_CBC_PAD is refused for wrap: the construction authenticates nothing. " +
		"Set crypto.allow_legacy_key_wrap=true to enable it"

	refusal := status.Error(codes.InvalidArgument, gateMessage)

	if got := FromError(refusal); got != CKR_ARGUMENTS_BAD {
		t.Errorf("FromError(legacy wrap refusal) = %s, want CKR_ARGUMENTS_BAD", got.String())
	}

	// C_WrapKey's call site passes CKR_FUNCTION_FAILED as its fallback, so this
	// is the exact value the application receives.
	got := backendCKRV(refusal, CKR_FUNCTION_FAILED)
	if got != CKR_ARGUMENTS_BAD {
		t.Errorf("backendCKRV(legacy wrap refusal) = %s, want CKR_ARGUMENTS_BAD", got.String())
	}
	if got == CKR_GENERAL_ERROR || got == CKR_FUNCTION_FAILED {
		t.Errorf("a mechanism refused by policy reported %s, which an application reads as a module fault", got.String())
	}
}

// TestFromError_IgnoresNonStatusErrors covers the bad-input path: an ordinary
// error carries no status, and inventing one would report a capability
// boundary that the service never asserted.
func TestFromError_IgnoresNonStatusErrors(t *testing.T) {
	if got := FromError(errors.New("a plain error")); got != CKR_GENERAL_ERROR {
		t.Errorf("FromError(plain) = %s, want CKR_GENERAL_ERROR", got.String())
	}
	if got := FromError(status.Error(codes.Aborted, "an untranslated code")); got != CKR_GENERAL_ERROR {
		t.Errorf("FromError(codes.Aborted) = %s, want CKR_GENERAL_ERROR", got.String())
	}
	if rv, ok := grpcCKR(errors.New("a plain error")); ok || rv != CKR_GENERAL_ERROR {
		t.Errorf("grpcCKR(plain) = (%s, %v), want (CKR_GENERAL_ERROR, false)", rv.String(), ok)
	}
}
