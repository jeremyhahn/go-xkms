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

package xkms

import (
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	sshscope "github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	webauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
)

// sameType fails t unless A and B are the same type.
func sameType[A, B any](t *testing.T) {
	t.Helper()
	if reflect.TypeFor[A]() != reflect.TypeFor[B]() {
		t.Errorf("%v is not %v", reflect.TypeFor[A](), reflect.TypeFor[B]())
	}
}

// sameFunc reports whether two function values are the same function.
func sameFunc(t *testing.T, name string, got, want any) {
	t.Helper()
	if reflect.ValueOf(got).Pointer() != reflect.ValueOf(want).Pointer() {
		t.Errorf("%s is not the internal function", name)
	}
}

// TestConsumerExports_WebAuthn asserts the webauthn and webauthn/http
// symbols go-quicbaas consumes are aliases of the internal ones.
func TestConsumerExports_WebAuthn(t *testing.T) {
	sameType[WebAuthnUserStore, webauthn.UserStore](t)
	sameType[WebAuthnAuthResponse, webauthnhttp.AuthResponse](t)
	sameType[WebAuthnBeginLoginRequest, webauthnhttp.BeginLoginRequest](t)
	sameType[WebAuthnErrorResponse, webauthnhttp.ErrorResponse](t)
	sameType[WebAuthnMuxRouter, webauthnhttp.MuxRouter](t)
	sameType[WebAuthnMuxRoute, webauthnhttp.MuxRoute](t)
	sameType[WebAuthnRouteEntry, webauthnhttp.RouteEntry](t)

	if ErrWebAuthnCredentialNotFound != webauthn.ErrCredentialNotFound {
		t.Error("ErrWebAuthnCredentialNotFound is not webauthn.ErrCredentialNotFound")
	}
	sameFunc(t, "IsWebAuthnUserNotFound", IsWebAuthnUserNotFound, webauthn.IsUserNotFound)
	sameFunc(t, "IsWebAuthnCredentialNotFound", IsWebAuthnCredentialNotFound, webauthn.IsCredentialNotFound)
	sameFunc(t, "WebAuthnUserIDFromHandle", WebAuthnUserIDFromHandle, webauthn.UserIDFromHandle)
	sameFunc(t, "WebAuthnMountChi", WebAuthnMountChi, webauthnhttp.MountChi)
	sameFunc(t, "WebAuthnMountMux", WebAuthnMountMux, webauthnhttp.MountMux)
	sameFunc(t, "WebAuthnMountStdlib", WebAuthnMountStdlib, webauthnhttp.MountStdlib)

	consts := map[string][2]string{
		"HeaderSessionID":        {WebAuthnHeaderSessionID, webauthnhttp.HeaderSessionID},
		"InvalidRequest":         {WebAuthnErrorCodeInvalidRequest, webauthnhttp.ErrorCodeInvalidRequest},
		"InvalidSession":         {WebAuthnErrorCodeInvalidSession, webauthnhttp.ErrorCodeInvalidSession},
		"SessionExpired":         {WebAuthnErrorCodeSessionExpired, webauthnhttp.ErrorCodeSessionExpired},
		"UserNotFound":           {WebAuthnErrorCodeUserNotFound, webauthnhttp.ErrorCodeUserNotFound},
		"NoCredentials":          {WebAuthnErrorCodeNoCredentials, webauthnhttp.ErrorCodeNoCredentials},
		"VerificationFailed":     {WebAuthnErrorCodeVerificationFailed, webauthnhttp.ErrorCodeVerificationFailed},
		"RegistrationRefused":    {WebAuthnErrorCodeRegistrationRefused, webauthnhttp.ErrorCodeRegistrationRefused},
		"SessionLimit":           {WebAuthnErrorCodeSessionLimit, webauthnhttp.ErrorCodeSessionLimit},
		"InternalError":          {WebAuthnErrorCodeInternalError, webauthnhttp.ErrorCodeInternalError},
		"Unauthenticated":        {WebAuthnErrorCodeUnauthenticated, webauthnhttp.ErrorCodeUnauthenticated},
		"SessionAccountMismatch": {WebAuthnErrorCodeSessionAccountMismatch, webauthnhttp.ErrorCodeSessionAccountMismatch},
		"CredentialExists":       {WebAuthnErrorCodeCredentialExists, webauthnhttp.ErrorCodeCredentialExists},
	}
	for name, pair := range consts {
		if pair[0] != pair[1] {
			t.Errorf("WebAuthn %s = %q, want %q", name, pair[0], pair[1])
		}
	}
}

// TestConsumerExports_KeyVersion asserts the keyversion symbols
// go-quicbaas consumes are aliases of the internal ones.
func TestConsumerExports_KeyVersion(t *testing.T) {
	sameType[KeyVersionInvalidRecordKeyError, keyversion.InvalidRecordKeyError](t)
	sameType[KeyVersionInvalidVersionError, keyversion.InvalidVersionError](t)

	if ErrKeyVersionNilRecord != keyversion.ErrNilRecord {
		t.Error("ErrKeyVersionNilRecord is not keyversion.ErrNilRecord")
	}
	sameFunc(t, "KeyVersionBaseKeyID", KeyVersionBaseKeyID, keyversion.BaseKeyID)
	sameFunc(t, "KeyVersionCheckKeyID", KeyVersionCheckKeyID, keyversion.CheckKeyID)
	sameFunc(t, "KeyVersionImplicit", KeyVersionImplicit, keyversion.Implicit)
	sameFunc(t, "KeyVersionIsReserved", KeyVersionIsReserved, keyversion.IsReserved)
	sameFunc(t, "KeyVersionTenantSegment", KeyVersionTenantSegment, keyversion.TenantSegment)
}

// TestConsumerExports_SSHScope asserts the ssh/scope symbols go-quicbaas
// consumes are aliases of the internal ones.
func TestConsumerExports_SSHScope(t *testing.T) {
	sameType[SSHKeyIDMalformedError, sshscope.KeyIDMalformedError](t)
	sameType[SSHKindInvalidError, sshscope.KindInvalidError](t)
	sameType[SSHScopeInvalidError, sshscope.ScopeInvalidError](t)
	sameType[SSHKind, sshscope.Kind](t)

	if SSHKindKeys != sshscope.KindKeys ||
		SSHKindKnownHosts != sshscope.KindKnownHosts ||
		SSHKindAuthorizedKeys != sshscope.KindAuthorizedKeys {
		t.Error("SSHKind constants differ from ssh/scope")
	}
	sameFunc(t, "SSHBuildKeyID", SSHBuildKeyID, sshscope.BuildKeyID)
	sameFunc(t, "SSHValidateFilter", SSHValidateFilter, sshscope.ValidateFilter)
}

// TestConsumerExports_TPM2 asserts the tpm2 PCR and quote symbols
// go-quicbaas consumes stay aliases of the internal ones.
func TestConsumerExports_TPM2(t *testing.T) {
	sameType[PCRBank, tpm2.PCRBank](t)
	sameType[Quote, tpm2.Quote](t)
	sameFunc(t, "ParsePCRBankAlgID", ParsePCRBankAlgID, tpm2.ParsePCRBankAlgID)
	sameFunc(t, "ParsePCRBankCryptoHash", ParsePCRBankCryptoHash, tpm2.ParsePCRBankCryptoHash)
	sameFunc(t, "PCRDigestSize", PCRDigestSize, tpm2.PCRDigestSize)
}
