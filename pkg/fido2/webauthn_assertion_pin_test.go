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

package fido2

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

// These tests cover the assertion half of CTAP2 PIN support. The registration
// half is covered by TestRegisterWebAuthnWithPIN and TestRegisterWebAuthnPINErrors
// in webauthn_attestation_test.go, and the two share one simulator: a mock
// authenticator with a PIN set refuses an unauthorized request on either
// ceremony, so "the PIN reached the wire" is proved rather than assumed.

// pinAssertionOptions is a minimal login ceremony for a PIN-protected
// authenticator.
func pinAssertionOptions(t *testing.T, pin string) WebAuthnAuthenticationOptions {
	t.Helper()

	return WebAuthnAuthenticationOptions{
		Challenge: []byte("authentication-challenge"),
		Origin:    "https://xkms.example.com",
		RPID:      "xkms.example.com",
		// A PIN-protected key has no built-in user verification method, so
		// this must NOT reach the wire as the "uv" option once a PIN is
		// supplied — the simulator rejects that combination outright.
		RequireUserVerification: true,
		PIN:                     testSecret(t, pin),
	}
}

// TestAuthenticateWebAuthnWithPIN is the load-bearing proof for the gap this
// change closes: a login ceremony completes against a PIN-protected
// authenticator, and the assertion it yields is one the relying party's own
// parser accepts.
func TestAuthenticateWebAuthnWithPIN(t *testing.T) {
	handler := newPINProtectedHandler(t, "123456")

	assertion, err := handler.AuthenticateWebAuthn(pinAssertionOptions(t, "123456"))
	if err != nil {
		t.Fatalf("AuthenticateWebAuthn with PIN: %v", err)
	}
	if len(assertion.CredentialID) == 0 {
		t.Fatal("assertion carries no credential id")
	}

	// The assertion must survive the same parser FinishAuthentication uses.
	if _, err := protocol.ParseCredentialRequestResponseBody(
		bytes.NewReader(assertion.PublicKeyCredentialJSON),
	); err != nil {
		t.Fatalf("server-side parse of the assertion: %v", err)
	}
}

func TestAuthenticateWebAuthnPINErrors(t *testing.T) {
	t.Run("PIN-protected key refuses an unauthorized request", func(t *testing.T) {
		handler := newPINProtectedHandler(t, "123456")

		// No PIN supplied: this is the failure "xkey auth login" hit before
		// the PIN was threaded through, and it must stay legible. The "uv"
		// option is off here so the refusal is unambiguously about the missing
		// pinUvAuthParam rather than about asking a PIN-only key for built-in
		// user verification.
		opts := pinAssertionOptions(t, "")
		opts.RequireUserVerification = false

		assertion, err := handler.AuthenticateWebAuthn(opts)
		if assertion != nil {
			t.Fatal("an unauthorized request must not yield an assertion")
		}
		if !errors.Is(err, ErrPINRequired) {
			t.Fatalf("want ErrPINRequired, got %v", err)
		}
	})

	t.Run("wrong PIN is not reported as a refusal", func(t *testing.T) {
		handler := newPINProtectedHandler(t, "123456")

		assertion, err := handler.AuthenticateWebAuthn(pinAssertionOptions(t, "999999"))
		if assertion != nil {
			t.Fatal("a wrong PIN must not yield an assertion")
		}
		if !errors.Is(err, ErrInvalidPIN) {
			t.Fatalf("want ErrInvalidPIN, got %v", err)
		}
	})

	t.Run("a key with no PIN reports a supplied one as pointless", func(t *testing.T) {
		handler := newPINProtectedHandler(t, "")

		// GetPINToken against a key with no PIN set is an error rather than a
		// silent success, so the operator learns the PIN was pointless instead
		// of believing user verification happened.
		assertion, err := handler.AuthenticateWebAuthn(pinAssertionOptions(t, "123456"))
		if assertion != nil {
			t.Fatal("expected no assertion")
		}
		if !errors.Is(err, ErrPINNotSet) {
			t.Fatalf("want ErrPINNotSet, got %v", err)
		}
	})

	t.Run("a key with no PIN still asserts with no PIN", func(t *testing.T) {
		// The no-PIN path must not regress: an authenticator without a PIN
		// configured completes the ceremony with an empty PIN exactly as it
		// did before PIN support existed.
		handler := newPINProtectedHandler(t, "")

		assertion, err := handler.AuthenticateWebAuthn(pinAssertionOptions(t, ""))
		if err != nil {
			t.Fatalf("AuthenticateWebAuthn without PIN: %v", err)
		}
		if len(assertion.PublicKeyCredentialJSON) == 0 {
			t.Fatal("assertion carries no credential document")
		}
	})
}

// TestAssert_CarriesPINToAPINProtectedAuthenticator proves the JSON-driven
// entry point — the one "xkey auth login" calls — passes the PIN through to
// the authenticator. Without it the ceremony fails with CTAP2_ERR_PIN_REQUIRED.
func TestAssert_CarriesPINToAPINProtectedAuthenticator(t *testing.T) {
	handler := newPINProtectedHandler(t, "123456")

	challenge := []byte("server-issued-challenge-value-32")
	optionsJSON := buildRequestOptionsJSON(t, challenge, "xkms.example.com", nil, protocol.VerificationRequired)

	assertionJSON, err := handler.Assert(context.Background(), WebAuthnAssertionRequest{
		OptionsJSON: optionsJSON,
		Origin:      "https://xkms.example.com",
		PIN:         testSecret(t, "123456"),
	})
	if err != nil {
		t.Fatalf("Assert with PIN: %v", err)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertionJSON))
	if err != nil {
		t.Fatalf("ParseCredentialRequestResponseBody rejected assertion: %v", err)
	}
	if parsed.Response.CollectedClientData.Origin != "https://xkms.example.com" {
		t.Errorf("clientData origin: got %q want https://xkms.example.com",
			parsed.Response.CollectedClientData.Origin)
	}
}

func TestAssertPINErrors(t *testing.T) {
	optionsJSON := buildRequestOptionsJSON(t,
		[]byte("server-issued-challenge-value-32"), "xkms.example.com", nil, protocol.VerificationPreferred)

	t.Run("no PIN against a PIN-protected key surfaces ErrPINRequired", func(t *testing.T) {
		handler := newPINProtectedHandler(t, "123456")

		assertionJSON, err := handler.Assert(context.Background(), WebAuthnAssertionRequest{
			OptionsJSON: optionsJSON,
			Origin:      "https://xkms.example.com",
		})
		if assertionJSON != nil {
			t.Fatal("an unauthorized request must not yield an assertion")
		}
		if !errors.Is(err, ErrPINRequired) {
			t.Fatalf("want ErrPINRequired, got %v", err)
		}
	})

	t.Run("wrong PIN surfaces ErrInvalidPIN", func(t *testing.T) {
		handler := newPINProtectedHandler(t, "123456")

		assertionJSON, err := handler.Assert(context.Background(), WebAuthnAssertionRequest{
			OptionsJSON: optionsJSON,
			Origin:      "https://xkms.example.com",
			PIN:         testSecret(t, "999999"),
		})
		if assertionJSON != nil {
			t.Fatal("a wrong PIN must not yield an assertion")
		}
		if !errors.Is(err, ErrInvalidPIN) {
			t.Fatalf("want ErrInvalidPIN, got %v", err)
		}
	})

	t.Run("empty options are rejected before the device is touched", func(t *testing.T) {
		handler := newPINProtectedHandler(t, "123456")

		if _, err := handler.Assert(context.Background(), WebAuthnAssertionRequest{PIN: testSecret(t, "123456")}); !errors.Is(err, ErrAssertionOptionsRequired) {
			t.Fatalf("want ErrAssertionOptionsRequired, got %v", err)
		}
	})

	t.Run("a cancelled context is honored before the PIN is used", func(t *testing.T) {
		handler := newPINProtectedHandler(t, "123456")

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if _, err := handler.Assert(ctx, WebAuthnAssertionRequest{
			OptionsJSON: optionsJSON,
			PIN:         testSecret(t, "123456"),
		}); !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	})
}

// TestAssertShorthandsDelegate proves the two PIN-less shorthands still reach
// the same code path — the property that keeps them from drifting into a second
// assertion implementation.
func TestAssertShorthandsDelegate(t *testing.T) {
	optionsJSON := buildRequestOptionsJSON(t,
		[]byte("server-issued-challenge-value-32"), "xkms.example.com", nil, protocol.VerificationPreferred)

	t.Run("AssertWithOptions on a PIN-protected key reports the missing PIN", func(t *testing.T) {
		handler := newPINProtectedHandler(t, "123456")

		if _, err := handler.AssertWithOptions(context.Background(), optionsJSON); !errors.Is(err, ErrPINRequired) {
			t.Fatalf("want ErrPINRequired, got %v", err)
		}
	})

	t.Run("AssertWithOptionsAndOrigin binds the explicit origin", func(t *testing.T) {
		handler := newPINProtectedHandler(t, "")

		assertionJSON, err := handler.AssertWithOptionsAndOrigin(
			context.Background(), optionsJSON, "https://portal.example.com")
		if err != nil {
			t.Fatalf("AssertWithOptionsAndOrigin: %v", err)
		}

		parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertionJSON))
		if err != nil {
			t.Fatalf("ParseCredentialRequestResponseBody: %v", err)
		}
		if parsed.Response.CollectedClientData.Origin != "https://portal.example.com" {
			t.Errorf("clientData origin: got %q want https://portal.example.com",
				parsed.Response.CollectedClientData.Origin)
		}
	})
}
