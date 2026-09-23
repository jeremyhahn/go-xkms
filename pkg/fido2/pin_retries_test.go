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
	"errors"
	"strings"
	"testing"
)

// newPINRetriesAuthenticator builds an Authenticator over a mock device whose
// simulator enforces pin, which is what makes the retry counter real: a wrong
// PIN costs an attempt exactly as it does on a security key.
func newPINRetriesAuthenticator(t *testing.T, pin string) (*Authenticator, *authenticatorSim) {
	t.Helper()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.sim.pin = pin

	config := DefaultConfig
	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	if err != nil {
		t.Fatalf("NewCTAPHIDDevice: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := ctapDev.Close(); closeErr != nil {
			t.Errorf("close CTAP device: %v", closeErr)
		}
	})

	auth, err := NewAuthenticator(ctapDev, &config)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return auth, mockDev.sim
}

// TestPINRetriesReportsTheAuthenticatorCounter proves the getPINRetries
// subcommand is issued and its answer decoded.
func TestPINRetriesReportsTheAuthenticatorCounter(t *testing.T) {
	auth, sim := newPINRetriesAuthenticator(t, "123456")
	sim.pinRetries = 5
	sim.pinRetriesSet = true

	retries, err := auth.PINRetries()
	if err != nil {
		t.Fatalf("PINRetries: %v", err)
	}
	if retries != 5 {
		t.Fatalf("retries: got %d want 5", retries)
	}
}

func TestPINRetriesErrors(t *testing.T) {
	t.Run("an authenticator that refuses the subcommand is reported", func(t *testing.T) {
		auth, sim := newPINRetriesAuthenticator(t, "123456")
		sim.failPINRetries = true

		retries, err := auth.PINRetries()
		if err == nil {
			t.Fatal("expected an error from a refused getPINRetries")
		}
		if retries != 0 {
			t.Fatalf("retries on failure: got %d want 0", retries)
		}
		if !errors.Is(err, ErrPINRetriesUnavailable) {
			t.Fatalf("want ErrPINRetriesUnavailable, got %v", err)
		}
	})

	t.Run("an authenticator that answers nothing at all is reported", func(t *testing.T) {
		auth, sim := newPINRetriesAuthenticator(t, "123456")
		sim.failClientPIN = true

		if _, err := auth.PINRetries(); !errors.Is(err, ErrPINRetriesUnavailable) {
			t.Fatalf("want ErrPINRetriesUnavailable, got %v", err)
		}
	})
}

// TestAuthorizeWithPINSurfacesRemainingAttempts is the reason the counter
// exists: a mistyped PIN must say how close the key is to a lockout, because a
// lockout discovered by hitting it needs a reset.
func TestAuthorizeWithPINSurfacesRemainingAttempts(t *testing.T) {
	auth, sim := newPINRetriesAuthenticator(t, "123456")
	sim.pinRetries = 3
	sim.pinRetriesSet = true

	_, _, err := auth.AuthorizeWithPIN(testSecret(t, "999999"), []byte("client-data-hash"))
	if err == nil {
		t.Fatal("a wrong PIN must not authorize the request")
	}

	// The classification must survive the annotation: callers switch on it.
	if !errors.Is(err, ErrInvalidPIN) {
		t.Fatalf("want ErrInvalidPIN, got %v", err)
	}

	var attempts *PINAttemptsError
	if !errors.As(err, &attempts) {
		t.Fatalf("want a PINAttemptsError, got %T: %v", err, err)
	}
	if attempts.Retries != 2 {
		t.Fatalf("remaining attempts: got %d want 2 (3 minus the one just consumed)", attempts.Retries)
	}
	if !strings.Contains(err.Error(), "2 attempts remaining") {
		t.Fatalf("the message must name the remaining attempts, got %q", err.Error())
	}
}

func TestAuthorizeWithPINAnnotationErrors(t *testing.T) {
	t.Run("a counter the authenticator will not report leaves the failure intact", func(t *testing.T) {
		auth, sim := newPINRetriesAuthenticator(t, "123456")
		sim.failPINRetries = true

		_, _, err := auth.AuthorizeWithPIN(testSecret(t, "999999"), []byte("client-data-hash"))
		if !errors.Is(err, ErrInvalidPIN) {
			t.Fatalf("want ErrInvalidPIN, got %v", err)
		}

		// An unavailable counter must never displace the failure the caller
		// needs to see, nor be reported as if it were one.
		var attempts *PINAttemptsError
		if errors.As(err, &attempts) {
			t.Fatal("an unavailable counter must not produce a PINAttemptsError")
		}
		if errors.Is(err, ErrPINRetriesUnavailable) {
			t.Fatalf("the retry query's own failure must not mask the PIN failure: %v", err)
		}
	})

	t.Run("a non-PIN failure is not annotated", func(t *testing.T) {
		// A key with no PIN set answers getPINToken with CTAP2_ERR_PIN_NOT_SET,
		// which carries no attempt count to report.
		auth, _ := newPINRetriesAuthenticator(t, "")

		_, _, err := auth.AuthorizeWithPIN(testSecret(t, "123456"), []byte("client-data-hash"))
		if !errors.Is(err, ErrPINNotSet) {
			t.Fatalf("want ErrPINNotSet, got %v", err)
		}

		var attempts *PINAttemptsError
		if errors.As(err, &attempts) {
			t.Fatal("a key with no PIN set has no attempt count to annotate")
		}
	})

	t.Run("an exhausted counter blocks the key rather than reporting success", func(t *testing.T) {
		auth, sim := newPINRetriesAuthenticator(t, "123456")
		sim.pinRetries = 1
		sim.pinRetriesSet = true

		_, _, err := auth.AuthorizeWithPIN(testSecret(t, "999999"), []byte("client-data-hash"))
		if !errors.Is(err, ErrPINBlocked) {
			t.Fatalf("want ErrPINBlocked once the last attempt is spent, got %v", err)
		}
	})
}

// TestPINAttemptsErrorMessage covers the rendering and the unwrap contract
// directly, including the blocked case where zero attempts remain.
func TestPINAttemptsErrorMessage(t *testing.T) {
	err := &PINAttemptsError{Err: ErrInvalidPIN, Retries: 0}

	if !strings.Contains(err.Error(), ErrInvalidPIN.Error()) {
		t.Errorf("the message must carry the underlying failure, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "0 attempts remaining") {
		t.Errorf("the message must name the remaining attempts, got %q", err.Error())
	}
	if !errors.Is(err, ErrInvalidPIN) {
		t.Error("errors.Is must still match the underlying failure")
	}
}
