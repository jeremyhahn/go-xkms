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

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/spf13/cobra"
)

// This file holds the ONE way a CTAP2 authenticator PIN enters the xkmsctl
// WebAuthn verbs — "user register", "user login", "admin create". It is the
// xkmsctl twin of xkey/cmd/xkey/cmd/pin_input.go (go-xkms#299): the two
// binaries cannot share the package (the resolver lives inside the xkey
// binary's command package, and moving it would change xkey, which go-xkms#309
// scopes out), so the flag names and the precedence order are re-stated here
// VERBATIM. A divergent second precedence order is the failure mode to avoid:
// an operator who learns `printf '%s' "$PIN" | xkey auth login --pin-stdin`
// must be able to drive xkmsctl the same way.
//
// The one deliberate difference is the environment variable name: xkey reads
// XKEY_PIN, and xkmsctl's environment namespace is XKMS_*. A bare XKMS_PIN
// would sit beside XKMS_SO_PIN and XKMS_USER_PIN — the PKCS#11 token PINs the
// init ceremony reads — and an operator exporting it for the wrong subsystem
// would authorize nothing while looking configured, so the variable names the
// authenticator: XKMS_FIDO2_PIN.

// pinFlagStdin, pinFlagValue and pinEnvVar name the three PIN sources. They
// are constants so the flag declaration, the resolver, and the error text
// cannot drift apart.
const (
	pinFlagStdin = "pin-stdin"
	pinFlagValue = "pin"
	pinEnvVar    = "XKMS_FIDO2_PIN"
)

// pinUsage is the operator-facing description of the three PIN sources,
// embedded verbatim in the long help of every WebAuthn verb that accepts one.
const pinUsage = `The authenticator PIN may be supplied three ways, in precedence order:

  --pin-stdin      read the PIN from standard input (preferred: it keeps the
                   PIN out of the process list and the shell history)
  XKMS_FIDO2_PIN   environment variable
  --pin            flag value (visible in 'ps'; use for local development only)`

// addPINFlags declares the PIN input flags resolvePINInput reads. Every
// WebAuthn verb that takes a PIN uses it, so the flag names and their help
// text are identical everywhere.
func addPINFlags(cmd *cobra.Command) {
	cmd.Flags().String(pinFlagValue, "", "authenticator PIN (visible in the process list; prefer --pin-stdin)")
	cmd.Flags().Bool(pinFlagStdin, false, "read the authenticator PIN from standard input")
}

// resolvePINInput returns the PIN from the highest-precedence source the
// command was given: standard input (--pin-stdin), then XKMS_FIDO2_PIN, then
// --pin, sealed into protected memory. Reading from stdin is preferred
// because a PIN passed as a flag is visible to every process on the host via
// /proc.
//
// A nil return value means no source supplied a PIN. That is a legitimate
// state — an authenticator with no PIN configured needs none — so the
// ceremony rejects a missing PIN itself (see ceremonyFailure) rather than
// having this resolver decide for it.
func resolvePINInput(ctx context.Context, cmd *cobra.Command) (*secure.Secret, error) {
	fromStdin, err := cmd.Flags().GetBool(pinFlagStdin)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrPINInputFlagsMissing, Err: err}
	}
	if fromStdin {
		data, readErr := io.ReadAll(secretStdin)
		if readErr != nil {
			return nil, &WrappedError{Sentinel: ErrPINInputStdinRead, Err: readErr}
		}
		pin := strings.TrimRight(string(data), "\r\n")
		if pin == "" {
			return nil, ErrPINInputStdinEmpty
		}
		return sealPIN(ctx, pin)
	}

	if pin := os.Getenv(pinEnvVar); pin != "" {
		return sealPIN(ctx, pin)
	}

	pin, err := cmd.Flags().GetString(pinFlagValue)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrPINInputFlagsMissing, Err: err}
	}
	if pin == "" {
		return nil, nil
	}
	return sealPIN(ctx, pin)
}

// sealPIN seals a resolved PIN value into protected memory for
// resolvePINInput. It exists as a single chokepoint so the plaintext PIN
// string, however it was resolved, is copied into a *secure.Secret and
// never held in a struct afterward.
func sealPIN(ctx context.Context, pin string) (*secure.Secret, error) {
	secret, err := secure.NewSecret(ctx, []byte(pin))
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrPINInputSealFailed, Err: err}
	}
	return secret, nil
}

// ceremonyFailure classifies an authenticator failure before it reaches the
// operator. An authenticator that answers CTAP2_ERR_PIN_REQUIRED when no PIN
// was supplied is reporting missing INPUT, so it is named as such and the
// sources that supply it are printed; the raw CTAP error is kept as the cause
// so nothing is lost.
//
// The same status when a PIN WAS supplied is not a missing-input problem — it
// means the authenticator rejected an authorization that was attempted — and
// is reported verbatim rather than sending the operator to re-enter a PIN they
// already gave. A wrong PIN keeps its fido2.PINAttemptsError annotation for the
// same reason: a lockout must never read as anything else.
func ceremonyFailure(sentinel error, pin *secure.Secret, cause error) error {
	if pin == nil && errors.Is(cause, fido2.ErrPINRequired) {
		return &WrappedError{Sentinel: ErrWebAuthnPINRequired, Err: cause}
	}
	return &WrappedError{Sentinel: sentinel, Err: cause}
}
