// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package phone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/stretchr/testify/require"
)

var errVerifierRefused = errors.New("verifier refused the answer")

// connectedVerifyUserBackend is a backend connected over an established
// Noise session whose phone answers every request with {"ok": true}.
func connectedVerifyUserBackend(t *testing.T, verify pairingproto.VerifyUserFunc) *PhoneKeyBackend {
	t.Helper()
	client, server := establishedNoiseSessionPair(t)
	backend := &PhoneKeyBackend{
		cfg:     &PhoneKeyBackendConfig{VerifyUser: verify},
		session: client,
		transport: &scriptedTransport{respond: func(_ context.Context, sent []byte) ([]byte, error) {
			plaintext, err := server.Decrypt(sent)
			if err != nil {
				return nil, err
			}
			req, err := pairingproto.DecodeRequest(plaintext)
			if err != nil {
				return nil, err
			}
			resultJSON, err := json.Marshal(map[string]bool{"ok": true})
			if err != nil {
				return nil, err
			}
			respBytes, err := pairingproto.EncodeResponse(req.ID, req.Generation, json.RawMessage(resultJSON))
			if err != nil {
				return nil, err
			}
			return server.Encrypt(respBytes)
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	backend.connected.Store(true)
	return backend
}

// TestVerifyUser_RoundTripsOverTheSessionWithItsBinding proves the verifier
// is handed the live session's channel binding and an exchange that reaches
// the phone through it.
func TestVerifyUser_RoundTripsOverTheSessionWithItsBinding(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	var gotBinding []byte
	var gotRPName string
	var gotResp *pairingproto.Response
	backend := connectedVerifyUserBackend(t, func(ctx context.Context, exchange pairingproto.RPCExchange, binding []byte, rpName string) error {
		gotBinding = binding
		gotRPName = rpName
		resp, err := exchange(ctx, pairingproto.NewRequest(pairingproto.MethodLocalVerifyUser, nil))
		gotResp = resp
		return err
	})

	require.NoError(t, backend.VerifyUser(context.Background(), "example.com"))

	want, err := pairingproto.AttestChannelBinding(backend.session)
	require.NoError(t, err)
	require.Equal(t, want, gotBinding)
	require.Equal(t, "example.com", gotRPName, "the RP the token is for is sent as asked")
	require.NotNil(t, gotResp)
	require.Nil(t, gotResp.Error)
}

// TestVerifyUser_NoRPNamesTheAuthenticator proves a token with no RP scope
// is asked for on behalf of the authenticator, never with an empty RP name
// the verifier would refuse.
func TestVerifyUser_NoRPNamesTheAuthenticator(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	var gotRPName string
	backend := connectedVerifyUserBackend(t, func(_ context.Context, _ pairingproto.RPCExchange, _ []byte, rpName string) error {
		gotRPName = rpName
		return nil
	})

	require.NoError(t, backend.VerifyUser(context.Background(), ""))
	require.Equal(t, VerifyUserAuthenticatorName, gotRPName)
}

// TestVerifyUser_VerifierRefusalIsReturned proves a refused answer is never
// reported as a verified user.
func TestVerifyUser_VerifierRefusalIsReturned(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	backend := connectedVerifyUserBackend(t, func(context.Context, pairingproto.RPCExchange, []byte, string) error {
		return errVerifierRefused
	})

	err := backend.VerifyUser(context.Background(), "example.com")
	require.ErrorIs(t, err, errVerifierRefused)
	require.NotErrorIs(t, err, keybackend.ErrUserVerificationUnavailable, "a refusal is a failed verification")
}

// TestVerifyUser_PhoneRefusalIsTyped guards #1712: each refusal the phone
// answers local.verifyUser with reaches the caller as its own typed error.
func TestVerifyUser_PhoneRefusalIsTyped(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	refusals := []struct {
		name string
		code int
		want error
	}{
		{"user cancelled", pairingproto.ErrorCodeUserCancelled, ErrUserCancelled},
		{"no biometric enrolled", pairingproto.ErrorCodeVerifyUserNotEnrolled, ErrUserVerificationNotEnrolled},
		{"lockout", pairingproto.ErrorCodeVerifyUserLockout, ErrUserVerificationLockout},
		{"not paired", pairingproto.ErrorCodeNotPaired, ErrNotPaired},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			backend := refusingPhone(t, func(ctx context.Context, exchange pairingproto.RPCExchange, _ []byte, _ string) error {
				resp, err := exchange(ctx, pairingproto.NewRequest(pairingproto.MethodLocalVerifyUser, nil))
				if err != nil {
					return err
				}
				// As attestation.NewUserVerifier reports a phone's RPC error.
				return fmt.Errorf("%w: %w", errVerifierRefused, resp.Error)
			}, tt.code)

			err := backend.VerifyUser(context.Background(), "example.com")
			require.ErrorIs(t, err, tt.want)
			require.ErrorIs(t, err, errVerifierRefused, "the verifier's own error is kept")
		})
	}
}

// TestVerifyUser_CancelledPromptIsCancelled pins that a prompt the user
// dismissed on the phone (-32001) reaches the authenticator as
// keybackend.ErrUserVerificationCancelled, on which it spends no uvRetries,
// and still as the phone's typed refusal.
func TestVerifyUser_CancelledPromptIsCancelled(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	backend := refusingPhone(t, func(ctx context.Context, exchange pairingproto.RPCExchange, _ []byte, _ string) error {
		resp, err := exchange(ctx, pairingproto.NewRequest(pairingproto.MethodLocalVerifyUser, nil))
		if err != nil {
			return err
		}
		// As attestation.NewUserVerifier reports a phone's RPC error.
		return fmt.Errorf("%w: %w", errVerifierRefused, resp.Error)
	}, pairingproto.ErrorCodeUserCancelled)

	for range 3 {
		err := backend.VerifyUser(context.Background(), "example.com")
		require.ErrorIs(t, err, keybackend.ErrUserVerificationCancelled)
		require.ErrorIs(t, err, pairingproto.ErrUserCancelled)
		require.ErrorIs(t, err, errVerifierRefused, "the verifier's own error is kept")
		require.NotErrorIs(t, err, keybackend.ErrUserVerificationUnavailable)
	}
}

// TestVerifyUser_UnloadableTrustIsUnavailable pins that a trust the verifier
// could not load — devices.yaml or the trust store could not be read — is an
// outage, not a failed verification: no prompt was sent, so every such call
// answers ErrUserVerificationUnavailable with the loader's cause kept.
func TestVerifyUser_UnloadableTrustIsUnavailable(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	errNoStore := errors.New("test: trust store unreadable")
	backend := connectedVerifyUserBackend(t, attestation.NewUserVerifier(
		func() (*xkms.AndroidDeviceTrust, error) { return nil, errNoStore },
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	))

	for range 3 {
		err := backend.VerifyUser(context.Background(), "example.com")
		require.ErrorIs(t, err, keybackend.ErrUserVerificationUnavailable)
		require.ErrorIs(t, err, errNoStore)
	}
}

func TestVerifyUser_HostCancelIsKeptOverTheTransportError(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	cases := map[string]error{
		"BLE timeout":           ErrTimeout,
		"USB connection failed": ErrConnectionFailed,
	}
	for name, transportErr := range cases {
		t.Run(name, func(t *testing.T) {
			client, _ := establishedNoiseSessionPair(t)
			hostCtx, cancelHost := context.WithCancel(context.Background())
			defer cancelHost()
			backend := &PhoneKeyBackend{
				cfg: &PhoneKeyBackendConfig{VerifyUser: func(ctx context.Context, exchange pairingproto.RPCExchange, _ []byte, _ string) error {
					_, err := exchange(ctx, pairingproto.NewRequest(pairingproto.MethodLocalVerifyUser, nil))
					return err
				}},
				session: client,
				transport: &scriptedTransport{respond: func(context.Context, []byte) ([]byte, error) {
					cancelHost()
					return nil, transportErr
				}},
				log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			backend.connected.Store(true)

			err := backend.VerifyUser(hostCtx, "example.com")
			require.ErrorIs(t, err, context.Canceled, "CTAP2_ERR_KEEPALIVE_CANCEL, not CTAP1_ERR_OTHER")
			require.NotErrorIs(t, err, keybackend.ErrUserVerificationUnavailable)
		})
	}
}

// refusingPhone is a connected backend whose phone answers every request with
// an RPC error carrying code.
func refusingPhone(t *testing.T, verify pairingproto.VerifyUserFunc, code int) *PhoneKeyBackend {
	t.Helper()
	client, server := establishedNoiseSessionPair(t)
	backend := &PhoneKeyBackend{
		cfg:     &PhoneKeyBackendConfig{VerifyUser: verify},
		session: client,
		transport: &scriptedTransport{respond: func(_ context.Context, sent []byte) ([]byte, error) {
			plaintext, err := server.Decrypt(sent)
			if err != nil {
				return nil, err
			}
			req, err := pairingproto.DecodeRequest(plaintext)
			if err != nil {
				return nil, err
			}
			respBytes, err := pairingproto.EncodeErrorResponse(req.ID, req.Generation, code, "refused", nil)
			if err != nil {
				return nil, err
			}
			return server.Encrypt(respBytes)
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	backend.connected.Store(true)
	return backend
}

// TestVerifyUser_UnansweredExchangeIsUnavailable proves an exchange the phone
// never answered — the link dropped or timed out — reaches the verifier, and
// so the authenticator, as unavailable rather than as a refusal, and spends
// no uvRetries.
func TestVerifyUser_UnansweredExchangeIsUnavailable(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	client, _ := establishedNoiseSessionPair(t)
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{VerifyUser: func(ctx context.Context, exchange pairingproto.RPCExchange, _ []byte, _ string) error {
			_, err := exchange(ctx, pairingproto.NewRequest(pairingproto.MethodLocalVerifyUser, nil))
			return err
		}},
		session: client,
		transport: &scriptedTransport{respond: func(context.Context, []byte) ([]byte, error) {
			return nil, context.DeadlineExceeded
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	backend.connected.Store(true)

	err := backend.VerifyUser(context.Background(), "example.com")
	require.ErrorIs(t, err, keybackend.ErrUserVerificationUnavailable)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestVerifyUser_SilentPhoneIsBoundedByTheDeadline pins the verify-user
// deadline: a phone that never answers, called with a context that has no
// deadline of its own (the authenticator's command context), still ends the
// exchange within verifyUserTimeout, as an unavailable verification.
func TestVerifyUser_SilentPhoneIsBoundedByTheDeadline(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	saved := verifyUserTimeout
	verifyUserTimeout = 50 * time.Millisecond
	t.Cleanup(func() { verifyUserTimeout = saved })

	client, _ := establishedNoiseSessionPair(t)
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{VerifyUser: func(ctx context.Context, exchange pairingproto.RPCExchange, _ []byte, _ string) error {
			_, err := exchange(ctx, pairingproto.NewRequest(pairingproto.MethodLocalVerifyUser, nil))
			return err
		}},
		session: client,
		transport: &scriptedTransport{respond: func(ctx context.Context, _ []byte) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	backend.connected.Store(true)

	done := make(chan error, 1)
	go func() { done <- backend.VerifyUser(context.Background(), "example.com") }()

	select {
	case err := <-done:
		require.ErrorIs(t, err, keybackend.ErrUserVerificationUnavailable)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(5 * time.Second):
		t.Fatal("VerifyUser waited past its deadline on a phone that never answers")
	}
}

// TestVerifyUser_UnreadableStatusListIsUnavailable proves an answer that could
// not be judged because the revocation status list was unavailable is not a
// refusal: the user was neither verified nor refused.
func TestVerifyUser_UnreadableStatusListIsUnavailable(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	backend := connectedVerifyUserBackend(t, func(context.Context, pairingproto.RPCExchange, []byte, string) error {
		return fmt.Errorf("verify: %w", xkms.ErrAndroidStatusListUnavailable)
	})

	err := backend.VerifyUser(context.Background(), "example.com")
	require.ErrorIs(t, err, keybackend.ErrUserVerificationUnavailable)
	require.ErrorIs(t, err, xkms.ErrAndroidStatusListUnavailable)
}

// TestVerifyUser_MalformedStatusListFileIsUnavailable pins that a local
// status-list file that does not parse is an outage of the list, not a
// failed verification: VerifyUser answers ErrUserVerificationUnavailable, on
// which the authenticator spends no uvRetries (CTAP 2.1 §6.5.5.7.3).
func TestVerifyUser_MalformedStatusListFileIsUnavailable(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	path := filepath.Join(t.TempDir(), "status.json")
	require.NoError(t, os.WriteFile(path, []byte("not a status list"), 0o600))
	backend := connectedVerifyUserBackend(t, func(context.Context, pairingproto.RPCExchange, []byte, string) error {
		_, err := xkms.LoadAndroidStatusListFile(path)
		return err
	})

	err := backend.VerifyUser(context.Background(), "example.com")
	require.ErrorIs(t, err, keybackend.ErrUserVerificationUnavailable)
	require.ErrorIs(t, err, xkms.ErrAndroidStatusListMalformed)
}

// TestVerifyUser_NoVerifierRefuses proves a backend built without a
// verifier fails closed instead of treating the user as verified.
func TestVerifyUser_NoVerifierRefuses(t *testing.T) {
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	backend.connected.Store(true)

	err := backend.VerifyUser(context.Background(), "example.com")
	require.ErrorIs(t, err, ErrUserVerifierUnavailable)
	require.ErrorIs(t, err, keybackend.ErrUserVerificationUnavailable, "a missing verifier spends no uvRetries")
}

// TestVerifyUser_NotConnectedNeverCallsTheVerifier proves no exchange is
// attempted before a session exists.
func TestVerifyUser_NotConnectedNeverCallsTheVerifier(t *testing.T) {
	called := false
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{VerifyUser: func(context.Context, pairingproto.RPCExchange, []byte, string) error {
			called = true
			return nil
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err := backend.VerifyUser(context.Background(), "example.com")
	require.ErrorIs(t, err, ErrNotConnected)
	require.ErrorIs(t, err, keybackend.ErrUserVerificationUnavailable, "no session spends no uvRetries")
	require.False(t, called)
}
