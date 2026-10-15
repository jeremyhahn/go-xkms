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

package authenticator

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	tokenTestSOPIN    = "securepin123"
	tokenTestNewSOPIN = "newsecurepin456"
	tokenTestWrongPIN = "wrongpin999999"
)

// recordingUPHandler answers user presence with a fixed verdict and counts how
// many times it was asked, so tests can assert on ordering as well as outcome.
type recordingUPHandler struct {
	approve bool
	calls   atomic.Int32
}

func (h *recordingUPHandler) RequestUserPresence(ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error) {
	h.calls.Add(1)
	return &UserPresenceResult{Approved: h.approve}, nil
}

func (h *recordingUPHandler) RequestUserVerification(ctx context.Context, req *UserVerificationRequest) (*UserVerificationResult, error) {
	h.calls.Add(1)
	return &UserVerificationResult{Verified: h.approve}, nil
}

// newTokenTestConfig returns a config whose storage outlives an authenticator,
// so a restart can be simulated by building a second authenticator over it.
func newTokenTestConfig() *Config {
	return &Config{
		UserPresenceHandler: NewAutoGrantHandler(),
		Storage:             NewMemoryStorage(),
		EnablePIN:           true,
		PINMinLength:        4,
		PINMaxRetries:       8,
		SupportedAlgorithms: []int{COSEAlgES256},
	}
}

// newTokenTestAuthenticator builds an uninitialized authenticator.
func newTokenTestAuthenticator(t *testing.T) (*Authenticator, *Config) {
	t.Helper()

	config := newTokenTestConfig()
	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })
	return auth, config
}

// powerCycle rebuilds the authenticator over the same storage, which is what a
// power cycle is for a software authenticator: persisted state survives,
// per-boot state does not.
func powerCycle(t *testing.T, config *Config) *Authenticator {
	t.Helper()

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })
	return auth
}

// initializedToken returns an authenticator whose token has been initialized
// through the supported path.
func initializedToken(t *testing.T) (*Authenticator, *Config) {
	t.Helper()

	auth, config := newTokenTestAuthenticator(t)
	require.NoError(t, auth.InitializeToken(context.Background(), tokenTestSOPIN))
	require.True(t, auth.IsTokenInitialized())
	return auth, config
}

// TestUninitializedTokenRefusesSOGatedOperations pins the fail-closed rule: a
// token with no Security Officer refuses SO-gated work and says which of the
// two refusals applies, rather than treating "no SO PIN" as "no SO required".
func TestUninitializedTokenRefusesSOGatedOperations(t *testing.T) {
	soGated := map[string]struct {
		handler vendorSOPINHandlerFunc
		params  map[interface{}]interface{}
	}{
		"ResetUserPIN": {
			handler: handleVendorResetUserPIN,
			params:  map[interface{}]interface{}{vendorParamKeyNewPinHash: make([]byte, PINHashSize)},
		},
		"ReplaceAttestKey": {
			handler: handleVendorReplaceAttestKey,
			params:  map[interface{}]interface{}{},
		},
		"SetRPPolicy": {
			handler: handleVendorSetRPPolicy,
			params:  map[interface{}]interface{}{vendorParamKeyRPID: "example.com"},
		},
		"DeleteRPPolicy": {
			handler: handleVendorDeleteRPPolicy,
			params:  map[interface{}]interface{}{vendorParamKeyRPID: "example.com"},
		},
		"SetProfile": {
			handler: handleVendorSetProfile,
			params:  map[interface{}]interface{}{vendorParamKeyEnableEP: true},
		},
	}

	for name, tc := range soGated {
		t.Run(name+" is refused", func(t *testing.T) {
			auth, _ := newTokenTestAuthenticator(t)

			_, err := tc.handler(auth, tc.params)

			require.ErrorIs(t, err, ErrTokenUninitialized)
			require.NotErrorIs(t, err, ErrKeyManagerLocked,
				"an uninitialized token is not a locked one")
		})
	}

	t.Run("ChangeSOPIN is refused", func(t *testing.T) {
		auth, _ := newTokenTestAuthenticator(t)

		err := auth.ChangeSOPIN(context.Background(), tokenTestSOPIN, tokenTestNewSOPIN)

		require.ErrorIs(t, err, ErrTokenUninitialized)
	})

	t.Run("UnlockSO is refused", func(t *testing.T) {
		auth, _ := newTokenTestAuthenticator(t)

		err := auth.UnlockSO(context.Background(), tokenTestSOPIN)

		require.ErrorIs(t, err, ErrTokenUninitialized)
	})

	t.Run("state reads as uninitialized, not as an empty flag set", func(t *testing.T) {
		auth, _ := newTokenTestAuthenticator(t)

		require.False(t, auth.IsTokenInitialized())
		require.Equal(t, TokenFlags(0), auth.TokenFlags())
		require.Equal(t, "uninitialized", auth.TokenFlags().String())
	})

	t.Run("the refusal maps to CTAP2_ERR_NOT_ALLOWED", func(t *testing.T) {
		require.Equal(t, byte(StatusNotAllowed), errorToStatus(ErrTokenUninitialized))
		require.Equal(t, byte(StatusNotAllowed), errorToStatus(ErrTokenInitWindowClosed))

		// An SO that exists but has not authenticated is a different wire
		// answer, because it calls for a different response.
		require.Equal(t, byte(StatusPINRequired), errorToStatus(ErrKeyManagerLocked))
		require.NotEqual(t, errorToStatus(ErrTokenUninitialized), errorToStatus(ErrKeyManagerLocked))
	})
}

// TestInitializeTokenBoundsTheTrustOnFirstUseWindow covers CTAP 2.1 §6.9's two
// bounds applied to first initialization: a post-power-up window, and user
// presence.
func TestInitializeTokenBoundsTheTrustOnFirstUseWindow(t *testing.T) {
	t.Run("succeeds inside the window with user presence", func(t *testing.T) {
		auth, _ := newTokenTestAuthenticator(t)
		handler := &recordingUPHandler{approve: true}
		auth.SetUserPresenceHandler(handler)

		require.NoError(t, auth.InitializeToken(context.Background(), tokenTestSOPIN))

		require.True(t, auth.IsTokenInitialized())
		require.Equal(t, TokenFlagInitialized, auth.TokenFlags())
		require.Equal(t, int32(1), handler.calls.Load())
	})

	t.Run("refused outside the post-power-up window", func(t *testing.T) {
		auth, _ := newTokenTestAuthenticator(t)
		handler := &recordingUPHandler{approve: true}
		auth.SetUserPresenceHandler(handler)

		auth.mu.Lock()
		auth.poweredUpAt = time.Now().Add(-auth.config.TokenInitWindow - time.Second)
		auth.mu.Unlock()

		err := auth.InitializeToken(context.Background(), tokenTestSOPIN)

		require.ErrorIs(t, err, ErrTokenInitWindowClosed)
		require.False(t, auth.IsTokenInitialized())
		require.Zero(t, handler.calls.Load(),
			"a request already refused must not prompt the user")
	})

	t.Run("refused without user presence", func(t *testing.T) {
		auth, _ := newTokenTestAuthenticator(t)
		handler := &recordingUPHandler{approve: false}
		auth.SetUserPresenceHandler(handler)

		err := auth.InitializeToken(context.Background(), tokenTestSOPIN)

		require.ErrorIs(t, err, ErrUserPresenceRequired)
		require.False(t, auth.IsTokenInitialized())
		require.Equal(t, int32(1), handler.calls.Load())
	})

	t.Run("the window is exactly Config.TokenInitWindow wide", func(t *testing.T) {
		auth, _ := newTokenTestAuthenticator(t)

		auth.mu.Lock()
		auth.poweredUpAt = time.Now().Add(-auth.config.TokenInitWindow + 2*time.Second)
		auth.mu.Unlock()
		require.True(t, auth.tokenInitWindowOpen())

		auth.mu.Lock()
		auth.poweredUpAt = time.Now().Add(-auth.config.TokenInitWindow - time.Millisecond)
		auth.mu.Unlock()
		require.False(t, auth.tokenInitWindowOpen())
	})

	t.Run("a malformed PIN is refused before the user is prompted", func(t *testing.T) {
		auth, _ := newTokenTestAuthenticator(t)
		handler := &recordingUPHandler{approve: true}
		auth.SetUserPresenceHandler(handler)

		err := auth.InitializeToken(context.Background(), "abc")

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
		require.False(t, auth.IsTokenInitialized())
		require.Zero(t, handler.calls.Load())
	})

	t.Run("initializing twice is refused", func(t *testing.T) {
		auth, _ := initializedToken(t)

		err := auth.InitializeToken(context.Background(), tokenTestNewSOPIN)

		require.ErrorIs(t, err, ErrKeyManagerAlreadyInitialized)

		// And the original SO PIN still works.
		require.NoError(t, auth.UnlockSO(context.Background(), tokenTestSOPIN))
	})

	t.Run("initialization is persisted", func(t *testing.T) {
		_, config := initializedToken(t)

		restarted := powerCycle(t, config)

		require.True(t, restarted.IsTokenInitialized())
		require.NoError(t, restarted.UnlockSO(context.Background(), tokenTestSOPIN))
	})

	t.Run("the window is closed by the time it would matter after a restart", func(t *testing.T) {
		auth, config := newTokenTestAuthenticator(t)
		require.True(t, auth.tokenInitWindowOpen())

		restarted := powerCycle(t, config)
		restarted.mu.Lock()
		restarted.poweredUpAt = time.Now().Add(-restarted.config.TokenInitWindow - time.Second)
		restarted.mu.Unlock()

		require.ErrorIs(t,
			restarted.InitializeToken(context.Background(), tokenTestSOPIN),
			ErrTokenInitWindowClosed)
	})
}

// TestChangeSOPINRequiresSecurityOfficer pins that the SO PIN changes only for
// a caller who already holds it, and that a failed attempt is not destructive.
func TestChangeSOPINRequiresSecurityOfficer(t *testing.T) {
	t.Run("the current SO PIN changes it", func(t *testing.T) {
		auth, _ := initializedToken(t)

		require.NoError(t, auth.ChangeSOPIN(context.Background(), tokenTestSOPIN, tokenTestNewSOPIN))

		auth.keyManager.Lock()
		require.NoError(t, auth.UnlockSO(context.Background(), tokenTestNewSOPIN))
	})

	t.Run("the old SO PIN stops working after a change", func(t *testing.T) {
		auth, _ := initializedToken(t)
		require.NoError(t, auth.ChangeSOPIN(context.Background(), tokenTestSOPIN, tokenTestNewSOPIN))

		auth.keyManager.Lock()
		err := auth.UnlockSO(context.Background(), tokenTestSOPIN)

		require.ErrorIs(t, err, ErrSOPINInvalid)
	})

	t.Run("a wrong current SO PIN is refused", func(t *testing.T) {
		auth, _ := initializedToken(t)

		err := auth.ChangeSOPIN(context.Background(), tokenTestWrongPIN, tokenTestNewSOPIN)

		require.ErrorIs(t, err, ErrSOPINInvalid)
	})

	t.Run("a refused change leaves the current SO PIN working", func(t *testing.T) {
		auth, _ := initializedToken(t)

		require.Error(t, auth.ChangeSOPIN(context.Background(), tokenTestWrongPIN, tokenTestNewSOPIN))

		// The salt must not have been rotated on an unproven PIN: doing so
		// would make the real SO PIN underivable and brick the token.
		auth.keyManager.Lock()
		require.NoError(t, auth.UnlockSO(context.Background(), tokenTestSOPIN))
		require.Error(t, auth.UnlockSO(context.Background(), tokenTestNewSOPIN))
	})

	t.Run("a wrong current SO PIN spends a retry", func(t *testing.T) {
		auth, _ := initializedToken(t)

		require.Error(t, auth.ChangeSOPIN(context.Background(), tokenTestWrongPIN, tokenTestNewSOPIN))

		require.Equal(t, DefaultSOPINMaxRetries-1, auth.state.SOPINManager.Retries())
	})

	t.Run("a malformed new SO PIN does not spend a retry", func(t *testing.T) {
		auth, _ := initializedToken(t)

		err := auth.ChangeSOPIN(context.Background(), tokenTestSOPIN, "abc")

		require.ErrorIs(t, err, ErrSOPINPolicyViolation)
		require.Equal(t, DefaultSOPINMaxRetries, auth.state.SOPINManager.Retries())
	})
}

// TestSOPINRetryAccountingIsEnforced covers CTAP 2.1 §6.5.5.7: a bounded retry
// budget, a power cycle forced after three consecutive failures, a terminal
// lockout at exhaustion, and a counter that survives a restart.
func TestSOPINRetryAccountingIsEnforced(t *testing.T) {
	t.Run("consecutive failures decrement the counter", func(t *testing.T) {
		auth, _ := initializedToken(t)

		for i := 1; i <= PINMaxConsecutiveFailures; i++ {
			auth.keyManager.Lock()
			require.Error(t, auth.UnlockSO(context.Background(), tokenTestWrongPIN))
			require.Equal(t, DefaultSOPINMaxRetries-i, auth.state.SOPINManager.Retries())
		}
	})

	t.Run("a power cycle is forced at the spec threshold", func(t *testing.T) {
		auth, config := initializedToken(t)

		var last error
		for i := 0; i < PINMaxConsecutiveFailures; i++ {
			auth.keyManager.Lock()
			last = auth.UnlockSO(context.Background(), tokenTestWrongPIN)
		}
		require.ErrorIs(t, last, ErrSOPINAuthBlocked)

		// Even the correct SO PIN is refused, and the budget is not spent
		// further, until the authenticator is power-cycled.
		before := auth.state.SOPINManager.Retries()
		require.ErrorIs(t,
			auth.UnlockSO(context.Background(), tokenTestSOPIN),
			ErrSOPINAuthBlocked)
		require.Equal(t, before, auth.state.SOPINManager.Retries())

		// After a power cycle attempts resume, and the correct PIN works.
		restarted := powerCycle(t, config)
		require.False(t, restarted.state.SOPINManager.IsAuthBlocked())
		require.NoError(t, restarted.UnlockSO(context.Background(), tokenTestSOPIN))
	})

	t.Run("the counter survives a restart", func(t *testing.T) {
		auth, config := initializedToken(t)

		auth.keyManager.Lock()
		require.Error(t, auth.UnlockSO(context.Background(), tokenTestWrongPIN))
		spent := auth.state.SOPINManager.Retries()
		require.Equal(t, DefaultSOPINMaxRetries-1, spent)

		restarted := powerCycle(t, config)

		require.True(t, restarted.IsTokenInitialized())
		require.Equal(t, spent, restarted.state.SOPINManager.Retries(),
			"a restart must not hand back a spent retry")
	})

	t.Run("the budget is exhausted across power cycles and locks out", func(t *testing.T) {
		auth, config := initializedToken(t)

		for spent := 1; spent <= DefaultSOPINMaxRetries; spent++ {
			auth.keyManager.Lock()
			err := auth.UnlockSO(context.Background(), tokenTestWrongPIN)
			require.Error(t, err)
			require.Equal(t, DefaultSOPINMaxRetries-spent, auth.state.SOPINManager.Retries())

			// A power cycle clears the consecutive counter but never refunds
			// the budget, so an attacker cannot restart their way out.
			auth = powerCycle(t, config)
		}

		require.True(t, auth.state.SOPINManager.IsBlocked())
		require.ErrorIs(t,
			auth.UnlockSO(context.Background(), tokenTestSOPIN),
			ErrSOPINBlocked,
			"lockout is terminal: even the correct SO PIN is refused")

		// And the lockout itself survives a restart.
		restarted := powerCycle(t, config)
		require.True(t, restarted.state.SOPINManager.IsBlocked())
		require.ErrorIs(t,
			restarted.UnlockSO(context.Background(), tokenTestSOPIN),
			ErrSOPINBlocked)
	})

	t.Run("a success restores the budget", func(t *testing.T) {
		auth, _ := initializedToken(t)

		auth.keyManager.Lock()
		require.Error(t, auth.UnlockSO(context.Background(), tokenTestWrongPIN))
		require.Equal(t, DefaultSOPINMaxRetries-1, auth.state.SOPINManager.Retries())

		require.NoError(t, auth.UnlockSO(context.Background(), tokenTestSOPIN))
		require.Equal(t, DefaultSOPINMaxRetries, auth.state.SOPINManager.Retries())
	})

	t.Run("PKCS#11 flags track the counter", func(t *testing.T) {
		auth, _ := initializedToken(t)
		require.Equal(t, TokenFlagInitialized, auth.TokenFlags())

		auth.keyManager.Lock()
		require.Error(t, auth.UnlockSO(context.Background(), tokenTestWrongPIN))
		require.NotZero(t, auth.TokenFlags()&TokenFlagSOPINCountLow)
		require.Zero(t, auth.TokenFlags()&TokenFlagSOPINFinalTry)

		auth.state.SOPINManager.SetRetries(1)
		require.NotZero(t, auth.TokenFlags()&TokenFlagSOPINFinalTry)
		require.Zero(t, auth.TokenFlags()&TokenFlagSOPINLocked)

		auth.state.SOPINManager.SetRetries(0)
		require.NotZero(t, auth.TokenFlags()&TokenFlagSOPINLocked)
		require.Equal(t,
			"initialized|so-pin-count-low|so-pin-final-try|so-pin-locked",
			auth.TokenFlags().String())
	})

	t.Run("SO PIN errors map to their CTAP status codes", func(t *testing.T) {
		require.Equal(t, byte(StatusPINInvalid), errorToStatus(ErrSOPINInvalid))
		require.Equal(t, byte(StatusPINBlocked), errorToStatus(ErrSOPINBlocked))
		require.Equal(t, byte(StatusPINAuthBlocked), errorToStatus(ErrSOPINAuthBlocked))
		require.Equal(t, byte(StatusPINNotSet), errorToStatus(ErrSOPINNotSet))
		require.Equal(t, byte(StatusPINRequired), errorToStatus(ErrSOPINRequired))
		require.Equal(t, byte(StatusPINPolicyViolation), errorToStatus(ErrSOPINPolicyViolation))
	})
}

// TestInitializedTokenPermitsSecurityOfficer is the positive control: the fix
// is a gate, not a wall. An authenticated Security Officer gets through.
func TestInitializedTokenPermitsSecurityOfficer(t *testing.T) {
	t.Run("an SO-gated operation succeeds after SO authentication", func(t *testing.T) {
		auth, _ := initializedToken(t)
		require.NoError(t, auth.UnlockSO(context.Background(), tokenTestSOPIN))

		resp, err := handleVendorReplaceAttestKey(auth, map[interface{}]interface{}{})

		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
	})

	t.Run("the same operation is refused before SO authentication", func(t *testing.T) {
		auth, _ := initializedToken(t)
		auth.keyManager.Lock()

		_, err := handleVendorReplaceAttestKey(auth, map[interface{}]interface{}{})

		require.ErrorIs(t, err, ErrKeyManagerLocked)
		require.NotErrorIs(t, err, ErrTokenUninitialized,
			"an initialized token must not report itself uninitialized")
	})

	t.Run("initialization over the CTAP transport works end to end", func(t *testing.T) {
		auth, _ := newTokenTestAuthenticator(t)

		resp, err := handleVendorSetSOPIN(auth, map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetSOPIN),
			vendorParamKeyPin:       tokenTestSOPIN,
		})

		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])
		require.True(t, auth.IsTokenInitialized())

		unlockResp, err := handleVendorUnlockWithSOPIN(auth, map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdUnlockWithSOPIN),
			vendorParamKeyPin:       tokenTestSOPIN,
		})
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), unlockResp[0])
	})
}

// TestResetReturnsTokenToUninitialized covers the only path back to the
// uninitialized state, and the window re-arm that keeps it usable.
func TestResetReturnsTokenToUninitialized(t *testing.T) {
	t.Run("reset requires an authenticated SO on an initialized token", func(t *testing.T) {
		auth, _ := initializedToken(t)
		auth.keyManager.Lock()

		_, err := auth.handleReset()

		require.ErrorIs(t, err, ErrSOPINRequired)
		require.True(t, auth.IsTokenInitialized())
	})

	t.Run("reset returns the token to uninitialized and re-arms the window", func(t *testing.T) {
		auth, _ := initializedToken(t)
		require.NoError(t, auth.UnlockSO(context.Background(), tokenTestSOPIN))

		// Age the window so the re-arm is observable rather than incidental.
		auth.mu.Lock()
		auth.poweredUpAt = time.Now().Add(-auth.config.TokenInitWindow - time.Second)
		auth.mu.Unlock()
		require.False(t, auth.tokenInitWindowOpen())

		_, err := auth.handleReset()
		require.NoError(t, err)

		require.False(t, auth.IsTokenInitialized())
		require.Equal(t, "uninitialized", auth.TokenFlags().String())
		require.True(t, auth.tokenInitWindowOpen())

		// The token can be initialized again, with a different SO PIN.
		require.NoError(t, auth.InitializeToken(context.Background(), tokenTestNewSOPIN))
		require.NoError(t, auth.UnlockSO(context.Background(), tokenTestNewSOPIN))
	})

	t.Run("reset on an uninitialized token still requires user presence", func(t *testing.T) {
		auth, _ := newTokenTestAuthenticator(t)
		handler := &recordingUPHandler{approve: false}
		auth.SetUserPresenceHandler(handler)

		_, err := auth.handleReset()

		require.ErrorIs(t, err, ErrUserPresenceRequired)
		require.Equal(t, int32(1), handler.calls.Load())
	})
}

// TestTokenFlagsString covers the rendering used in operator-facing output.
func TestTokenFlagsString(t *testing.T) {
	cases := map[string]struct {
		flags TokenFlags
		want  string
	}{
		"uninitialized":            {0, "uninitialized"},
		"count low without init":   {TokenFlagSOPINCountLow, "uninitialized"},
		"initialized":              {TokenFlagInitialized, "initialized"},
		"count low":                {TokenFlagInitialized | TokenFlagSOPINCountLow, "initialized|so-pin-count-low"},
		"final try":                {TokenFlagInitialized | TokenFlagSOPINFinalTry, "initialized|so-pin-final-try"},
		"locked":                   {TokenFlagInitialized | TokenFlagSOPINLocked, "initialized|so-pin-locked"},
		"every SO flag at once":    {TokenFlagInitialized | TokenFlagSOPINCountLow | TokenFlagSOPINFinalTry | TokenFlagSOPINLocked, "initialized|so-pin-count-low|so-pin-final-try|so-pin-locked"},
		"unknown bits are ignored": {TokenFlagInitialized | 1<<20, "initialized"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.flags.String())
		})
	}
}

// TestTokenInitWindowConfigDefaults covers the config knob that widens the
// trust-on-first-use window.
func TestTokenInitWindowConfigDefaults(t *testing.T) {
	t.Run("zero selects the default", func(t *testing.T) {
		config := newTokenTestConfig()
		config.TokenInitWindow = 0

		config.SetDefaults()

		require.Equal(t, DefaultTokenInitWindow, config.TokenInitWindow)
	})

	t.Run("negative selects the default rather than disabling the bound", func(t *testing.T) {
		config := newTokenTestConfig()
		config.TokenInitWindow = -time.Hour

		config.SetDefaults()

		require.Equal(t, DefaultTokenInitWindow, config.TokenInitWindow)
	})

	t.Run("an explicit window is honoured", func(t *testing.T) {
		config := newTokenTestConfig()
		config.TokenInitWindow = 45 * time.Second

		config.SetDefaults()

		require.Equal(t, 45*time.Second, config.TokenInitWindow)
	})
}

// TestSOPINStateSurvivesPersistence covers the two persistence paths the retry
// counter has to cross. Both silently dropped it: MemoryStorage.copyState never
// carried the SO credential at all, and SerializableState.SOPINRetries carried
// `omitempty`, which drops exactly the value that matters most.
func TestSOPINStateSurvivesPersistence(t *testing.T) {
	t.Run("MemoryStorage carries the SO credential and the wrapped keys", func(t *testing.T) {
		auth, _ := initializedToken(t)
		auth.state.SOPINManager.SetRetries(3)
		require.NoError(t, auth.saveState())

		storage, ok := auth.storage.(*MemoryStorage)
		require.True(t, ok)

		loaded, err := storage.LoadState()
		require.NoError(t, err)

		require.NotNil(t, loaded.SOPINManager, "the SO credential must survive")
		require.True(t, loaded.SOPINManager.IsSet)
		require.Equal(t, 3, loaded.SOPINManager.Retries())
		require.Equal(t, auth.state.SOPINManager.Salt, loaded.SOPINManager.Salt)
		require.NotEmpty(t, loaded.WrappedAK, "the key hierarchy must survive")
		require.NotEmpty(t, loaded.WrappedCMKSO)

		// The snapshot must not alias the live manager, or persisting would
		// mean nothing.
		loaded.SOPINManager.SetRetries(1)
		require.Equal(t, 3, auth.state.SOPINManager.Retries())
	})

	t.Run("the per-power-cycle counter is not carried across a load", func(t *testing.T) {
		auth, _ := initializedToken(t)
		auth.state.SOPINManager.consecutiveFailures.failures.Store(PINMaxConsecutiveFailures)
		require.True(t, auth.state.SOPINManager.IsAuthBlocked())
		require.NoError(t, auth.saveState())

		storage, ok := auth.storage.(*MemoryStorage)
		require.True(t, ok)
		loaded, err := storage.LoadState()
		require.NoError(t, err)

		require.False(t, loaded.SOPINManager.IsAuthBlocked(),
			"a power cycle is what clears the power-cycle block")
	})

	t.Run("JSON serialization round-trips a lockout at zero", func(t *testing.T) {
		auth, _ := initializedToken(t)
		auth.state.SOPINManager.SetRetries(0)

		serializable, err := stateToSerializable(auth.state)
		require.NoError(t, err)

		encoded, err := json.Marshal(serializable)
		require.NoError(t, err)

		var decoded SerializableState
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		require.Equal(t, 0, decoded.SOPINRetries)

		restored, err := serializableToState(&decoded)
		require.NoError(t, err)

		require.NotNil(t, restored.SOPINManager)
		require.True(t, restored.SOPINManager.IsBlocked(),
			"a lockout must not be lost in serialization")
	})

	t.Run("JSON serialization round-trips a partially spent budget", func(t *testing.T) {
		auth, _ := initializedToken(t)
		auth.state.SOPINManager.SetRetries(5)

		serializable, err := stateToSerializable(auth.state)
		require.NoError(t, err)
		encoded, err := json.Marshal(serializable)
		require.NoError(t, err)

		var decoded SerializableState
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		restored, err := serializableToState(&decoded)
		require.NoError(t, err)

		require.Equal(t, 5, restored.SOPINManager.Retries())
		require.Equal(t, auth.state.SOPINManager.Salt, restored.SOPINManager.Salt)
	})
}

// TestTokenLifecycleErrorPaths covers the refusals that are not about
// credentials: a missing key manager and a storage backend that cannot record
// the outcome.
func TestTokenLifecycleErrorPaths(t *testing.T) {
	t.Run("InitializeToken without a key manager is refused", func(t *testing.T) {
		auth, _ := newTokenTestAuthenticator(t)
		auth.keyManager = nil

		err := auth.InitializeToken(context.Background(), tokenTestSOPIN)

		require.ErrorIs(t, err, ErrKeyManagerNoSOPIN)
	})

	t.Run("ChangeSOPIN without a key manager is refused", func(t *testing.T) {
		auth, _ := initializedToken(t)
		auth.keyManager = nil

		err := auth.ChangeSOPIN(context.Background(), tokenTestSOPIN, tokenTestNewSOPIN)

		require.ErrorIs(t, err, ErrKeyManagerNoSOPIN)
	})

	t.Run("UnlockSO without a key manager is refused", func(t *testing.T) {
		auth, _ := initializedToken(t)
		auth.keyManager = nil

		err := auth.UnlockSO(context.Background(), tokenTestSOPIN)

		require.ErrorIs(t, err, ErrKeyManagerNoSOPIN)
	})

	t.Run("InitializeToken reports a storage failure rather than claiming success", func(t *testing.T) {
		auth, _ := newTokenTestAuthenticator(t)
		storage, ok := auth.storage.(*MemoryStorage)
		require.True(t, ok)
		require.NoError(t, storage.Close())

		err := auth.InitializeToken(context.Background(), tokenTestSOPIN)

		require.ErrorIs(t, err, ErrStorageError)
	})

	t.Run("UnlockSO reports a storage failure on an otherwise successful unlock", func(t *testing.T) {
		auth, _ := initializedToken(t)
		auth.keyManager.Lock()
		storage, ok := auth.storage.(*MemoryStorage)
		require.True(t, ok)
		require.NoError(t, storage.Close())

		err := auth.UnlockSO(context.Background(), tokenTestSOPIN)

		require.ErrorIs(t, err, ErrStorageError)
	})

	t.Run("UnlockSO reports the PIN failure ahead of a storage failure", func(t *testing.T) {
		auth, _ := initializedToken(t)
		auth.keyManager.Lock()
		storage, ok := auth.storage.(*MemoryStorage)
		require.True(t, ok)
		require.NoError(t, storage.Close())

		err := auth.UnlockSO(context.Background(), tokenTestWrongPIN)

		require.ErrorIs(t, err, ErrSOPINInvalid,
			"a caller must learn the PIN was wrong, not that a write failed")
	})

	t.Run("ChangeSOPIN reports a storage failure on an otherwise successful change", func(t *testing.T) {
		auth, _ := initializedToken(t)
		storage, ok := auth.storage.(*MemoryStorage)
		require.True(t, ok)
		require.NoError(t, storage.Close())

		err := auth.ChangeSOPIN(context.Background(), tokenTestSOPIN, tokenTestNewSOPIN)

		require.ErrorIs(t, err, ErrStorageError)
	})
}
