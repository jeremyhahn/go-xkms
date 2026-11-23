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

package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/pinselect"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// fakePKCS11Provider stands in for the PKCS#11 backend: only Close is used.
type fakePKCS11Provider struct {
	types.KeyProvider
	closed bool
	closes int
}

func (f *fakePKCS11Provider) Close() error {
	f.closed = true
	f.closes++
	return nil
}

// backendPINTestServer builds a Server with an enabled PKCS#11 backend whose
// configured PIN is pin, the given backend_pin strategy, and an opener that
// records the PIN each start receives (compared, never printed).
func backendPINTestServer(t *testing.T, strategy string, pin []byte, tpm, barrier bool) (*Server, *[][]byte, *[]*fakePKCS11Provider) {
	t.Helper()
	ctx := context.Background()
	cfg := &config.Config{}
	cfg.Datastore.Path = t.TempDir()
	cfg.BackendPIN.Strategy = strategy
	pkcs11Cfg := &config.PKCS11Config{Enabled: true}
	if pin != nil {
		pv, err := types.NewLiteralSecretValue(ctx, pin)
		require.NoError(t, err)
		pkcs11Cfg.Pin = pv
	}
	cfg.Backends.PKCS11 = pkcs11Cfg

	var opened [][]byte
	var providers []*fakePKCS11Provider
	s := &Server{
		ctx:          ctx,
		config:       cfg,
		keyProviders: map[string]types.KeyProvider{},
		backendPINProbe: func() (bool, bool) {
			return tpm, barrier
		},
	}
	s.pkcs11PINOpener = func(p []byte) (types.KeyProvider, error) {
		opened = append(opened, append([]byte(nil), p...))
		fp := &fakePKCS11Provider{}
		providers = append(providers, fp)
		return fp, nil
	}
	return s, &opened, &providers
}

func TestResolveBackendPIN_SealedPersistsAndReportsStrategy(t *testing.T) {
	s, opened, _ := backendPINTestServer(t, "sealed", []byte("backend-pin-1"), false, true)

	require.NoError(t, s.resolveBackendPIN())
	require.Equal(t, "sealed", s.BackendPINStrategy(), "status reports the resolved strategy")

	persisted, err := pinselect.LoadBackendPINStrategy(filepath.Join(s.config.Datastore.Path, "pin"))
	require.NoError(t, err)
	require.Equal(t, pinselect.BackendPINSealed, persisted)

	// Sealed: nothing is opened at resolve time (before unseal).
	require.Empty(t, *opened)
	_, started := s.keyProviders["pkcs11"]
	require.False(t, started)
}

func TestResolveBackendPIN_AutoWithoutTPMSelectsSealed(t *testing.T) {
	s, _, _ := backendPINTestServer(t, "", []byte("backend-pin-1"), false, true)
	require.NoError(t, s.resolveBackendPIN())
	require.Equal(t, "sealed", s.BackendPINStrategy())
}

func TestResolveBackendPIN_RefusedFailsClosed(t *testing.T) {
	s, opened, _ := backendPINTestServer(t, "tpm2", []byte("backend-pin-1"), false, true)

	err := s.resolveBackendPIN()
	require.Error(t, err)
	var unavailable *pinselect.BackendPINUnavailableError
	require.True(t, errors.As(err, &unavailable), "typed refusal is reachable")
	require.Equal(t, "", s.BackendPINStrategy())
	require.Empty(t, *opened)
}

// tpm2 is reported only when the PIN is actually sealed to the TPM
// (credentials.seal_strategy tpm2): a TPM alone with a barrier-sealed PIN
// never satisfies strategy or minimum tpm2 (docs/SPEC.md:78).
func TestResolveBackendPIN_TPM2RequiresTPMSealedPIN(t *testing.T) {
	for _, seal := range []string{"", "barrier", "manual"} {
		s, _, _ := backendPINTestServer(t, "tpm2", []byte("backend-pin-1"), true, true)
		s.config.BackendPIN.Minimum = "tpm2"
		s.config.Credentials.SealStrategy = seal
		err := s.resolveBackendPIN()
		var unavailable *pinselect.BackendPINUnavailableError
		require.True(t, errors.As(err, &unavailable), "seal_strategy %q: err = %v", seal, err)
		require.Equal(t, "", s.BackendPINStrategy())
		_, statErr := os.Stat(pinselect.BackendPINStrategyPath(s.backendPINDir()))
		require.True(t, os.IsNotExist(statErr), "nothing persisted for seal_strategy %q", seal)
	}

	s, _, _ := backendPINTestServer(t, "tpm2", []byte("backend-pin-1"), true, true)
	s.config.BackendPIN.Minimum = "tpm2"
	s.config.Credentials.SealStrategy = "tpm2"
	require.NoError(t, s.resolveBackendPIN())
	require.Equal(t, "tpm2", s.BackendPINStrategy())
}

func TestResolveBackendPIN_AutoWithTPMButBarrierSealSelectsSealed(t *testing.T) {
	s, _, _ := backendPINTestServer(t, "auto", []byte("backend-pin-1"), true, true)
	s.config.Credentials.SealStrategy = "barrier"
	require.NoError(t, s.resolveBackendPIN())
	require.Equal(t, "sealed", s.BackendPINStrategy())
}

func TestResolveBackendPIN_BelowMinimumFailsClosed(t *testing.T) {
	s, _, _ := backendPINTestServer(t, "sealed", []byte("backend-pin-1"), false, true)
	s.config.BackendPIN.Minimum = "manual"

	err := s.resolveBackendPIN()
	var below *pinselect.BackendPINBelowMinimumError
	require.True(t, errors.As(err, &below))
}

func TestResolveBackendPIN_NoPKCS11IsNoOp(t *testing.T) {
	s, _, _ := backendPINTestServer(t, "sealed", nil, false, true)
	s.config.Backends.PKCS11 = nil

	require.NoError(t, s.resolveBackendPIN())
	require.Equal(t, "", s.BackendPINStrategy())
	require.NoError(t, s.startPKCS11AfterUnseal())
}

func TestStartPKCS11AfterUnseal_SealedStartsWithReleasedPIN(t *testing.T) {
	pin := []byte("backend-pin-1")
	s, opened, _ := backendPINTestServer(t, "sealed", pin, false, true)
	require.NoError(t, s.resolveBackendPIN())

	require.NoError(t, s.startPKCS11AfterUnseal())
	require.Len(t, *opened, 1)
	require.True(t, bytes.Equal(pin, (*opened)[0]), "backend opened with the released PIN")
	_, started := s.keyProviders["pkcs11"]
	require.True(t, started)

	// A PIN supplied with the unseal request is refused for sealed.
	require.ErrorIs(t, s.UnsealBackendPIN(context.Background(), []byte("other")), pinselect.ErrBackendPINNotManual)
}

// The plaintext copy handed to the opener is wiped once the opener
// returns, on success and on failure (docs/SPEC.md:78 zeroization).
func TestOpenPKCS11WithHeldPIN_WipesOpenerCopy(t *testing.T) {
	for _, fail := range []bool{false, true} {
		pin := []byte("backend-pin-1")
		s, _, _ := backendPINTestServer(t, "sealed", pin, false, true)
		require.NoError(t, s.resolveBackendPIN())
		var captured []byte
		s.pkcs11PINOpener = func(p []byte) (types.KeyProvider, error) {
			captured = p
			require.True(t, bytes.Equal(pin, p), "opener sees the PIN")
			if fail {
				return nil, errors.New("open failed")
			}
			return &fakePKCS11Provider{}, nil
		}
		err := s.startPKCS11AfterUnseal()
		if fail {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		require.Len(t, captured, len(pin))
		require.True(t, bytes.Equal(make([]byte, len(pin)), captured), "opener copy wiped (fail=%v)", fail)
	}
}

func TestStartPKCS11AfterUnseal_SealedWithoutPINFailsClosed(t *testing.T) {
	s, opened, _ := backendPINTestServer(t, "sealed", nil, false, true)
	require.NoError(t, s.resolveBackendPIN())

	require.Error(t, s.startPKCS11AfterUnseal())
	require.Empty(t, *opened)
}

func TestManualBackendPIN_FromUnsealRequestNeverPersistedStopsAtSeal(t *testing.T) {
	s, opened, providers := backendPINTestServer(t, "manual", nil, false, true)
	require.NoError(t, s.resolveBackendPIN())
	require.Equal(t, "manual", s.BackendPINStrategy())

	// Manual: the backend does not start at boot.
	require.NoError(t, s.startPKCS11AfterUnseal())
	require.Empty(t, *opened)

	// The unseal request must carry the PIN.
	require.ErrorIs(t, s.UnsealBackendPIN(context.Background(), nil), pinselect.ErrBackendPINRequired)

	supplied := []byte("operator-pin-1")
	require.NoError(t, s.UnsealBackendPIN(context.Background(), supplied))
	require.Len(t, *opened, 1)
	require.True(t, bytes.Equal(supplied, (*opened)[0]))
	_, started := s.keyProviders["pkcs11"]
	require.True(t, started)

	// Never persisted: the PIN directory holds the strategy record only.
	entries, err := os.ReadDir(filepath.Join(s.config.Datastore.Path, "pin"))
	require.NoError(t, err)
	for _, e := range entries {
		require.Equal(t, filepath.Base(pinselect.BackendPINStrategyPath("")), e.Name())
		data, readErr := os.ReadFile(filepath.Join(s.config.Datastore.Path, "pin", e.Name()))
		require.NoError(t, readErr)
		require.False(t, bytes.Contains(data, supplied), "manual PIN is never written to disk")
	}

	// Seal: the backend stops and the PIN is zeroized.
	require.NoError(t, s.SealBackendPIN())
	require.Len(t, *providers, 1)
	require.True(t, (*providers)[0].closed)
	_, started = s.keyProviders["pkcs11"]
	require.False(t, started)
	_, pinErr := s.backendPIN.PIN()
	require.Error(t, pinErr)
}

func TestSealBackendPIN_SealedKeepsBackendRunning(t *testing.T) {
	s, _, providers := backendPINTestServer(t, "sealed", []byte("backend-pin-1"), false, true)
	require.NoError(t, s.resolveBackendPIN())
	require.NoError(t, s.startPKCS11AfterUnseal())

	require.NoError(t, s.SealBackendPIN())
	require.False(t, (*providers)[0].closed)
	_, pinErr := s.backendPIN.PIN()
	require.Error(t, pinErr, "the released PIN copy is zeroized at seal")
}

// Shutdown zeroizes the held backend PIN and closes the PKCS#11 provider
// exactly once, under both strategies that hold a PIN (#2262).
func TestShutdown_ZeroizesBackendPINClosesProviderOnce(t *testing.T) {
	for _, strategy := range []string{"sealed", "manual"} {
		t.Run(strategy, func(t *testing.T) {
			var pin []byte
			if strategy == "sealed" {
				pin = []byte("backend-pin-1")
			}
			s, _, providers := backendPINTestServer(t, strategy, pin, false, true)
			ctx, cancel := context.WithCancel(context.Background())
			s.ctx, s.cancel = ctx, cancel
			s.logger = slog.New(slog.DiscardHandler)
			s.shutdownCh = make(chan struct{})
			require.NoError(t, s.resolveBackendPIN())
			require.NoError(t, s.startPKCS11AfterUnseal())
			if strategy == "manual" {
				require.NoError(t, s.UnsealBackendPIN(context.Background(), []byte("operator-pin-1")))
			}
			_, pinErr := s.backendPIN.PIN()
			require.NoError(t, pinErr, "PIN held before shutdown")
			require.Len(t, *providers, 1)

			_ = s.Shutdown()

			_, pinErr = s.backendPIN.PIN()
			require.Error(t, pinErr, "PIN zeroized at shutdown")
			require.Equal(t, 1, (*providers)[0].closes, "PKCS#11 provider closed exactly once")
		})
	}
}
