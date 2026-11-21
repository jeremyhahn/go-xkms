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
}

func (f *fakePKCS11Provider) Close() error {
	f.closed = true
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
