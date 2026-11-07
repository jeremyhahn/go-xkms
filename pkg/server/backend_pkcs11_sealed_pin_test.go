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

//go:build pkcs11 && tpm_simulator

package server

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	"github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
	"github.com/jeremyhahn/go-xkms/pkg/preseal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// sealedPINServer builds a *Server whose pkcs11 backend has no configured
// PIN and whose node TPM is an in-process simulator, the state
// `xkmsd seal-pkcs11-pin` leaves behind. When pin is non-empty it is sealed
// into the pre-barrier store first. The simulator is a process-wide
// singleton, so these tests never run in parallel.
func sealedPINServer(t *testing.T, token softhsmtest.Token, pin string) *Server {
	t.Helper()
	tpm, err := tpm2backend.NewBackend(&tpm2backend.Config{
		UseSimulator:    true,
		Keys:            tpmblobtest.New(t),
		CN:              "server-sealed-pin",
		PlatformPCRs:    pkgtpm2.DefaultPlatformPCRs(),
		PlatformPCRBank: pkgtpm2.PCRBankSHA256,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, tpm.Close()) })

	s := &Server{
		config: &config.Config{
			Datastore: config.DatastoreConfig{Path: t.TempDir()},
			Backends: config.BackendsConfig{PKCS11: &config.PKCS11Config{
				Enabled: true,
				Library: token.Library,
				Token:   token.Label,
			}},
		},
		backends:     make(map[string]xkms.Backend),
		keyProviders: make(map[string]types.KeyProvider),
		logger:       slog.Default(),
		nodeSealTPM:  tpm,
	}
	s.setSharedStorage(storage.NewMemory())

	dir, err := embeddednode.ResolvePresealDir(s.config)
	require.NoError(t, err)
	store, err := preseal.Open(tpm.TPM(), dir, nil)
	require.NoError(t, err)
	if pin != "" {
		require.NoError(t, store.Put(context.Background(), preseal.PKCS11PIN, []byte(pin)))
	}
	require.NoError(t, store.Close())
	return s
}

func TestInitPKCS11Backend_UsesTheSealedPIN(t *testing.T) {
	token := softhsmtest.Provision(t, "server-backend-sealed-pin")
	s := sealedPINServer(t, token, token.UserPIN)

	require.NoError(t, s.initPKCS11Backend())
	opened := s.keyProviders["pkcs11"]
	require.NotNil(t, opened, "the backend must open with the PIN seal-pkcs11-pin sealed")
	assert.NoError(t, opened.Close())
}

func TestInitPKCS11Backend_NoSealedPINKeepsTheMissingPINAnswer(t *testing.T) {
	token := softhsmtest.Provision(t, "server-backend-no-sealed-pin")
	s := sealedPINServer(t, token, "")

	err := s.initPKCS11Backend()
	var createErr *ErrBackendCreate
	require.True(t, errors.As(err, &createErr), "error = %v, want *ErrBackendCreate", err)
	assert.ErrorIs(t, err, pkcs11.ErrInvalidUserPIN)
	assert.Empty(t, s.keyProviders)
}

func TestInitPKCS11Backend_SealedPINReleaseFailureRefuses(t *testing.T) {
	token := softhsmtest.Provision(t, "server-backend-sealed-pin-store")
	s := sealedPINServer(t, token, token.UserPIN)
	s.config.Datastore.Path = ""

	err := s.initPKCS11Backend()
	var initErr *ErrBackendInit
	require.True(t, errors.As(err, &initErr), "error = %v, want *ErrBackendInit", err)
	var pathErr *embeddednode.ErrDatastorePathRequired
	assert.True(t, errors.As(err, &pathErr), "error = %v, want ErrDatastorePathRequired", err)
	assert.Empty(t, s.keyProviders)
}
