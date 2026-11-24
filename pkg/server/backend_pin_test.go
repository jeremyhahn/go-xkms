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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	qrdbsecret "github.com/jeremyhahn/go-qrdb/pkg/secret"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/pinselect"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
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
	// The PIN is stored under the barrier unless a test says otherwise:
	// sealed needs barrier-backed credential storage.
	cfg.Credentials.SealStrategy = "barrier"
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
	for _, seal := range []string{"", "barrier", "manual", "awskms"} {
		s, _, _ := backendPINTestServer(t, "tpm2", []byte("backend-pin-1"), true, true)
		s.config.BackendPIN.Minimum = "tpm2"
		s.config.Credentials.SealStrategy = seal
		err := s.resolveBackendPIN()
		var store *pinselect.BackendPINStoreError
		require.True(t, errors.As(err, &store), "seal_strategy %q: err = %v", seal, err)
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

// auto selects tpm2 whenever a TPM 2.0 is present (docs/SPEC.md:78), and
// never the weaker sealed: a TPM host whose PIN is stored under the barrier
// is refused before a record is persisted, not downgraded to sealed.
func TestResolveBackendPIN_AutoWithTPMSelectsTPM2(t *testing.T) {
	s, _, _ := backendPINTestServer(t, "auto", []byte("backend-pin-1"), true, true)
	s.config.Credentials.SealStrategy = "tpm2"
	require.NoError(t, s.resolveBackendPIN())
	require.Equal(t, "tpm2", s.BackendPINStrategy())
	persisted, err := pinselect.LoadBackendPINStrategy(s.backendPINDir())
	require.NoError(t, err)
	require.Equal(t, pinselect.BackendPINTPM2, persisted)
}

// backendPINSimulatorTPM configures s with a TPM 2.0 simulator
// (backends.tpm2 use_simulator) the backend PIN can be sealed to, and
// closes the TPM the server opens for it when the test ends.
func backendPINSimulatorTPM(t *testing.T, s *Server) {
	t.Helper()
	s.logger = slog.New(slog.DiscardHandler)
	s.config.Backends.TPM2 = &config.TPM2Config{Enabled: true, UseSimulator: true}
	t.Cleanup(func() {
		if s.platformStoreTPMClose != nil {
			_ = s.platformStoreTPMClose()
		}
	})
}

// skipWithoutTPMSimulator skips when the build has no TPM simulator (no
// tpm_simulator tag): the TPM seal then cannot run at all.
func skipWithoutTPMSimulator(t *testing.T, err error) {
	t.Helper()
	// pkg/tpm2's ErrSimulatorNotAvailable exists only without the tag.
	if err != nil && strings.Contains(err.Error(), "build with -tags tpm_simulator") {
		t.Skip("needs the tpm_simulator build tag")
	}
}

// TestResolveBackendPIN_AutoWithTPMAndBarrierStoreSealsToTPM proves auto
// (and tpm2) on a TPM host start as tpm2 whatever credentials.seal_strategy
// is: the configured PIN, stored under the barrier, is sealed to the TPM
// and every release unseals it from there (Codex round 1, finding 3).
func TestResolveBackendPIN_AutoWithTPMAndBarrierStoreSealsToTPM(t *testing.T) {
	for _, strategy := range []string{"auto", "tpm2"} {
		t.Run(strategy, func(t *testing.T) {
			ctx := context.Background()
			pin := []byte("backend-pin-1")
			s, opened, _ := backendPINTestServer(t, strategy, nil, true, true)
			require.Equal(t, "barrier", s.config.Credentials.SealStrategy)
			backendPINSimulatorTPM(t, s)
			creds := newFakeBackendPINCredentials(map[string][]byte{"pkcs11-pin": pin})
			s.backendPINCredentials = creds
			s.config.Backends.PKCS11.Pin = creds.resolve(t, "pkcs11-pin")

			err := s.resolveBackendPIN()
			skipWithoutTPMSimulator(t, err)
			require.NoError(t, err)
			require.Empty(t, s.BackendPINStrategy(), "tpm2 is not reported while the barrier copy exists")
			persisted, err := pinselect.LoadBackendPINStrategy(s.backendPINDir())
			require.NoError(t, err)
			require.Equal(t, pinselect.BackendPINTPM2, persisted)

			require.NoError(t, s.startPKCS11AfterUnseal())
			require.Len(t, *opened, 1)
			require.True(t, bytes.Equal(pin, (*opened)[0]), "backend opened with the configured PIN")
			require.Equal(t, "tpm2", s.BackendPINStrategy())

			// The server keeps the TPM-sealed copy, not the plaintext: with
			// the configured PIN gone, the next release still unseals the
			// same PIN from the TPM.
			require.NoError(t, s.SealBackendPIN())
			s.config.Backends.PKCS11.Pin = nil
			require.NoError(t, s.backendPIN.Unseal(ctx, nil))
			got, err := s.backendPIN.PIN()
			require.NoError(t, err)
			require.True(t, bytes.Equal(pin, got), "released PIN unsealed from the TPM")
		})
	}
}

// fakeBackendPINCredentials is a barrier-backed credential store: the
// values resolution reads for credential:// references.
type fakeBackendPINCredentials struct {
	mu        sync.Mutex
	values    map[string][]byte
	stores    int
	failStore map[string]bool
	// failDelete makes DeleteCredential of a name fail, leaving it stored.
	failDelete map[string]bool
}

func newFakeBackendPINCredentials(values map[string][]byte) *fakeBackendPINCredentials {
	f := &fakeBackendPINCredentials{values: map[string][]byte{}, failStore: map[string]bool{}, failDelete: map[string]bool{}}
	for name, v := range values {
		f.values[name] = append([]byte(nil), v...)
	}
	return f
}

func (f *fakeBackendPINCredentials) StoreCredential(_ context.Context, name string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stores++
	if f.failStore[name] {
		return errors.New("fake credential store: store refused")
	}
	f.values[name] = append([]byte(nil), value...)
	return nil
}

func (f *fakeBackendPINCredentials) DeleteCredential(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDelete[name] {
		return errors.New("fake credential store: delete refused")
	}
	delete(f.values, name)
	return nil
}

func (f *fakeBackendPINCredentials) ListCredentials(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(f.values))
	for name := range f.values {
		names = append(names, name)
	}
	return names, nil
}

func (f *fakeBackendPINCredentials) RetrieveCredentialBuffer(_ context.Context, name string) (*secure.Buffer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.values[name]
	if !ok {
		return nil, errors.New("fake credential store: not found")
	}
	return secure.NewBufferFromBytes(append([]byte(nil), v...))
}

// has reports whether name is stored.
func (f *fakeBackendPINCredentials) has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.values[name]
	return ok
}

func (f *fakeBackendPINCredentials) value(name string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.values[name]...)
}

func (f *fakeBackendPINCredentials) storeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stores
}

// resolve returns the SecretValue config resolution yields for
// credential://name from the store's current value.
func (f *fakeBackendPINCredentials) resolve(t *testing.T, name string) *types.SecretValue {
	t.Helper()
	v, err := qrdbsecret.NewSecretValue(context.Background(), "credential://"+name, f.value(name), qrdbsecret.StrategyCredential)
	require.NoError(t, err)
	return v
}

// With credentials.seal_strategy: barrier and backend_pin.minimum: tpm2 the
// PIN moves into TPM custody: the barrier credential holds only the
// TPM-sealed blob after the first start, and a second start unseals that
// blob without sealing again. A PIN whose weaker copy cannot be removed is
// refused at start-up.
func TestResolveBackendPIN_TPM2MinimumLeavesNoBarrierPINCopy(t *testing.T) {
	pin := []byte("backend-pin-1")
	s, opened, _ := backendPINTestServer(t, "", nil, true, true)
	s.config.BackendPIN.Minimum = "tpm2"
	backendPINSimulatorTPM(t, s)
	creds := newFakeBackendPINCredentials(map[string][]byte{"pkcs11-pin": pin})
	s.backendPINCredentials = creds
	s.config.Backends.PKCS11.Pin = creds.resolve(t, "pkcs11-pin")

	err := s.resolveBackendPIN()
	skipWithoutTPMSimulator(t, err)
	require.NoError(t, err)
	require.NoError(t, s.startPKCS11AfterUnseal())
	require.Len(t, *opened, 1)
	require.True(t, bytes.Equal(pin, (*opened)[0]), "backend opened with the configured PIN")
	require.Equal(t, "tpm2", s.BackendPINStrategy())

	stored := creds.value("pkcs11-pin")
	require.NotEmpty(t, stored, "the credential holds the TPM-sealed blob")
	require.False(t, bytes.Contains(stored, pin), "no barrier-stored plaintext PIN copy is left")
	require.False(t, creds.has(backendPINCustodyJournal("pkcs11-pin")), "no staging credential is left after the migration")
	storesAfterFirst := creds.storeCount()

	// Second start: resolution reads the sealed blob; the release unseals
	// it from the TPM and seals nothing again.
	require.NoError(t, s.SealBackendPIN())
	s.backendPIN = nil
	delete(s.keyProviders, "pkcs11")
	s.config.Backends.PKCS11.Pin = creds.resolve(t, "pkcs11-pin")
	require.NoError(t, s.resolveBackendPIN())
	require.NoError(t, s.startPKCS11AfterUnseal())
	require.Len(t, *opened, 2)
	require.True(t, bytes.Equal(pin, (*opened)[1]), "second start opened with the PIN unsealed from the TPM")
	require.Equal(t, storesAfterFirst, creds.storeCount(), "no re-seal from a barrier copy")
	require.Equal(t, stored, creds.value("pkcs11-pin"))
	require.Equal(t, "tpm2", s.BackendPINStrategy())

	// A PIN that is not a credential:// reference keeps a copy the server
	// cannot remove: refused at start-up, nothing opened.
	s2, opened2, _ := backendPINTestServer(t, "", pin, true, true)
	s2.config.BackendPIN.Minimum = "tpm2"
	s2.logger = s.logger
	s2.platformStoreTPM = s.platformStoreTPM // the simulator s opened
	err = s2.resolveBackendPIN()
	var custody *BackendPINTPMCustodyError
	require.ErrorAs(t, err, &custody)
	require.Nil(t, s2.backendPIN)
	require.Empty(t, *opened2)
}

// The TPM custody migration replaces the barrier-stored plaintext PIN with
// its TPM-sealed envelope. Interrupted at any write, the PIN stays
// recoverable (the plaintext under name, or the envelope under name or the
// staging credential), and the start-up recovery completes the migration
// without any plaintext copy left.
func TestReplaceBackendPINCredential_InterruptedMigrationRecoverable(t *testing.T) {
	const name = "pkcs11-pin"
	staging := backendPINCustodyJournal(name)
	pin := []byte("backend-pin-1")
	blob := &types.SealedData{Backend: types.BackendType("tpm2"), TPMPublic: []byte("dummy-public"), TPMPrivate: []byte("dummy-private")}
	ctx := context.Background()

	for _, tc := range []struct {
		name       string
		failStore  string
		failDelete string
	}{
		{name: "store of name fails (and the restore with it)", failStore: name},
		{name: "delete of name fails", failDelete: name},
		{name: "store of staging fails", failStore: staging},
		{name: "delete of staging fails", failDelete: staging},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := backendPINTestServer(t, "", nil, true, true)
			creds := newFakeBackendPINCredentials(map[string][]byte{name: pin})
			s.backendPINCredentials = creds
			s.config.Backends.PKCS11.Pin = creds.resolve(t, name)
			p := s.primaryBackendPINSecret()
			if tc.failStore != "" {
				creds.failStore[tc.failStore] = true
			}
			if tc.failDelete != "" {
				creds.failDelete[tc.failDelete] = true
			}

			_ = s.replaceBackendPINCredential(ctx, p, append([]byte(nil), pin...), blob)

			recoverable := bytes.Equal(creds.value(name), pin) ||
				bytes.HasPrefix(creds.value(name), []byte(backendPINTPMEnvelope)) ||
				bytes.HasPrefix(creds.value(staging), []byte(backendPINTPMEnvelope))
			require.True(t, recoverable, "the PIN must stay recoverable after an interrupted migration")
			require.False(t, creds.has(staging) && bytes.Contains(creds.value(staging), pin),
				"the staging credential never holds the plaintext PIN")

			creds.failStore = map[string]bool{}
			creds.failDelete = map[string]bool{}
			require.NoError(t, s.recoverBackendPINCustody(ctx))
			if bytes.Equal(creds.value(name), pin) {
				// Interrupted before the plaintext was removed: the next
				// release migrates it again from the start.
				require.NoError(t, s.replaceBackendPINCredential(ctx, p, append([]byte(nil), pin...), blob))
			}
			require.True(t, bytes.HasPrefix(creds.value(name), []byte(backendPINTPMEnvelope)), "name holds the TPM-sealed envelope")
			require.False(t, creds.has(staging), "the staging credential is removed")
			for _, n := range []string{name, staging} {
				require.False(t, bytes.Contains(creds.value(n), pin), "no stored value holds the plaintext PIN")
			}
		})
	}
}

// distinctPINsServer is a tpm2 server with distinct key backend and RNG
// PKCS#11 PINs, both credential:// references under barrier storage.
func distinctPINsServer(t *testing.T, keyPIN, rngPIN []byte) (*Server, *fakeBackendPINCredentials, *[][]byte) {
	t.Helper()
	s, opened, _ := backendPINTestServer(t, "tpm2", nil, true, true)
	creds := newFakeBackendPINCredentials(map[string][]byte{"pkcs11-pin": keyPIN, "rng-pin": rngPIN})
	s.backendPINCredentials = creds
	s.config.Backends.PKCS11.Pin = creds.resolve(t, "pkcs11-pin")
	s.config.RNG.Mode = "pkcs11"
	s.config.RNG.PKCS11 = &config.RNGPKCS11Config{PINRequired: true, PIN: creds.resolve(t, "rng-pin")}
	return s, creds, opened
}

// TestRecoverBackendPINCustody_IgnoresOperatorCredentialNamedLikeTheJournal
// proves the custody journal lives outside the operator credential
// namespace: an operator credential that happens to be named like the old
// journal is neither treated as an interrupted migration nor overwritten.
func TestRecoverBackendPINCustody_IgnoresOperatorCredentialNamedLikeTheJournal(t *testing.T) {
	const name = "pkcs11-pin"
	const operatorName = "pkcs11-pin-tpm2-staged"
	pin := []byte("backend-pin-1")
	operatorValue := []byte("operator-value")
	blob := &types.SealedData{Backend: types.BackendType("tpm2"), TPMPublic: []byte("dummy-public"), TPMPrivate: []byte("dummy-private")}
	ctx := context.Background()

	newServer := func(t *testing.T) (*Server, *fakeBackendPINCredentials) {
		t.Helper()
		s, _, _ := backendPINTestServer(t, "sealed", nil, false, true)
		s.config.Credentials.SealStrategy = "barrier"
		creds := newFakeBackendPINCredentials(map[string][]byte{
			name:         append([]byte(nil), pin...),
			operatorName: append([]byte(nil), operatorValue...),
		})
		s.backendPINCredentials = creds
		s.config.Backends.PKCS11.Pin = creds.resolve(t, name)
		return s, creds
	}

	s, creds := newServer(t)
	require.NoError(t, s.recoverBackendPINCustody(ctx))
	require.Equal(t, pin, creds.value(name), "recovery leaves the PIN credential unchanged")
	require.Equal(t, operatorValue, creds.value(operatorName), "recovery leaves the operator credential unchanged")

	s, creds = newServer(t)
	p := s.primaryBackendPINSecret()
	require.NoError(t, s.replaceBackendPINCredential(ctx, p, append([]byte(nil), pin...), blob))
	require.True(t, bytes.HasPrefix(creds.value(name), []byte(backendPINTPMEnvelope)), "name holds the TPM-sealed envelope")
	require.Equal(t, operatorValue, creds.value(operatorName), "the migration leaves the operator credential unchanged")
	require.False(t, creds.has(backendPINCustodyJournal(name)), "no custody journal is left after the migration")
}

// Distinct backends.pkcs11.pin and rng.pkcs11.pin both enter the PIN
// lifecycle: each is sealed to the TPM in its own credential and held,
// and the strategy is not reported while either is not in TPM custody.
func TestResolveBackendPIN_DistinctBackendAndRNGPINsBothEnterLifecycle(t *testing.T) {
	keyPIN, rngPIN := []byte("backend-pin-1"), []byte("rng-pin-2")
	s, creds, opened := distinctPINsServer(t, keyPIN, rngPIN)
	backendPINSimulatorTPM(t, s)

	err := s.resolveBackendPIN()
	skipWithoutTPMSimulator(t, err)
	require.NoError(t, err)
	require.NotNil(t, s.rngBackendPIN, "the RNG PIN has its own holder")
	require.NoError(t, s.startPKCS11AfterUnseal())
	require.Len(t, *opened, 1)
	require.True(t, bytes.Equal(keyPIN, (*opened)[0]), "key backend opened with its own PIN")
	got, err := s.rngBackendPIN.PIN()
	require.NoError(t, err)
	require.True(t, bytes.Equal(rngPIN, got), "RNG PIN held")
	for name, pin := range map[string][]byte{"pkcs11-pin": keyPIN, "rng-pin": rngPIN} {
		stored := creds.value(name)
		require.NotEmpty(t, stored, name)
		require.False(t, bytes.Contains(stored, pin), "%s holds only its TPM-sealed blob", name)
	}
	require.Equal(t, "tpm2", s.BackendPINStrategy())

	// The RNG PIN cannot move into TPM custody: start-up fails closed and
	// tpm2 is not reported.
	s2, creds2, _ := distinctPINsServer(t, keyPIN, rngPIN)
	s2.logger = s.logger
	s2.platformStoreTPM = s.platformStoreTPM // the simulator s opened
	creds2.failStore["rng-pin"] = true
	require.NoError(t, s2.resolveBackendPIN())
	err = s2.startPKCS11AfterUnseal()
	var custody *BackendPINTPMCustodyError
	require.ErrorAs(t, err, &custody)
	require.Equal(t, "rng.pkcs11.pin", custody.Field)
	require.Empty(t, s2.BackendPINStrategy(), "status not satisfied while the RNG PIN is not in TPM custody")
}

// auto reads TPM 2.0 presence from the hardware probe, not from
// backends.tpm2.enabled: a TPM host with the tpm2 key backend disabled
// selects and persists tpm2, and a detected TPM that cannot seal the PIN
// fails closed with nothing persisted (never sealed).
func TestResolveBackendPIN_AutoSelectsTPM2OnTPMPresenceWithTPM2BackendDisabled(t *testing.T) {
	s, _, _ := backendPINTestServer(t, "auto", []byte("backend-pin-1"), false, true)
	s.backendPINProbe = nil
	s.barrier = backendPINUnsealedBarrier(t)
	s.config.Backends.TPM2 = &config.TPM2Config{Enabled: false}
	s.tpmDeviceProbe = func() bool { return true }
	s.config.Credentials.SealStrategy = "tpm2"
	require.NoError(t, s.resolveBackendPIN())
	require.Equal(t, "tpm2", s.BackendPINStrategy())
	persisted, err := pinselect.LoadBackendPINStrategy(s.backendPINDir())
	require.NoError(t, err)
	require.Equal(t, pinselect.BackendPINTPM2, persisted)

	// Detected TPM, PIN under the barrier, but no usable TPM sealer.
	s2, opened, _ := backendPINTestServer(t, "auto", []byte("backend-pin-1"), false, true)
	s2.logger = slog.New(slog.DiscardHandler)
	s2.backendPINProbe = nil
	s2.barrier = backendPINUnsealedBarrier(t)
	s2.config.Backends.TPM2 = &config.TPM2Config{Enabled: false}
	s2.tpmDeviceProbe = func() bool { return true }
	err = s2.resolveBackendPIN()
	var sealerErr *BackendPINTPMSealerError
	require.ErrorAs(t, err, &sealerErr)
	require.Nil(t, s2.backendPIN)
	require.Empty(t, *opened)
	_, statErr := os.Stat(pinselect.BackendPINStrategyPath(s2.backendPINDir()))
	require.ErrorIs(t, statErr, os.ErrNotExist, "nothing persisted")
}

// The backend PIN policy refuses before config secret resolution: a
// manual strategy, or a strategy its credential storage does not provide,
// never waits on a credential:// PIN reference that cannot resolve.
func requireAutoPreflightRefusal(t *testing.T, err error) {
	t.Helper()
	var unavailable *pinselect.BackendPINUnavailableError
	var custody *BackendPINTPMCustodyError
	require.True(t, errors.As(err, &unavailable) || errors.As(err, &custody),
		"error = %v, want BackendPINUnavailableError or BackendPINTPMCustodyError", err)
}

func TestNew_BackendPINPolicyRefusesBeforeResolvingCredentialReference(t *testing.T) {
	for _, tc := range []struct {
		strategy string
		check    func(t *testing.T, err error)
	}{
		{"manual", func(t *testing.T, err error) {
			require.ErrorIs(t, err, ErrBackendPINManualUnavailable)
		}},
		// Seal is off: sealed has no barrier to store the PIN under.
		{"sealed", func(t *testing.T, err error) {
			var unavailable *pinselect.BackendPINUnavailableError
			require.ErrorAs(t, err, &unavailable)
			require.Equal(t, "no barrier", unavailable.Reason)
		}},
		// Default (manual) credential storage cannot move the PIN into
		// TPM custody.
		{"tpm2", func(t *testing.T, err error) {
			var custody *BackendPINTPMCustodyError
			require.ErrorAs(t, err, &custody)
		}},
		// Default and auto: sealed without a barrier, or tpm2 with the PIN
		// outside TPM custody, depending on a host TPM; nothing else.
		{"", requireAutoPreflightRefusal},
		{"auto", requireAutoPreflightRefusal},
	} {
		t.Run(tc.strategy, func(t *testing.T) {
			xkms.Reset()
			defer xkms.Reset()
			cfg := createMinimalConfig(t)
			cfg.Backends.PKCS11 = &config.PKCS11Config{
				Enabled: true,
				Library: "/usr/lib/softhsm/libsofthsm2.so",
				Token:   "test",
				Pin:     &types.SecretValue{Raw: "credential://pkcs11-pin"},
			}
			cfg.BackendPIN.Strategy = tc.strategy

			done := make(chan error, 1)
			go func() {
				srv, err := New(cfg)
				if srv != nil {
					_ = srv.Shutdown()
				}
				done <- err
			}()
			select {
			case err := <-done:
				tc.check(t, err)
			case <-time.After(20 * time.Second):
				t.Fatal("New waited on the credential reference before the backend PIN policy refused")
			}
		})
	}
}

// The preflight derives what auto (or a persisted record) selects, so a
// default or auto configuration that resolveBackendPIN would refuse is
// refused before config secret resolution waits on a credential:// PIN.
// It persists nothing and never refuses an accepted configuration.
func TestBackendPINPolicyPreflight_DefaultAndAutoUseTheEffectiveStrategy(t *testing.T) {
	unresolved := func(s *Server) {
		s.config.Credentials.SealStrategy = ""
		s.config.Backends.PKCS11.Pin = &types.SecretValue{Raw: "credential://pkcs11-pin"}
	}
	requireNotPersisted := func(t *testing.T, s *Server) {
		t.Helper()
		_, err := pinselect.LoadBackendPINStrategy(s.backendPINDir())
		require.ErrorIs(t, err, pinselect.ErrBackendPINStrategyNotPersisted)
	}
	for _, strategy := range []string{"", "auto"} {
		t.Run("strategy="+strategy, func(t *testing.T) {
			t.Run("tpm", func(t *testing.T) {
				s, _, _ := backendPINTestServer(t, strategy, nil, true, true)
				unresolved(s)
				err := s.backendPINPolicyPreflight()
				var custody *BackendPINTPMCustodyError
				require.ErrorAs(t, err, &custody)
				requireNotPersisted(t, s)
			})
			t.Run("barrier", func(t *testing.T) {
				s, _, _ := backendPINTestServer(t, strategy, nil, false, true)
				unresolved(s)
				err := s.backendPINPolicyPreflight()
				var storeErr *pinselect.BackendPINStoreError
				require.ErrorAs(t, err, &storeErr)
				require.Equal(t, pinselect.BackendPINSealed, storeErr.Strategy)
				require.Equal(t, pinselect.BackendPINManual, storeErr.Store)
				requireNotPersisted(t, s)
			})
			t.Run("neither", func(t *testing.T) {
				s, _, _ := backendPINTestServer(t, strategy, nil, false, false)
				unresolved(s)
				err := s.backendPINPolicyPreflight()
				var unavailable *pinselect.BackendPINUnavailableError
				require.ErrorAs(t, err, &unavailable)
				requireNotPersisted(t, s)
			})
		})
	}

	t.Run("persisted tpm2 record", func(t *testing.T) {
		s, _, _ := backendPINTestServer(t, "auto", nil, true, true)
		unresolved(s)
		require.NoError(t, pinselect.SaveBackendPINStrategy(s.backendPINDir(), pinselect.BackendPINTPM2))
		err := s.backendPINPolicyPreflight()
		var custody *BackendPINTPMCustodyError
		require.ErrorAs(t, err, &custody)
	})

	// No false refusal: configurations resolveBackendPIN accepts pass.
	for _, tpm := range []bool{false, true} {
		t.Run("accepted tpm="+strconv.FormatBool(tpm), func(t *testing.T) {
			s, _, _ := backendPINTestServer(t, "auto", nil, tpm, true)
			s.config.Backends.PKCS11.Pin = &types.SecretValue{Raw: "credential://pkcs11-pin"}
			s.backendPINCredentials = newFakeBackendPINCredentials(map[string][]byte{"pkcs11-pin": []byte("backend-pin-1")})
			require.NoError(t, s.backendPINPolicyPreflight())
			requireNotPersisted(t, s)
		})
	}
}

// TestResolveBackendPIN_AutoWithTPMWithoutTPMSealerFailsClosed proves a TPM
// the PIN cannot be sealed to refuses start-up with a typed error, never
// falling back to sealed, and persists nothing.
func TestResolveBackendPIN_AutoWithTPMWithoutTPMSealerFailsClosed(t *testing.T) {
	// The probe reports a TPM, but backends.tpm2 is not configured.
	s, _, _ := backendPINTestServer(t, "auto", []byte("backend-pin-1"), true, true)
	s.logger = slog.New(slog.DiscardHandler)
	err := s.resolveBackendPIN()
	var sealer *BackendPINTPMSealerError
	require.True(t, errors.As(err, &sealer), "err = %v", err)
	var store *pinselect.BackendPINStoreError
	require.True(t, errors.As(err, &store), "err = %v", err)
	require.Equal(t, pinselect.BackendPINTPM2, store.Strategy)
	require.Equal(t, "", s.BackendPINStrategy())
	_, statErr := os.Stat(pinselect.BackendPINStrategyPath(s.backendPINDir()))
	require.True(t, os.IsNotExist(statErr), "no sealed record persisted on a TPM host")

	// sealed with a TPM-only store stays refused.
	s, _, _ = backendPINTestServer(t, "sealed", []byte("backend-pin-1"), true, true)
	s.config.Credentials.SealStrategy = "tpm2"
	require.True(t, errors.As(s.resolveBackendPIN(), &store))
	require.Equal(t, pinselect.BackendPINSealed, store.Strategy)
}

// sealed needs barrier-backed credential storage: a PIN stored elsewhere
// (a cloud seal, the manual default) is refused before a record is
// persisted, a persisted sealed record is refused once the storage changed,
// and a release re-checks the storage.
func TestResolveBackendPIN_SealedRequiresBarrierCredentialStorage(t *testing.T) {
	for _, seal := range []string{"", "manual", "awskms", "tpm2"} {
		s, opened, _ := backendPINTestServer(t, "sealed", []byte("backend-pin-1"), false, true)
		s.config.Credentials.SealStrategy = seal
		var store *pinselect.BackendPINStoreError
		require.True(t, errors.As(s.resolveBackendPIN(), &store), "seal_strategy %q", seal)
		require.Equal(t, pinselect.BackendPINSealed, store.Strategy)
		require.Equal(t, "", s.BackendPINStrategy())
		require.Empty(t, *opened)
		_, statErr := os.Stat(pinselect.BackendPINStrategyPath(s.backendPINDir()))
		require.True(t, os.IsNotExist(statErr), "nothing persisted for seal_strategy %q", seal)
	}

	// A persisted sealed record does not survive a storage change on restart.
	s, _, _ := backendPINTestServer(t, "auto", []byte("backend-pin-1"), false, true)
	require.NoError(t, s.resolveBackendPIN())
	require.Equal(t, "sealed", s.BackendPINStrategy())
	dir := s.backendPINDir()
	restarted, opened, _ := backendPINTestServer(t, "auto", []byte("backend-pin-1"), false, true)
	restarted.config.Datastore.Path = s.config.Datastore.Path
	require.Equal(t, dir, restarted.backendPINDir())
	restarted.config.Credentials.SealStrategy = "awskms"
	var store *pinselect.BackendPINStoreError
	require.True(t, errors.As(restarted.resolveBackendPIN(), &store), "persisted sealed refused after the storage changed")
	require.Empty(t, *opened)

	// The release re-checks the storage the strategy asserts.
	s, opened, _ = backendPINTestServer(t, "sealed", []byte("backend-pin-1"), false, true)
	require.NoError(t, s.resolveBackendPIN())
	s.config.Credentials.SealStrategy = "awskms"
	err := s.startPKCS11AfterUnseal()
	require.ErrorIs(t, err, errBackendPINNotBarrierSealed)
	require.Empty(t, *opened)
}

// A barrier sealed by the PKCS#11 token would store the token's own PIN
// under the token: sealed is refused for barrier.strategy pkcs11 whatever
// credentials.seal_strategy is (docs/SPEC.md:78).
func TestResolveBackendPIN_SealedUnderPKCS11BarrierIsSelfStore(t *testing.T) {
	for _, credSeal := range []string{"barrier", ""} {
		s, opened, _ := backendPINTestServer(t, "sealed", []byte("backend-pin-1"), false, true)
		s.config.Barrier.Strategy = "pkcs11"
		s.config.Credentials.SealStrategy = credSeal
		require.ErrorIs(t, s.resolveBackendPIN(), pinselect.ErrBackendPINSelfStore, "seal_strategy=%q", credSeal)
		require.Nil(t, s.backendPIN)
		require.Empty(t, *opened)
		_, statErr := os.Stat(pinselect.BackendPINStrategyPath(s.backendPINDir()))
		require.ErrorIs(t, statErr, os.ErrNotExist, "nothing persisted")
	}
}

// PKCS#11 is never the store for its own PIN, but only sealed stores the PIN
// under the barrier: a PIN sealed to the TPM (credentials.seal_strategy tpm2)
// under barrier.strategy pkcs11 is not a self-store and resolves to tpm2,
// while sealed under the same barrier stays refused (docs/plans/2262.md).
func TestResolveBackendPIN_TPM2UnderPKCS11BarrierIsNotSelfStore(t *testing.T) {
	for _, strategy := range []string{"tpm2", "auto"} {
		s, opened, _ := backendPINTestServer(t, strategy, []byte("backend-pin-1"), true, true)
		s.config.Barrier.Strategy = "pkcs11"
		s.config.Credentials.SealStrategy = "tpm2"
		require.NoError(t, s.resolveBackendPIN(), "strategy=%q", strategy)
		require.Equal(t, "tpm2", s.BackendPINStrategy(), "strategy=%q", strategy)
		persisted, err := pinselect.LoadBackendPINStrategy(s.backendPINDir())
		require.NoError(t, err)
		require.Equal(t, pinselect.BackendPINTPM2, persisted, "strategy=%q", strategy)
		require.Empty(t, *opened, "strategy=%q", strategy)
	}

	s, opened, _ := backendPINTestServer(t, "sealed", []byte("backend-pin-1"), true, true)
	s.config.Barrier.Strategy = "pkcs11"
	s.config.Credentials.SealStrategy = "tpm2"
	require.ErrorIs(t, s.resolveBackendPIN(), pinselect.ErrBackendPINSelfStore)
	require.Nil(t, s.backendPIN)
	require.Empty(t, *opened)
}

// rngPKCS11PINServer is a backend PIN test server whose only PKCS#11 PIN is
// an active rng.pkcs11.pin: the PKCS#11 key backend is absent.
func rngPKCS11PINServer(t *testing.T, strategy string, pin []byte) (*Server, *[][]byte) {
	t.Helper()
	s, opened, _ := backendPINTestServer(t, strategy, nil, false, true)
	s.config.Backends.PKCS11 = nil
	pv, err := types.NewLiteralSecretValue(context.Background(), pin)
	require.NoError(t, err)
	s.config.RNG.Mode = "pkcs11"
	s.config.RNG.PKCS11 = &config.RNGPKCS11Config{PINRequired: true, PIN: pv}
	return s, opened
}

// The policy covers rng.pkcs11.pin on its own (docs/SPEC.md:78): with the
// key backend absent, an active RNG PIN is still resolved, persisted and
// held to the minimum.
func TestResolveBackendPIN_RNGPINWithoutKeyBackendEnforcesMinimum(t *testing.T) {
	s, _ := rngPKCS11PINServer(t, "sealed", []byte("rng-pin-1"))
	s.config.BackendPIN.Minimum = "tpm2"
	var below *pinselect.BackendPINBelowMinimumError
	require.True(t, errors.As(s.resolveBackendPIN(), &below), "minimum tpm2 enforced for the RNG PIN")
	require.Nil(t, s.backendPIN)
}

// An omitted rng.mode is auto (Config.GetRNGConfig, the RNG resolver), so
// an rng.pkcs11.pin under it is held to the policy like mode auto.
func TestResolveBackendPIN_RNGPINWithDefaultModeIsPolicyBound(t *testing.T) {
	s, _ := rngPKCS11PINServer(t, "sealed", []byte("rng-pin-1"))
	s.config.RNG.Mode = ""
	s.config.BackendPIN.Minimum = "tpm2"
	var below *pinselect.BackendPINBelowMinimumError
	require.True(t, errors.As(s.resolveBackendPIN(), &below), "minimum enforced for the RNG PIN under the default mode")
	require.Nil(t, s.backendPIN)

	s, _ = rngPKCS11PINServer(t, "", []byte("rng-pin-1"))
	s.config.RNG.Mode = ""
	require.NoError(t, s.resolveBackendPIN())
	require.Equal(t, "sealed", s.BackendPINStrategy())
	persisted, err := pinselect.LoadBackendPINStrategy(s.backendPINDir())
	require.NoError(t, err)
	require.Equal(t, pinselect.BackendPINSealed, persisted)
}

// An active RNG PIN gets the release/seal lifecycle: released after
// unseal, zeroized at seal; no PKCS#11 key backend is opened for it.
func TestResolveBackendPIN_RNGPINWithoutKeyBackendReleasedAndZeroized(t *testing.T) {
	pin := []byte("rng-pin-1")
	s, opened := rngPKCS11PINServer(t, "sealed", pin)
	require.NoError(t, s.resolveBackendPIN())
	require.Equal(t, "sealed", s.BackendPINStrategy())
	_, statErr := os.Stat(pinselect.BackendPINStrategyPath(s.backendPINDir()))
	require.NoError(t, statErr, "strategy persisted")

	require.NoError(t, s.startPKCS11AfterUnseal())
	held, err := s.backendPIN.PIN()
	require.NoError(t, err)
	require.True(t, bytes.Equal(pin, held), "RNG PIN released after unseal")
	clear(held)
	require.Empty(t, *opened, "no PKCS#11 key backend opened for the RNG PIN")

	require.NoError(t, s.SealBackendPIN())
	_, err = s.backendPIN.PIN()
	require.Error(t, err, "RNG PIN zeroized at seal")
}

// An RNG PIN that is not active (another RNG mode, or no PIN) resolves
// nothing.
func TestResolveBackendPIN_InactiveRNGPINIsNoOp(t *testing.T) {
	s, _ := rngPKCS11PINServer(t, "sealed", []byte("rng-pin-1"))
	s.config.RNG.Mode = "software"
	require.NoError(t, s.resolveBackendPIN())
	require.Equal(t, "", s.BackendPINStrategy())
}

func TestResolveBackendPIN_BelowMinimumFailsClosed(t *testing.T) {
	s, _, _ := backendPINTestServer(t, "sealed", []byte("backend-pin-1"), false, true)
	// No TPM: sealed sits below a tpm2 minimum (manual is refused outright).
	s.config.BackendPIN.Minimum = "tpm2"

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
	// resolveBackendPIN refuses manual for now (no unseal seam); the holder
	// lifecycle it would install is still kept correct.
	s.installBackendPIN(pinselect.BackendPINManual)
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
	if !errors.Is(err, os.ErrNotExist) {
		require.NoError(t, err)
	}
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

// Manual is refused until it can be operational (docs/SPEC.md:78): the
// go-qrdb unseal request carries no backend PIN and the xkms service has no
// late keystore registration. A manual strategy, a manual minimum, or a
// persisted manual record fails closed at resolution with a named error,
// before any strategy is persisted or any token is opened.
func TestResolveBackendPIN_ManualRefusedUntilUnsealSeam(t *testing.T) {
	for _, tc := range []struct{ strategy, minimum string }{
		{"manual", ""}, {"manual", "manual"}, {"sealed", "manual"}, {"auto", "manual"},
	} {
		s, opened, _ := backendPINTestServer(t, tc.strategy, []byte("backend-pin-1"), false, true)
		s.config.BackendPIN.Minimum = tc.minimum
		err := s.resolveBackendPIN()
		require.ErrorIs(t, err, ErrBackendPINManualUnavailable, "%+v", tc)
		require.Nil(t, s.backendPIN, "%+v", tc)
		require.Empty(t, *opened, "%+v", tc)
		_, statErr := os.Stat(pinselect.BackendPINStrategyPath(s.backendPINDir()))
		require.ErrorIs(t, statErr, os.ErrNotExist, "nothing persisted for %+v", tc)
	}

	// A record persisted as manual by an earlier release is refused too.
	s, opened, _ := backendPINTestServer(t, "", []byte("backend-pin-1"), false, true)
	_, err := pinselect.ResolveBackendPIN(pinselect.BackendPINConfig{
		PINDir:           s.backendPINDir(),
		Strategy:         pinselect.BackendPINManual,
		BarrierAvailable: true,
	})
	require.NoError(t, err)
	require.ErrorIs(t, s.resolveBackendPIN(), ErrBackendPINManualUnavailable)
	require.Nil(t, s.backendPIN)
	require.Empty(t, *opened)
}

// backendPINUnsealedBarrier is a real, unsealed system barrier.
func backendPINUnsealedBarrier(t *testing.T) *seal.Barrier {
	t.Helper()
	b, err := seal.NewBarrier(slog.New(slog.DiscardHandler), storage.NewMemory(),
		seal.BarrierConfig{RootKeyPath: "core/seal", PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase}},
		seal.NewSoftwareStrategy())
	require.NoError(t, err)
	creds, err := seal.CredentialsFor(t.Context(), []byte("test-system-pw"))
	require.NoError(t, err)
	defer creds.Secret.Destroy()
	require.NoError(t, b.Initialize(context.Background(), creds))
	return b
}

// Sealing the running barrier (not shutdown) zeroizes the held PIN under
// every strategy and stops a manual PKCS#11 provider (docs/SPEC.md:78).
func TestBarrierSeal_ZeroizesBackendPIN(t *testing.T) {
	t.Run("sealed", func(t *testing.T) {
		s, _, providers := backendPINTestServer(t, "sealed", []byte("backend-pin-1"), false, true)
		s.barrier = backendPINUnsealedBarrier(t)
		require.NoError(t, s.resolveBackendPIN())
		require.NoError(t, s.startPKCS11AfterUnseal())
		_, err := s.backendPIN.PIN()
		require.NoError(t, err)

		require.NoError(t, s.barrier.Seal())
		_, err = s.backendPIN.PIN()
		require.Error(t, err, "held PIN zeroized at barrier seal")
		require.Len(t, *providers, 1)
		require.False(t, (*providers)[0].closed, "sealed keeps the backend running")
	})
	t.Run("manual", func(t *testing.T) {
		s, _, providers := backendPINTestServer(t, "manual", nil, false, true)
		s.barrier = backendPINUnsealedBarrier(t)
		// resolveBackendPIN refuses manual for now; the holder lifecycle
		// it would install is still kept correct for when the seam lands.
		s.installBackendPIN(pinselect.BackendPINManual)
		require.NoError(t, s.UnsealBackendPIN(context.Background(), []byte("operator-pin-1")))

		require.NoError(t, s.barrier.Seal())
		_, err := s.backendPIN.PIN()
		require.Error(t, err, "held PIN zeroized at barrier seal")
		require.Len(t, *providers, 1)
		require.True(t, (*providers)[0].closed, "manual stops the backend at barrier seal")
		_, started := s.keyProviders["pkcs11"]
		require.False(t, started)
	})
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
			if strategy == "manual" {
				// resolveBackendPIN refuses manual for now (no unseal seam).
				s.installBackendPIN(pinselect.BackendPINManual)
			} else {
				require.NoError(t, s.resolveBackendPIN())
			}
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
