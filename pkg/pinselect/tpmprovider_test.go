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

package pinselect

import (
	"errors"
	"testing"

	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// fakePlatformKeyStorer is a minimal pkgtpm2.PlatformKeyStorer for
// tpmProvider tests.
type fakePlatformKeyStorer struct {
	initialized bool
	authReady   bool
	provisioned bool
}

func (f *fakePlatformKeyStorer) SRKAttributes() *types.KeyAttributes         { return nil }
func (f *fakePlatformKeyStorer) Backend() store.KeyBackend                   { return nil }
func (f *fakePlatformKeyStorer) Initialize(string, string) error             { return nil }
func (f *fakePlatformKeyStorer) EnrollPlatformSRK(string, string) error      { return nil }
func (f *fakePlatformKeyStorer) InitializeWithDefaults() error               { return nil }
func (f *fakePlatformKeyStorer) IsInitialized() bool                         { return f.initialized }
func (f *fakePlatformKeyStorer) PINBackend() qrdbsdk.PINBackend              { return nil }
func (f *fakePlatformKeyStorer) PlatformPolicyEnabled() bool                 { return false }
func (f *fakePlatformKeyStorer) VerifyAuth(string) error                     { return nil }
func (f *fakePlatformKeyStorer) ChangeAuth(string, string) error             { return nil }
func (f *fakePlatformKeyStorer) GetLockoutInfo() (int, int, int, int, error) { return 0, 0, 0, 0, nil }
func (f *fakePlatformKeyStorer) DictionaryAttackLockoutReset([]byte) error   { return nil }
func (f *fakePlatformKeyStorer) IsProvisioned() bool                         { return f.provisioned }
func (f *fakePlatformKeyStorer) IsAuthReady() bool                           { return f.authReady }
func (f *fakePlatformKeyStorer) SetAuthReady(ready bool)                     { f.authReady = ready }

var _ pkgtpm2.PlatformKeyStorer = (*fakePlatformKeyStorer)(nil)

// fakeTPMModule is a minimal PlatformKeyStoreProvider stand-in.
type fakeTPMModule struct {
	pks pkgtpm2.PlatformKeyStorer
}

func (f *fakeTPMModule) PlatformKeyStore() pkgtpm2.PlatformKeyStorer { return f.pks }

var _ PlatformKeyStoreProvider = (*fakeTPMModule)(nil)

func TestNewTPMProvider_OffersReadySRK(t *testing.T) {
	pks := &fakePlatformKeyStorer{initialized: true, authReady: true, provisioned: true}
	tpm := &fakeTPMModule{pks: pks}

	provider := NewTPMProvider(func() (PlatformKeyStoreProvider, error) {
		return tpm, nil
	}, false, nil)

	pa, ok := provider.PlatformAuth()
	if !ok {
		t.Fatal("PlatformAuth() ok = false, want true for an initialized, auth-ready SRK")
	}
	if pa == nil {
		t.Fatal("PlatformAuth() returned nil provider with ok = true")
	}
}

func TestNewTPMProvider_UnconfirmedSRKWithoutPersistedTPM2IsUnavailable(t *testing.T) {
	pks := &fakePlatformKeyStorer{initialized: true, authReady: false, provisioned: true}
	tpm := &fakeTPMModule{pks: pks}

	provider := NewTPMProvider(func() (PlatformKeyStoreProvider, error) {
		return tpm, nil
	}, false, nil)

	if _, ok := provider.PlatformAuth(); ok {
		t.Fatal("PlatformAuth() ok = true, want false for an unconfirmed SRK when tpm2 is not the persisted strategy")
	}
}

func TestNewTPMProvider_UnconfirmedSRKWithPersistedTPM2IsOffered(t *testing.T) {
	pks := &fakePlatformKeyStorer{initialized: true, authReady: false, provisioned: true}
	tpm := &fakeTPMModule{pks: pks}

	provider := NewTPMProvider(func() (PlatformKeyStoreProvider, error) {
		return tpm, nil
	}, true, nil)

	if _, ok := provider.PlatformAuth(); !ok {
		t.Fatal("PlatformAuth() ok = false, want true: persisted strategy is tpm2, so an unconfirmed SRK must still be offered")
	}
}

func TestNewTPMProvider_AcquireErrorIsUnavailable(t *testing.T) {
	sentinel := errors.New("tpm device not found")
	provider := NewTPMProvider(func() (PlatformKeyStoreProvider, error) {
		return nil, sentinel
	}, true, nil)

	if _, ok := provider.PlatformAuth(); ok {
		t.Fatal("PlatformAuth() ok = true, want false when the acquire func fails")
	}
}

func TestNewTPMProvider_UninitializedSRKIsUnavailable(t *testing.T) {
	pks := &fakePlatformKeyStorer{initialized: false}
	tpm := &fakeTPMModule{pks: pks}

	provider := NewTPMProvider(func() (PlatformKeyStoreProvider, error) {
		return tpm, nil
	}, true, nil)

	if _, ok := provider.PlatformAuth(); ok {
		t.Fatal("PlatformAuth() ok = true, want false when no SRK is initialized")
	}
}

func TestNewTPMProvider_NilPlatformKeyStoreIsUnavailable(t *testing.T) {
	tpm := &fakeTPMModule{pks: nil}

	provider := NewTPMProvider(func() (PlatformKeyStoreProvider, error) {
		return tpm, nil
	}, true, nil)

	if _, ok := provider.PlatformAuth(); ok {
		t.Fatal("PlatformAuth() ok = true, want false when PlatformKeyStore() returns nil")
	}
}

func TestNewTPMProvider_NilAcquireFuncIsUnavailable(t *testing.T) {
	provider := NewTPMProvider(nil, true, nil)

	if _, ok := provider.PlatformAuth(); ok {
		t.Fatal("PlatformAuth() ok = true, want false for a nil acquire func")
	}
}
