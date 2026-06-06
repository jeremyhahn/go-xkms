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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/pintpm2"
)

// fakePlatformAuth is a minimal pintpm2.PlatformAuthProvider for selector
// tests. provisioned controls IsProvisioned.
type fakePlatformAuth struct{ provisioned bool }

func (f *fakePlatformAuth) VerifyAuth(string) error                              { return nil }
func (f *fakePlatformAuth) ChangeAuth(string, string) error                     { return nil }
func (f *fakePlatformAuth) GetLockoutInfo() (int, int, int, int, error)         { return 0, 0, 0, 0, nil }
func (f *fakePlatformAuth) DictionaryAttackLockoutReset([]byte) error           { return nil }
func (f *fakePlatformAuth) IsProvisioned() bool                                 { return f.provisioned }

var _ pintpm2.PlatformAuthProvider = (*fakePlatformAuth)(nil)

type fakeTPMProvider struct {
	pa        pintpm2.PlatformAuthProvider
	available bool
}

func (p fakeTPMProvider) PlatformAuth() (pintpm2.PlatformAuthProvider, bool) {
	return p.pa, p.available
}

type fakePKCS11Provider struct {
	backend   qrdbsdk.PINBackend
	available bool
}

func (p fakePKCS11Provider) Backend() (qrdbsdk.PINBackend, bool) { return p.backend, p.available }

// softwareProvider builds an in-memory software backend for tests. failErr,
// when set, makes Storage return an error to exercise the failure path.
type softwareProvider struct{ failErr error }

func (s softwareProvider) Storage() (qrdbsdk.PINStorage, error) {
	if s.failErr != nil {
		return nil, s.failErr
	}
	return nil, nil // nil store => in-memory software backend
}
func (s softwareProvider) HashConfig() qrdbsdk.PINHashConfig { return qrdbsdk.DefaultHashConfig() }

func TestSelect_PrefersTPMWhenAvailable(t *testing.T) {
	be, err := Select(Config{
		TPM:      fakeTPMProvider{pa: &fakePlatformAuth{provisioned: true}, available: true},
		Software: softwareProvider{},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if be.Strategy() != qrdbsdk.PINStrategyTPM2 {
		t.Fatalf("expected TPM2 backend, got strategy %q", be.Strategy())
	}
}

func TestSelect_FallsThroughTPMUnavailableToPKCS11(t *testing.T) {
	pkBackend, err := qrdbsdk.NewSoftwareBackend(nil, qrdbsdk.DefaultHashConfig()) // stand-in instance
	if err != nil {
		t.Fatalf("stand-in backend: %v", err)
	}
	be, err := Select(Config{
		TPM:      fakeTPMProvider{available: false},
		PKCS11:   fakePKCS11Provider{backend: pkBackend, available: true},
		Software: softwareProvider{},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if be != pkBackend {
		t.Fatal("expected the PKCS#11 provider's backend instance to be returned")
	}
}

func TestSelect_FallsBackToSoftware(t *testing.T) {
	be, err := Select(Config{
		TPM:      fakeTPMProvider{available: false},
		PKCS11:   fakePKCS11Provider{available: false},
		Software: softwareProvider{},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if be.Strategy() != qrdbsdk.PINStrategySoftware {
		t.Fatalf("expected software backend, got strategy %q", be.Strategy())
	}
}

func TestSelect_NilHardwareProvidersYieldSoftware(t *testing.T) {
	be, err := Select(Config{Software: softwareProvider{}})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if be.Strategy() != qrdbsdk.PINStrategySoftware {
		t.Fatalf("expected software backend, got %q", be.Strategy())
	}
}

func TestSelect_CustomPreferenceCanForceSoftwareOverTPM(t *testing.T) {
	be, err := Select(Config{
		TPM:        fakeTPMProvider{pa: &fakePlatformAuth{provisioned: true}, available: true},
		Software:   softwareProvider{},
		Preference: []qrdbsdk.PINStrategyID{qrdbsdk.PINStrategySoftware},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if be.Strategy() != qrdbsdk.PINStrategySoftware {
		t.Fatalf("expected software (forced by preference), got %q", be.Strategy())
	}
}

func TestSelect_NilSoftwareProviderIsError(t *testing.T) {
	_, err := Select(Config{TPM: fakeTPMProvider{available: false}})
	if !errors.Is(err, ErrNoSoftwareProvider) {
		t.Fatalf("expected ErrNoSoftwareProvider, got %v", err)
	}
}

func TestSelect_PreferenceWithoutSoftwareAndNoHardwareIsError(t *testing.T) {
	_, err := Select(Config{
		Software:   softwareProvider{},
		Preference: []qrdbsdk.PINStrategyID{qrdbsdk.PINStrategyTPM2}, // no software, no TPM provider
	})
	if !errors.Is(err, ErrNoBackendAvailable) {
		t.Fatalf("expected ErrNoBackendAvailable, got %v", err)
	}
}

func TestSelect_SoftwareStorageFailureIsWrapped(t *testing.T) {
	sentinel := errors.New("disk gone")
	_, err := Select(Config{Software: softwareProvider{failErr: sentinel}})
	var se *SoftwareStorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected SoftwareStorageError, got %T %v", err, err)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel, got %v", err)
	}
}
