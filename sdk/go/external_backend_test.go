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

package xkms

import (
	"errors"
	"testing"
)

// errExternalFactoryCalled marks the factory registered by the test below.
var errExternalFactoryCalled = errors.New("sdk test: external factory called")

// TestRegisterExternalBackend_ThroughSDK registers a backend type using only
// the SDK's names, as a module outside go-xkms must, and proves it becomes a
// valid, supported type whose factory the registry hands back.
func TestRegisterExternalBackend_ThroughSDK(t *testing.T) {
	name := ServiceBackendType("sdk-ext-backend")
	var factory ServiceBackendFactory = func(map[string]interface{}) (KeyProvider, error) {
		return nil, errExternalFactoryCalled
	}

	if err := RegisterExternalBackend(ExternalBackend{Type: name, Factory: factory}); err != nil {
		t.Fatalf("RegisterExternalBackend: %v", err)
	}
	if !name.IsValid() {
		t.Fatal("registered type is not valid")
	}
	if !StoreType(name).IsValid() {
		t.Fatal("registered type is not a valid store type")
	}
	got, ok := GetBackendFactory(name)
	if !ok {
		t.Fatal("registered factory not found")
	}
	if _, err := got(nil); !errors.Is(err, errExternalFactoryCalled) {
		t.Fatalf("factory returned %v, want the registered factory", err)
	}
}

// TestRegisterExternalBackend_ThroughSDKRefusals proves refusals surface the
// SDK's typed errors.
func TestRegisterExternalBackend_ThroughSDKRefusals(t *testing.T) {
	factory := func(map[string]interface{}) (KeyProvider, error) { return nil, errExternalFactoryCalled }

	tests := []struct {
		name    string
		backend ExternalBackend
		want    error
	}{
		{"builtin", ExternalBackend{Type: BackendTPM2, Factory: factory}, ErrBackendTypeRegistered},
		{"malformed", ExternalBackend{Type: "sdk ext", Factory: factory}, ErrInvalidBackendTypeName},
		{"nil factory", ExternalBackend{Type: "sdk-ext-nofactory"}, ErrNilBackendFactory},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := RegisterExternalBackend(tc.backend)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			var regErr *BackendTypeRegistrationError
			if !errors.As(err, &regErr) {
				t.Fatalf("got %T, want *BackendTypeRegistrationError", err)
			}
		})
	}
}
