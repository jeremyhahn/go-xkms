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

package config

import (
	"errors"
	"reflect"
	"testing"
)

func TestBackendPINConfig_ValidAccepted(t *testing.T) {
	for _, s := range []string{"", "auto", "tpm2", "sealed", "manual"} {
		for _, m := range []string{"", "sealed", "tpm2", "manual"} {
			c := BackendPINConfig{Strategy: s, Minimum: m}
			if err := c.Validate(); err != nil {
				t.Errorf("strategy %q minimum %q: %v", s, m, err)
			}
		}
	}
}

func TestBackendPINConfig_PKCS11IsRefused(t *testing.T) {
	c := BackendPINConfig{Strategy: "pkcs11"}
	if err := c.Validate(); !errors.Is(err, ErrBackendPINSelfStore) {
		t.Fatalf("err = %v, want ErrBackendPINSelfStore", err)
	}
}

func TestBackendPINConfig_UnknownStrategyIsRefused(t *testing.T) {
	c := BackendPINConfig{Strategy: "plaintext"}
	if err := c.Validate(); !errors.Is(err, ErrInvalidBackendPINStrategy) {
		t.Fatalf("err = %v, want ErrInvalidBackendPINStrategy", err)
	}
}

func TestBackendPINConfig_MinimumAutoOrUnknownIsRefused(t *testing.T) {
	for _, m := range []string{"auto", "pkcs11", "none"} {
		c := BackendPINConfig{Minimum: m}
		if err := c.Validate(); !errors.Is(err, ErrInvalidBackendPINStrategy) {
			t.Errorf("minimum %q: err = %v, want ErrInvalidBackendPINStrategy", m, err)
		}
	}
}

func TestBackendPINConfig_YAMLKey(t *testing.T) {
	f, ok := reflect.TypeOf(Config{}).FieldByName("BackendPIN")
	if !ok {
		t.Fatal("Config has no BackendPIN field")
	}
	if got := f.Tag.Get("yaml"); got != "backend_pin" {
		t.Fatalf("yaml tag = %q, want backend_pin", got)
	}
}

func TestConfigValidate_RefusesInvalidBackendPIN(t *testing.T) {
	c := &Config{BackendPIN: BackendPINConfig{Strategy: "pkcs11"}}
	if err := c.Validate(); !errors.Is(err, ErrBackendPINSelfStore) {
		t.Fatalf("Config.Validate err = %v, want ErrBackendPINSelfStore", err)
	}
}
