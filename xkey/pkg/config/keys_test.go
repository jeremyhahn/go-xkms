// Copyright (C) 2026 Jeremy Hahn
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// configLeafKeys returns every leaf key of Config with the type of its field.
func configLeafKeys(t *testing.T) map[string]reflect.Type {
	t.Helper()
	keys := make(map[string]reflect.Type)
	walkConfigKeys(reflect.ValueOf(DefaultConfig()).Elem(), "", func(key string, value reflect.Value) {
		keys[key] = value.Type()
	})
	require.NotEmpty(t, keys)
	return keys
}

// TestRegisterConfigKeys_EveryLeafIsKnownToViper proves that the walk reaches
// every leaf of the config tree: each one is a registered key, so a partial
// file and the environment merge at leaf granularity, and no section is an
// opaque default. The spot checks pin the keys the documentation names.
func TestRegisterConfigKeys_EveryLeafIsKnownToViper(t *testing.T) {
	v := newViperInstance()
	known := make(map[string]struct{})
	for _, key := range v.AllKeys() {
		known[key] = struct{}{}
	}

	leaves := configLeafKeys(t)
	for key := range leaves {
		_, ok := known[key]
		assert.True(t, ok, "leaf %q is not a registered key", key)
	}
	for _, key := range []string{
		"log.level", "backend.default", "backend.tpm2.device", "gui.theme",
		"gui.server.address", "gui.auto_unseal.pcrs", "tpm.device",
		"fido2.always_uv", "xkmsd.address", "policy.min_pin_length",
		"oidc.callback_host", "oidc.callback_port",
		"agent.listen_address", "phone.relay_listen_address",
		"backends.local", "backends.remote", "backends.defaults", "fido2.extensions",
	} {
		_, ok := leaves[key]
		assert.True(t, ok, "expected leaf %q", key)
	}
	for _, sectionOnly := range []string{"xkmsd", "log", "gui", "policy", "fido2"} {
		_, ok := known[sectionOnly]
		assert.False(t, ok, "section %q must not be registered as an opaque key", sectionOnly)
	}
}

// singleValueLeaf reports whether one environment variable can express a
// value of type t: scalars and lists of scalars, which viper splits on commas.
func singleValueLeaf(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Map:
		return false
	case reflect.Slice, reflect.Array:
		return t.Elem().Kind() != reflect.Struct && t.Elem().Kind() != reflect.Pointer
	default:
		return true
	}
}

// TestRegisterConfigKeys_EveryScalarLeafReadsItsEnvironmentVariable proves
// that each leaf a single variable can express reads XKEY_<KEY>: with the
// variable set, viper reports the environment value for the key, whatever
// the default.
func TestRegisterConfigKeys_EveryScalarLeafReadsItsEnvironmentVariable(t *testing.T) {
	leaves := configLeafKeys(t)
	var scalar, composite int
	for key, typ := range leaves {
		if !singleValueLeaf(typ) {
			composite++
			continue
		}
		scalar++
		t.Setenv("XKEY_"+strings.ToUpper(strings.ReplaceAll(key, ".", "_")), "probe-"+key)
	}
	require.Greater(t, scalar, 50, "the walk found too few scalar leaves")
	require.Equal(t, 5, composite,
		"composite leaves: backends.local, backends.remote, backends.defaults, fido2.extensions, "+
			"policy.pairing_allowed_applications")

	v := newViperInstance()
	for key, typ := range leaves {
		if !singleValueLeaf(typ) {
			continue
		}
		assert.Equal(t, "probe-"+key, v.GetString(key), "leaf %q does not read its environment variable", key)
	}
}

// TestRegisterConfigKeys_DefaultsSurviveLeafRegistration proves that
// registering leaves keeps every default: a load with no file and no
// environment is DefaultConfig.
func TestRegisterConfigKeys_DefaultsSurviveLeafRegistration(t *testing.T) {
	v := newViperInstance()
	cfg, err := unmarshalAndValidate(v)
	require.NoError(t, err)
	assert.Equal(t, DefaultConfig(), cfg)
}

// TestConfigKeyName_TagShapes proves the tag reading: a plain tag, a tag with
// options, an omitted tag, and the "-" exclusion.
func TestConfigKeyName_TagShapes(t *testing.T) {
	type tagged struct {
		Plain    string `mapstructure:"plain_key"`
		Options  string `mapstructure:"opt_key,omitempty"`
		Untagged string
		Skipped  string `mapstructure:"-"`
	}
	typ := reflect.TypeOf(tagged{})
	assert.Equal(t, "plain_key", configKeyName(typ.Field(0)))
	assert.Equal(t, "opt_key", configKeyName(typ.Field(1)))
	assert.Equal(t, "untagged", configKeyName(typ.Field(2)))
	assert.Equal(t, "", configKeyName(typ.Field(3)))
}

// TestWalkConfigKeys_NilPointerSectionIsDescended proves that a nil pointer
// to a struct still registers its keys, so the environment can populate a
// section the defaults leave unset, and that a "-" field is skipped.
func TestWalkConfigKeys_NilPointerSectionIsDescended(t *testing.T) {
	type inner struct {
		Device string `mapstructure:"device"`
	}
	type outer struct {
		Nested *inner `mapstructure:"nested"`
		Hidden string `mapstructure:"-"`
		_      string
		Name   string `mapstructure:"name"`
	}
	var keys []string
	walkConfigKeys(reflect.ValueOf(&outer{}).Elem(), "root", func(key string, value reflect.Value) {
		keys = append(keys, key)
	})
	assert.ElementsMatch(t, []string{"root.nested.device", "root.name"}, keys)
}
