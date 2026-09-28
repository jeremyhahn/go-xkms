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

package gui

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/autofill"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// unmappedGUIConfigDataFields lists every gui.GUIConfig field that
// services.GUIConfigData deliberately does not carry, and why it is safe to
// omit. A field belongs here only when it is not editable through any
// Settings UI control: applyDataToConfig merges a GUIConfigData onto a copy
// of the pre-existing GUIConfig, so omitting a field from GUIConfigData
// means the merge always preserves it from that pre-existing config instead
// of wiping it on the next unrelated settings save.
//
// TestConfigDataRoundTrip walks every exported GUIConfig field and requires
// it to be either mapped through configToData/applyDataToConfig or listed
// here. A new field that is added to GUIConfig without doing one of the two
// fails that test -- this is the regression guard for go-xkms#1122, where
// ServerSPKIPin and FIDO2FirmwareVersion had neither and were silently
// zeroed by every GUI settings save.
var unmappedGUIConfigDataFields = map[string]string{
	"ServerSPKIPin": "not exposed by any Settings UI control; set only via the " +
		"gui.server_spki_pin CLI flag/env or by editing gui.json directly (go-xkms#1122)",
	"FIDO2FirmwareVersion": "set once at startup from the build-time version string " +
		"(gui.FirmwareVersion / ParseFirmwareVersion); not user-configurable (go-xkms#1122)",
}

// setDistinctFieldValue sets fv to a value that depends on seed, so two
// GUIConfig instances built with different seeds are guaranteed to differ
// in every field. It fails the test, naming the field, for any kind it does
// not yet know how to fill -- GUIConfig gaining a field of a new kind must
// extend this helper rather than be silently skipped by the round trip.
func setDistinctFieldValue(t *testing.T, fv reflect.Value, name string, seed int) {
	t.Helper()
	switch fv.Kind() {
	case reflect.Bool:
		fv.SetBool(seed%2 == 0)
	case reflect.String:
		fv.SetString(fmt.Sprintf("%s-value-%d", name, seed))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fv.SetInt(int64(seed*97 + 1))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		fv.SetUint(uint64(seed*97 + 1))
	case reflect.Slice:
		switch fv.Type().Elem().Kind() {
		case reflect.Int:
			fv.Set(reflect.ValueOf([]int{seed, seed + 1, seed + 2}))
		default:
			t.Fatalf("round-trip test does not know how to fill GUIConfig field %q of slice type %s; extend setDistinctFieldValue", name, fv.Type())
		}
	case reflect.Ptr:
		if fv.Type() == reflect.TypeOf((*xkms.AutoFillPolicy)(nil)) {
			fv.Set(reflect.ValueOf(&xkms.AutoFillPolicy{
				FillMode:              autofill.FillModeAutoFill,
				TOTPPolicy:            autofill.TOTPPolicyAuto,
				SessionTimeoutSec:     seed,
				RequireAuthentication: seed%2 == 0,
				AllowedDomains:        []string{fmt.Sprintf("allowed-%d.example", seed)},
				BlockedDomains:        []string{fmt.Sprintf("blocked-%d.example", seed)},
				MaxFillsPerMinute:     seed,
				AuditEnabled:          seed%2 == 1,
			}))
			return
		}
		t.Fatalf("round-trip test does not know how to fill GUIConfig field %q of pointer type %s; extend setDistinctFieldValue", name, fv.Type())
	default:
		t.Fatalf("round-trip test does not know how to fill GUIConfig field %q of kind %s; extend setDistinctFieldValue", name, fv.Kind())
	}
}

// fillDistinctGUIConfig returns a GUIConfig with every exported field set to
// a value derived from seed, via reflection over GUIConfig's field list so
// the helper never falls out of sync with the struct definition.
func fillDistinctGUIConfig(t *testing.T, seed int) *GUIConfig {
	t.Helper()
	cfg := &GUIConfig{}
	v := reflect.ValueOf(cfg).Elem()
	ty := v.Type()
	for i := 0; i < ty.NumField(); i++ {
		setDistinctFieldValue(t, v.Field(i), ty.Field(i).Name, seed+i)
	}
	return cfg
}

// TestConfigDataRoundTrip proves every exported GUIConfig field is either
// carried by the configToData/applyDataToConfig DTO mapping or explicitly
// listed in unmappedGUIConfigDataFields. This is the go-xkms#1122 regression
// guard: before the fix, ServerSPKIPin and FIDO2FirmwareVersion had neither,
// so applyDataToConfig's predecessor (dataToConfig) silently zeroed them on
// every GUI settings save.
func TestConfigDataRoundTrip(t *testing.T) {
	full := fillDistinctGUIConfig(t, 1)    // stands in for the GUI's edits
	base := fillDistinctGUIConfig(t, 1000) // stands in for the pre-existing config

	data := configToData(full)
	merged := applyDataToConfig(base, data)

	fullVal := reflect.ValueOf(full).Elem()
	baseVal := reflect.ValueOf(base).Elem()
	mergedVal := reflect.ValueOf(merged).Elem()
	ty := fullVal.Type()

	for i := 0; i < ty.NumField(); i++ {
		name := ty.Field(i).Name
		mergedField := mergedVal.Field(i).Interface()

		if reason, unmapped := unmappedGUIConfigDataFields[name]; unmapped {
			assert.Equal(t, baseVal.Field(i).Interface(), mergedField,
				"field %q is listed in unmappedGUIConfigDataFields (%s); applyDataToConfig must preserve it from the pre-existing config, never wipe it",
				name, reason)
			continue
		}

		assert.Equal(t, fullVal.Field(i).Interface(), mergedField,
			"field %q round-tripped incorrectly through configToData/applyDataToConfig -- "+
				"either map it in both functions or add it to unmappedGUIConfigDataFields with a reason",
			name)
	}
}

// TestApplyDataToConfig_PreservesUnrelatedSettingsSave exercises the actual
// save path go-xkms#1122 reported broken: AppService hands the GUI a
// GUIConfigData built from the current config (configToData), the GUI edits
// one field and posts the DTO back, and the SetConfigUpdater callback wired
// in NewApp (app.go) merges it via applyDataToConfig and persists the result
// with SaveGUIConfig. ServerSPKIPin and FIDO2FirmwareVersion must survive
// that round trip both in memory and in the file SaveGUIConfig writes.
func TestApplyDataToConfig_PreservesUnrelatedSettingsSave(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmpDir, ".config"))
	viper.Reset()
	t.Cleanup(viper.Reset)

	base := DefaultGUIConfig()
	base.ServerSPKIPin = "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff001122"
	base.FIDO2FirmwareVersion = 10203
	require.NoError(t, SaveGUIConfig(base))

	// Simulate the DTO the frontend actually receives and edits (NewApp
	// hands services.NewAppService(configToData(cfg))).
	data := configToData(base)
	require.IsType(t, &services.GUIConfigData{}, data)

	// Simulate Settings.svelte's autoSave: spread the current config and
	// overwrite only the field the form owns -- here, an unrelated theme
	// change, never the SPKI pin or firmware version (neither has a form
	// control to edit).
	data.Theme = ThemeDark

	// Simulate AppService.UpdateConfig invoking the ConfigUpdater callback
	// wired in NewApp's appSvc.SetConfigUpdater.
	merged := applyDataToConfig(base, data)
	require.NoError(t, merged.Validate())

	assert.Equal(t, base.ServerSPKIPin, merged.ServerSPKIPin,
		"SPKI pin must survive an unrelated settings save in memory")
	assert.Equal(t, base.FIDO2FirmwareVersion, merged.FIDO2FirmwareVersion,
		"firmware version must survive an unrelated settings save in memory")
	assert.Equal(t, ThemeDark, merged.Theme, "the edited field must still take effect")

	require.NoError(t, SaveGUIConfig(merged))

	reloaded, err := LoadGUIConfig()
	require.NoError(t, err)
	assert.Equal(t, base.ServerSPKIPin, reloaded.ServerSPKIPin,
		"SPKI pin must survive on disk after SaveGUIConfig")
	assert.Equal(t, base.FIDO2FirmwareVersion, reloaded.FIDO2FirmwareVersion,
		"firmware version must survive on disk after SaveGUIConfig")
	assert.Equal(t, ThemeDark, reloaded.Theme)
}
