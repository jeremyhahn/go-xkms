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

package gui

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateTheme_ValidThemes(t *testing.T) {
	tests := []struct {
		name  string
		theme string
	}{
		{"light", ThemeLight},
		{"dark", ThemeDark},
		{"system", ThemeSystem},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTheme(tc.theme)
			assert.NoError(t, err)
		})
	}
}

func TestValidateTheme_InvalidThemes(t *testing.T) {
	tests := []struct {
		name  string
		theme string
	}{
		{"empty", ""},
		{"unknown", "sepia"},
		{"numeric", "123"},
		{"uppercase", "DARK"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTheme(tc.theme)
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidTheme))
		})
	}
}

func TestErrorSentinels_NotNil(t *testing.T) {
	sentinels := []error{
		ErrWindowCreate,
		ErrWindowShow,
		ErrWindowHide,
		ErrConfigLoad,
		ErrConfigSave,
		ErrServiceStart,
		ErrServiceStop,
		ErrTraySetup,
		ErrTrayIconLoad,
		ErrEventEmit,
		ErrNotInitialized,
		ErrInvalidTheme,
		ErrAlreadyRunning,
		ErrShutdown,
		ErrInvalidProtocol,
		ErrFIDO2StorageUnavailable,
		ErrDataDirInit,
		ErrDataDirAlreadyInit,
	}
	for _, err := range sentinels {
		t.Run(err.Error(), func(t *testing.T) {
			assert.NotNil(t, err)
			assert.NotEmpty(t, err.Error())
		})
	}
}

func TestErrorSentinels_AreDistinct(t *testing.T) {
	sentinels := []error{
		ErrWindowCreate,
		ErrWindowShow,
		ErrWindowHide,
		ErrConfigLoad,
		ErrConfigSave,
		ErrServiceStart,
		ErrServiceStop,
		ErrTraySetup,
		ErrTrayIconLoad,
		ErrEventEmit,
		ErrNotInitialized,
		ErrInvalidTheme,
		ErrAlreadyRunning,
		ErrShutdown,
		ErrInvalidProtocol,
		ErrFIDO2StorageUnavailable,
		ErrDataDirInit,
		ErrDataDirAlreadyInit,
	}
	seen := make(map[string]struct{})
	for _, err := range sentinels {
		msg := err.Error()
		_, exists := seen[msg]
		assert.False(t, exists, "duplicate error message: %s", msg)
		seen[msg] = struct{}{}
	}
}
