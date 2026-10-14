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

package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadExtensionSettings(t *testing.T) {
	tests := []struct {
		name    string
		content string // empty means the file does not exist
		want    map[string]json.RawMessage
	}{
		{"missing file", "", nil},
		{"not JSON", "{oops", nil},
		{"no extensions block", `{"profile":{}}`, nil},
		{"extensions not an object", `{"extensions":[1]}`, nil},
		{"no settings block", `{"extensions":{"other":1}}`, nil},
		{"settings not an object", `{"extensions":{"settings":"x"}}`, nil},
		{"settings present", `{"extensions":{"settings":{"` + extAlpha + `":{"state":1}}}}`,
			map[string]json.RawMessage{extAlpha: json.RawMessage(`{"state":1}`)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "Preferences")
			if tt.content != "" {
				require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))
			}
			assert.Equal(t, tt.want, loadExtensionSettings(path))
		})
	}
}

func TestMergeExtensionSettingsCorruptNestedBlocks(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"extensions not an object", `{"extensions":"x"}`},
		{"settings not an object", `{"extensions":{"settings":[1]}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "Secure Preferences")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))

			err := mergeExtensionSettings(path, map[string]json.RawMessage{extAlpha: json.RawMessage(`{"state":1}`)})
			assert.ErrorIs(t, err, ErrSecureBrowserExtImport)

			data, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			assert.Equal(t, tt.content, string(data), "a corrupt profile file must be left untouched")
		})
	}
}

func TestMergeExtensionSettingsUncreatableProfileDir(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))

	err := mergeExtensionSettings(filepath.Join(blocker, "Default", "Preferences"),
		map[string]json.RawMessage{extAlpha: json.RawMessage(`{"state":1}`)})
	assert.ErrorIs(t, err, ErrSecureBrowserExtImport)
}

func TestGenerateNativeMessagingHostRejectsBadManifests(t *testing.T) {
	tests := []struct {
		name    string
		content string // empty means the manifest does not exist
	}{
		{"missing manifest", ""},
		{"corrupt JSON", "{not json"},
		{"path not a string", `{"name":"com.example.host","path":42}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newTestSecureBrowserService(t, nil)
			dir := t.TempDir()
			src := filepath.Join(dir, "com.example.host.json")
			if tt.content != "" {
				require.NoError(t, os.WriteFile(src, []byte(tt.content), 0o600))
			}
			manifestDir := filepath.Join(dir, "manifests")
			wrapperDir := filepath.Join(dir, "wrappers")

			err := svc.generateNativeMessagingHost(src, "com.example.host.json", dir, manifestDir, wrapperDir)
			assert.ErrorIs(t, err, ErrSecureBrowserExtImport)
			assert.NoDirExists(t, manifestDir)
			assert.NoDirExists(t, wrapperDir)
		})
	}
}

func TestGenerateNativeMessagingHostSkipsManifestWithoutPath(t *testing.T) {
	for _, content := range []string{`{"name":"com.example.host"}`, `{"name":"com.example.host","path":""}`} {
		svc, _ := newTestSecureBrowserService(t, nil)
		dir := t.TempDir()
		src := filepath.Join(dir, "com.example.host.json")
		require.NoError(t, os.WriteFile(src, []byte(content), 0o600))
		manifestDir := filepath.Join(dir, "manifests")
		wrapperDir := filepath.Join(dir, "wrappers")

		require.NoError(t, svc.generateNativeMessagingHost(src, "com.example.host.json", dir, manifestDir, wrapperDir))
		assert.NoDirExists(t, manifestDir, "a host with no binary has nothing to mirror")
		assert.NoDirExists(t, wrapperDir)
	}
}

func TestGenerateNativeMessagingHostUnwritableTargets(t *testing.T) {
	tests := []struct {
		name          string
		blockManifest bool
	}{
		{"wrapper dir blocked", false},
		{"manifest dir blocked", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newTestSecureBrowserService(t, nil)
			dir := t.TempDir()
			src := filepath.Join(dir, "com.example.host.json")
			require.NoError(t, os.WriteFile(src, []byte(`{"name":"com.example.host","path":"/opt/example/host"}`), 0o600))

			blocker := filepath.Join(dir, "blocker")
			require.NoError(t, os.WriteFile(blocker, nil, 0o600))
			manifestDir := filepath.Join(dir, "manifests")
			wrapperDir := filepath.Join(blocker, "wrappers")
			if tt.blockManifest {
				manifestDir = filepath.Join(blocker, "manifests")
				wrapperDir = filepath.Join(dir, "wrappers")
			}

			err := svc.generateNativeMessagingHost(src, "com.example.host.json", dir, manifestDir, wrapperDir)
			assert.ErrorIs(t, err, ErrSecureBrowserExtImport)
			assert.NoFileExists(t, filepath.Join(manifestDir, "com.example.host.json"))
		})
	}
}

func TestResolveSourceProfileDefaultsToChromeProfile(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, err := svc.resolveSourceProfile("")
	assert.ErrorIs(t, err, ErrSecureBrowserSourceProfile, "no Chrome profile under HOME")

	want := filepath.Join(home, ".config", "google-chrome", "Default")
	require.NoError(t, os.MkdirAll(want, 0o700))
	got, err := svc.resolveSourceProfile("")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}
