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

package secretservice

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestPathMapper_CollectionPathRoundTrip(t *testing.T) {
	mapper := NewPathMapper(DefaultConfig())

	tests := []struct {
		name       string
		folderPath string
	}{
		{
			name:       "root folder",
			folderPath: "",
		},
		{
			name:       "simple folder",
			folderPath: "Work",
		},
		{
			name:       "nested folder",
			folderPath: "Work/Email",
		},
		{
			name:       "deeply nested",
			folderPath: "Work/Email/Projects/2025",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := mapper.CollectionPathFromFolder(tt.folderPath)
			recovered := mapper.FolderFromCollectionPath(path)

			// Root folder maps to default collection, which maps back to default folder
			expectedFolder := tt.folderPath
			if tt.folderPath == "" {
				expectedFolder = mapper.config.DefaultCollectionFolder
			}

			if recovered != expectedFolder {
				t.Errorf("round-trip failed: %q -> %q -> %q, want %q",
					tt.folderPath, path, recovered, expectedFolder)
			}
		})
	}
}

func TestPathMapper_ItemPathRoundTrip(t *testing.T) {
	mapper := NewPathMapper(DefaultConfig())

	tests := []struct {
		name       string
		folderPath string
		passwordID string
	}{
		{
			name:       "root item",
			folderPath: "",
			passwordID: "gmail",
		},
		{
			name:       "nested item",
			folderPath: "Work",
			passwordID: "work/slack",
		},
		{
			name:       "item with special chars",
			folderPath: "Personal",
			passwordID: "user@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collPath := mapper.CollectionPathFromFolder(tt.folderPath)
			itemPath := mapper.ItemPathFromPassword(collPath, tt.passwordID)

			recoveredColl, recoveredID, err := mapper.PasswordIDFromItemPath(itemPath)
			if err != nil {
				t.Fatalf("PasswordIDFromItemPath() error = %v", err)
			}

			if recoveredColl != collPath {
				t.Errorf("collection path: got %q, want %q", recoveredColl, collPath)
			}
			if recoveredID != tt.passwordID {
				t.Errorf("password ID: got %q, want %q", recoveredID, tt.passwordID)
			}
		})
	}
}

func TestPathMapper_FolderFromAlias(t *testing.T) {
	config := DefaultConfig()
	config.CollectionFolderMap["custom"] = "Custom/Folder"
	mapper := NewPathMapper(config)

	tests := []struct {
		alias      string
		wantFolder string
	}{
		{"default", ""},
		{"login", ""},
		{"ssh", "ssh"},
		{"wifi", "wifi"},
		{"custom", "Custom/Folder"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.alias, func(t *testing.T) {
			got := mapper.FolderFromAlias(tt.alias)
			if got != tt.wantFolder {
				t.Errorf("FolderFromAlias(%q) = %q, want %q", tt.alias, got, tt.wantFolder)
			}
		})
	}
}

func TestPathMapper_IsDefaultCollection(t *testing.T) {
	mapper := NewPathMapper(DefaultConfig())

	tests := []struct {
		path dbus.ObjectPath
		want bool
	}{
		{dbus.ObjectPath(CollectionPathPrefix + "default"), true},
		{dbus.ObjectPath(CollectionPathPrefix + "login"), true},
		{dbus.ObjectPath(CollectionPathPrefix + "Work"), false},
		{dbus.ObjectPath(AliasPathPrefix + "default"), true},
		{dbus.ObjectPath(AliasPathPrefix + "login"), true},
	}

	for _, tt := range tests {
		t.Run(string(tt.path), func(t *testing.T) {
			got := mapper.IsDefaultCollection(tt.path)
			if got != tt.want {
				t.Errorf("IsDefaultCollection(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestAttributesToSearchCriteria(t *testing.T) {
	tests := []struct {
		name  string
		attrs ItemAttributes
		want  map[string]string
	}{
		{
			name:  "empty",
			attrs: ItemAttributes{},
			want:  map[string]string{},
		},
		{
			name: "standard attributes",
			attrs: ItemAttributes{
				"service":  "github",
				"username": "user@example.com",
			},
			want: map[string]string{
				"service":  "github",
				"username": "user@example.com",
			},
		},
		{
			name: "normalized attributes",
			attrs: ItemAttributes{
				"Application": "github",
				"User":        "testuser",
				"URL":         "https://github.com",
			},
			want: map[string]string{
				"service":  "github",
				"username": "testuser",
				"url":      "https://github.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AttributesToSearchCriteria(tt.attrs)
			if len(got) != len(tt.want) {
				t.Errorf("length mismatch: got %d, want %d", len(got), len(tt.want))
				return
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("key %q: got %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestPasswordToItemAttributes(t *testing.T) {
	attrs := PasswordToItemAttributes("GitHub", "user@example.com", "https://github.com")

	if attrs["service"] != "GitHub" {
		t.Errorf("service = %q, want %q", attrs["service"], "GitHub")
	}
	if attrs["username"] != "user@example.com" {
		t.Errorf("username = %q, want %q", attrs["username"], "user@example.com")
	}
	if attrs["url"] != "https://github.com" {
		t.Errorf("url = %q, want %q", attrs["url"], "https://github.com")
	}
	if attrs["xdg:schema"] != "org.freedesktop.Secret.Generic" {
		t.Errorf("xdg:schema = %q, want %q", attrs["xdg:schema"], "org.freedesktop.Secret.Generic")
	}
}

func TestMatchAttributes(t *testing.T) {
	itemAttrs := ItemAttributes{
		"service":  "github",
		"username": "user@example.com",
		"url":      "https://github.com",
	}

	tests := []struct {
		name   string
		search ItemAttributes
		want   bool
	}{
		{
			name:   "empty search matches all",
			search: ItemAttributes{},
			want:   true,
		},
		{
			name:   "exact service match",
			search: ItemAttributes{"service": "github"},
			want:   true,
		},
		{
			name:   "multiple matches",
			search: ItemAttributes{"service": "github", "username": "user@example.com"},
			want:   true,
		},
		{
			name:   "no match - wrong value",
			search: ItemAttributes{"service": "gitlab"},
			want:   false,
		},
		{
			name:   "no match - missing key",
			search: ItemAttributes{"password": "secret"},
			want:   false,
		},
		{
			name:   "partial match fails",
			search: ItemAttributes{"service": "github", "password": "secret"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchAttributes(itemAttrs, tt.search)
			if got != tt.want {
				t.Errorf("MatchAttributes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPathMapper_SessionPath(t *testing.T) {
	mapper := NewPathMapper(DefaultConfig())

	path := mapper.SessionPath("123")
	expected := dbus.ObjectPath(SessionPathPrefix + "123")
	if path != expected {
		t.Errorf("SessionPath() = %q, want %q", path, expected)
	}
}

func TestPathMapper_PromptPath(t *testing.T) {
	mapper := NewPathMapper(DefaultConfig())

	path := mapper.PromptPath("456")
	expected := dbus.ObjectPath(PromptPathPrefix + "456")
	if path != expected {
		t.Errorf("PromptPath() = %q, want %q", path, expected)
	}
}
