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

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Mode is the desktop connection mode.
type Mode string

const (
	// ModeRemote points the console at a remote xkmsd URL.
	ModeRemote Mode = "remote"
	// ModeStandalone boots the engine in-process on a loopback listener.
	ModeStandalone Mode = "standalone"
)

// Connection is what the SPA needs to reach an engine: which mode, the base
// URL, and (standalone only) the per-launch loopback token. It is surfaced to
// the webview via the ConnectionBinding so the SPA's sdkClient can point
// itself at the right engine.
type Connection struct {
	Mode    Mode   `json:"mode"`
	BaseURL string `json:"base_url"`
	Token   string `json:"token,omitempty"`
}

// Bookmark is a saved remote-server target.
type Bookmark struct {
	Name    string `json:"name"`
	BaseURL string `json:"base_url"`
}

// bookmarksFile returns the path to the desktop bookmark store under the OS
// user config dir.
func bookmarksFile() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", &ConfigError{Reason: "resolve user config dir", Err: err}
	}
	appDir := filepath.Join(dir, "xkms-desktop")
	if mkErr := os.MkdirAll(appDir, 0o700); mkErr != nil {
		return "", &ConfigError{Reason: "create config dir", Err: mkErr}
	}
	return filepath.Join(appDir, "bookmarks.json"), nil
}

// loadBookmarks reads saved remote-server bookmarks. A missing file yields an
// empty list, not an error.
func loadBookmarks() ([]Bookmark, error) {
	path, err := bookmarksFile()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is under the app config dir
	if err != nil {
		if os.IsNotExist(err) {
			return []Bookmark{}, nil
		}
		return nil, &ConfigError{Reason: "read bookmarks", Err: err}
	}
	var marks []Bookmark
	if len(data) == 0 {
		return []Bookmark{}, nil
	}
	if err := json.Unmarshal(data, &marks); err != nil {
		return nil, &ConfigError{Reason: "decode bookmarks", Err: err}
	}
	return marks, nil
}

// saveBookmarks persists the bookmark list (mode 0600).
func saveBookmarks(marks []Bookmark) error {
	path, err := bookmarksFile()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(marks, "", "  ")
	if err != nil {
		return &ConfigError{Reason: "encode bookmarks", Err: err}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return &ConfigError{Reason: "write bookmarks", Err: err}
	}
	return nil
}
