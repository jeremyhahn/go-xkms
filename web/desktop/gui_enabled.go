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

//go:build desktop

package main

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"

	"github.com/jeremyhahn/go-xkms/web/desktop/frontend"
)

// bridge is bound into the webview's JavaScript context. The SPA calls
// GetConnection() at boot to learn which engine to talk to and, in standalone
// mode, the per-launch loopback token.
type bridge struct {
	conn Connection
}

// GetConnection returns the active connection as a JSON string so the SPA can
// point its SDK client at the right engine. The SPA reads base_url into
// window.__XKMS_API_BASE_URL__ and, for standalone mode, uses the token as a
// static loopback bearer.
func (b *bridge) GetConnection() string {
	data, err := json.Marshal(b.conn)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// ListBookmarks returns the saved remote-server bookmarks.
func (b *bridge) ListBookmarks() []Bookmark {
	marks, err := loadBookmarks()
	if err != nil {
		return []Bookmark{}
	}
	return marks
}

// SaveBookmark appends or updates a bookmark and persists the list.
func (b *bridge) SaveBookmark(name, baseURL string) error {
	marks, err := loadBookmarks()
	if err != nil {
		return err
	}
	updated := false
	for i := range marks {
		if marks[i].Name == name {
			marks[i].BaseURL = baseURL
			updated = true
			break
		}
	}
	if !updated {
		marks = append(marks, Bookmark{Name: name, BaseURL: baseURL})
	}
	return saveBookmarks(marks)
}

// runGUI launches the Wails window serving the embedded SPA with the bridge
// bound. It blocks until the window closes.
func runGUI(conn Connection, logger *slog.Logger) error {
	b := &bridge{conn: conn}

	err := wails.Run(&options.App{
		Title:  "xKMS Console",
		Width:  1280,
		Height: 800,
		AssetServer: &assetserver.Options{
			Assets: frontend.Assets,
		},
		OnStartup: func(_ context.Context) {
			logger.Info("xKMS desktop started", "mode", conn.Mode, "base_url", conn.BaseURL)
		},
		Bind: []interface{}{b},
	})
	if err != nil {
		return &ConfigError{Reason: "wails run", Err: err}
	}
	return nil
}
