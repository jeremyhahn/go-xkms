// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package client

const (
	defaultTitle     = "Trusted ACME Client"
	defaultWidth     = 1024
	defaultHeight    = 768
	defaultMinWidth  = 800
	defaultMinHeight = 600
)

// GUIConfig defines configuration for the ACME client desktop GUI application.
type GUIConfig struct {
	// Title is the window title.
	Title string
	// Width is the initial window width in pixels.
	Width int
	// Height is the initial window height in pixels.
	Height int
	// MinWidth is the minimum window width in pixels.
	MinWidth int
	// MinHeight is the minimum window height in pixels.
	MinHeight int
}

// DefaultGUIConfig returns a GUIConfig with sensible defaults.
func DefaultGUIConfig() *GUIConfig {
	return &GUIConfig{
		Title:     defaultTitle,
		Width:     defaultWidth,
		Height:    defaultHeight,
		MinWidth:  defaultMinWidth,
		MinHeight: defaultMinHeight,
	}
}
