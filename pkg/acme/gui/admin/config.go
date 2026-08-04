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

package admin

const (
	defaultTitle     = "Trusted CA Admin"
	defaultWidth     = 1280
	defaultHeight    = 800
	defaultMinWidth  = 1024
	defaultMinHeight = 700
	defaultTransport = "unix"
	defaultAddress   = "/run/trusted-ca-grpc.sock"
	defaultTimeout   = 30
)

// GUIConfig defines configuration for the admin desktop GUI application.
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
	// Transport specifies the protocol used to connect to the CA server.
	// Supported values: unix, rest, grpc, quic, mcp.
	Transport string
	// Address is the CA server address (socket path or host:port).
	Address string
	// TLSCert is the client TLS certificate file path.
	TLSCert string
	// TLSKey is the client TLS private key file path.
	TLSKey string
	// TLSCA is the CA certificate file path for TLS verification.
	TLSCA string
	// TLSInsecure skips TLS certificate verification.
	TLSInsecure bool
	// Token is the authentication token for the CA server.
	Token string
	// Timeout is the request timeout in seconds.
	Timeout int
}

// DefaultGUIConfig returns a GUIConfig with sensible defaults.
func DefaultGUIConfig() *GUIConfig {
	return &GUIConfig{
		Title:     defaultTitle,
		Width:     defaultWidth,
		Height:    defaultHeight,
		MinWidth:  defaultMinWidth,
		MinHeight: defaultMinHeight,
		Transport: defaultTransport,
		Address:   defaultAddress,
		Timeout:   defaultTimeout,
	}
}
