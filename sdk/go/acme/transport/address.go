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

package transport

import (
	"net/url"
	"strings"
)

// AddressType represents the type of address.
type AddressType int

const (
	// AddressTypeTCP is a standard TCP address.
	AddressTypeTCP AddressType = iota

	// AddressTypeUnix is a Unix domain socket path.
	AddressTypeUnix

	// AddressTypeUnixAbstract is a Linux abstract Unix socket.
	AddressTypeUnixAbstract

	// AddressTypeHTTP is an HTTP URL address (for REST/MCP transports).
	AddressTypeHTTP

	// AddressTypeHTTPS is an HTTPS URL address (for REST/MCP transports).
	AddressTypeHTTPS

	// AddressTypeEmbedded is an embedded in-process transport.
	AddressTypeEmbedded
)

// String returns the string representation of the address type.
func (t AddressType) String() string {
	switch t {
	case AddressTypeTCP:
		return "tcp"
	case AddressTypeUnix:
		return "unix"
	case AddressTypeUnixAbstract:
		return "unix-abstract"
	case AddressTypeHTTP:
		return "http"
	case AddressTypeHTTPS:
		return "https"
	case AddressTypeEmbedded:
		return "embedded"
	default:
		return "unknown"
	}
}

// ParsedAddress contains the parsed address components.
type ParsedAddress struct {
	// Type is the address type.
	Type AddressType

	// Address is the normalized address for connection.
	// For HTTP/HTTPS URLs, this is the host:port portion.
	Address string

	// Original is the original input address.
	Original string

	// DialAddress is the address to use with net.Dial or gRPC.
	// For HTTP/HTTPS URLs, this is the host:port extracted from the URL.
	DialAddress string

	// Path is the URL path component (only set for HTTP/HTTPS URLs).
	Path string

	// Scheme is the URL scheme (http, https, unix, etc.).
	Scheme string
}

// ParseAddress parses an address string and returns its components.
//
// Supported formats:
//   - "localhost:50051" - TCP address
//   - "/var/run/trusted-ca.sock" - Unix socket (auto-detected by leading /)
//   - "unix:///var/run/trusted-ca.sock" - Explicit Unix socket
//   - "unix-abstract://trusted-ca" - Linux abstract Unix socket
//   - "http://localhost:8080/api" - HTTP URL (extracts host:port for gRPC)
//   - "https://localhost:8443/api" - HTTPS URL (extracts host:port for gRPC)
//   - "embedded://local" - Embedded in-process transport
func ParseAddress(address string) *ParsedAddress {
	parsed := &ParsedAddress{
		Original: address,
	}

	switch {
	case strings.HasPrefix(address, "embedded://"):
		parsed.Type = AddressTypeEmbedded
		parsed.Scheme = "embedded"
		parsed.Address = strings.TrimPrefix(address, "embedded://")
		parsed.DialAddress = parsed.Address

	case strings.HasPrefix(address, "unix-abstract://"):
		parsed.Type = AddressTypeUnixAbstract
		parsed.Scheme = "unix-abstract"
		parsed.Address = strings.TrimPrefix(address, "unix-abstract://")
		parsed.DialAddress = "unix-abstract:" + parsed.Address

	case strings.HasPrefix(address, "unix://"):
		parsed.Type = AddressTypeUnix
		parsed.Scheme = "unix"
		parsed.Address = strings.TrimPrefix(address, "unix://")
		parsed.DialAddress = "unix://" + parsed.Address

	case strings.HasPrefix(address, "http://"):
		parseHTTPURL(address, "http", AddressTypeHTTP, parsed)

	case strings.HasPrefix(address, "https://"):
		parseHTTPURL(address, "https", AddressTypeHTTPS, parsed)

	case strings.HasPrefix(address, "/"):
		// Auto-detect Unix socket from path
		parsed.Type = AddressTypeUnix
		parsed.Scheme = "unix"
		parsed.Address = address
		parsed.DialAddress = "unix://" + address

	default:
		// Default to TCP
		parsed.Type = AddressTypeTCP
		parsed.Scheme = "tcp"
		parsed.Address = address
		parsed.DialAddress = address
	}

	return parsed
}

// parseHTTPURL extracts host:port from an HTTP/HTTPS URL.
func parseHTTPURL(address, scheme string, addrType AddressType, parsed *ParsedAddress) {
	parsed.Type = addrType
	parsed.Scheme = scheme

	u, err := url.Parse(address)
	if err != nil {
		// Fallback: strip scheme and use remainder
		remainder := strings.TrimPrefix(address, scheme+"://")
		if idx := strings.Index(remainder, "/"); idx >= 0 {
			parsed.Path = remainder[idx:]
			remainder = remainder[:idx]
		}
		parsed.Address = remainder
		parsed.DialAddress = remainder
		return
	}

	parsed.Address = u.Host
	parsed.DialAddress = u.Host
	parsed.Path = u.Path

	// If no port specified, use default ports
	if !strings.Contains(u.Host, ":") {
		switch scheme {
		case "http":
			parsed.Address = u.Host + ":80"
			parsed.DialAddress = u.Host + ":80"
		case "https":
			parsed.Address = u.Host + ":443"
			parsed.DialAddress = u.Host + ":443"
		}
	}
}

// IsUnix returns true if this is any type of Unix socket address.
func (p *ParsedAddress) IsUnix() bool {
	return p.Type == AddressTypeUnix || p.Type == AddressTypeUnixAbstract
}

// IsTCP returns true if this is a TCP address.
func (p *ParsedAddress) IsTCP() bool {
	return p.Type == AddressTypeTCP
}

// IsHTTP returns true if this is an HTTP or HTTPS URL.
func (p *ParsedAddress) IsHTTP() bool {
	return p.Type == AddressTypeHTTP || p.Type == AddressTypeHTTPS
}

// IsEmbedded returns true if this is an embedded transport address.
func (p *ParsedAddress) IsEmbedded() bool {
	return p.Type == AddressTypeEmbedded
}

// Network returns the network type for use with net.Dial.
func (p *ParsedAddress) Network() string {
	switch p.Type {
	case AddressTypeUnix, AddressTypeUnixAbstract:
		return "unix"
	case AddressTypeEmbedded:
		return "embedded"
	default:
		return "tcp"
	}
}

// NormalizeForGRPC returns the address in a format suitable for gRPC dialing.
func (p *ParsedAddress) NormalizeForGRPC() string {
	switch p.Type {
	case AddressTypeUnix:
		return "unix:" + p.Address
	case AddressTypeUnixAbstract:
		return "unix:@" + p.Address
	case AddressTypeHTTP, AddressTypeHTTPS:
		return p.Address
	case AddressTypeEmbedded:
		return "passthrough:///" + p.Address
	default:
		return p.Address
	}
}

// NormalizeForREST returns the address in a format suitable for HTTP clients.
// For Unix sockets, this returns an empty string as HTTP clients need special
// handling via custom dialers.
func (p *ParsedAddress) NormalizeForREST() string {
	if p.IsUnix() || p.IsEmbedded() {
		return ""
	}
	return p.Address
}

// FullURL returns the complete URL for HTTP/HTTPS addresses.
// For non-HTTP addresses, returns the original address.
func (p *ParsedAddress) FullURL() string {
	if p.IsHTTP() {
		return p.Scheme + "://" + p.Address + p.Path
	}
	return p.Original
}
