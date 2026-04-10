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

// Package qrgen provides QR code generation and pairing payload encoding
// for the xKey device pairing system.
package qrgen

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
)

const (
	// currentVersion is the supported pairing payload version.
	currentVersion = 1

	// pairingType is the expected Type field value.
	pairingType = "xkey-pair"

	// uriScheme is the xKey pairing URI scheme prefix.
	uriScheme = "xkey-pair://"

	// maxNameLength is the maximum allowed device name length.
	maxNameLength = 64
)

// Pairing payload errors.
var (
	// ErrInvalidPayload indicates the payload is missing required fields
	// or contains invalid data.
	ErrInvalidPayload = errors.New("qrgen: invalid pairing payload")

	// ErrUnsupportedVersion indicates the payload version is not supported.
	ErrUnsupportedVersion = errors.New("qrgen: unsupported payload version")

	// ErrInvalidURI indicates the URI does not use the xkey-pair:// scheme.
	ErrInvalidURI = errors.New("qrgen: invalid xkey-pair URI")

	// ErrInvalidTransport indicates the transport type is not one of tcp, ble, or usb.
	ErrInvalidTransport = errors.New("qrgen: invalid transport type")

	// ErrInvalidNoisePub indicates the noise public key is not valid base64url
	// or does not decode to exactly 32 bytes (Curve25519 key).
	ErrInvalidNoisePub = errors.New("qrgen: invalid noise public key")

	// ErrInvalidAddr indicates the address format is invalid (e.g. missing host:port for TCP).
	ErrInvalidAddr = errors.New("qrgen: invalid address format")

	// ErrNameTooLong indicates the device name exceeds the maximum allowed length.
	ErrNameTooLong = errors.New("qrgen: device name exceeds maximum length")
)

// PairingPayload is the data encoded in a pairing QR code.
type PairingPayload struct {
	// Version is the payload format version. Must be 1.
	Version int `json:"v"`

	// Type identifies the payload type. Must be "xkey-pair".
	Type string `json:"type"`

	// NoisePub is the base64url-encoded Noise static public key.
	NoisePub string `json:"noise_pub"`

	// Addr is the TCP address (host:port) of the device.
	Addr string `json:"addr"`

	// Transport is the transport protocol: "tcp", "ble", or "usb".
	Transport string `json:"transport"`

	// Name is a human-readable device name.
	Name string `json:"name"`

	// Code is an optional one-time pairing code.
	Code string `json:"code,omitempty"`
}

// validate checks that required fields are present and valid.
func (p *PairingPayload) validate() error {
	if p.Version != currentVersion {
		return ErrUnsupportedVersion
	}
	if p.Type != pairingType {
		return ErrInvalidPayload
	}
	if p.NoisePub == "" {
		return ErrInvalidNoisePub
	}
	// Validate NoisePub is valid base64url and 32 bytes.
	decoded, err := base64.RawURLEncoding.DecodeString(p.NoisePub)
	if err != nil || len(decoded) != 32 {
		return ErrInvalidNoisePub
	}
	if p.Addr == "" {
		return ErrInvalidAddr
	}
	// Validate transport.
	switch p.Transport {
	case "tcp", "ble", "usb":
		// Valid.
	default:
		return ErrInvalidTransport
	}
	// For TCP, validate addr has host:port format.
	if p.Transport == "tcp" {
		if _, _, err := net.SplitHostPort(p.Addr); err != nil {
			return ErrInvalidAddr
		}
	}
	// Name length limit.
	if len(p.Name) > maxNameLength {
		return ErrNameTooLong
	}
	return nil
}

// EncodePairingPayload marshals the payload to JSON and base64url-encodes it.
func EncodePairingPayload(p *PairingPayload) (string, error) {
	if p == nil {
		return "", ErrInvalidPayload
	}
	if err := p.validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return "", ErrInvalidPayload
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodePairingPayload base64url-decodes the data and unmarshals the JSON
// payload. If base64 decoding fails, it attempts to parse the input as raw JSON.
func DecodePairingPayload(data string) (*PairingPayload, error) {
	if data == "" {
		return nil, ErrInvalidPayload
	}

	var jsonBytes []byte

	decodedBytes, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		// Fall back to raw JSON if base64 decode fails.
		jsonBytes = []byte(data)
	} else {
		jsonBytes = decodedBytes
	}

	var p PairingPayload
	if err := json.Unmarshal(jsonBytes, &p); err != nil {
		return nil, ErrInvalidPayload
	}

	if err := p.validate(); err != nil {
		return nil, err
	}

	return &p, nil
}

// ToURI converts a PairingPayload to an xkey-pair:// URI.
// The URI format is: xkey-pair://<base64url-encoded-json>
func ToURI(p *PairingPayload) (string, error) {
	encoded, err := EncodePairingPayload(p)
	if err != nil {
		return "", err
	}
	return uriScheme + encoded, nil
}

// FromURI parses an xkey-pair:// URI back to a PairingPayload.
func FromURI(uri string) (*PairingPayload, error) {
	if !strings.HasPrefix(uri, uriScheme) {
		return nil, ErrInvalidURI
	}
	encoded := strings.TrimPrefix(uri, uriScheme)
	if encoded == "" {
		return nil, ErrInvalidPayload
	}
	return DecodePairingPayload(encoded)
}
