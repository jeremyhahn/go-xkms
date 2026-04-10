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

package qrgen

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testNoisePub32 is a valid base64url-encoded 32-byte Curve25519 key for tests.
var testNoisePub32 = base64.RawURLEncoding.EncodeToString(make([]byte, 32))

func validPayload() *PairingPayload {
	return &PairingPayload{
		Version:   1,
		Type:      "xkey-pair",
		NoisePub:  testNoisePub32,
		Addr:      "192.168.1.100:9443",
		Transport: "tcp",
		Name:      "xKey Desktop",
		Code:      "ABC123",
	}
}

func TestEncodeDecode(t *testing.T) {
	p := validPayload()

	encoded, err := EncodePairingPayload(p)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	decoded, err := DecodePairingPayload(encoded)
	require.NoError(t, err)
	assert.Equal(t, p.Version, decoded.Version)
	assert.Equal(t, p.Type, decoded.Type)
	assert.Equal(t, p.NoisePub, decoded.NoisePub)
	assert.Equal(t, p.Addr, decoded.Addr)
	assert.Equal(t, p.Transport, decoded.Transport)
	assert.Equal(t, p.Name, decoded.Name)
	assert.Equal(t, p.Code, decoded.Code)
}

func TestEncodeDecodeWithoutOptionalCode(t *testing.T) {
	p := validPayload()
	p.Code = ""

	encoded, err := EncodePairingPayload(p)
	require.NoError(t, err)

	decoded, err := DecodePairingPayload(encoded)
	require.NoError(t, err)
	assert.Equal(t, "", decoded.Code)
	assert.Equal(t, p.NoisePub, decoded.NoisePub)
}

func TestEncodeDecodeEmpty(t *testing.T) {
	tests := []struct {
		name    string
		payload *PairingPayload
		wantErr error
	}{
		{
			name:    "nil payload",
			payload: nil,
			wantErr: ErrInvalidPayload,
		},
		{
			name: "empty NoisePub",
			payload: &PairingPayload{
				Version:   1,
				Type:      "xkey-pair",
				NoisePub:  "",
				Addr:      "192.168.1.100:9443",
				Transport: "tcp",
				Name:      "test",
			},
			wantErr: ErrInvalidNoisePub,
		},
		{
			name: "empty Addr",
			payload: &PairingPayload{
				Version:   1,
				Type:      "xkey-pair",
				NoisePub:  testNoisePub32,
				Addr:      "",
				Transport: "tcp",
				Name:      "test",
			},
			wantErr: ErrInvalidAddr,
		},
		{
			name: "wrong type",
			payload: &PairingPayload{
				Version:   1,
				Type:      "wrong-type",
				NoisePub:  testNoisePub32,
				Addr:      "192.168.1.100:9443",
				Transport: "tcp",
				Name:      "test",
			},
			wantErr: ErrInvalidPayload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodePairingPayload(tt.payload)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestURIRoundTrip(t *testing.T) {
	p := validPayload()

	uri, err := ToURI(p)
	require.NoError(t, err)
	assert.True(t, len(uri) > len("xkey-pair://"))
	assert.Contains(t, uri, "xkey-pair://")

	decoded, err := FromURI(uri)
	require.NoError(t, err)
	assert.Equal(t, p.Version, decoded.Version)
	assert.Equal(t, p.Type, decoded.Type)
	assert.Equal(t, p.NoisePub, decoded.NoisePub)
	assert.Equal(t, p.Addr, decoded.Addr)
	assert.Equal(t, p.Transport, decoded.Transport)
	assert.Equal(t, p.Name, decoded.Name)
	assert.Equal(t, p.Code, decoded.Code)
}

func TestInvalidURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr error
	}{
		{
			name:    "wrong scheme",
			uri:     "https://example.com/pair",
			wantErr: ErrInvalidURI,
		},
		{
			name:    "empty string",
			uri:     "",
			wantErr: ErrInvalidURI,
		},
		{
			name:    "no scheme",
			uri:     "some-random-data",
			wantErr: ErrInvalidURI,
		},
		{
			name:    "scheme only",
			uri:     "xkey-pair://",
			wantErr: ErrInvalidPayload,
		},
		{
			name:    "scheme with garbage",
			uri:     "xkey-pair://not-valid-base64-or-json!!!",
			wantErr: ErrInvalidPayload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FromURI(tt.uri)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestUnsupportedVersion(t *testing.T) {
	tests := []struct {
		name    string
		version int
	}{
		{name: "version 0", version: 0},
		{name: "version 2", version: 2},
		{name: "version 99", version: 99},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPayload()
			p.Version = tt.version
			_, err := EncodePairingPayload(p)
			assert.ErrorIs(t, err, ErrUnsupportedVersion)
		})
	}
}

func TestDecodeRawJSON(t *testing.T) {
	p := validPayload()
	data, err := json.Marshal(p)
	require.NoError(t, err)

	decoded, err := DecodePairingPayload(string(data))
	require.NoError(t, err)
	assert.Equal(t, p.Version, decoded.Version)
	assert.Equal(t, p.Type, decoded.Type)
	assert.Equal(t, p.NoisePub, decoded.NoisePub)
	assert.Equal(t, p.Addr, decoded.Addr)
	assert.Equal(t, p.Transport, decoded.Transport)
	assert.Equal(t, p.Name, decoded.Name)
	assert.Equal(t, p.Code, decoded.Code)
}

func TestDecodeRawJSONInvalid(t *testing.T) {
	_, err := DecodePairingPayload("{invalid json")
	assert.ErrorIs(t, err, ErrInvalidPayload)
}

func TestDecodeEmptyString(t *testing.T) {
	_, err := DecodePairingPayload("")
	assert.ErrorIs(t, err, ErrInvalidPayload)
}

func TestDecodeUnsupportedVersionInJSON(t *testing.T) {
	raw := `{"v":2,"type":"xkey-pair","noise_pub":"` + testNoisePub32 + `","addr":"1.2.3.4:443","transport":"tcp","name":"test"}`
	_, err := DecodePairingPayload(raw)
	assert.ErrorIs(t, err, ErrUnsupportedVersion)
}

func TestToURIInvalidPayload(t *testing.T) {
	_, err := ToURI(nil)
	assert.ErrorIs(t, err, ErrInvalidPayload)
}

func TestFromURIEmptyPayloadAfterScheme(t *testing.T) {
	_, err := FromURI("xkey-pair://")
	assert.ErrorIs(t, err, ErrInvalidPayload)
}

// New validation tests.

func TestValidate_InvalidTransport(t *testing.T) {
	p := validPayload()
	p.Transport = "invalid"
	_, err := EncodePairingPayload(p)
	assert.ErrorIs(t, err, ErrInvalidTransport)
}

func TestValidate_InvalidNoisePubNotBase64(t *testing.T) {
	p := validPayload()
	p.NoisePub = "not-valid!!!"
	_, err := EncodePairingPayload(p)
	assert.ErrorIs(t, err, ErrInvalidNoisePub)
}

func TestValidate_InvalidNoisePubWrongLength(t *testing.T) {
	// 16 bytes instead of required 32.
	p := validPayload()
	p.NoisePub = base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	_, err := EncodePairingPayload(p)
	assert.ErrorIs(t, err, ErrInvalidNoisePub)
}

func TestValidate_InvalidAddrNoPort(t *testing.T) {
	p := validPayload()
	p.Transport = "tcp"
	p.Addr = "192.168.1.1" // Missing port.
	_, err := EncodePairingPayload(p)
	assert.ErrorIs(t, err, ErrInvalidAddr)
}

func TestValidate_NameTooLong(t *testing.T) {
	p := validPayload()
	p.Name = strings.Repeat("a", 65) // Exceeds maxNameLength of 64.
	_, err := EncodePairingPayload(p)
	assert.ErrorIs(t, err, ErrNameTooLong)
}

func TestValidate_BLETransportNoPortRequired(t *testing.T) {
	p := validPayload()
	p.Transport = "ble"
	p.Addr = "device-uuid" // BLE does not require host:port format.
	encoded, err := EncodePairingPayload(p)
	assert.NoError(t, err)
	assert.NotEmpty(t, encoded)
}

func TestValidate_USBTransport(t *testing.T) {
	p := validPayload()
	p.Transport = "usb"
	p.Addr = "usb-device-path"
	encoded, err := EncodePairingPayload(p)
	assert.NoError(t, err)
	assert.NotEmpty(t, encoded)
}

func TestValidate_NameExactlyMaxLength(t *testing.T) {
	p := validPayload()
	p.Name = strings.Repeat("a", 64) // Exactly maxNameLength, should succeed.
	_, err := EncodePairingPayload(p)
	assert.NoError(t, err)
}
