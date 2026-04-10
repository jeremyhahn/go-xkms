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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateQR(t *testing.T) {
	p := validPayload()

	img, err := GenerateQR(p)
	require.NoError(t, err)
	require.NotNil(t, img)

	bounds := img.Bounds()
	assert.GreaterOrEqual(t, bounds.Dx(), defaultQRSize)
	assert.GreaterOrEqual(t, bounds.Dy(), defaultQRSize)
}

func TestGenerateQRNilPayload(t *testing.T) {
	_, err := GenerateQR(nil)
	assert.ErrorIs(t, err, ErrInvalidPayload)
}

func TestGenerateQRInvalidPayload(t *testing.T) {
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
			name: "missing NoisePub",
			payload: &PairingPayload{
				Version:   1,
				Type:      "xkey-pair",
				Addr:      "192.168.1.100:9443",
				Transport: "tcp",
				Name:      "test",
			},
			wantErr: ErrInvalidNoisePub,
		},
		{
			name: "wrong version",
			payload: &PairingPayload{
				Version:   2,
				Type:      "xkey-pair",
				NoisePub:  testNoisePub32,
				Addr:      "192.168.1.100:9443",
				Transport: "tcp",
				Name:      "test",
			},
			wantErr: ErrUnsupportedVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateQR(tt.payload)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestGenerateTerminalQR(t *testing.T) {
	p := validPayload()

	result, err := GenerateTerminalQR(p)
	require.NoError(t, err)
	assert.NotEmpty(t, result)

	// Terminal QR codes contain Unicode block characters.
	assert.Contains(t, result, "\u2580") // ▀ (WHITE_BLACK)
}

func TestGenerateTerminalQRNilPayload(t *testing.T) {
	_, err := GenerateTerminalQR(nil)
	assert.ErrorIs(t, err, ErrInvalidPayload)
}

func TestGenerateTerminalQRInvalidPayload(t *testing.T) {
	p := &PairingPayload{
		Version: 99,
		Type:    "xkey-pair",
	}
	_, err := GenerateTerminalQR(p)
	assert.Error(t, err)
}

func TestGenerateQRFromString(t *testing.T) {
	img, err := GenerateQRFromString("https://example.com", 200)
	require.NoError(t, err)
	require.NotNil(t, img)

	bounds := img.Bounds()
	assert.GreaterOrEqual(t, bounds.Dx(), 200)
	assert.GreaterOrEqual(t, bounds.Dy(), 200)
}

func TestGenerateQRFromStringEmpty(t *testing.T) {
	_, err := GenerateQRFromString("", 200)
	assert.ErrorIs(t, err, ErrQRGenerationFailed)
}

func TestGenerateQRFromStringZeroSize(t *testing.T) {
	_, err := GenerateQRFromString("hello", 0)
	assert.ErrorIs(t, err, ErrQRGenerationFailed)
}

func TestGenerateQRFromStringNegativeSize(t *testing.T) {
	_, err := GenerateQRFromString("hello", -1)
	assert.ErrorIs(t, err, ErrQRGenerationFailed)
}

func TestGenerateQRFromStringSmallSize(t *testing.T) {
	img, err := GenerateQRFromString("test", 50)
	require.NoError(t, err)
	require.NotNil(t, img)

	bounds := img.Bounds()
	assert.Greater(t, bounds.Dx(), 0)
	assert.Greater(t, bounds.Dy(), 0)
}

func TestGenerateQRFromStringLargeContent(t *testing.T) {
	// A reasonably long URI that exercises larger QR versions.
	content := "xkey-pair://eyJ2IjoxLCJ0eXBlIjoieGtleS1wYWlyIiwibm9pc2VfcHViIjoiZEdWemRDMXViMmx6WlMxd2RXSnNhV010YTJWNSIsImFkZHIiOiIxOTIuMTY4LjEuMTAwOjk0NDMiLCJ0cmFuc3BvcnQiOiJ0Y3AiLCJuYW1lIjoieEtleSBEZXNrdG9wIiwiY29kZSI6IkFCQzEyMyJ9"
	img, err := GenerateQRFromString(content, 512)
	require.NoError(t, err)
	require.NotNil(t, img)

	bounds := img.Bounds()
	assert.GreaterOrEqual(t, bounds.Dx(), 512)
	assert.GreaterOrEqual(t, bounds.Dy(), 512)
}
