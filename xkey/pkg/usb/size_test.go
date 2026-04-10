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

package usb

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSize_ValidInputs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int64
	}{
		{"kilobytes_upper", "512K", 512 * KB},
		{"kilobytes_lower", "512k", 512 * KB},
		{"megabytes_upper", "100M", 100 * MB},
		{"megabytes_lower", "100m", 100 * MB},
		{"gigabytes_upper", "4G", 4 * GB},
		{"gigabytes_lower", "4g", 4 * GB},
		{"terabytes_upper", "1T", 1 * TB},
		{"terabytes_lower", "1t", 1 * TB},
		{"one_megabyte", "1M", MB},
		{"one_gigabyte", "1G", GB},
		{"large_value", "64G", 64 * GB},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSize(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseSize_InvalidInputs(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty_string", ""},
		{"single_char", "G"},
		{"no_unit", "42"},
		{"unknown_unit", "4X"},
		{"negative_value", "-1G"},
		{"zero_value", "0G"},
		{"non_numeric", "abcG"},
		{"float_value", "1.5G"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSize(tt.input)
			assert.Error(t, err)

			var usbErr *USBError
			assert.True(t, errors.As(err, &usbErr))
			assert.Equal(t, "parse_size", usbErr.Operation)
		})
	}
}

func TestParseSize_WrapsErrInvalidSize(t *testing.T) {
	_, err := ParseSize("X")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSize))
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{"zero", 0, "0B"},
		{"bytes", 512, "512B"},
		{"kilobytes", 1024, "1.0K"},
		{"kilobytes_fractional", 1536, "1.5K"},
		{"megabytes", MB, "1.0M"},
		{"megabytes_fractional", 3 * MB / 2, "1.5M"},
		{"gigabytes", GB, "1.0G"},
		{"gigabytes_fractional", 4*GB + GB/2, "4.5G"},
		{"terabytes", TB, "1024.0G"},
		{"just_under_kb", 1023, "1023B"},
		{"just_under_mb", MB - 1, "1024.0K"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, FormatSize(tt.bytes))
		})
	}
}

func TestSizeConstants(t *testing.T) {
	assert.Equal(t, int64(1024), KB)
	assert.Equal(t, int64(1024*1024), MB)
	assert.Equal(t, int64(1024*1024*1024), GB)
	assert.Equal(t, int64(1024*1024*1024*1024), TB)
	assert.Equal(t, int64(1*GB), MinImageSize)
	assert.Equal(t, int64(512*MB), FAT32PartitionSize)
}

func TestParseSize_RoundTrip(t *testing.T) {
	// Parse then format should produce a recognizable representation.
	size, err := ParseSize("4G")
	require.NoError(t, err)
	assert.Equal(t, "4.0G", FormatSize(size))

	size, err = ParseSize("512M")
	require.NoError(t, err)
	assert.Equal(t, "512.0M", FormatSize(size))
}
