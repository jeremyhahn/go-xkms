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
	"fmt"
	"strconv"
)

const (
	// KB is one kibibyte.
	KB int64 = 1024
	// MB is one mebibyte.
	MB = 1024 * KB
	// GB is one gibibyte.
	GB = 1024 * MB
	// TB is one tebibyte.
	TB = 1024 * GB

	// MinImageSize is the minimum image size (1 GB).
	// The FAT32 partition needs 512 MB and LUKS2 needs space for headers
	// plus usable data.
	MinImageSize = 1 * GB

	// FAT32PartitionSize is the fixed size of the FAT32 boot partition.
	FAT32PartitionSize = 512 * MB
)

// sizeUnits maps unit suffixes to their byte multipliers.
var sizeUnits = map[byte]int64{
	'K': KB,
	'k': KB,
	'M': MB,
	'm': MB,
	'G': GB,
	'g': GB,
	'T': TB,
	't': TB,
}

// ParseSize converts a human-readable size string (e.g., "4G", "512M")
// to bytes. Supported units: K, M, G, T (case-insensitive).
// The numeric portion must be a positive integer.
func ParseSize(s string) (int64, error) {
	if len(s) < 2 {
		return 0, &USBError{
			Operation: "parse_size",
			Err:       fmt.Errorf("%w: input too short: %q", ErrInvalidSize, s),
		}
	}

	unit := s[len(s)-1]
	valueStr := s[:len(s)-1]

	multiplier, ok := sizeUnits[unit]
	if !ok {
		return 0, &USBError{
			Operation: "parse_size",
			Err:       fmt.Errorf("%w: unknown unit %q in %q", ErrInvalidSize, string(unit), s),
		}
	}

	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil {
		return 0, &USBError{
			Operation: "parse_size",
			Err:       fmt.Errorf("%w: invalid numeric value %q: %v", ErrInvalidSize, valueStr, err),
		}
	}

	if value <= 0 {
		return 0, &USBError{
			Operation: "parse_size",
			Err:       fmt.Errorf("%w: size must be positive, got %d", ErrInvalidSize, value),
		}
	}

	return value * multiplier, nil
}

// FormatSize converts bytes to a human-readable string.
func FormatSize(bytes int64) string {
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1fG", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1fM", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1fK", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}
