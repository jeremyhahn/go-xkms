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

//go:build ble

package phone

import (
	"testing"
)

func TestSafeSlice_NilData(t *testing.T) {
	result := safeSlice(nil, 0, 16)
	if result != nil {
		t.Fatalf("expected nil for nil data, got %v", result)
	}
}

func TestSafeSlice_EmptyData(t *testing.T) {
	result := safeSlice([]byte{}, 0, 16)
	if result != nil {
		t.Fatalf("expected nil for empty data, got %v", result)
	}
}

func TestSafeSlice_StartBeyondLength(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	result := safeSlice(data, 10, 16)
	if result != nil {
		t.Fatalf("expected nil when start > len(data), got %v", result)
	}
}

func TestSafeSlice_StartAtLength(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	result := safeSlice(data, 3, 16)
	if result != nil {
		t.Fatalf("expected nil when start == len(data), got %v", result)
	}
}

func TestSafeSlice_ShorterThanMax(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	result := safeSlice(data, 0, 16)
	if len(result) != 5 {
		t.Fatalf("expected 5 bytes, got %d", len(result))
	}
	for i, b := range data {
		if result[i] != b {
			t.Fatalf("byte %d: expected %x, got %x", i, b, result[i])
		}
	}
}

func TestSafeSlice_ExactMax(t *testing.T) {
	data := make([]byte, 16)
	for i := range data {
		data[i] = byte(i)
	}
	result := safeSlice(data, 0, 16)
	if len(result) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(result))
	}
}

func TestSafeSlice_TruncatesLonger(t *testing.T) {
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}
	result := safeSlice(data, 0, 16)
	if len(result) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(result))
	}
	if result[15] != 15 {
		t.Fatalf("expected byte 15 to be 0x0f, got %x", result[15])
	}
}

func TestSafeSlice_WithOffset(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	result := safeSlice(data, 2, 3)
	if len(result) != 3 {
		t.Fatalf("expected 3 bytes, got %d", len(result))
	}
	if result[0] != 0x02 || result[1] != 0x03 || result[2] != 0x04 {
		t.Fatalf("expected [02 03 04], got %v", result)
	}
}

func TestSafeSlice_OffsetClipsEnd(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03}
	result := safeSlice(data, 2, 16)
	if len(result) != 2 {
		t.Fatalf("expected 2 bytes (clipped), got %d", len(result))
	}
	if result[0] != 0x02 || result[1] != 0x03 {
		t.Fatalf("expected [02 03], got %v", result)
	}
}
