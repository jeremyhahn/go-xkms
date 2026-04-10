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

package ccid

import (
	"bytes"
	"errors"
	"testing"
)

func TestParseCommandAPDU_Case1_NoBody(t *testing.T) {
	// Case 1: CLA INS P1 P2 (no data, no Le)
	data := []byte{0x00, 0xA4, 0x04, 0x00}

	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("ParseCommandAPDU failed: %v", err)
	}

	if cmd.CLA != 0x00 {
		t.Errorf("CLA = 0x%02X, want 0x00", cmd.CLA)
	}
	if cmd.INS != 0xA4 {
		t.Errorf("INS = 0x%02X, want 0xA4", cmd.INS)
	}
	if cmd.P1 != 0x04 {
		t.Errorf("P1 = 0x%02X, want 0x04", cmd.P1)
	}
	if cmd.P2 != 0x00 {
		t.Errorf("P2 = 0x%02X, want 0x00", cmd.P2)
	}
	if len(cmd.Data) != 0 {
		t.Errorf("Data length = %d, want 0", len(cmd.Data))
	}
	if cmd.Le != -1 {
		t.Errorf("Le = %d, want -1", cmd.Le)
	}
}

func TestParseCommandAPDU_Case2_LeOnly(t *testing.T) {
	// Case 2: CLA INS P1 P2 Le
	data := []byte{0x00, 0xCA, 0x00, 0x4F, 0x10}

	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("ParseCommandAPDU failed: %v", err)
	}

	if len(cmd.Data) != 0 {
		t.Errorf("Data length = %d, want 0", len(cmd.Data))
	}
	if cmd.Le != 16 {
		t.Errorf("Le = %d, want 16", cmd.Le)
	}
}

func TestParseCommandAPDU_Case2_Le0Means256(t *testing.T) {
	// Le=0 means "up to 256 bytes"
	data := []byte{0x00, 0xCA, 0x00, 0x4F, 0x00}

	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("ParseCommandAPDU failed: %v", err)
	}

	if cmd.Le != 256 {
		t.Errorf("Le = %d, want 256", cmd.Le)
	}
}

func TestParseCommandAPDU_Case3_DataNoLe(t *testing.T) {
	// Case 3: CLA INS P1 P2 Lc Data...
	aid := []byte{0xA0, 0x00, 0x00, 0x03, 0x08}
	data := append([]byte{0x00, 0xA4, 0x04, 0x00, byte(len(aid))}, aid...)

	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("ParseCommandAPDU failed: %v", err)
	}

	if !bytes.Equal(cmd.Data, aid) {
		t.Errorf("Data = %x, want %x", cmd.Data, aid)
	}
	if cmd.Le != -1 {
		t.Errorf("Le = %d, want -1", cmd.Le)
	}
}

func TestParseCommandAPDU_Case4_DataAndLe(t *testing.T) {
	// Case 4: CLA INS P1 P2 Lc Data... Le
	aid := []byte{0xA0, 0x00, 0x00}
	data := append([]byte{0x00, 0xA4, 0x04, 0x00, byte(len(aid))}, aid...)
	data = append(data, 0x20) // Le = 32

	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("ParseCommandAPDU failed: %v", err)
	}

	if !bytes.Equal(cmd.Data, aid) {
		t.Errorf("Data = %x, want %x", cmd.Data, aid)
	}
	if cmd.Le != 32 {
		t.Errorf("Le = %d, want 32", cmd.Le)
	}
}

func TestParseCommandAPDU_TooShort(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"one byte", []byte{0x00}},
		{"two bytes", []byte{0x00, 0xA4}},
		{"three bytes", []byte{0x00, 0xA4, 0x04}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCommandAPDU(tt.data)
			if !errors.Is(err, ErrAPDUMalformed) {
				t.Errorf("ParseCommandAPDU error = %v, want ErrAPDUMalformed", err)
			}
		})
	}
}

func TestParseCommandAPDU_LcMismatch(t *testing.T) {
	// Lc says 10 bytes but only 3 are present
	data := []byte{0x00, 0xA4, 0x04, 0x00, 0x0A, 0x01, 0x02, 0x03}

	_, err := ParseCommandAPDU(data)
	if !errors.Is(err, ErrAPDUMalformed) {
		t.Errorf("ParseCommandAPDU error = %v, want ErrAPDUMalformed", err)
	}
}

func TestParseCommandAPDU_ExtendedLeOnly(t *testing.T) {
	// Extended Le: [CLA INS P1 P2 0x00 Le1 Le2]
	data := []byte{0x00, 0xB0, 0x00, 0x00, 0x00, 0x01, 0x00}

	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("ParseCommandAPDU failed: %v", err)
	}

	if cmd.Le != 256 {
		t.Errorf("Le = %d, want 256", cmd.Le)
	}
}

func TestParseCommandAPDU_ExtendedWithData(t *testing.T) {
	// Extended: [CLA INS P1 P2 0x00 Lc1 Lc2 Data... Le1 Le2]
	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i)
	}

	data := []byte{0x00, 0x2A, 0x9E, 0x9A, 0x00}
	data = append(data, byte(len(payload)>>8), byte(len(payload)&0xFF))
	data = append(data, payload...)
	data = append(data, 0x01, 0x00) // Le=256

	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("ParseCommandAPDU failed: %v", err)
	}

	if len(cmd.Data) != 300 {
		t.Errorf("Data length = %d, want 300", len(cmd.Data))
	}
	if cmd.Le != 256 {
		t.Errorf("Le = %d, want 256", cmd.Le)
	}
}

func TestCommandAPDU_Serialize_Case1(t *testing.T) {
	cmd := &CommandAPDU{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Le: -1}
	result := cmd.Serialize()
	expected := []byte{0x00, 0xA4, 0x04, 0x00}

	if !bytes.Equal(result, expected) {
		t.Errorf("Serialize = %x, want %x", result, expected)
	}
}

func TestCommandAPDU_Serialize_Case2(t *testing.T) {
	cmd := &CommandAPDU{CLA: 0x00, INS: 0xCA, P1: 0x00, P2: 0x4F, Le: 16}
	result := cmd.Serialize()
	expected := []byte{0x00, 0xCA, 0x00, 0x4F, 0x10}

	if !bytes.Equal(result, expected) {
		t.Errorf("Serialize = %x, want %x", result, expected)
	}
}

func TestCommandAPDU_Serialize_Case3(t *testing.T) {
	aid := []byte{0xA0, 0x00, 0x00}
	cmd := &CommandAPDU{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Data: aid, Le: -1}
	result := cmd.Serialize()
	expected := append([]byte{0x00, 0xA4, 0x04, 0x00, 0x03}, aid...)

	if !bytes.Equal(result, expected) {
		t.Errorf("Serialize = %x, want %x", result, expected)
	}
}

func TestCommandAPDU_Serialize_Case4(t *testing.T) {
	aid := []byte{0xA0, 0x00, 0x00}
	cmd := &CommandAPDU{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Data: aid, Le: 32}
	result := cmd.Serialize()
	expected := append([]byte{0x00, 0xA4, 0x04, 0x00, 0x03}, aid...)
	expected = append(expected, 0x20)

	if !bytes.Equal(result, expected) {
		t.Errorf("Serialize = %x, want %x", result, expected)
	}
}

func TestCommandAPDU_SerializeRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		cmd  *CommandAPDU
	}{
		{
			name: "Case 1",
			cmd:  &CommandAPDU{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Le: -1},
		},
		{
			name: "Case 2 with Le",
			cmd:  &CommandAPDU{CLA: 0x00, INS: 0xCA, P1: 0x00, P2: 0x4F, Le: 100},
		},
		{
			name: "Case 3 with data",
			cmd:  &CommandAPDU{CLA: 0x00, INS: 0x20, P1: 0x00, P2: 0x80, Data: []byte("123456"), Le: -1},
		},
		{
			name: "Case 4 with data and Le",
			cmd:  &CommandAPDU{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Data: []byte{0xA0, 0x00, 0x00}, Le: 50},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serialized := tt.cmd.Serialize()
			parsed, err := ParseCommandAPDU(serialized)
			if err != nil {
				t.Fatalf("round-trip parse failed: %v", err)
			}

			if parsed.CLA != tt.cmd.CLA {
				t.Errorf("CLA = 0x%02X, want 0x%02X", parsed.CLA, tt.cmd.CLA)
			}
			if parsed.INS != tt.cmd.INS {
				t.Errorf("INS = 0x%02X, want 0x%02X", parsed.INS, tt.cmd.INS)
			}
			if parsed.P1 != tt.cmd.P1 {
				t.Errorf("P1 = 0x%02X, want 0x%02X", parsed.P1, tt.cmd.P1)
			}
			if parsed.P2 != tt.cmd.P2 {
				t.Errorf("P2 = 0x%02X, want 0x%02X", parsed.P2, tt.cmd.P2)
			}
			if !bytes.Equal(parsed.Data, tt.cmd.Data) {
				t.Errorf("Data mismatch: got %x, want %x", parsed.Data, tt.cmd.Data)
			}
			if parsed.Le != tt.cmd.Le {
				t.Errorf("Le = %d, want %d", parsed.Le, tt.cmd.Le)
			}
		})
	}
}

func TestResponseAPDU_Serialize(t *testing.T) {
	resp := &ResponseAPDU{
		Data: []byte{0x01, 0x02, 0x03},
		SW1:  0x90,
		SW2:  0x00,
	}

	result := resp.Serialize()
	expected := []byte{0x01, 0x02, 0x03, 0x90, 0x00}

	if !bytes.Equal(result, expected) {
		t.Errorf("Serialize = %x, want %x", result, expected)
	}
}

func TestResponseAPDU_SerializeNoData(t *testing.T) {
	resp := &ResponseAPDU{SW1: 0x6D, SW2: 0x00}
	result := resp.Serialize()
	expected := []byte{0x6D, 0x00}

	if !bytes.Equal(result, expected) {
		t.Errorf("Serialize = %x, want %x", result, expected)
	}
}

func TestResponseAPDU_StatusWord(t *testing.T) {
	resp := &ResponseAPDU{SW1: 0x90, SW2: 0x00}
	if resp.StatusWord() != SW_SUCCESS {
		t.Errorf("StatusWord = 0x%04X, want 0x%04X", resp.StatusWord(), SW_SUCCESS)
	}
}

func TestResponseAPDU_IsSuccess(t *testing.T) {
	tests := []struct {
		name    string
		sw1     byte
		sw2     byte
		success bool
	}{
		{"success", 0x90, 0x00, true},
		{"wrong_length", 0x67, 0x00, false},
		{"ins_not_supported", 0x6D, 0x00, false},
		{"internal_error", 0x6F, 0x00, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &ResponseAPDU{SW1: tt.sw1, SW2: tt.sw2}
			if resp.IsSuccess() != tt.success {
				t.Errorf("IsSuccess = %v, want %v", resp.IsSuccess(), tt.success)
			}
		})
	}
}

func TestNewSuccessResponse(t *testing.T) {
	data := []byte{0xDE, 0xAD}
	resp := NewSuccessResponse(data)

	if !bytes.Equal(resp.Data, data) {
		t.Errorf("Data = %x, want %x", resp.Data, data)
	}
	if resp.SW1 != 0x90 || resp.SW2 != 0x00 {
		t.Errorf("Status = %02X%02X, want 9000", resp.SW1, resp.SW2)
	}
}

func TestNewSuccessResponse_NilData(t *testing.T) {
	resp := NewSuccessResponse(nil)
	if resp.Data != nil {
		t.Errorf("Data = %v, want nil", resp.Data)
	}
	if !resp.IsSuccess() {
		t.Error("Expected success status")
	}
}

func TestNewErrorResponse(t *testing.T) {
	tests := []struct {
		name string
		sw   uint16
	}{
		{"file_not_found", SW_FILE_NOT_FOUND},
		{"wrong_length", SW_WRONG_LENGTH},
		{"wrong_data", SW_WRONG_DATA},
		{"ins_not_supported", SW_INS_NOT_SUPPORTED},
		{"cla_not_supported", SW_CLA_NOT_SUPPORTED},
		{"internal_error", SW_INTERNAL_ERROR},
		{"security_status", SW_SECURITY_STATUS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := NewErrorResponse(tt.sw)

			if len(resp.Data) != 0 {
				t.Errorf("Data length = %d, want 0", len(resp.Data))
			}
			if resp.StatusWord() != tt.sw {
				t.Errorf("StatusWord = 0x%04X, want 0x%04X", resp.StatusWord(), tt.sw)
			}
			if resp.IsSuccess() {
				t.Error("Expected non-success status")
			}
		})
	}
}

func TestStatusWordConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint16
		expected uint16
	}{
		{"SW_SUCCESS", SW_SUCCESS, 0x9000},
		{"SW_FILE_NOT_FOUND", SW_FILE_NOT_FOUND, 0x6A82},
		{"SW_WRONG_LENGTH", SW_WRONG_LENGTH, 0x6700},
		{"SW_WRONG_DATA", SW_WRONG_DATA, 0x6A80},
		{"SW_INS_NOT_SUPPORTED", SW_INS_NOT_SUPPORTED, 0x6D00},
		{"SW_CLA_NOT_SUPPORTED", SW_CLA_NOT_SUPPORTED, 0x6E00},
		{"SW_INTERNAL_ERROR", SW_INTERNAL_ERROR, 0x6F00},
		{"SW_SECURITY_STATUS", SW_SECURITY_STATUS, 0x6982},
		{"SW_CONDITIONS_NOT_SATISFIED", SW_CONDITIONS_NOT_SATISFIED, 0x6985},
		{"SW_WRONG_P1P2", SW_WRONG_P1P2, 0x6A86},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = 0x%04X, want 0x%04X", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

func TestInstructionByteConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant byte
		expected byte
	}{
		{"INS_SELECT", INS_SELECT, 0xA4},
		{"INS_VERIFY", INS_VERIFY, 0x20},
		{"INS_PSO", INS_PSO, 0x2A},
		{"INS_READ_BINARY", INS_READ_BINARY, 0xB0},
		{"INS_GENERATE_ASYMMETRIC", INS_GENERATE_ASYMMETRIC, 0x47},
		{"INS_GET_DATA", INS_GET_DATA, 0xCA},
		{"INS_PUT_DATA", INS_PUT_DATA, 0xDA},
		{"INS_GET_RESPONSE", INS_GET_RESPONSE, 0xC0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = 0x%02X, want 0x%02X", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

func TestParseCommandAPDU_Le256SerializesAs0(t *testing.T) {
	cmd := &CommandAPDU{CLA: 0x00, INS: 0xCA, P1: 0x00, P2: 0x4F, Le: 256}
	serialized := cmd.Serialize()

	// Le=256 should serialize as 0x00
	if serialized[len(serialized)-1] != 0x00 {
		t.Errorf("Le byte = 0x%02X, want 0x00 for Le=256", serialized[len(serialized)-1])
	}

	// Round-trip: should parse back as 256
	parsed, err := ParseCommandAPDU(serialized)
	if err != nil {
		t.Fatalf("ParseCommandAPDU failed: %v", err)
	}
	if parsed.Le != 256 {
		t.Errorf("Le = %d, want 256", parsed.Le)
	}
}
