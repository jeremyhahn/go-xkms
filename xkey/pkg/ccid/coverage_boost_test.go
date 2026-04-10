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
	"context"
	"crypto"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// --- APDU parsing edge cases for coverage ---

func TestParseShortAPDU_Lc0NoRemaining(t *testing.T) {
	// Lc=0 with no remaining bytes: treated as Lc=0 data with no Le.
	data := []byte{0x00, 0xA4, 0x04, 0x00, 0x00}
	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Le != 256 {
		t.Errorf("Le = %d, want 256 (Le=0 means 256)", cmd.Le)
	}
}

func TestParseShortAPDU_Lc0WithLe(t *testing.T) {
	// Lc=0 followed by Le byte: should be treated as Le.
	data := []byte{0x00, 0xA4, 0x04, 0x00, 0x00, 0x20}
	// remaining = [0x00, 0x20], remaining[0]=0x00, len=2 < 3 => parseShortAPDU.
	// lc=0x00, remaining after lc = [0x20]. lc==0, len(remaining)==1 => Le=0x20=32.
	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Le != 32 {
		t.Errorf("Le = %d, want 32", cmd.Le)
	}
}

func TestParseShortAPDU_Lc0WithLeZero(t *testing.T) {
	// Lc=0 with Le=0 (meaning 256) through parseShortAPDU.
	// remaining = [0x00, 0x00], len=2 < 3 => parseShortAPDU.
	// lc=0x00, remaining after lc = [0x00]. len==1.
	// Le=int(0x00)=0, if le==0 then le=256.
	data := []byte{0x00, 0xA4, 0x04, 0x00, 0x00, 0x00}
	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Le != 256 {
		t.Errorf("Le = %d, want 256 (Le=0 in short form means 256)", cmd.Le)
	}
}

func TestParseShortAPDU_Lc0WithMultipleExtraBytes(t *testing.T) {
	// Lc=3 but only 2 data bytes available => malformed.
	data := []byte{0x00, 0xA4, 0x04, 0x00, 0x03, 0x01, 0x02}
	_, err := ParseCommandAPDU(data)
	if !errors.Is(err, ErrAPDUMalformed) {
		t.Errorf("error = %v, want ErrAPDUMalformed", err)
	}
}

func TestParseShortAPDU_Case4_With2ByteExtLe(t *testing.T) {
	// Case 4 with short Lc and 2-byte extended Le after data.
	aid := []byte{0xA0, 0x00, 0x00}
	data := append([]byte{0x00, 0xA4, 0x04, 0x00, byte(len(aid))}, aid...)
	// Add 2-byte Le (extended Le after short Lc data)
	data = append(data, 0x01, 0x00) // Le=256

	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Le != 256 {
		t.Errorf("Le = %d, want 256", cmd.Le)
	}
}

func TestParseShortAPDU_Case4_Le0In2Byte(t *testing.T) {
	// 2-byte Le=0x0000 means 65536.
	aid := []byte{0xA0, 0x00, 0x00}
	data := append([]byte{0x00, 0xA4, 0x04, 0x00, byte(len(aid))}, aid...)
	data = append(data, 0x00, 0x00) // Le=0 means 65536

	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Le != 65536 {
		t.Errorf("Le = %d, want 65536", cmd.Le)
	}
}

func TestParseShortAPDU_Case4_Le0_SingleByte(t *testing.T) {
	// Case 4: short Lc with data, Le=0x00 (single byte) meaning 256.
	// [CLA INS P1 P2 Lc=2 D1 D2 Le=0x00]
	data := []byte{0x00, 0xA4, 0x04, 0x00, 0x02, 0xA0, 0x00, 0x00}
	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Le != 256 {
		t.Errorf("Le = %d, want 256 (Le=0 single-byte means 256)", cmd.Le)
	}
}

func TestParseShortAPDU_Case3_TooManyTrailingBytes(t *testing.T) {
	// Data present with 3+ trailing bytes (not 0, 1, or 2) = malformed.
	aid := []byte{0xA0, 0x00}
	data := append([]byte{0x00, 0xA4, 0x04, 0x00, byte(len(aid))}, aid...)
	data = append(data, 0x01, 0x02, 0x03) // 3 trailing bytes

	_, err := ParseCommandAPDU(data)
	if !errors.Is(err, ErrAPDUMalformed) {
		t.Errorf("error = %v, want ErrAPDUMalformed", err)
	}
}

func TestParseExtendedAPDU_LeZeroMeans65536(t *testing.T) {
	// Extended Le only: [0x00 0x00 0x00] means Le=65536.
	data := []byte{0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00}

	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Le != 65536 {
		t.Errorf("Le = %d, want 65536", cmd.Le)
	}
}

func TestParseExtendedAPDU_Lc0Error(t *testing.T) {
	// Extended Lc=0 is malformed: [0x00 0x00 0x00 <data>]
	// len(remaining) > 3 but Lc=0 => error.
	data := []byte{0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF}
	_, err := ParseCommandAPDU(data)
	if !errors.Is(err, ErrAPDUMalformed) {
		t.Errorf("error = %v, want ErrAPDUMalformed", err)
	}
}

func TestParseExtendedAPDU_DataNoLe(t *testing.T) {
	// Extended Lc with data but no Le.
	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i)
	}

	data := []byte{0x00, 0x2A, 0x9E, 0x9A, 0x00}
	data = append(data, byte(len(payload)>>8), byte(len(payload)&0xFF))
	data = append(data, payload...)

	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cmd.Data) != 300 {
		t.Errorf("Data length = %d, want 300", len(cmd.Data))
	}
	if cmd.Le != -1 {
		t.Errorf("Le = %d, want -1 (no Le)", cmd.Le)
	}
}

func TestParseExtendedAPDU_DataLcMismatch(t *testing.T) {
	// Extended Lc says 500 but only 300 bytes present.
	data := []byte{0x00, 0x2A, 0x9E, 0x9A, 0x00, 0x01, 0xF4} // Lc=500
	payload := make([]byte, 300)
	data = append(data, payload...)

	_, err := ParseCommandAPDU(data)
	if !errors.Is(err, ErrAPDUMalformed) {
		t.Errorf("error = %v, want ErrAPDUMalformed", err)
	}
}

func TestParseExtendedAPDU_TrailingBytesMalformed(t *testing.T) {
	// Extended data with 1 trailing byte (not 0 or 2) => malformed.
	payload := make([]byte, 300)
	data := []byte{0x00, 0x2A, 0x9E, 0x9A, 0x00}
	data = append(data, byte(len(payload)>>8), byte(len(payload)&0xFF))
	data = append(data, payload...)
	data = append(data, 0xFF) // 1 trailing byte

	_, err := ParseCommandAPDU(data)
	if !errors.Is(err, ErrAPDUMalformed) {
		t.Errorf("error = %v, want ErrAPDUMalformed", err)
	}
}

func TestParseExtendedAPDU_LeAfterData_Zero(t *testing.T) {
	// Extended Le=0x0000 after data means 65536.
	payload := make([]byte, 300)
	data := []byte{0x00, 0x2A, 0x9E, 0x9A, 0x00}
	data = append(data, byte(len(payload)>>8), byte(len(payload)&0xFF))
	data = append(data, payload...)
	data = append(data, 0x00, 0x00) // Le=0 means 65536

	cmd, err := ParseCommandAPDU(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Le != 65536 {
		t.Errorf("Le = %d, want 65536", cmd.Le)
	}
}

func TestParseCommandAPDU_TooLong(t *testing.T) {
	// APDU exceeding MaxAPDUDataLength + MinAPDULength + 3 = 65542 bytes.
	data := make([]byte, 65543)
	data[0] = 0x00 // CLA
	data[1] = 0xB0 // INS
	data[2] = 0x00 // P1
	data[3] = 0x00 // P2

	_, err := ParseCommandAPDU(data)
	if !errors.Is(err, ErrAPDUTooLong) {
		t.Errorf("error = %v, want ErrAPDUTooLong", err)
	}
}

// --- CommandAPDU.Serialize extended coverage ---

func TestCommandAPDU_Serialize_ExtendedData(t *testing.T) {
	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i)
	}
	cmd := &CommandAPDU{CLA: 0x00, INS: 0x2A, P1: 0x9E, P2: 0x9A, Data: payload, Le: -1}
	result := cmd.Serialize()

	// Should start with CLA INS P1 P2 0x00 Lc_high Lc_low
	if result[4] != 0x00 {
		t.Errorf("Extended marker = 0x%02X, want 0x00", result[4])
	}
	lcHigh := result[5]
	lcLow := result[6]
	lc := int(lcHigh)<<8 | int(lcLow)
	if lc != 300 {
		t.Errorf("Lc = %d, want 300", lc)
	}
}

func TestCommandAPDU_Serialize_ExtendedDataAndLe(t *testing.T) {
	payload := make([]byte, 300)
	cmd := &CommandAPDU{CLA: 0x00, INS: 0x2A, P1: 0x9E, P2: 0x9A, Data: payload, Le: 500}
	result := cmd.Serialize()

	// Verify Le at the end.
	leHigh := result[len(result)-2]
	leLow := result[len(result)-1]
	le := int(leHigh)<<8 | int(leLow)
	if le != 500 {
		t.Errorf("Le = %d, want 500", le)
	}
}

func TestCommandAPDU_Serialize_ExtendedLeOnly(t *testing.T) {
	cmd := &CommandAPDU{CLA: 0x00, INS: 0xB0, P1: 0x00, P2: 0x00, Le: 500}
	result := cmd.Serialize()

	// Should be [CLA INS P1 P2 0x00 Le_high Le_low]
	if len(result) != 7 {
		t.Errorf("length = %d, want 7", len(result))
	}
	if result[4] != 0x00 {
		t.Errorf("Extended Le prefix = 0x%02X, want 0x00", result[4])
	}
	le := int(result[5])<<8 | int(result[6])
	if le != 500 {
		t.Errorf("Le = %d, want 500", le)
	}
}

func TestCommandAPDU_Serialize_Le65536(t *testing.T) {
	cmd := &CommandAPDU{CLA: 0x00, INS: 0xB0, P1: 0x00, P2: 0x00, Le: 65536}
	result := cmd.Serialize()

	// Le=65536 should serialize as 0x0000.
	leHigh := result[len(result)-2]
	leLow := result[len(result)-1]
	if leHigh != 0x00 || leLow != 0x00 {
		t.Errorf("Le bytes = %02X %02X, want 00 00 for Le=65536", leHigh, leLow)
	}
}

func TestCommandAPDU_Serialize_ExtendedRoundTrip(t *testing.T) {
	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i)
	}
	original := &CommandAPDU{CLA: 0x00, INS: 0x2A, P1: 0x9E, P2: 0x9A, Data: payload, Le: 500}
	serialized := original.Serialize()
	parsed, err := ParseCommandAPDU(serialized)
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}
	if !bytes.Equal(parsed.Data, original.Data) {
		t.Errorf("Data mismatch after round-trip")
	}
	if parsed.Le != original.Le {
		t.Errorf("Le = %d, want %d", parsed.Le, original.Le)
	}
}

// --- Bridge coverage: encrypt/decrypt error paths, GetData OpenPGP ---

func TestPKCS11Bridge_PSO_Encipher_EmptyData(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_PSO, P1: PSO_ENCIPHER_P1, P2: PSO_ENCIPHER_P2}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_WRONG_DATA {
		t.Errorf("StatusWord = 0x%04X, want SW_WRONG_DATA", resp.StatusWord())
	}
}

func TestPKCS11Bridge_PSO_Encipher_TransportError(t *testing.T) {
	mt := &mockTransport{
		encryptFn: func(_ context.Context, _ *transport.EncryptRequest) (*transport.EncryptResponse, error) {
			return nil, errors.New("encrypt error")
		},
	}
	bridge, err := NewPKCS11Bridge(mt, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_PSO, P1: PSO_ENCIPHER_P1, P2: PSO_ENCIPHER_P2, Data: []byte("data")}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_INTERNAL_ERROR {
		t.Errorf("StatusWord = 0x%04X, want SW_INTERNAL_ERROR", resp.StatusWord())
	}
}

func TestPKCS11Bridge_PSO_Decipher_EmptyData(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_PSO, P1: PSO_DECIPHER_P1, P2: PSO_DECIPHER_P2}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_WRONG_DATA {
		t.Errorf("StatusWord = 0x%04X, want SW_WRONG_DATA", resp.StatusWord())
	}
}

func TestPKCS11Bridge_PSO_Decipher_TransportError(t *testing.T) {
	mt := &mockTransport{
		decryptFn: func(_ context.Context, _ *transport.DecryptRequest) (*transport.DecryptResponse, error) {
			return nil, errors.New("decrypt error")
		},
	}
	bridge, err := NewPKCS11Bridge(mt, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	data := make([]byte, 28) // 12 nonce + 16 ciphertext
	cmd := &CommandAPDU{CLA: 0x00, INS: INS_PSO, P1: PSO_DECIPHER_P1, P2: PSO_DECIPHER_P2, Data: data}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_INTERNAL_ERROR {
		t.Errorf("StatusWord = 0x%04X, want SW_INTERNAL_ERROR", resp.StatusWord())
	}
}

func TestPKCS11Bridge_ReadBinary_WithApplet(t *testing.T) {
	bridge := newTestBridge(t)

	// Select PIV applet first.
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_READ_BINARY, P1: 0x00, P2: 0x00}
	resp := bridge.HandleAPDU(cmd)

	// ReadBinary with an applet selected returns FILE_NOT_FOUND (no file selected).
	if resp.StatusWord() != SW_FILE_NOT_FOUND {
		t.Errorf("StatusWord = 0x%04X, want SW_FILE_NOT_FOUND", resp.StatusWord())
	}
}

func TestPKCS11Bridge_GetData_AID_OpenPGP(t *testing.T) {
	bridge := newTestBridge(t)

	// Select OpenPGP applet.
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDOpenPGP})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_GET_DATA, P1: 0x00, P2: 0x4F}
	resp := bridge.HandleAPDU(cmd)

	if !resp.IsSuccess() {
		t.Errorf("GET DATA AID (OpenPGP) failed: SW=0x%04X", resp.StatusWord())
	}
	if !bytes.Equal(resp.Data, AIDOpenPGP) {
		t.Errorf("Response data = %x, want OpenPGP AID %x", resp.Data, AIDOpenPGP)
	}
}

func TestPKCS11Bridge_GetData_NoApplet(t *testing.T) {
	bridge := newTestBridge(t)

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_GET_DATA, P1: 0x00, P2: 0x4F}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_CONDITIONS_NOT_SATISFIED {
		t.Errorf("StatusWord = 0x%04X, want SW_CONDITIONS_NOT_SATISFIED", resp.StatusWord())
	}
}

func TestPKCS11Bridge_GenerateAsymmetric_RSA(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_GENERATE_ASYMMETRIC, P1: 0x00, P2: 0x00, Data: []byte{0x01}}
	resp := bridge.HandleAPDU(cmd)

	if !resp.IsSuccess() {
		t.Errorf("GENERATE ASYMMETRIC RSA failed: SW=0x%04X", resp.StatusWord())
	}
}

func TestPKCS11Bridge_GenerateAsymmetric_Ed25519(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_GENERATE_ASYMMETRIC, P1: 0x00, P2: 0x00, Data: []byte{0x03}}
	resp := bridge.HandleAPDU(cmd)

	if !resp.IsSuccess() {
		t.Errorf("GENERATE ASYMMETRIC Ed25519 failed: SW=0x%04X", resp.StatusWord())
	}
}

func TestPKCS11Bridge_GenerateAsymmetric_NoData(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	// No data: defaults to ECDSA.
	cmd := &CommandAPDU{CLA: 0x00, INS: INS_GENERATE_ASYMMETRIC, P1: 0x00, P2: 0x00}
	resp := bridge.HandleAPDU(cmd)

	if !resp.IsSuccess() {
		t.Errorf("GENERATE ASYMMETRIC (default) failed: SW=0x%04X", resp.StatusWord())
	}
}

func TestPKCS11Bridge_GenerateAsymmetric_TransportError(t *testing.T) {
	mt := &mockTransport{
		generateKeyFn: func(_ context.Context, _ *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
			return nil, errors.New("keygen error")
		},
	}
	bridge, err := NewPKCS11Bridge(mt, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_GENERATE_ASYMMETRIC, P1: 0x00, P2: 0x00, Data: []byte{0x02}}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_INTERNAL_ERROR {
		t.Errorf("StatusWord = 0x%04X, want SW_INTERNAL_ERROR", resp.StatusWord())
	}
}

func TestPKCS11Bridge_PSO_VerifySig_TransportError(t *testing.T) {
	mt := &mockTransport{
		verifyFn: func(_ context.Context, _ *transport.VerifyRequest) (*transport.VerifyResponse, error) {
			return nil, errors.New("verify error")
		},
	}
	bridge, err := NewPKCS11Bridge(mt, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	sig := []byte("sig")
	hash := []byte("hash")
	data := []byte{0x00, byte(len(sig))}
	data = append(data, sig...)
	data = append(data, hash...)

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_PSO, P1: PSO_VERIFY_P1, P2: PSO_VERIFY_P2, Data: data}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_SECURITY_STATUS {
		t.Errorf("StatusWord = 0x%04X, want SW_SECURITY_STATUS", resp.StatusWord())
	}
}

func TestPKCS11Bridge_PSO_VerifySig_InvalidSignature(t *testing.T) {
	mt := &mockTransport{
		verifyFn: func(_ context.Context, _ *transport.VerifyRequest) (*transport.VerifyResponse, error) {
			return &transport.VerifyResponse{Valid: false}, nil
		},
	}
	bridge, err := NewPKCS11Bridge(mt, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	sig := []byte("bad")
	hash := []byte("hash")
	data := []byte{0x00, byte(len(sig))}
	data = append(data, sig...)
	data = append(data, hash...)

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_PSO, P1: PSO_VERIFY_P1, P2: PSO_VERIFY_P2, Data: data}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_SECURITY_STATUS {
		t.Errorf("StatusWord = 0x%04X, want SW_SECURITY_STATUS", resp.StatusWord())
	}
}

// --- hashName coverage ---

func TestHashName(t *testing.T) {
	tests := []struct {
		hash     crypto.Hash
		expected string
	}{
		{crypto.SHA256, "SHA-256"},
		{crypto.SHA384, "SHA-384"},
		{crypto.SHA512, "SHA-512"},
		{crypto.SHA1, "SHA-1"},
		{crypto.MD5, "SHA-256"}, // Unknown -> default
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := hashName(tt.hash)
			if got != tt.expected {
				t.Errorf("hashName(%v) = %q, want %q", tt.hash, got, tt.expected)
			}
		})
	}
}

// --- CCID device XfrBlock parse error path ---

func TestCCIDDevice_HandleCCIDMessage_XfrBlock_MalformedAPDU(t *testing.T) {
	handler := &stubHandler{
		atr: DefaultATR(),
	}

	dev, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	// Power on first.
	powerOnMsg := make([]byte, CCIDHeaderLength)
	powerOnMsg[0] = PC_to_RDR_IccPowerOn
	binary.LittleEndian.PutUint32(powerOnMsg[1:5], 0)
	powerOnMsg[5] = 0x00
	powerOnMsg[6] = 0x01
	dev.handleCCIDMessage(powerOnMsg)

	// XfrBlock with 1 byte APDU data (too short for valid APDU).
	msg := make([]byte, CCIDHeaderLength+1)
	msg[0] = PC_to_RDR_XfrBlock
	binary.LittleEndian.PutUint32(msg[1:5], 1)
	msg[5] = 0x00
	msg[6] = 0x02
	msg[CCIDHeaderLength] = 0xFF // Only 1 byte, too short for APDU

	response := dev.handleCCIDMessage(msg)
	if response == nil {
		t.Fatal("Expected response for malformed APDU")
	}

	// Should return a DataBlock with SW_WRONG_LENGTH error.
	if response[0] != RDR_to_PC_DataBlock {
		t.Errorf("Response type = 0x%02X, want RDR_to_PC_DataBlock", response[0])
	}
}

// --- CCIDDevice.Stop coverage ---

func TestCCIDDevice_Stop_AlreadyStopped(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	dev, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	err = dev.Stop()
	if !errors.Is(err, ErrDeviceNotRunning) {
		t.Errorf("Stop() error = %v, want ErrDeviceNotRunning", err)
	}
}

// --- XfrBlock with dataLen exceeding message ---

func TestCCIDDevice_HandleCCIDMessage_XfrBlock_DataLenExceedsMsg(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}

	dev, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	// Power on first.
	powerOnMsg := make([]byte, CCIDHeaderLength)
	powerOnMsg[0] = PC_to_RDR_IccPowerOn
	binary.LittleEndian.PutUint32(powerOnMsg[1:5], 0)
	powerOnMsg[5] = 0x00
	powerOnMsg[6] = 0x01
	dev.handleCCIDMessage(powerOnMsg)

	// XfrBlock: dataLen says 100 but message only has 8 bytes of data.
	// This triggers the apduEnd > len(msg) truncation at ccid.go:360.
	apduData := []byte{0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	msg := make([]byte, CCIDHeaderLength+len(apduData))
	msg[0] = PC_to_RDR_XfrBlock
	binary.LittleEndian.PutUint32(msg[1:5], 100) // Claims 100 bytes
	msg[5] = 0x00
	msg[6] = 0x03
	copy(msg[CCIDHeaderLength:], apduData)

	response := dev.handleCCIDMessage(msg)
	if response == nil {
		t.Fatal("Expected response for truncated XfrBlock")
	}

	// Should return a DataBlock (the APDU data got truncated/clamped but still parsed).
	if response[0] != RDR_to_PC_DataBlock {
		t.Errorf("Response type = 0x%02X, want RDR_to_PC_DataBlock", response[0])
	}
}

// --- matchAID byte mismatch coverage ---

func TestPKCS11Bridge_Select_AIDMismatch(t *testing.T) {
	bridge := newTestBridge(t)

	// Create an AID that starts with the same prefix as PIV but differs
	// in a later byte. AIDPIV starts with [0xA0, 0x00, 0x00, 0x03, 0x08, ...].
	// We match the first 4 bytes but differ at byte 5.
	mismatchAID := make([]byte, len(AIDPIV))
	copy(mismatchAID, AIDPIV)
	mismatchAID[4] = 0xFF // Differs from AIDPIV[4]=0x08

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: mismatchAID}
	resp := bridge.HandleAPDU(cmd)

	// Unknown AID -> FILE_NOT_FOUND.
	if resp.StatusWord() != SW_FILE_NOT_FOUND {
		t.Errorf("StatusWord = 0x%04X, want SW_FILE_NOT_FOUND", resp.StatusWord())
	}
}
