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
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockTransport implements PKCS11Transport for testing.
type mockTransport struct {
	generateKeyFn func(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error)
	signFn        func(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error)
	verifyFn      func(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error)
	encryptFn     func(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error)
	decryptFn     func(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error)
}

func (m *mockTransport) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	if m.generateKeyFn != nil {
		return m.generateKeyFn(ctx, req)
	}
	return &transport.GenerateKeyResponse{
		KeyID:        req.KeyID,
		KeyType:      req.Algorithm,
		PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
	}, nil
}

func (m *mockTransport) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	if m.signFn != nil {
		return m.signFn(ctx, req)
	}
	return &transport.SignResponse{Signature: []byte("mock-signature")}, nil
}

func (m *mockTransport) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	if m.verifyFn != nil {
		return m.verifyFn(ctx, req)
	}
	return &transport.VerifyResponse{Valid: true}, nil
}

func (m *mockTransport) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	if m.encryptFn != nil {
		return m.encryptFn(ctx, req)
	}
	return &transport.EncryptResponse{
		Ciphertext: []byte("encrypted-data"),
		Nonce:      make([]byte, 12),
	}, nil
}

func (m *mockTransport) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	if m.decryptFn != nil {
		return m.decryptFn(ctx, req)
	}
	return &transport.DecryptResponse{Plaintext: []byte("decrypted-data")}, nil
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newTestBridge(t *testing.T) *PKCS11Bridge {
	t.Helper()
	bridge, err := NewPKCS11Bridge(&mockTransport{}, newTestLogger())
	if err != nil {
		t.Fatalf("NewPKCS11Bridge failed: %v", err)
	}
	return bridge
}

func TestNewPKCS11Bridge(t *testing.T) {
	bridge, err := NewPKCS11Bridge(&mockTransport{}, newTestLogger())
	if err != nil {
		t.Fatalf("NewPKCS11Bridge failed: %v", err)
	}
	if bridge == nil {
		t.Fatal("NewPKCS11Bridge returned nil")
	}
}

func TestNewPKCS11Bridge_NilTransport(t *testing.T) {
	_, err := NewPKCS11Bridge(nil, newTestLogger())
	if !errors.Is(err, ErrNilService) {
		t.Errorf("error = %v, want ErrNilService", err)
	}
}

func TestNewPKCS11Bridge_NilLogger(t *testing.T) {
	_, err := NewPKCS11Bridge(&mockTransport{}, nil)
	if !errors.Is(err, ErrNilLogger) {
		t.Errorf("error = %v, want ErrNilLogger", err)
	}
}

func TestPKCS11Bridge_GetATR(t *testing.T) {
	bridge := newTestBridge(t)
	atr := bridge.GetATR()

	if len(atr) == 0 {
		t.Fatal("GetATR returned empty ATR")
	}
	if atr[0] != 0x3B {
		t.Errorf("ATR TS byte = 0x%02X, want 0x3B (direct convention)", atr[0])
	}
}

func TestPKCS11Bridge_HandleAPDU_NilCommand(t *testing.T) {
	bridge := newTestBridge(t)
	resp := bridge.HandleAPDU(nil)

	if resp.StatusWord() != SW_INTERNAL_ERROR {
		t.Errorf("StatusWord = 0x%04X, want SW_INTERNAL_ERROR", resp.StatusWord())
	}
}

func TestPKCS11Bridge_HandleAPDU_UnsupportedInstruction(t *testing.T) {
	bridge := newTestBridge(t)
	cmd := &CommandAPDU{CLA: 0x00, INS: 0xFF, P1: 0x00, P2: 0x00}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_INS_NOT_SUPPORTED {
		t.Errorf("StatusWord = 0x%04X, want SW_INS_NOT_SUPPORTED", resp.StatusWord())
	}
}

func TestPKCS11Bridge_Select_PIV(t *testing.T) {
	bridge := newTestBridge(t)

	cmd := &CommandAPDU{
		CLA:  0x00,
		INS:  INS_SELECT,
		P1:   0x04,
		P2:   0x00,
		Data: AIDPIV,
	}

	resp := bridge.HandleAPDU(cmd)
	if !resp.IsSuccess() {
		t.Errorf("PIV SELECT failed: SW=0x%04X", resp.StatusWord())
	}
}

func TestPKCS11Bridge_Select_OpenPGP(t *testing.T) {
	bridge := newTestBridge(t)

	cmd := &CommandAPDU{
		CLA:  0x00,
		INS:  INS_SELECT,
		P1:   0x04,
		P2:   0x00,
		Data: AIDOpenPGP,
	}

	resp := bridge.HandleAPDU(cmd)
	if !resp.IsSuccess() {
		t.Errorf("OpenPGP SELECT failed: SW=0x%04X", resp.StatusWord())
	}
}

func TestPKCS11Bridge_Select_UnknownAID(t *testing.T) {
	bridge := newTestBridge(t)

	cmd := &CommandAPDU{
		CLA:  0x00,
		INS:  INS_SELECT,
		P1:   0x04,
		P2:   0x00,
		Data: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := bridge.HandleAPDU(cmd)
	if resp.StatusWord() != SW_FILE_NOT_FOUND {
		t.Errorf("StatusWord = 0x%04X, want SW_FILE_NOT_FOUND", resp.StatusWord())
	}
}

func TestPKCS11Bridge_Select_WrongP1(t *testing.T) {
	bridge := newTestBridge(t)

	cmd := &CommandAPDU{
		CLA:  0x00,
		INS:  INS_SELECT,
		P1:   0x00, // Wrong P1
		P2:   0x00,
		Data: AIDPIV,
	}

	resp := bridge.HandleAPDU(cmd)
	if resp.StatusWord() != SW_WRONG_P1P2 {
		t.Errorf("StatusWord = 0x%04X, want SW_WRONG_P1P2", resp.StatusWord())
	}
}

func TestPKCS11Bridge_Select_EmptyData(t *testing.T) {
	bridge := newTestBridge(t)

	cmd := &CommandAPDU{
		CLA: 0x00,
		INS: INS_SELECT,
		P1:  0x04,
		P2:  0x00,
	}

	resp := bridge.HandleAPDU(cmd)
	if resp.StatusWord() != SW_WRONG_DATA {
		t.Errorf("StatusWord = 0x%04X, want SW_WRONG_DATA", resp.StatusWord())
	}
}

func TestPKCS11Bridge_Verify_Success(t *testing.T) {
	bridge := newTestBridge(t)

	// First select an applet
	selectCmd := &CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV}
	bridge.HandleAPDU(selectCmd)

	// Then verify PIN
	verifyCmd := &CommandAPDU{
		CLA:  0x00,
		INS:  INS_VERIFY,
		P1:   0x00,
		P2:   0x80,
		Data: []byte("123456"),
	}

	resp := bridge.HandleAPDU(verifyCmd)
	if !resp.IsSuccess() {
		t.Errorf("VERIFY failed: SW=0x%04X", resp.StatusWord())
	}

	if bridge.SessionCount() != 1 {
		t.Errorf("SessionCount = %d, want 1", bridge.SessionCount())
	}
}

func TestPKCS11Bridge_Verify_NoAppletSelected(t *testing.T) {
	bridge := newTestBridge(t)

	cmd := &CommandAPDU{
		CLA:  0x00,
		INS:  INS_VERIFY,
		P1:   0x00,
		P2:   0x80,
		Data: []byte("123456"),
	}

	resp := bridge.HandleAPDU(cmd)
	if resp.StatusWord() != SW_CONDITIONS_NOT_SATISFIED {
		t.Errorf("StatusWord = 0x%04X, want SW_CONDITIONS_NOT_SATISFIED", resp.StatusWord())
	}
}

func TestPKCS11Bridge_Verify_EmptyPIN(t *testing.T) {
	bridge := newTestBridge(t)

	// Select applet first
	selectCmd := &CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV}
	bridge.HandleAPDU(selectCmd)

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_WRONG_DATA {
		t.Errorf("StatusWord = 0x%04X, want SW_WRONG_DATA", resp.StatusWord())
	}
}

func TestPKCS11Bridge_PSO_Sign(t *testing.T) {
	bridge := newTestBridge(t)

	// Setup: select + verify
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	// Sign
	cmd := &CommandAPDU{
		CLA:  0x00,
		INS:  INS_PSO,
		P1:   PSO_SIGN_P1,
		P2:   PSO_SIGN_P2,
		Data: []byte("data to sign"),
	}

	resp := bridge.HandleAPDU(cmd)
	if !resp.IsSuccess() {
		t.Errorf("PSO SIGN failed: SW=0x%04X", resp.StatusWord())
	}
	if len(resp.Data) == 0 {
		t.Error("Expected signature data in response")
	}
}

func TestPKCS11Bridge_PSO_Sign_NoSession(t *testing.T) {
	bridge := newTestBridge(t)

	cmd := &CommandAPDU{
		CLA:  0x00,
		INS:  INS_PSO,
		P1:   PSO_SIGN_P1,
		P2:   PSO_SIGN_P2,
		Data: []byte("data"),
	}

	resp := bridge.HandleAPDU(cmd)
	if resp.StatusWord() != SW_SECURITY_STATUS {
		t.Errorf("StatusWord = 0x%04X, want SW_SECURITY_STATUS", resp.StatusWord())
	}
}

func TestPKCS11Bridge_PSO_Sign_EmptyData(t *testing.T) {
	bridge := newTestBridge(t)

	// Setup
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_PSO, P1: PSO_SIGN_P1, P2: PSO_SIGN_P2}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_WRONG_DATA {
		t.Errorf("StatusWord = 0x%04X, want SW_WRONG_DATA", resp.StatusWord())
	}
}

func TestPKCS11Bridge_PSO_Sign_TransportError(t *testing.T) {
	mt := &mockTransport{
		signFn: func(_ context.Context, _ *transport.SignRequest) (*transport.SignResponse, error) {
			return nil, errors.New("sign error")
		},
	}

	bridge, err := NewPKCS11Bridge(mt, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_PSO, P1: PSO_SIGN_P1, P2: PSO_SIGN_P2, Data: []byte("data")}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_INTERNAL_ERROR {
		t.Errorf("StatusWord = 0x%04X, want SW_INTERNAL_ERROR", resp.StatusWord())
	}
}

func TestPKCS11Bridge_PSO_Encipher(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	cmd := &CommandAPDU{
		CLA:  0x00,
		INS:  INS_PSO,
		P1:   PSO_ENCIPHER_P1,
		P2:   PSO_ENCIPHER_P2,
		Data: []byte("plaintext"),
	}

	resp := bridge.HandleAPDU(cmd)
	if !resp.IsSuccess() {
		t.Errorf("PSO ENCIPHER failed: SW=0x%04X", resp.StatusWord())
	}
	if len(resp.Data) == 0 {
		t.Error("Expected ciphertext data in response")
	}
}

func TestPKCS11Bridge_PSO_Decipher(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	// Nonce (12 bytes) + ciphertext
	data := make([]byte, 12+16)
	copy(data[12:], []byte("ciphertext-data!"))

	cmd := &CommandAPDU{
		CLA:  0x00,
		INS:  INS_PSO,
		P1:   PSO_DECIPHER_P1,
		P2:   PSO_DECIPHER_P2,
		Data: data,
	}

	resp := bridge.HandleAPDU(cmd)
	if !resp.IsSuccess() {
		t.Errorf("PSO DECIPHER failed: SW=0x%04X", resp.StatusWord())
	}
}

func TestPKCS11Bridge_PSO_Decipher_TooShort(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	// Only 12 bytes (nonce only, no ciphertext)
	cmd := &CommandAPDU{
		CLA:  0x00,
		INS:  INS_PSO,
		P1:   PSO_DECIPHER_P1,
		P2:   PSO_DECIPHER_P2,
		Data: make([]byte, 12),
	}

	resp := bridge.HandleAPDU(cmd)
	if resp.StatusWord() != SW_WRONG_DATA {
		t.Errorf("StatusWord = 0x%04X, want SW_WRONG_DATA", resp.StatusWord())
	}
}

func TestPKCS11Bridge_PSO_UnsupportedP1P2(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_PSO, P1: 0xFF, P2: 0xFF, Data: []byte("data")}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_INS_NOT_SUPPORTED {
		t.Errorf("StatusWord = 0x%04X, want SW_INS_NOT_SUPPORTED", resp.StatusWord())
	}
}

func TestPKCS11Bridge_GenerateAsymmetric(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	cmd := &CommandAPDU{
		CLA:  0x00,
		INS:  INS_GENERATE_ASYMMETRIC,
		P1:   0x00,
		P2:   0x00,
		Data: []byte{0x02}, // ECDSA
	}

	resp := bridge.HandleAPDU(cmd)
	if !resp.IsSuccess() {
		t.Errorf("GENERATE ASYMMETRIC failed: SW=0x%04X", resp.StatusWord())
	}
	if len(resp.Data) == 0 {
		t.Error("Expected public key PEM in response")
	}
}

func TestPKCS11Bridge_GenerateAsymmetric_NoSession(t *testing.T) {
	bridge := newTestBridge(t)

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_GENERATE_ASYMMETRIC, P1: 0x00, P2: 0x00}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_SECURITY_STATUS {
		t.Errorf("StatusWord = 0x%04X, want SW_SECURITY_STATUS", resp.StatusWord())
	}
}

func TestPKCS11Bridge_ReadBinary_NoApplet(t *testing.T) {
	bridge := newTestBridge(t)

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_READ_BINARY, P1: 0x00, P2: 0x00}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_CONDITIONS_NOT_SATISFIED {
		t.Errorf("StatusWord = 0x%04X, want SW_CONDITIONS_NOT_SATISFIED", resp.StatusWord())
	}
}

func TestPKCS11Bridge_GetData_AID_PIV(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_GET_DATA, P1: 0x00, P2: 0x4F}
	resp := bridge.HandleAPDU(cmd)

	if !resp.IsSuccess() {
		t.Errorf("GET DATA AID failed: SW=0x%04X", resp.StatusWord())
	}
}

func TestPKCS11Bridge_GetData_UnknownTag(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_GET_DATA, P1: 0xFF, P2: 0xFF}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_FILE_NOT_FOUND {
		t.Errorf("StatusWord = 0x%04X, want SW_FILE_NOT_FOUND", resp.StatusWord())
	}
}

func TestPKCS11Bridge_CloseAllSessions(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("654321")})

	if bridge.SessionCount() != 2 {
		t.Errorf("SessionCount = %d, want 2", bridge.SessionCount())
	}

	bridge.CloseAllSessions()

	if bridge.SessionCount() != 0 {
		t.Errorf("SessionCount after close = %d, want 0", bridge.SessionCount())
	}
}

func TestPKCS11Bridge_SetDefaultBackend(t *testing.T) {
	bridge := newTestBridge(t)
	bridge.SetDefaultBackend("tpm2")

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	session := bridge.getAuthenticatedSession()
	if session == nil {
		t.Fatal("Expected authenticated session")
	}
	if session.SelectedBackend != "tpm2" {
		t.Errorf("SelectedBackend = %s, want tpm2", session.SelectedBackend)
	}
}

func TestMatchAID(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		aid   []byte
		match bool
	}{
		{"exact match", AIDPIV, AIDPIV, true},
		{"prefix match", append(AIDPIV, 0x00), AIDPIV, true},
		{"data too short", AIDPIV[:3], AIDPIV, false},
		{"mismatch", []byte{0xFF, 0xFF, 0xFF}, AIDPIV, false},
		{"empty data", nil, AIDPIV, false},
		{"empty aid", []byte{0x01}, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchAID(tt.data, tt.aid); got != tt.match {
				t.Errorf("matchAID = %v, want %v", got, tt.match)
			}
		})
	}
}

func TestPKCS11Bridge_PSO_VerifySig_ValidData(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	// [sigLen_high, sigLen_low, sig_bytes..., hash_data...]
	sig := []byte("sig")
	hash := []byte("hash-data")
	data := []byte{0x00, byte(len(sig))}
	data = append(data, sig...)
	data = append(data, hash...)

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_PSO, P1: PSO_VERIFY_P1, P2: PSO_VERIFY_P2, Data: data}
	resp := bridge.HandleAPDU(cmd)

	if !resp.IsSuccess() {
		t.Errorf("PSO VERIFY failed: SW=0x%04X", resp.StatusWord())
	}
}

func TestPKCS11Bridge_PSO_VerifySig_TooShort(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	cmd := &CommandAPDU{CLA: 0x00, INS: INS_PSO, P1: PSO_VERIFY_P1, P2: PSO_VERIFY_P2, Data: []byte{0x00}}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_WRONG_DATA {
		t.Errorf("StatusWord = 0x%04X, want SW_WRONG_DATA", resp.StatusWord())
	}
}

func TestPKCS11Bridge_PSO_VerifySig_SigLenOverflow(t *testing.T) {
	bridge := newTestBridge(t)

	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_SELECT, P1: 0x04, P2: 0x00, Data: AIDPIV})
	bridge.HandleAPDU(&CommandAPDU{CLA: 0x00, INS: INS_VERIFY, P1: 0x00, P2: 0x80, Data: []byte("123456")})

	// sigLen says 255 but only 1 byte of data follows
	cmd := &CommandAPDU{CLA: 0x00, INS: INS_PSO, P1: PSO_VERIFY_P1, P2: PSO_VERIFY_P2, Data: []byte{0x00, 0xFF, 0x01}}
	resp := bridge.HandleAPDU(cmd)

	if resp.StatusWord() != SW_WRONG_DATA {
		t.Errorf("StatusWord = 0x%04X, want SW_WRONG_DATA", resp.StatusWord())
	}
}
