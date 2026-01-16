// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package mcp

import (
	"encoding/json"
	"testing"
)

func TestJSONRPCRequest_MarshalJSON(t *testing.T) {
	req := JSONRPCRequest{
		JSONRPC:       "2.0",
		Method:        "test.method",
		Params:        json.RawMessage(`{"key": "value"}`),
		ID:            1,
		CorrelationID: "corr-123",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded JSONRPCRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.JSONRPC != req.JSONRPC {
		t.Errorf("JSONRPC mismatch: got %v, want %v", decoded.JSONRPC, req.JSONRPC)
	}
	if decoded.Method != req.Method {
		t.Errorf("Method mismatch: got %v, want %v", decoded.Method, req.Method)
	}
	if decoded.CorrelationID != req.CorrelationID {
		t.Errorf("CorrelationID mismatch: got %v, want %v", decoded.CorrelationID, req.CorrelationID)
	}
}

func TestJSONRPCResponse_MarshalJSON(t *testing.T) {
	resp := JSONRPCResponse{
		JSONRPC:       "2.0",
		Result:        map[string]string{"status": "ok"},
		ID:            1,
		CorrelationID: "corr-123",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded JSONRPCResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.JSONRPC != resp.JSONRPC {
		t.Errorf("JSONRPC mismatch: got %v, want %v", decoded.JSONRPC, resp.JSONRPC)
	}
	if decoded.CorrelationID != resp.CorrelationID {
		t.Errorf("CorrelationID mismatch: got %v, want %v", decoded.CorrelationID, resp.CorrelationID)
	}
}

func TestJSONRPCResponse_WithError(t *testing.T) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Error: &JSONRPCError{
			Code:    ErrCodeInternalError,
			Message: "internal error",
			Data:    "additional info",
		},
		ID:            1,
		CorrelationID: "corr-456",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded JSONRPCResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Error == nil {
		t.Fatal("expected error to be present")
	}
	if decoded.Error.Code != ErrCodeInternalError {
		t.Errorf("Error.Code mismatch: got %v, want %v", decoded.Error.Code, ErrCodeInternalError)
	}
	if decoded.Error.Message != "internal error" {
		t.Errorf("Error.Message mismatch: got %v, want %v", decoded.Error.Message, "internal error")
	}
}

func TestErrorCodes(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected int
	}{
		{"ParseError", ErrCodeParseError, -32700},
		{"InvalidRequest", ErrCodeInvalidRequest, -32600},
		{"MethodNotFound", ErrCodeMethodNotFound, -32601},
		{"InvalidParams", ErrCodeInvalidParams, -32602},
		{"InternalError", ErrCodeInternalError, -32603},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.expected {
				t.Errorf("got %v, expected %v", tt.code, tt.expected)
			}
		})
	}
}

func TestJSONRPCNotification_MarshalJSON(t *testing.T) {
	notif := JSONRPCNotification{
		JSONRPC: "2.0",
		Method:  "key.created",
		Params:  map[string]string{"key_id": "test-key"},
	}

	data, err := json.Marshal(notif)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded JSONRPCNotification
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.JSONRPC != notif.JSONRPC {
		t.Errorf("JSONRPC mismatch: got %v, want %v", decoded.JSONRPC, notif.JSONRPC)
	}
	if decoded.Method != notif.Method {
		t.Errorf("Method mismatch: got %v, want %v", decoded.Method, notif.Method)
	}
}

func TestHealthResult_MarshalJSON(t *testing.T) {
	result := HealthResult{Status: "healthy"}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded HealthResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Status != result.Status {
		t.Errorf("Status mismatch: got %v, want %v", decoded.Status, result.Status)
	}
}

func TestGenerateKeyParams_MarshalJSON(t *testing.T) {
	params := GenerateKeyParams{
		KeyID:      "test-key",
		Backend:    "memory",
		KeyType:    "rsa",
		KeySize:    2048,
		Curve:      "",
		Algorithm:  "",
		Exportable: true,
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded GenerateKeyParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.KeyID != params.KeyID {
		t.Errorf("KeyID mismatch: got %v, want %v", decoded.KeyID, params.KeyID)
	}
	if decoded.Backend != params.Backend {
		t.Errorf("Backend mismatch: got %v, want %v", decoded.Backend, params.Backend)
	}
	if decoded.KeyType != params.KeyType {
		t.Errorf("KeyType mismatch: got %v, want %v", decoded.KeyType, params.KeyType)
	}
	if decoded.KeySize != params.KeySize {
		t.Errorf("KeySize mismatch: got %v, want %v", decoded.KeySize, params.KeySize)
	}
	if decoded.Exportable != params.Exportable {
		t.Errorf("Exportable mismatch: got %v, want %v", decoded.Exportable, params.Exportable)
	}
}

func TestSignParams_MarshalJSON(t *testing.T) {
	params := SignParams{
		KeyID:   "test-key",
		Backend: "memory",
		Data:    []byte("test data"),
		Hash:    "SHA256",
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded SignParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.KeyID != params.KeyID {
		t.Errorf("KeyID mismatch: got %v, want %v", decoded.KeyID, params.KeyID)
	}
	if decoded.Hash != params.Hash {
		t.Errorf("Hash mismatch: got %v, want %v", decoded.Hash, params.Hash)
	}
	if string(decoded.Data) != string(params.Data) {
		t.Errorf("Data mismatch: got %v, want %v", decoded.Data, params.Data)
	}
}

func TestEncryptParams_MarshalJSON(t *testing.T) {
	params := EncryptParams{
		KeyID:          "test-key",
		Backend:        "memory",
		Plaintext:      []byte("secret data"),
		AdditionalData: []byte("additional"),
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded EncryptParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.KeyID != params.KeyID {
		t.Errorf("KeyID mismatch: got %v, want %v", decoded.KeyID, params.KeyID)
	}
	if string(decoded.Plaintext) != string(params.Plaintext) {
		t.Errorf("Plaintext mismatch")
	}
	if string(decoded.AdditionalData) != string(params.AdditionalData) {
		t.Errorf("AdditionalData mismatch")
	}
}

func TestDecryptParams_MarshalJSON(t *testing.T) {
	params := DecryptParams{
		KeyID:          "test-key",
		Backend:        "memory",
		Ciphertext:     []byte("encrypted"),
		Nonce:          []byte("nonce123"),
		Tag:            []byte("auth-tag"),
		AdditionalData: []byte("aad"),
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded DecryptParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.KeyID != params.KeyID {
		t.Errorf("KeyID mismatch: got %v, want %v", decoded.KeyID, params.KeyID)
	}
	if string(decoded.Nonce) != string(params.Nonce) {
		t.Errorf("Nonce mismatch")
	}
	if string(decoded.Tag) != string(params.Tag) {
		t.Errorf("Tag mismatch")
	}
}

func TestImportExportParams_MarshalJSON(t *testing.T) {
	importParams := ImportKeyParams{
		KeyID:       "test-key",
		Backend:     "memory",
		WrappedKey:  []byte("wrapped"),
		Algorithm:   "RSA_OAEP_SHA256",
		ImportToken: []byte("token"),
		Metadata:    map[string]string{"purpose": "test"},
	}

	data, err := json.Marshal(importParams)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ImportKeyParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.KeyID != importParams.KeyID {
		t.Errorf("KeyID mismatch: got %v, want %v", decoded.KeyID, importParams.KeyID)
	}
	if decoded.Algorithm != importParams.Algorithm {
		t.Errorf("Algorithm mismatch: got %v, want %v", decoded.Algorithm, importParams.Algorithm)
	}
}

func TestCopyKeyParams_MarshalJSON(t *testing.T) {
	params := CopyKeyParams{
		SourceBackend: "memory",
		SourceKeyID:   "source-key",
		DestBackend:   "tpm2",
		DestKeyID:     "dest-key",
		KeyType:       "rsa",
		Algorithm:     "RSA_OAEP_SHA256",
		KeySize:       2048,
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded CopyKeyParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.SourceBackend != params.SourceBackend {
		t.Errorf("SourceBackend mismatch: got %v, want %v", decoded.SourceBackend, params.SourceBackend)
	}
	if decoded.DestBackend != params.DestBackend {
		t.Errorf("DestBackend mismatch: got %v, want %v", decoded.DestBackend, params.DestBackend)
	}
	if decoded.KeySize != params.KeySize {
		t.Errorf("KeySize mismatch: got %v, want %v", decoded.KeySize, params.KeySize)
	}
}

func TestCertParams_MarshalJSON(t *testing.T) {
	saveParams := SaveCertParams{
		KeyID:   "test-key",
		CertPEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}

	data, err := json.Marshal(saveParams)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded SaveCertParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.KeyID != saveParams.KeyID {
		t.Errorf("KeyID mismatch: got %v, want %v", decoded.KeyID, saveParams.KeyID)
	}
	if decoded.CertPEM != saveParams.CertPEM {
		t.Errorf("CertPEM mismatch")
	}
}

func TestEventNotification_MarshalJSON(t *testing.T) {
	notif := EventNotification{
		Event: "key.created",
		KeyID: "test-key",
		Data:  map[string]string{"backend": "memory"},
	}

	data, err := json.Marshal(notif)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded EventNotification
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Event != notif.Event {
		t.Errorf("Event mismatch: got %v, want %v", decoded.Event, notif.Event)
	}
	if decoded.KeyID != notif.KeyID {
		t.Errorf("KeyID mismatch: got %v, want %v", decoded.KeyID, notif.KeyID)
	}
}

func TestListBackendsResult_MarshalJSON(t *testing.T) {
	result := ListBackendsResult{
		Backends: []string{"memory", "tpm2", "pkcs11"},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ListBackendsResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(decoded.Backends) != len(result.Backends) {
		t.Errorf("Backends length mismatch: got %v, want %v", len(decoded.Backends), len(result.Backends))
	}
}

func TestKeyInfo_MarshalJSON(t *testing.T) {
	keyInfo := KeyInfo{CN: "test-key-cn"}

	data, err := json.Marshal(keyInfo)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded KeyInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.CN != keyInfo.CN {
		t.Errorf("CN mismatch: got %v, want %v", decoded.CN, keyInfo.CN)
	}
}

func TestListKeysResult_MarshalJSON(t *testing.T) {
	result := ListKeysResult{
		Keys: []KeyInfo{
			{CN: "key1"},
			{CN: "key2"},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ListKeysResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(decoded.Keys) != len(result.Keys) {
		t.Errorf("Keys length mismatch: got %v, want %v", len(decoded.Keys), len(result.Keys))
	}
}

func TestGetTLSCertificateResult_MarshalJSON(t *testing.T) {
	result := GetTLSCertificateResult{
		CertPEM:        "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
		ChainPEMs:      []string{"chain1", "chain2"},
		PrivateKeyType: "RSA",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded GetTLSCertificateResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.CertPEM != result.CertPEM {
		t.Errorf("CertPEM mismatch")
	}
	if decoded.PrivateKeyType != result.PrivateKeyType {
		t.Errorf("PrivateKeyType mismatch: got %v, want %v", decoded.PrivateKeyType, result.PrivateKeyType)
	}
	if len(decoded.ChainPEMs) != len(result.ChainPEMs) {
		t.Errorf("ChainPEMs length mismatch")
	}
}
