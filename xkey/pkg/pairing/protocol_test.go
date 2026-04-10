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

package pairing

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONRPCConstants(t *testing.T) {
	assert.Equal(t, "2.0", JSONRPCVersion)
	assert.Equal(t, "generateKey", MethodGenerateKey)
	assert.Equal(t, "sign", MethodSign)
	assert.Equal(t, "deleteKey", MethodDeleteKey)
	assert.Equal(t, "loadKey", MethodLoadKey)
	assert.Equal(t, "getInfo", MethodGetInfo)
	assert.Equal(t, "ping", MethodPing)
}

func TestErrorCodes(t *testing.T) {
	// Standard JSON-RPC error codes
	assert.Equal(t, -32700, ErrorCodeParseError)
	assert.Equal(t, -32600, ErrorCodeInvalidRequest)
	assert.Equal(t, -32601, ErrorCodeMethodNotFound)
	assert.Equal(t, -32602, ErrorCodeInvalidParams)
	assert.Equal(t, -32603, ErrorCodeInternalError)

	// Application-specific error codes
	assert.Equal(t, -32000, ErrorCodeKeyNotFound)
	assert.Equal(t, -32001, ErrorCodeUserCancelled)
	assert.Equal(t, -32002, ErrorCodeBiometricFailed)
	assert.Equal(t, -32003, ErrorCodeKeyExists)
	assert.Equal(t, -32004, ErrorCodeUnsupportedAlg)
	assert.Equal(t, -32005, ErrorCodeInvalidCredID)
	assert.Equal(t, -32006, ErrorCodeStorageFull)
	assert.Equal(t, -32007, ErrorCodeOperationTimeout)
	assert.Equal(t, -32008, ErrorCodeBackendDenied)
	assert.Equal(t, -32009, ErrorCodeAttestFailed)
	assert.Equal(t, -32010, ErrorCodeAttestUnsupported)
	assert.Equal(t, -32011, ErrorCodeOperationDenied)
	assert.Equal(t, -32012, ErrorCodeInvalidPublicKey)
	assert.Equal(t, -32013, ErrorCodeDecryptFailed)
	assert.Equal(t, -32014, ErrorCodeHMACFailed)
	assert.Equal(t, -32015, ErrorCodeECDHFailed)
	assert.Equal(t, -32016, ErrorCodeInvalidFormat)
}

func TestNextRequestID(t *testing.T) {
	id1 := nextRequestID()
	id2 := nextRequestID()
	id3 := nextRequestID()

	assert.Equal(t, id1+1, id2)
	assert.Equal(t, id2+1, id3)
}

func TestNewRequest(t *testing.T) {
	req := NewRequest(MethodPing, nil)

	require.NotNil(t, req)
	assert.Equal(t, JSONRPCVersion, req.JSONRPC)
	assert.NotZero(t, req.ID)
	assert.Equal(t, MethodPing, req.Method)
	assert.Nil(t, req.Params)
}

func TestNewRequest_WithParams(t *testing.T) {
	params := &GenerateKeyParams{
		CredentialID: []byte("test-cred-id"),
		Algorithm:    COSEAlgES256,
	}
	req := NewRequest(MethodGenerateKey, params)

	require.NotNil(t, req)
	assert.Equal(t, params, req.Params)
}

func TestEncodeRequest(t *testing.T) {
	req := &Request{
		JSONRPC: JSONRPCVersion,
		ID:      1,
		Method:  MethodPing,
	}

	data, err := EncodeRequest(req)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, JSONRPCVersion, decoded["jsonrpc"])
	assert.Equal(t, float64(1), decoded["id"])
	assert.Equal(t, MethodPing, decoded["method"])
}

func TestDecodeResponse_Success(t *testing.T) {
	data := `{"jsonrpc":"2.0","id":1,"result":{"pong":true}}`

	resp, err := DecodeResponse([]byte(data))
	require.NoError(t, err)

	assert.Equal(t, JSONRPCVersion, resp.JSONRPC)
	assert.Equal(t, uint64(1), resp.ID)
	assert.NotNil(t, resp.Result)
	assert.Nil(t, resp.Error)
}

func TestDecodeResponse_Error(t *testing.T) {
	data := `{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"key not found"}}`

	resp, err := DecodeResponse([]byte(data))
	require.NoError(t, err)

	assert.Equal(t, uint64(2), resp.ID)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrorCodeKeyNotFound, resp.Error.Code)
	assert.Equal(t, "key not found", resp.Error.Message)
}

func TestDecodeResponse_InvalidJSON(t *testing.T) {
	data := `{invalid json}`

	_, err := DecodeResponse([]byte(data))
	assert.Error(t, err)
}

func TestDecodeResult_PingResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      1,
		Result:  json.RawMessage(`{"pong":true}`),
	}

	result, err := DecodeResult[PingResult](resp)
	require.NoError(t, err)
	assert.True(t, result.Pong)
}

func TestDecodeResult_GenerateKeyResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      2,
		Result:  json.RawMessage(`{"publicKey":"AQIDBA=="}`),
	}

	result, err := DecodeResult[GenerateKeyResult](resp)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, result.PublicKeyCOSE)
}

func TestDecodeResult_WithError(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      3,
		Error: &RPCError{
			Code:    ErrorCodeKeyNotFound,
			Message: "key not found",
		},
	}

	result, err := DecodeResult[PingResult](resp)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestRPCError_Error(t *testing.T) {
	err := &RPCError{
		Code:    ErrorCodeKeyNotFound,
		Message: "key not found",
	}
	assert.Equal(t, "key not found", err.Error())

	errWithData := &RPCError{
		Code:    ErrorCodeInvalidParams,
		Message: "invalid params",
		Data:    "credentialId required",
	}
	assert.Equal(t, "invalid params: credentialId required", errWithData.Error())
}

func TestMapRPCError(t *testing.T) {
	tests := []struct {
		name     string
		rpcErr   *RPCError
		expected error
	}{
		{"nil", nil, nil},
		{"key not found", &RPCError{Code: ErrorCodeKeyNotFound}, ErrKeyNotFound},
		{"user cancelled", &RPCError{Code: ErrorCodeUserCancelled}, ErrUserCancelled},
		{"biometric failed", &RPCError{Code: ErrorCodeBiometricFailed}, ErrBiometricFailed},
		{"unsupported algorithm", &RPCError{Code: ErrorCodeUnsupportedAlg}, ErrUnsupportedAlgorithm},
		{"invalid credential ID", &RPCError{Code: ErrorCodeInvalidCredID}, ErrInvalidCredentialID},
		{"timeout", &RPCError{Code: ErrorCodeOperationTimeout}, ErrTimeout},
		{"key exists", &RPCError{Code: ErrorCodeKeyExists}, ErrKeyExists},
		{"storage full", &RPCError{Code: ErrorCodeStorageFull}, ErrStorageFull},
		{"backend denied", &RPCError{Code: ErrorCodeBackendDenied}, ErrBackendDenied},
		{"attestation failed", &RPCError{Code: ErrorCodeAttestFailed}, ErrAttestationFailed},
		{"attestation unsupported", &RPCError{Code: ErrorCodeAttestUnsupported}, ErrAttestationNotSupported},
		{"operation denied", &RPCError{Code: ErrorCodeOperationDenied}, ErrOperationDenied},
		{"invalid public key", &RPCError{Code: ErrorCodeInvalidPublicKey}, ErrInvalidPublicKey},
		{"decrypt failed", &RPCError{Code: ErrorCodeDecryptFailed}, ErrDecryptFailed},
		{"hmac failed", &RPCError{Code: ErrorCodeHMACFailed}, ErrHMACFailed},
		{"ecdh failed", &RPCError{Code: ErrorCodeECDHFailed}, ErrECDHFailed},
		{"invalid format", &RPCError{Code: ErrorCodeInvalidFormat}, ErrInvalidFormat},
		{"parse error", &RPCError{Code: ErrorCodeParseError}, ErrProtocolError},
		{"internal error", &RPCError{Code: ErrorCodeInternalError}, ErrInvalidResponse},
		{"unknown", &RPCError{Code: -99999}, ErrProtocolError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MapRPCError(tt.rpcErr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateKeyParams_JSONRoundTrip(t *testing.T) {
	original := &GenerateKeyParams{
		CredentialID: []byte{0x01, 0x02, 0x03},
		Algorithm:    COSEAlgES256,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded GenerateKeyParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.CredentialID, decoded.CredentialID)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
}

func TestSignParams_JSONRoundTrip(t *testing.T) {
	original := &SignParams{
		CredentialID:             []byte{0x01, 0x02, 0x03},
		DataHash:                 []byte("test hash data"),
		UserVerificationRequired: true,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded SignParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.CredentialID, decoded.CredentialID)
	assert.Equal(t, original.DataHash, decoded.DataHash)
	assert.Equal(t, original.UserVerificationRequired, decoded.UserVerificationRequired)
}

func TestDecodeRequest_Success(t *testing.T) {
	data := `{"jsonrpc":"2.0","id":42,"method":"ping"}`

	req, err := DecodeRequest([]byte(data))
	require.NoError(t, err)

	assert.Equal(t, JSONRPCVersion, req.JSONRPC)
	assert.Equal(t, uint64(42), req.ID)
	assert.Equal(t, MethodPing, req.Method)
}

func TestDecodeRequest_WithParams(t *testing.T) {
	data := `{"jsonrpc":"2.0","id":1,"method":"generateKey","params":{"credentialId":"AQID","algorithm":-7}}`

	req, err := DecodeRequest([]byte(data))
	require.NoError(t, err)

	assert.Equal(t, JSONRPCVersion, req.JSONRPC)
	assert.Equal(t, uint64(1), req.ID)
	assert.Equal(t, MethodGenerateKey, req.Method)
	assert.NotNil(t, req.Params)
}

func TestDecodeRequest_InvalidJSON(t *testing.T) {
	data := `{invalid json}`

	_, err := DecodeRequest([]byte(data))
	assert.Error(t, err)
}

func TestDecodeRequest_EmptyData(t *testing.T) {
	_, err := DecodeRequest([]byte{})
	assert.Error(t, err)
}

func TestEncodeResponse_Success(t *testing.T) {
	result := &PingResult{Pong: true}

	data, err := EncodeResponse(123, result)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, JSONRPCVersion, decoded["jsonrpc"])
	assert.Equal(t, float64(123), decoded["id"])
	assert.NotNil(t, decoded["result"])
	assert.Nil(t, decoded["error"])

	// Verify result content
	resultMap := decoded["result"].(map[string]interface{})
	assert.True(t, resultMap["pong"].(bool))
}

func TestEncodeResponse_ComplexResult(t *testing.T) {
	result := &GetInfoResult{
		Version:             "1.0.0",
		DeviceName:          "Test Device",
		SupportedAlgorithms: []int{COSEAlgES256, COSEAlgES384},
		MaxCredentials:      100,
		CurrentCredentials:  5,
	}

	data, err := EncodeResponse(456, result)
	require.NoError(t, err)

	// Decode and verify
	resp, err := DecodeResponse(data)
	require.NoError(t, err)
	assert.Equal(t, uint64(456), resp.ID)
	assert.Nil(t, resp.Error)

	decoded, err := DecodeResult[GetInfoResult](resp)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", decoded.Version)
	assert.Equal(t, "Test Device", decoded.DeviceName)
	assert.Equal(t, []int{COSEAlgES256, COSEAlgES384}, decoded.SupportedAlgorithms)
}

func TestEncodeResponse_NilResult(t *testing.T) {
	data, err := EncodeResponse(789, nil)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, float64(789), decoded["id"])
}

func TestEncodeErrorResponse_Basic(t *testing.T) {
	data, err := EncodeErrorResponse(100, ErrorCodeKeyNotFound, "key not found", nil)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	resp, err := DecodeResponse(data)
	require.NoError(t, err)

	assert.Equal(t, uint64(100), resp.ID)
	assert.Nil(t, resp.Result)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrorCodeKeyNotFound, resp.Error.Code)
	assert.Equal(t, "key not found", resp.Error.Message)
	assert.Empty(t, resp.Error.Data)
}

func TestEncodeErrorResponse_WithStringData(t *testing.T) {
	data, err := EncodeErrorResponse(200, ErrorCodeInvalidParams, "invalid params", "credentialId is required")
	require.NoError(t, err)

	resp, err := DecodeResponse(data)
	require.NoError(t, err)

	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrorCodeInvalidParams, resp.Error.Code)
	assert.Equal(t, "invalid params", resp.Error.Message)
	assert.Equal(t, "credentialId is required", resp.Error.Data)
}

func TestEncodeErrorResponse_WithStructData(t *testing.T) {
	additionalInfo := map[string]string{
		"field":   "algorithm",
		"allowed": "-7,-8,-257",
	}

	data, err := EncodeErrorResponse(300, ErrorCodeUnsupportedAlg, "unsupported algorithm", additionalInfo)
	require.NoError(t, err)

	resp, err := DecodeResponse(data)
	require.NoError(t, err)

	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrorCodeUnsupportedAlg, resp.Error.Code)
	assert.Contains(t, resp.Error.Data, "field")
	assert.Contains(t, resp.Error.Data, "algorithm")
}

func TestEncodeErrorResponse_AllStandardCodes(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		message string
	}{
		{"parse error", ErrorCodeParseError, "parse error"},
		{"invalid request", ErrorCodeInvalidRequest, "invalid request"},
		{"method not found", ErrorCodeMethodNotFound, "method not found"},
		{"invalid params", ErrorCodeInvalidParams, "invalid params"},
		{"internal error", ErrorCodeInternalError, "internal error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := EncodeErrorResponse(1, tt.code, tt.message, nil)
			require.NoError(t, err)

			resp, err := DecodeResponse(data)
			require.NoError(t, err)
			require.NotNil(t, resp.Error)
			assert.Equal(t, tt.code, resp.Error.Code)
		})
	}
}

func TestEncodeErrorResponse_AllApplicationCodes(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		message string
	}{
		{"key not found", ErrorCodeKeyNotFound, "key not found"},
		{"user cancelled", ErrorCodeUserCancelled, "user cancelled"},
		{"biometric failed", ErrorCodeBiometricFailed, "biometric failed"},
		{"key exists", ErrorCodeKeyExists, "key exists"},
		{"unsupported algorithm", ErrorCodeUnsupportedAlg, "unsupported algorithm"},
		{"invalid credential ID", ErrorCodeInvalidCredID, "invalid credential ID"},
		{"storage full", ErrorCodeStorageFull, "storage full"},
		{"operation timeout", ErrorCodeOperationTimeout, "operation timeout"},
		{"backend denied", ErrorCodeBackendDenied, "backend denied"},
		{"attestation failed", ErrorCodeAttestFailed, "attestation failed"},
		{"attestation unsupported", ErrorCodeAttestUnsupported, "attestation unsupported"},
		{"operation denied", ErrorCodeOperationDenied, "operation denied"},
		{"invalid public key", ErrorCodeInvalidPublicKey, "invalid public key"},
		{"decrypt failed", ErrorCodeDecryptFailed, "decrypt failed"},
		{"hmac failed", ErrorCodeHMACFailed, "hmac failed"},
		{"ecdh failed", ErrorCodeECDHFailed, "ecdh failed"},
		{"invalid format", ErrorCodeInvalidFormat, "invalid format"},
		{"pairing rejected", ErrorCodePairingRejected, "pairing rejected"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := EncodeErrorResponse(1, tt.code, tt.message, nil)
			require.NoError(t, err)

			resp, err := DecodeResponse(data)
			require.NoError(t, err)
			require.NotNil(t, resp.Error)
			assert.Equal(t, tt.code, resp.Error.Code)
		})
	}
}

func TestDecodeResult_NilResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      1,
		Result:  nil,
	}

	_, err := DecodeResult[PingResult](resp)
	assert.Error(t, err)
}

func TestDecodeResult_InvalidJSON(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      1,
		Result:  json.RawMessage(`{invalid json}`),
	}

	_, err := DecodeResult[PingResult](resp)
	assert.Error(t, err)
}
