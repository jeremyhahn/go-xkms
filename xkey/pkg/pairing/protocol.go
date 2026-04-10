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
	"sync/atomic"
)

// JSON-RPC 2.0 constants.
const (
	JSONRPCVersion = "2.0"
)

// COSE algorithm constants for FIDO2 credential operations.
const (
	COSEAlgES256 = -7
	COSEAlgES384 = -35
	COSEAlgES512 = -36
)

// Method names for the xKey phone protocol.
const (
	MethodGenerateKey    = "generateKey"
	MethodSign           = "sign"
	MethodDeleteKey      = "deleteKey"
	MethodLoadKey        = "loadKey"
	MethodGetInfo        = "getInfo"
	MethodPing           = "ping"
	MethodPairingConfirm = "pairing.confirm"
)

// Error codes for JSON-RPC responses.
const (
	// Standard JSON-RPC error codes.
	ErrorCodeParseError     = -32700
	ErrorCodeInvalidRequest = -32600
	ErrorCodeMethodNotFound = -32601
	ErrorCodeInvalidParams  = -32602
	ErrorCodeInternalError  = -32603

	// Application-specific error codes (starting at -32000).
	ErrorCodeKeyNotFound        = -32000
	ErrorCodeUserCancelled      = -32001
	ErrorCodeBiometricFailed    = -32002
	ErrorCodeKeyExists          = -32003
	ErrorCodeUnsupportedAlg     = -32004
	ErrorCodeInvalidCredID      = -32005
	ErrorCodeStorageFull        = -32006
	ErrorCodeOperationTimeout   = -32007
	ErrorCodeBackendDenied      = -32008
	ErrorCodeAttestFailed       = -32009
	ErrorCodeAttestUnsupported  = -32010
	ErrorCodeOperationDenied    = -32011
	ErrorCodeInvalidPublicKey   = -32012
	ErrorCodeDecryptFailed      = -32013
	ErrorCodeHMACFailed         = -32014
	ErrorCodeECDHFailed         = -32015
	ErrorCodeInvalidFormat      = -32016
	ErrorCodePairingRejected    = -32017
	ErrorCodeShareDenied        = -32018
	ErrorCodeShareNotExportable = -32019

	// Backup/restore error codes.
	ErrorCodeBackupFailed   = -32020
	ErrorCodeBackupRestore  = -32021
	ErrorCodeBackupNotFound = -32022

	// OATH error codes.
	ErrorCodeOATHNotFound = -32023
	ErrorCodeOATHGenerate = -32024
	ErrorCodeOATHStore    = -32025

	// PIV error codes.
	ErrorCodePIVSlotNotFound = -32026
	ErrorCodePIVSlotOccupied = -32027
	ErrorCodePIVSignFailed   = -32028
	ErrorCodePIVInvalidSlot  = -32029

	// Sync error codes.
	ErrorCodeSyncFailed          = -32030
	ErrorCodeSyncConflict        = -32031
	ErrorCodeSyncRemoteUnavail   = -32032
	ErrorCodeSyncNoData          = -32033
	ErrorCodeSyncVersionMismatch = -32034
)

// requestIDCounter provides unique request IDs.
var requestIDCounter atomic.Uint64

// nextRequestID returns the next unique request ID.
func nextRequestID() uint64 {
	return requestIDCounter.Add(1)
}

// Request represents a JSON-RPC 2.0 request message.
type Request struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      uint64      `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// Response represents a JSON-RPC 2.0 response message.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// Error implements the error interface for RPCError.
func (e *RPCError) Error() string {
	if e.Data != "" {
		return e.Message + ": " + e.Data
	}
	return e.Message
}

// GenerateKeyParams contains parameters for the generateKey method.
type GenerateKeyParams struct {
	CredentialID             []byte `json:"credentialId"`
	Algorithm                int    `json:"algorithm"`
	UserVerificationRequired bool   `json:"userVerificationRequired"`
}

// GenerateKeyResult contains the result of the generateKey method.
type GenerateKeyResult struct {
	PublicKeyCOSE []byte `json:"publicKey"`
}

// SignParams contains parameters for the sign method.
type SignParams struct {
	CredentialID             []byte `json:"credentialId"`
	DataHash                 []byte `json:"dataHash"`
	UserVerificationRequired bool   `json:"userVerificationRequired"`
}

// SignResult contains the result of the sign method.
type SignResult struct {
	Signature []byte `json:"signature"`
}

// DeleteKeyParams contains parameters for the deleteKey method.
type DeleteKeyParams struct {
	CredentialID []byte `json:"credentialId"`
}

// DeleteKeyResult contains the result of the deleteKey method.
type DeleteKeyResult struct {
	Deleted bool `json:"deleted"`
}

// LoadKeyParams contains parameters for the loadKey method.
type LoadKeyParams struct {
	CredentialID []byte `json:"credentialId"`
	Algorithm    int    `json:"algorithm"`
}

// LoadKeyResult contains the result of the loadKey method.
type LoadKeyResult struct {
	Exists        bool   `json:"exists"`
	PublicKeyCOSE []byte `json:"publicKey,omitempty"`
}

// GetInfoResult contains the result of the getInfo method.
type GetInfoResult struct {
	Version             string `json:"version"`
	DeviceName          string `json:"deviceName"`
	SupportedAlgorithms []int  `json:"supportedAlgorithms"`
	MaxCredentials      int    `json:"maxCredentials"`
	CurrentCredentials  int    `json:"currentCredentials"`
}

// PingResult contains the result of the ping method.
type PingResult struct {
	Pong bool `json:"pong"`
}

// PairingConfirmParams contains parameters for the pairing.confirm method.
type PairingConfirmParams struct {
	DeviceName   string `json:"deviceName"`
	PublicKeyHex string `json:"publicKeyHex"`
}

// PairingConfirmResult contains the result of the pairing.confirm method.
type PairingConfirmResult struct {
	Confirmed  bool   `json:"confirmed"`
	DeviceName string `json:"deviceName"`
}

// NewRequest creates a new JSON-RPC request with auto-generated ID.
func NewRequest(method string, params interface{}) *Request {
	return &Request{
		JSONRPC: JSONRPCVersion,
		ID:      nextRequestID(),
		Method:  method,
		Params:  params,
	}
}

// EncodeRequest encodes a request to JSON bytes.
func EncodeRequest(req *Request) ([]byte, error) {
	return json.Marshal(req)
}

// DecodeResponse decodes a JSON response into Response struct.
func DecodeResponse(data []byte) (*Response, error) {
	var resp Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DecodeResult decodes the result field of a response into the provided type.
func DecodeResult[T any](resp *Response) (*T, error) {
	if resp.Error != nil {
		return nil, resp.Error
	}
	var result T
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// rpcErrorMap maps JSON-RPC error codes to package errors.
var rpcErrorMap = map[int]error{
	ErrorCodeKeyNotFound:        ErrKeyNotFound,
	ErrorCodeUserCancelled:      ErrUserCancelled,
	ErrorCodeBiometricFailed:    ErrBiometricFailed,
	ErrorCodeUnsupportedAlg:     ErrUnsupportedAlgorithm,
	ErrorCodeInvalidCredID:      ErrInvalidCredentialID,
	ErrorCodeOperationTimeout:   ErrTimeout,
	ErrorCodeKeyExists:          ErrKeyExists,
	ErrorCodeStorageFull:        ErrStorageFull,
	ErrorCodeParseError:         ErrProtocolError,
	ErrorCodeInvalidRequest:     ErrProtocolError,
	ErrorCodeInvalidParams:      ErrProtocolError,
	ErrorCodeMethodNotFound:     ErrProtocolError,
	ErrorCodeInternalError:      ErrInvalidResponse,
	ErrorCodeBackendDenied:      ErrBackendDenied,
	ErrorCodeAttestFailed:       ErrAttestationFailed,
	ErrorCodeAttestUnsupported:  ErrAttestationNotSupported,
	ErrorCodeOperationDenied:    ErrOperationDenied,
	ErrorCodeInvalidPublicKey:   ErrInvalidPublicKey,
	ErrorCodeDecryptFailed:      ErrDecryptFailed,
	ErrorCodeHMACFailed:         ErrHMACFailed,
	ErrorCodeECDHFailed:         ErrECDHFailed,
	ErrorCodeInvalidFormat:      ErrInvalidFormat,
	ErrorCodePairingRejected:    ErrPairingRejected,
	ErrorCodeShareDenied:        ErrShareDenied,
	ErrorCodeShareNotExportable: ErrShareNotExportable,
	// Backup/restore error codes.
	ErrorCodeBackupFailed:   ErrBackupFailed,
	ErrorCodeBackupRestore:  ErrBackupRestoreFailed,
	ErrorCodeBackupNotFound: ErrBackupNotFound,
	// OATH error codes.
	ErrorCodeOATHNotFound: ErrOATHCredentialNotFound,
	ErrorCodeOATHGenerate: ErrOATHGenerateFailed,
	ErrorCodeOATHStore:    ErrOATHStoreFailed,
	// PIV error codes.
	ErrorCodePIVSlotNotFound: ErrPIVSlotNotFound,
	ErrorCodePIVSlotOccupied: ErrPIVSlotOccupied,
	ErrorCodePIVSignFailed:   ErrPIVSignFailed,
	ErrorCodePIVInvalidSlot:  ErrPIVInvalidSlot,
	// Sync error codes.
	ErrorCodeSyncFailed:          ErrSyncFailed,
	ErrorCodeSyncConflict:        ErrSyncConflict,
	ErrorCodeSyncRemoteUnavail:   ErrSyncRemoteUnavailable,
	ErrorCodeSyncNoData:          ErrSyncNoData,
	ErrorCodeSyncVersionMismatch: ErrSyncVersionMismatch,
}

// MapRPCError maps JSON-RPC error codes to package errors.
func MapRPCError(rpcErr *RPCError) error {
	if rpcErr == nil {
		return nil
	}
	if err, ok := rpcErrorMap[rpcErr.Code]; ok {
		return err
	}
	return ErrProtocolError
}

// Server-side protocol helpers (for handling incoming requests).

// DecodeRequest decodes JSON bytes into a Request struct.
func DecodeRequest(data []byte) (*Request, error) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// EncodeResponse creates and encodes a successful JSON-RPC response.
func EncodeResponse(id uint64, result interface{}) ([]byte, error) {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Result:  resultJSON,
	}
	return json.Marshal(resp)
}

// EncodeErrorResponse creates and encodes a JSON-RPC error response.
func EncodeErrorResponse(id uint64, code int, message string, data interface{}) ([]byte, error) {
	rpcErr := &RPCError{
		Code:    code,
		Message: message,
	}
	if data != nil {
		if s, ok := data.(string); ok {
			rpcErr.Data = s
		} else if b, err := json.Marshal(data); err == nil {
			rpcErr.Data = string(b)
		}
	}
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error:   rpcErr,
	}
	return json.Marshal(resp)
}
