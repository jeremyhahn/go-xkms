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

package mocks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
)

// CommandCall represents a recorded TPM command execution.
type CommandCall struct {
	Command any
	Result  any
	Error   error
}

// MockTPM is a mock implementation of TPM transport for testing.
// It simulates TPM 2.0 hardware without requiring actual hardware or simulator.
//
// The mock supports:
//   - Configurable responses for TPM commands
//   - Error injection for testing failure paths
//   - Call history tracking for verification
//   - Thread-safe concurrent access
//
// Example usage:
//
//	mock := NewMockTPM()
//	mock.SetupCreatePrimary(tpm2.TPMHandle(0x80000000), nil)
//	result, err := mock.Execute(tpm2.CreatePrimary{})
type MockTPM struct {
	mu sync.RWMutex

	// ExecuteFunc is called for TPM command execution.
	// If nil, uses default mock command handlers.
	ExecuteFunc func(cmd any) (any, error)

	// SendFunc is called by Send(). If nil, returns empty bytes.
	SendFunc func([]byte) ([]byte, error)

	// CloseFunc is called by Close(). If nil, returns nil.
	CloseFunc func() error

	// Call tracking
	ExecuteCalls []CommandCall
	SendCalls    int
	CloseCalls   int

	// Mock state for specific commands
	createPrimaryResponse *tpm2.CreatePrimaryResponse
	createPrimaryError    error
	createResponse        *tpm2.CreateResponse
	createError           error
	loadResponse          *tpm2.LoadResponse
	loadError             error
	signResponse          *tpm2.SignResponse
	signError             error
	rsaDecryptResponse    *tpm2.RSADecryptResponse
	rsaDecryptError       error
	unsealResponse        *tpm2.UnsealResponse
	unsealError           error
	readPublicResponse    *tpm2.ReadPublicResponse
	readPublicError       error
	flushContextError     error
	evictControlError     error
}

// NewMockTPM creates a new MockTPM with default behavior.
func NewMockTPM() *MockTPM {
	return &MockTPM{}
}

// SetupCreatePrimary configures the mock response for CreatePrimary commands.
func (m *MockTPM) SetupCreatePrimary(handle tpm2.TPMHandle, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		m.createPrimaryError = err
		return
	}

	// Create a minimal RSA public key structure
	m.createPrimaryResponse = &tpm2.CreatePrimaryResponse{
		ObjectHandle: handle,
		OutPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Restricted:          true,
				Decrypt:             true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					KeyBits: 2048,
					Scheme: tpm2.TPMTRSAScheme{
						Scheme: tpm2.TPMAlgNull,
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgRSA,
				&tpm2.TPM2BPublicKeyRSA{
					Buffer: make([]byte, 256),
				},
			),
		}),
	}
}

// SetupCreateRSA configures the mock response for Create commands with RSA keys.
func (m *MockTPM) SetupCreateRSA(keySize int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		m.createError = err
		return
	}

	// Create an RSA public key for testing
	privateKey, _ := rsa.GenerateKey(rand.Reader, keySize)
	modulus := privateKey.N.Bytes()

	m.createResponse = &tpm2.CreateResponse{
		OutPrivate: tpm2.TPM2BPrivate{
			Buffer: []byte("mock-private-blob"),
		},
		OutPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
				Decrypt:             true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					KeyBits: tpm2.TPMKeyBits(keySize),
					Scheme: tpm2.TPMTRSAScheme{
						Scheme: tpm2.TPMAlgRSASSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgRSASSA,
							&tpm2.TPMSSigSchemeRSASSA{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgRSA,
				&tpm2.TPM2BPublicKeyRSA{
					Buffer: modulus,
				},
			),
		}),
	}
}

// SetupCreateECDSA configures the mock response for Create commands with ECDSA keys.
func (m *MockTPM) SetupCreateECDSA(curve elliptic.Curve, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		m.createError = err
		return
	}

	// Map Go curve to TPM curve
	var tpmCurve tpm2.TPMECCCurve
	switch curve {
	case elliptic.P256():
		tpmCurve = tpm2.TPMECCNistP256
	case elliptic.P384():
		tpmCurve = tpm2.TPMECCNistP384
	case elliptic.P521():
		tpmCurve = tpm2.TPMECCNistP521
	}

	// Generate a test ECDSA key
	privKey, _ := ecdsa.GenerateKey(curve, rand.Reader)

	m.createResponse = &tpm2.CreateResponse{
		OutPrivate: tpm2.TPM2BPrivate{
			Buffer: []byte("mock-private-blob-ecc"),
		},
		OutPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpmCurve,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDSA,
							&tpm2.TPMSSigSchemeECDSA{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{
						Buffer: privKey.X.Bytes(),
					},
					Y: tpm2.TPM2BECCParameter{
						Buffer: privKey.Y.Bytes(),
					},
				},
			),
		}),
	}
}

// SetupLoad configures the mock response for Load commands.
func (m *MockTPM) SetupLoad(handle tpm2.TPMHandle, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		m.loadError = err
		return
	}

	m.loadResponse = &tpm2.LoadResponse{
		ObjectHandle: handle,
	}
}

// SetupSign configures the mock response for Sign commands.
func (m *MockTPM) SetupSign(signature []byte, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		m.signError = err
		return
	}

	// Default to RSA signature
	m.signResponse = &tpm2.SignResponse{
		Signature: tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig: tpm2.TPM2BPublicKeyRSA{
						Buffer: signature,
					},
				},
			),
		},
	}
}

// SetupSignECDSA configures the mock response for ECDSA Sign commands.
func (m *MockTPM) SetupSignECDSA(r, s *big.Int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		m.signError = err
		return
	}

	m.signResponse = &tpm2.SignResponse{
		Signature: tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSignatureECC{
					Hash: tpm2.TPMAlgSHA256,
					SignatureR: tpm2.TPM2BECCParameter{
						Buffer: r.Bytes(),
					},
					SignatureS: tpm2.TPM2BECCParameter{
						Buffer: s.Bytes(),
					},
				},
			),
		},
	}
}

// SetupRSADecrypt configures the mock response for RSADecrypt commands.
func (m *MockTPM) SetupRSADecrypt(plaintext []byte, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		m.rsaDecryptError = err
		return
	}

	m.rsaDecryptResponse = &tpm2.RSADecryptResponse{
		Message: tpm2.TPM2BPublicKeyRSA{
			Buffer: plaintext,
		},
	}
}

// SetupUnseal configures the mock response for Unseal commands.
func (m *MockTPM) SetupUnseal(data []byte, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		m.unsealError = err
		return
	}

	m.unsealResponse = &tpm2.UnsealResponse{
		OutData: tpm2.TPM2BSensitiveData{
			Buffer: data,
		},
	}
}

// SetupReadPublic configures the mock response for ReadPublic commands.
func (m *MockTPM) SetupReadPublic(exists bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !exists {
		m.readPublicError = errors.New("handle does not exist")
		return
	}

	if err != nil {
		m.readPublicError = err
		return
	}

	m.readPublicResponse = &tpm2.ReadPublicResponse{
		OutPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
		}),
	}
}

// SetupFlushContext configures the mock response for FlushContext commands.
func (m *MockTPM) SetupFlushContext(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushContextError = err
}

// SetupEvictControl configures the mock response for EvictControl commands.
func (m *MockTPM) SetupEvictControl(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictControlError = err
}

// Send implements transport.TPM interface for low-level TPM communication.
// For this mock, Send is not the primary interface - use Execute() instead.
// This method exists only to satisfy the transport.TPM interface.
func (m *MockTPM) Send(input []byte) ([]byte, error) {
	m.mu.Lock()
	m.SendCalls++
	m.mu.Unlock()

	if m.SendFunc != nil {
		return m.SendFunc(input)
	}

	// The mock doesn't support wire protocol - tests should not call command.Execute(mock)
	// Instead, tests should set up the mock with Setup* methods and the code under test
	// will get the responses via Execute()
	return nil, fmt.Errorf("mock tpm: Send() not supported - wire protocol not implemented. Use mock.Execute() or integration tests with real TPM")
}

// Execute executes a TPM command and returns the response.
func (m *MockTPM) Execute(cmd any) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result any
	var err error

	if m.ExecuteFunc != nil {
		result, err = m.ExecuteFunc(cmd)
	} else {
		// Use default handlers based on command type
		result, err = m.handleCommand(cmd)
	}

	m.ExecuteCalls = append(m.ExecuteCalls, CommandCall{
		Command: cmd,
		Result:  result,
		Error:   err,
	})

	return result, err
}

// handleCommand routes commands to appropriate mock handlers.
func (m *MockTPM) handleCommand(cmd any) (any, error) {
	switch cmd.(type) {
	case tpm2.CreatePrimary:
		if m.createPrimaryError != nil {
			return nil, m.createPrimaryError
		}
		if m.createPrimaryResponse != nil {
			return m.createPrimaryResponse, nil
		}
		return nil, fmt.Errorf("mock tpm: CreatePrimary not configured")

	case tpm2.Create:
		if m.createError != nil {
			return nil, m.createError
		}
		if m.createResponse != nil {
			return m.createResponse, nil
		}
		return nil, fmt.Errorf("mock tpm: Create not configured")

	case tpm2.Load:
		if m.loadError != nil {
			return nil, m.loadError
		}
		if m.loadResponse != nil {
			return m.loadResponse, nil
		}
		return nil, fmt.Errorf("mock tpm: Load not configured")

	case tpm2.Sign:
		if m.signError != nil {
			return nil, m.signError
		}
		if m.signResponse != nil {
			return m.signResponse, nil
		}
		return nil, fmt.Errorf("mock tpm: Sign not configured")

	case tpm2.RSADecrypt:
		if m.rsaDecryptError != nil {
			return nil, m.rsaDecryptError
		}
		if m.rsaDecryptResponse != nil {
			return m.rsaDecryptResponse, nil
		}
		return nil, fmt.Errorf("mock tpm: RSADecrypt not configured")

	case tpm2.Unseal:
		if m.unsealError != nil {
			return nil, m.unsealError
		}
		if m.unsealResponse != nil {
			return m.unsealResponse, nil
		}
		return nil, fmt.Errorf("mock tpm: Unseal not configured")

	case tpm2.ReadPublic:
		if m.readPublicError != nil {
			return nil, m.readPublicError
		}
		if m.readPublicResponse != nil {
			return m.readPublicResponse, nil
		}
		return nil, fmt.Errorf("mock tpm: ReadPublic not configured")

	case tpm2.FlushContext:
		return &tpm2.FlushContextResponse{}, m.flushContextError

	case tpm2.EvictControl:
		if m.evictControlError != nil {
			return nil, m.evictControlError
		}
		return &tpm2.EvictControlResponse{}, nil

	default:
		return nil, fmt.Errorf("mock tpm: unsupported command type: %T", cmd)
	}
}

// Close closes the TPM connection.
func (m *MockTPM) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.CloseCalls++

	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

// Reset clears all call history and TPM state.
func (m *MockTPM) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ExecuteCalls = nil
	m.SendCalls = 0
	m.CloseCalls = 0
	m.createPrimaryResponse = nil
	m.createPrimaryError = nil
	m.createResponse = nil
	m.createError = nil
	m.loadResponse = nil
	m.loadError = nil
	m.signResponse = nil
	m.signError = nil
	m.rsaDecryptResponse = nil
	m.rsaDecryptError = nil
	m.unsealResponse = nil
	m.unsealError = nil
	m.readPublicResponse = nil
	m.readPublicError = nil
	m.flushContextError = nil
	m.evictControlError = nil
}

// ExecuteCallCount returns the number of Execute calls made.
func (m *MockTPM) ExecuteCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.ExecuteCalls)
}

// LastExecuteCall returns the most recent Execute call, or nil if none.
func (m *MockTPM) LastExecuteCall() *CommandCall {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.ExecuteCalls) == 0 {
		return nil
	}
	return &m.ExecuteCalls[len(m.ExecuteCalls)-1]
}

// GetExecuteCallsByType returns all Execute calls for a specific command type.
func (m *MockTPM) GetExecuteCallsByType(cmdType string) []CommandCall {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var calls []CommandCall
	for _, call := range m.ExecuteCalls {
		if fmt.Sprintf("%T", call.Command) == cmdType {
			calls = append(calls, call)
		}
	}
	return calls
}

// MockTPMCloser wraps MockTPM to implement the TPMCloser interface.
type MockTPMCloser struct {
	*MockTPM
}

// NewMockTPMCloser creates a new MockTPMCloser.
func NewMockTPMCloser() *MockTPMCloser {
	return &MockTPMCloser{
		MockTPM: NewMockTPM(),
	}
}
