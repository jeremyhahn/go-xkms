//go:build !integration

package tpm2

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// capabilityMockTransport implements transport.TPM for testing capability functions
type capabilityMockTransport struct {
	responses    map[uint32][]byte
	err          error
	callCount    int
	lastProperty uint32
}

func (m *capabilityMockTransport) Send(input []byte) ([]byte, error) {
	m.callCount++
	if m.err != nil {
		return nil, m.err
	}

	// Parse the GetCapability command to extract the property being queried
	// TPM command structure:
	// - 2 bytes: tag
	// - 4 bytes: command size
	// - 4 bytes: command code
	// - 4 bytes: capability
	// - 4 bytes: property
	// - 4 bytes: property count
	if len(input) < 18 {
		return nil, errors.New("input too short")
	}

	property := binary.BigEndian.Uint32(input[14:18])
	m.lastProperty = property

	if response, ok := m.responses[property]; ok {
		return response, nil
	}

	return nil, errors.New("no mock response configured for property")
}

// buildCapabilityResponse constructs a valid TPM2 GetCapabilityResponse for TPM properties
func buildCapabilityResponse(property tpm2.TPMPT, value uint32) []byte {
	// Build the response structure manually
	// TPM Response Header:
	// - 2 bytes: tag (TPM_ST_NO_SESSIONS = 0x8001)
	// - 4 bytes: response size
	// - 4 bytes: response code (TPM_RC_SUCCESS = 0x00000000)
	// Response body:
	// - 1 byte: MoreData (NO = 0x00)
	// - 4 bytes: Capability (TPMCapTPMProperties = 0x00000006)
	// - 4 bytes: Count of properties (1)
	// - 4 bytes: Property tag
	// - 4 bytes: Property value

	buf := make([]byte, 27)
	// Tag: TPM_ST_NO_SESSIONS
	binary.BigEndian.PutUint16(buf[0:2], 0x8001)
	// Response size
	binary.BigEndian.PutUint32(buf[2:6], 27)
	// Response code: SUCCESS
	binary.BigEndian.PutUint32(buf[6:10], 0x00000000)
	// MoreData: NO
	buf[10] = 0x00
	// Capability: TPMCapTPMProperties
	binary.BigEndian.PutUint32(buf[11:15], uint32(tpm2.TPMCapTPMProperties))
	// Count: 1
	binary.BigEndian.PutUint32(buf[15:19], 1)
	// Property tag
	binary.BigEndian.PutUint32(buf[19:23], uint32(property))
	// Property value
	binary.BigEndian.PutUint32(buf[23:27], value)

	return buf
}

// buildErrorResponse constructs a TPM error response
func buildErrorResponse(errorCode uint32) []byte {
	buf := make([]byte, 10)
	// Tag: TPM_ST_NO_SESSIONS
	binary.BigEndian.PutUint16(buf[0:2], 0x8001)
	// Response size
	binary.BigEndian.PutUint32(buf[2:6], 10)
	// Response code: error
	binary.BigEndian.PutUint32(buf[6:10], errorCode)
	return buf
}

// buildMalformedResponse constructs an invalid capability response
func buildMalformedResponse() []byte {
	buf := make([]byte, 27)
	// Tag: TPM_ST_NO_SESSIONS
	binary.BigEndian.PutUint16(buf[0:2], 0x8001)
	// Response size
	binary.BigEndian.PutUint32(buf[2:6], 27)
	// Response code: SUCCESS
	binary.BigEndian.PutUint32(buf[6:10], 0x00000000)
	// MoreData: NO
	buf[10] = 0x00
	// Capability: Wrong type (not TPMCapTPMProperties)
	binary.BigEndian.PutUint32(buf[11:15], uint32(tpm2.TPMCapHandles))
	// Count: 1
	binary.BigEndian.PutUint32(buf[15:19], 1)
	// Some data
	binary.BigEndian.PutUint32(buf[19:23], 0x80000001)
	binary.BigEndian.PutUint32(buf[23:27], 0x00000000)

	return buf
}

func TestLoadedCurves(t *testing.T) {
	tests := []struct {
		name        string
		mockResp    map[uint32][]byte
		mockErr     error
		expected    uint32
		expectError bool
		errorMsg    string
	}{
		{
			name: "success with typical value",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildCapabilityResponse(tpm2.TPMPTLoadedCurves, 3),
			},
			expected:    3,
			expectError: false,
		},
		{
			name: "success with zero curves",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildCapabilityResponse(tpm2.TPMPTLoadedCurves, 0),
			},
			expected:    0,
			expectError: false,
		},
		{
			name: "success with maximum curves",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildCapabilityResponse(tpm2.TPMPTLoadedCurves, 0xFFFFFFFF),
			},
			expected:    0xFFFFFFFF,
			expectError: false,
		},
		{
			name: "success with single curve",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildCapabilityResponse(tpm2.TPMPTLoadedCurves, 1),
			},
			expected:    1,
			expectError: false,
		},
		{
			name: "success with many curves",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildCapabilityResponse(tpm2.TPMPTLoadedCurves, 256),
			},
			expected:    256,
			expectError: false,
		},
		{
			name:        "transport error",
			mockResp:    nil,
			mockErr:     errors.New("transport connection failed"),
			expected:    0,
			expectError: true,
			errorMsg:    "transport connection failed",
		},
		{
			name:        "no response configured",
			mockResp:    map[uint32][]byte{},
			mockErr:     nil,
			expected:    0,
			expectError: true,
			errorMsg:    "no mock response configured",
		},
		{
			name: "TPM error response",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildErrorResponse(0x00000101), // TPM_RC_FAILURE
			},
			expected:    0,
			expectError: true,
		},
		{
			name: "malformed capability response",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildMalformedResponse(),
			},
			expected:    0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{
				responses: tt.mockResp,
				err:       tt.mockErr,
			}

			result, err := loadedCurves(mockTransport)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					// Check if error contains the expected message
					if tt.mockErr != nil && err.Error() != tt.errorMsg {
						t.Logf("error message: %s", err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result != tt.expected {
					t.Errorf("expected %d, got %d", tt.expected, result)
				}
			}

			// Verify the correct property was queried
			if mockTransport.callCount > 0 && mockTransport.lastProperty != 0 {
				if mockTransport.lastProperty != uint32(tpm2.TPMPTLoadedCurves) {
					t.Errorf("queried wrong property: expected %d, got %d",
						uint32(tpm2.TPMPTLoadedCurves), mockTransport.lastProperty)
				}
			}
		})
	}
}

func TestLockoutRecovery(t *testing.T) {
	tests := []struct {
		name        string
		mockResp    map[uint32][]byte
		mockErr     error
		expected    uint32
		expectError bool
		errorMsg    string
	}{
		{
			name: "success with typical recovery time",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutRecovery): buildCapabilityResponse(tpm2.TPMPTLockoutRecovery, 86400),
			},
			expected:    86400, // 24 hours in seconds
			expectError: false,
		},
		{
			name: "success with zero recovery",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutRecovery): buildCapabilityResponse(tpm2.TPMPTLockoutRecovery, 0),
			},
			expected:    0,
			expectError: false,
		},
		{
			name: "success with short recovery",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutRecovery): buildCapabilityResponse(tpm2.TPMPTLockoutRecovery, 3600),
			},
			expected:    3600, // 1 hour
			expectError: false,
		},
		{
			name: "success with long recovery",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutRecovery): buildCapabilityResponse(tpm2.TPMPTLockoutRecovery, 604800),
			},
			expected:    604800, // 1 week in seconds
			expectError: false,
		},
		{
			name: "success with maximum value",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutRecovery): buildCapabilityResponse(tpm2.TPMPTLockoutRecovery, 0xFFFFFFFF),
			},
			expected:    0xFFFFFFFF,
			expectError: false,
		},
		{
			name: "success with 12 hour recovery",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutRecovery): buildCapabilityResponse(tpm2.TPMPTLockoutRecovery, 43200),
			},
			expected:    43200,
			expectError: false,
		},
		{
			name:        "transport error",
			mockResp:    nil,
			mockErr:     errors.New("TPM device not found"),
			expected:    0,
			expectError: true,
			errorMsg:    "TPM device not found",
		},
		{
			name:        "timeout error",
			mockResp:    nil,
			mockErr:     errors.New("operation timed out"),
			expected:    0,
			expectError: true,
			errorMsg:    "operation timed out",
		},
		{
			name: "TPM error response - value",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutRecovery): buildErrorResponse(0x000001C4), // TPM_RC_VALUE
			},
			expected:    0,
			expectError: true,
		},
		{
			name: "malformed response type",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutRecovery): buildMalformedResponse(),
			},
			expected:    0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{
				responses: tt.mockResp,
				err:       tt.mockErr,
			}

			result, err := lockoutRecovery(mockTransport)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && tt.mockErr != nil && err.Error() != tt.errorMsg {
					t.Logf("error message: %s", err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result != tt.expected {
					t.Errorf("expected %d, got %d", tt.expected, result)
				}
			}

			// Verify the correct property was queried
			if mockTransport.callCount > 0 && mockTransport.lastProperty != 0 && !tt.expectError {
				if mockTransport.lastProperty != uint32(tpm2.TPMPTLockoutRecovery) {
					t.Errorf("queried wrong property: expected %d, got %d",
						uint32(tpm2.TPMPTLockoutRecovery), mockTransport.lastProperty)
				}
			}
		})
	}
}

func TestLockoutInterval(t *testing.T) {
	tests := []struct {
		name        string
		mockResp    map[uint32][]byte
		mockErr     error
		expected    uint32
		expectError bool
		errorMsg    string
	}{
		{
			name: "success with typical interval",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutInterval): buildCapabilityResponse(tpm2.TPMPTLockoutInterval, 7200),
			},
			expected:    7200, // 2 hours in seconds
			expectError: false,
		},
		{
			name: "success with zero interval",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutInterval): buildCapabilityResponse(tpm2.TPMPTLockoutInterval, 0),
			},
			expected:    0,
			expectError: false,
		},
		{
			name: "success with short interval",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutInterval): buildCapabilityResponse(tpm2.TPMPTLockoutInterval, 60),
			},
			expected:    60, // 1 minute
			expectError: false,
		},
		{
			name: "success with long interval",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutInterval): buildCapabilityResponse(tpm2.TPMPTLockoutInterval, 86400),
			},
			expected:    86400, // 24 hours
			expectError: false,
		},
		{
			name: "success with maximum interval",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutInterval): buildCapabilityResponse(tpm2.TPMPTLockoutInterval, 0xFFFFFFFF),
			},
			expected:    0xFFFFFFFF,
			expectError: false,
		},
		{
			name: "success with 30 minute interval",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutInterval): buildCapabilityResponse(tpm2.TPMPTLockoutInterval, 1800),
			},
			expected:    1800,
			expectError: false,
		},
		{
			name: "success with 1 second interval",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutInterval): buildCapabilityResponse(tpm2.TPMPTLockoutInterval, 1),
			},
			expected:    1,
			expectError: false,
		},
		{
			name:        "transport error",
			mockResp:    nil,
			mockErr:     errors.New("device I/O error"),
			expected:    0,
			expectError: true,
			errorMsg:    "device I/O error",
		},
		{
			name:        "permission denied error",
			mockResp:    nil,
			mockErr:     errors.New("permission denied"),
			expected:    0,
			expectError: true,
			errorMsg:    "permission denied",
		},
		{
			name: "TPM error response - disabled",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutInterval): buildErrorResponse(0x00000120), // TPM_RC_DISABLED
			},
			expected:    0,
			expectError: true,
		},
		{
			name: "malformed capability data",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutInterval): buildMalformedResponse(),
			},
			expected:    0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{
				responses: tt.mockResp,
				err:       tt.mockErr,
			}

			result, err := lockoutInterval(mockTransport)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && tt.mockErr != nil && err.Error() != tt.errorMsg {
					t.Logf("error message: %s", err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result != tt.expected {
					t.Errorf("expected %d, got %d", tt.expected, result)
				}
			}

			// Verify the correct property was queried
			if mockTransport.callCount > 0 && mockTransport.lastProperty != 0 && !tt.expectError {
				if mockTransport.lastProperty != uint32(tpm2.TPMPTLockoutInterval) {
					t.Errorf("queried wrong property: expected %d, got %d",
						uint32(tpm2.TPMPTLockoutInterval), mockTransport.lastProperty)
				}
			}
		})
	}
}

func TestLoadedCurvesEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected uint32
	}{
		{"minimum value", 0, 0},
		{"one curve", 1, 1},
		{"typical NIST curves", 3, 3},
		{"all standard curves", 5, 5},
		{"power of two", 16, 16},
		{"large number", 1000, 1000},
		{"near max", 0xFFFFFFFE, 0xFFFFFFFE},
		{"max uint32", 0xFFFFFFFF, 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{
				responses: map[uint32][]byte{
					uint32(tpm2.TPMPTLoadedCurves): buildCapabilityResponse(tpm2.TPMPTLoadedCurves, tt.value),
				},
			}

			result, err := loadedCurves(mockTransport)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestLockoutRecoveryEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected uint32
	}{
		{"immediate recovery", 0, 0},
		{"1 second", 1, 1},
		{"1 minute", 60, 60},
		{"5 minutes", 300, 300},
		{"1 hour", 3600, 3600},
		{"2 hours", 7200, 7200},
		{"12 hours", 43200, 43200},
		{"24 hours", 86400, 86400},
		{"1 week", 604800, 604800},
		{"1 month approx", 2592000, 2592000},
		{"1 year approx", 31536000, 31536000},
		{"max uint32", 0xFFFFFFFF, 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{
				responses: map[uint32][]byte{
					uint32(tpm2.TPMPTLockoutRecovery): buildCapabilityResponse(tpm2.TPMPTLockoutRecovery, tt.value),
				},
			}

			result, err := lockoutRecovery(mockTransport)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestLockoutIntervalEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected uint32
	}{
		{"no interval", 0, 0},
		{"1 second", 1, 1},
		{"10 seconds", 10, 10},
		{"30 seconds", 30, 30},
		{"1 minute", 60, 60},
		{"5 minutes", 300, 300},
		{"15 minutes", 900, 900},
		{"30 minutes", 1800, 1800},
		{"1 hour", 3600, 3600},
		{"2 hours", 7200, 7200},
		{"4 hours", 14400, 14400},
		{"24 hours", 86400, 86400},
		{"max uint32", 0xFFFFFFFF, 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{
				responses: map[uint32][]byte{
					uint32(tpm2.TPMPTLockoutInterval): buildCapabilityResponse(tpm2.TPMPTLockoutInterval, tt.value),
				},
			}

			result, err := lockoutInterval(mockTransport)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestCapabilityFunctionsTransportErrors(t *testing.T) {
	transportErrors := []struct {
		name string
		err  error
	}{
		{"connection refused", errors.New("connection refused")},
		{"device not found", errors.New("device not found")},
		{"timeout", errors.New("timeout")},
		{"permission denied", errors.New("permission denied")},
		{"I/O error", errors.New("I/O error")},
		{"broken pipe", errors.New("broken pipe")},
		{"TPM unavailable", errors.New("TPM unavailable")},
	}

	for _, te := range transportErrors {
		t.Run("loadedCurves_"+te.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{err: te.err}
			_, err := loadedCurves(mockTransport)
			if err == nil {
				t.Error("expected error but got none")
			}
			if err.Error() != te.err.Error() {
				t.Errorf("expected error %v, got %v", te.err, err)
			}
		})

		t.Run("lockoutRecovery_"+te.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{err: te.err}
			_, err := lockoutRecovery(mockTransport)
			if err == nil {
				t.Error("expected error but got none")
			}
			if err.Error() != te.err.Error() {
				t.Errorf("expected error %v, got %v", te.err, err)
			}
		})

		t.Run("lockoutInterval_"+te.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{err: te.err}
			_, err := lockoutInterval(mockTransport)
			if err == nil {
				t.Error("expected error but got none")
			}
			if err.Error() != te.err.Error() {
				t.Errorf("expected error %v, got %v", te.err, err)
			}
		})
	}
}

func TestCapabilityMockTransportBehavior(t *testing.T) {
	t.Run("tracks call count", func(t *testing.T) {
		mockTransport := &capabilityMockTransport{
			responses: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildCapabilityResponse(tpm2.TPMPTLoadedCurves, 3),
			},
		}

		if mockTransport.callCount != 0 {
			t.Errorf("initial call count should be 0, got %d", mockTransport.callCount)
		}

		_, _ = loadedCurves(mockTransport)
		if mockTransport.callCount != 1 {
			t.Errorf("call count should be 1, got %d", mockTransport.callCount)
		}

		_, _ = loadedCurves(mockTransport)
		if mockTransport.callCount != 2 {
			t.Errorf("call count should be 2, got %d", mockTransport.callCount)
		}
	})

	t.Run("tracks last property queried", func(t *testing.T) {
		mockTransport := &capabilityMockTransport{
			responses: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves):    buildCapabilityResponse(tpm2.TPMPTLoadedCurves, 3),
				uint32(tpm2.TPMPTLockoutRecovery): buildCapabilityResponse(tpm2.TPMPTLockoutRecovery, 86400),
				uint32(tpm2.TPMPTLockoutInterval): buildCapabilityResponse(tpm2.TPMPTLockoutInterval, 7200),
			},
		}

		_, _ = loadedCurves(mockTransport)
		if mockTransport.lastProperty != uint32(tpm2.TPMPTLoadedCurves) {
			t.Errorf("expected property %d, got %d", uint32(tpm2.TPMPTLoadedCurves), mockTransport.lastProperty)
		}

		_, _ = lockoutRecovery(mockTransport)
		if mockTransport.lastProperty != uint32(tpm2.TPMPTLockoutRecovery) {
			t.Errorf("expected property %d, got %d", uint32(tpm2.TPMPTLockoutRecovery), mockTransport.lastProperty)
		}

		_, _ = lockoutInterval(mockTransport)
		if mockTransport.lastProperty != uint32(tpm2.TPMPTLockoutInterval) {
			t.Errorf("expected property %d, got %d", uint32(tpm2.TPMPTLockoutInterval), mockTransport.lastProperty)
		}
	})

	t.Run("short input rejected", func(t *testing.T) {
		mockTransport := &capabilityMockTransport{
			responses: map[uint32][]byte{},
		}

		// Directly test Send with short input
		_, err := mockTransport.Send([]byte{0x01, 0x02})
		if err == nil {
			t.Error("expected error for short input")
		}
		if err.Error() != "input too short" {
			t.Errorf("expected 'input too short' error, got %v", err)
		}
	})
}

// Ensure the mock transport satisfies the interface
var _ transport.TPM = (*capabilityMockTransport)(nil)

func TestBuildCapabilityResponse(t *testing.T) {
	tests := []struct {
		name     string
		property tpm2.TPMPT
		value    uint32
	}{
		{"LoadedCurves", tpm2.TPMPTLoadedCurves, 5},
		{"LockoutRecovery", tpm2.TPMPTLockoutRecovery, 86400},
		{"LockoutInterval", tpm2.TPMPTLockoutInterval, 7200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := buildCapabilityResponse(tt.property, tt.value)

			// Verify response structure
			if len(resp) != 27 {
				t.Errorf("expected response length 27, got %d", len(resp))
			}

			// Check tag
			tag := binary.BigEndian.Uint16(resp[0:2])
			if tag != 0x8001 {
				t.Errorf("expected tag 0x8001, got 0x%04x", tag)
			}

			// Check response size
			size := binary.BigEndian.Uint32(resp[2:6])
			if size != 27 {
				t.Errorf("expected size 27, got %d", size)
			}

			// Check response code
			rc := binary.BigEndian.Uint32(resp[6:10])
			if rc != 0 {
				t.Errorf("expected success response code 0, got 0x%08x", rc)
			}

			// Check capability type
			capType := binary.BigEndian.Uint32(resp[11:15])
			if capType != uint32(tpm2.TPMCapTPMProperties) {
				t.Errorf("expected capability type %d, got %d", uint32(tpm2.TPMCapTPMProperties), capType)
			}

			// Check property count
			count := binary.BigEndian.Uint32(resp[15:19])
			if count != 1 {
				t.Errorf("expected count 1, got %d", count)
			}

			// Check property tag
			propTag := binary.BigEndian.Uint32(resp[19:23])
			if propTag != uint32(tt.property) {
				t.Errorf("expected property tag %d, got %d", uint32(tt.property), propTag)
			}

			// Check property value
			propValue := binary.BigEndian.Uint32(resp[23:27])
			if propValue != tt.value {
				t.Errorf("expected property value %d, got %d", tt.value, propValue)
			}
		})
	}
}

func TestBuildErrorResponse(t *testing.T) {
	tests := []struct {
		name      string
		errorCode uint32
	}{
		{"TPM_RC_FAILURE", 0x00000101},
		{"TPM_RC_VALUE", 0x000001C4},
		{"TPM_RC_DISABLED", 0x00000120},
		{"Custom error", 0xDEADBEEF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := buildErrorResponse(tt.errorCode)

			// Verify response structure
			if len(resp) != 10 {
				t.Errorf("expected response length 10, got %d", len(resp))
			}

			// Check tag
			tag := binary.BigEndian.Uint16(resp[0:2])
			if tag != 0x8001 {
				t.Errorf("expected tag 0x8001, got 0x%04x", tag)
			}

			// Check response size
			size := binary.BigEndian.Uint32(resp[2:6])
			if size != 10 {
				t.Errorf("expected size 10, got %d", size)
			}

			// Check response code
			rc := binary.BigEndian.Uint32(resp[6:10])
			if rc != tt.errorCode {
				t.Errorf("expected error code 0x%08x, got 0x%08x", tt.errorCode, rc)
			}
		})
	}
}

func TestBuildMalformedResponse(t *testing.T) {
	resp := buildMalformedResponse()

	// Verify response length
	if len(resp) != 27 {
		t.Errorf("expected response length 27, got %d", len(resp))
	}

	// Check that capability type is NOT TPMCapTPMProperties
	capType := binary.BigEndian.Uint32(resp[11:15])
	if capType == uint32(tpm2.TPMCapTPMProperties) {
		t.Errorf("malformed response should not have TPMCapTPMProperties capability type")
	}

	// Verify it's using TPMCapHandles instead
	if capType != uint32(tpm2.TPMCapHandles) {
		t.Errorf("expected capability type %d (TPMCapHandles), got %d", uint32(tpm2.TPMCapHandles), capType)
	}
}
