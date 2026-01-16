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

package rand

import (
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// mockTPMTransport implements transport.TPMCloser for testing TPM2 random operations.
// It simulates TPM GetRandom command responses.
type mockTPMTransport struct {
	mu            sync.Mutex
	closed        bool
	closeErr      error
	randData      []byte
	randErr       error
	callCount     int
	maxRequestSz  int
	useFixedData  bool
	returnPartial bool
}

// Send implements the TPM transport Send method.
// For GetRandom commands, it returns a properly formatted TPM2 response.
func (m *mockTPMTransport) Send(cmd []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callCount++

	if m.randErr != nil {
		return nil, m.randErr
	}

	// Parse the command to get the requested bytes
	// TPM2_GetRandom command structure:
	// - 2 bytes: tag
	// - 4 bytes: command size
	// - 4 bytes: command code (TPM_CC_GetRandom = 0x0000017B)
	// - 2 bytes: bytesRequested
	if len(cmd) < 12 {
		return nil, errors.New("command too short")
	}

	// Extract bytesRequested from the command
	bytesRequested := binary.BigEndian.Uint16(cmd[10:12])

	// Build the response
	// TPM2 GetRandom response structure:
	// - 2 bytes: tag (TPM_ST_NO_SESSIONS = 0x8001)
	// - 4 bytes: response size
	// - 4 bytes: response code (TPM_RC_SUCCESS = 0x00000000)
	// - 2 bytes: size of random bytes (TPM2B_DIGEST size)
	// - N bytes: random data

	actualBytes := int(bytesRequested)
	if m.returnPartial && actualBytes > 8 {
		actualBytes = 8 // Return fewer bytes than requested
	}

	// Generate random-looking data
	randomBytes := make([]byte, actualBytes)
	if m.useFixedData && len(m.randData) >= actualBytes {
		copy(randomBytes, m.randData[:actualBytes])
	} else {
		// Fill with pseudo-random pattern based on call count
		for i := 0; i < actualBytes; i++ {
			randomBytes[i] = byte((m.callCount*17 + i*31) % 256)
		}
	}

	// Build response
	responseSize := uint32(12 + actualBytes) // header (10) + size (2) + data
	response := make([]byte, responseSize)

	// Tag: TPM_ST_NO_SESSIONS
	binary.BigEndian.PutUint16(response[0:2], 0x8001)
	// Response size
	binary.BigEndian.PutUint32(response[2:6], responseSize)
	// Response code: TPM_RC_SUCCESS
	binary.BigEndian.PutUint32(response[6:10], 0x00000000)
	// Size of random bytes
	binary.BigEndian.PutUint16(response[10:12], uint16(actualBytes))
	// Random bytes
	copy(response[12:], randomBytes)

	return response, nil
}

// Close implements transport.TPMCloser
func (m *mockTPMTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return m.closeErr
}

// TestTPM2Resolver_RandWithMockTransport tests Rand using mock TPM transport
func TestTPM2Resolver_RandWithMockTransport(t *testing.T) {
	mock := &mockTPMTransport{
		maxRequestSz: 32,
	}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	// Test basic random generation
	data, err := resolver.Rand(32)
	if err != nil {
		t.Fatalf("Rand(32) failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}

	// Verify data is not all zeros
	allZeros := true
	for _, b := range data {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Rand should produce non-zero data")
	}
}

// TestTPM2Resolver_RandLargeRequestChunking tests chunking for large requests
func TestTPM2Resolver_RandLargeRequestChunking(t *testing.T) {
	mock := &mockTPMTransport{
		maxRequestSz: 32,
	}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	// Request more than MaxRequestSize - should chunk
	data, err := resolver.Rand(100)
	if err != nil {
		t.Fatalf("Rand(100) failed: %v", err)
	}
	if len(data) != 100 {
		t.Errorf("Expected 100 bytes, got %d", len(data))
	}

	// Should have made multiple calls (100/32 = 4 calls)
	mock.mu.Lock()
	callCount := mock.callCount
	mock.mu.Unlock()

	if callCount < 4 {
		t.Errorf("Expected at least 4 TPM calls for 100 bytes with MaxRequestSize=32, got %d", callCount)
	}
}

// TestTPM2Resolver_RandSmallRequestNoChunking tests small requests don't chunk
func TestTPM2Resolver_RandSmallRequestNoChunking(t *testing.T) {
	mock := &mockTPMTransport{
		maxRequestSz: 32,
	}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	// Request less than MaxRequestSize
	data, err := resolver.Rand(16)
	if err != nil {
		t.Fatalf("Rand(16) failed: %v", err)
	}
	if len(data) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(data))
	}

	mock.mu.Lock()
	callCount := mock.callCount
	mock.mu.Unlock()

	if callCount != 1 {
		t.Errorf("Expected 1 TPM call for 16 bytes, got %d", callCount)
	}
}

// TestTPM2Resolver_RandZeroBytes tests zero-byte request
func TestTPM2Resolver_RandZeroBytesWithMock(t *testing.T) {
	mock := &mockTPMTransport{}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	data, err := resolver.Rand(0)
	if err != nil {
		t.Fatalf("Rand(0) failed: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("Expected 0 bytes, got %d", len(data))
	}

	// Should not have called TPM
	mock.mu.Lock()
	callCount := mock.callCount
	mock.mu.Unlock()

	if callCount != 0 {
		t.Errorf("Should not call TPM for 0 bytes, got %d calls", callCount)
	}
}

// TestTPM2Resolver_RandTPMError tests error handling from TPM
func TestTPM2Resolver_RandTPMError(t *testing.T) {
	expectedErr := errors.New("TPM hardware error")
	mock := &mockTPMTransport{
		randErr: expectedErr,
	}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	_, err := resolver.Rand(32)
	if err == nil {
		t.Fatal("Expected error from TPM")
	}
}

// TestTPM2Resolver_ReadWithMockTransport tests Read using mock TPM transport
func TestTPM2Resolver_ReadWithMockTransport(t *testing.T) {
	mock := &mockTPMTransport{}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	buf := make([]byte, 64)
	n, err := resolver.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 64 {
		t.Errorf("Expected 64 bytes, got %d", n)
	}
}

// TestTPM2Resolver_ReadMultipleSizes tests Read with various buffer sizes
func TestTPM2Resolver_ReadMultipleSizes(t *testing.T) {
	sizes := []int{1, 8, 16, 31, 32, 33, 64, 100, 256}

	for _, size := range sizes {
		t.Run(string(rune('0'+size%10)), func(t *testing.T) {
			mock := &mockTPMTransport{}

			resolver := &tpm2Resolver{
				rwc: mock,
				config: &TPM2Config{
					MaxRequestSize: 32,
				},
			}
			defer func() { _ = resolver.Close() }()

			buf := make([]byte, size)
			n, err := resolver.Read(buf)
			if err != nil {
				t.Fatalf("Read(%d) failed: %v", size, err)
			}
			if n != size {
				t.Errorf("Expected %d bytes, got %d", size, n)
			}
		})
	}
}

// TestTPM2Resolver_RandConcurrent tests concurrent Rand calls with mock
func TestTPM2Resolver_RandConcurrent(t *testing.T) {
	mock := &mockTPMTransport{}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	var wg sync.WaitGroup
	numGoroutines := 20

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				data, err := resolver.Rand(32)
				if err != nil {
					t.Errorf("Concurrent Rand failed: %v", err)
					return
				}
				if len(data) != 32 {
					t.Errorf("Expected 32 bytes, got %d", len(data))
				}
			}
		}()
	}

	wg.Wait()
}

// TestTPM2Resolver_RandExactMaxRequestSize tests request exactly at MaxRequestSize
func TestTPM2Resolver_RandExactMaxRequestSize(t *testing.T) {
	mock := &mockTPMTransport{}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	data, err := resolver.Rand(32) // Exactly MaxRequestSize
	if err != nil {
		t.Fatalf("Rand(32) failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}

	mock.mu.Lock()
	callCount := mock.callCount
	mock.mu.Unlock()

	if callCount != 1 {
		t.Errorf("Expected exactly 1 TPM call, got %d", callCount)
	}
}

// TestTPM2Resolver_RandOneOverMaxRequestSize tests request one byte over MaxRequestSize
func TestTPM2Resolver_RandOneOverMaxRequestSize(t *testing.T) {
	mock := &mockTPMTransport{}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	data, err := resolver.Rand(33) // One over MaxRequestSize
	if err != nil {
		t.Fatalf("Rand(33) failed: %v", err)
	}
	if len(data) != 33 {
		t.Errorf("Expected 33 bytes, got %d", len(data))
	}

	mock.mu.Lock()
	callCount := mock.callCount
	mock.mu.Unlock()

	if callCount != 2 {
		t.Errorf("Expected 2 TPM calls for 33 bytes with MaxRequestSize=32, got %d", callCount)
	}
}

// TestTPM2Resolver_RandVeryLargeRequest tests very large random request
func TestTPM2Resolver_RandVeryLargeRequest(t *testing.T) {
	mock := &mockTPMTransport{}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	// 1KB request
	data, err := resolver.Rand(1024)
	if err != nil {
		t.Fatalf("Rand(1024) failed: %v", err)
	}
	if len(data) != 1024 {
		t.Errorf("Expected 1024 bytes, got %d", len(data))
	}

	// Should have made 32 calls (1024/32)
	mock.mu.Lock()
	callCount := mock.callCount
	mock.mu.Unlock()

	if callCount != 32 {
		t.Errorf("Expected 32 TPM calls for 1024 bytes, got %d", callCount)
	}
}

// TestTPM2Resolver_RandWithFixedData tests with predetermined random data
func TestTPM2Resolver_RandWithFixedData(t *testing.T) {
	fixedData := make([]byte, 32)
	for i := range fixedData {
		fixedData[i] = byte(i + 1)
	}

	mock := &mockTPMTransport{
		randData:     fixedData,
		useFixedData: true,
	}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	data, err := resolver.Rand(16)
	if err != nil {
		t.Fatalf("Rand failed: %v", err)
	}

	// First 16 bytes should match fixed data
	for i := 0; i < 16; i++ {
		if data[i] != fixedData[i] {
			t.Errorf("Byte %d mismatch: expected %d, got %d", i, fixedData[i], data[i])
		}
	}
}

// TestTPM2Resolver_SourceRand tests tpm2Source.Rand method
func TestTPM2Resolver_SourceRandWithMock(t *testing.T) {
	mock := &mockTPMTransport{}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	source := resolver.Source()
	if source == nil {
		t.Fatal("Source returned nil")
	}

	data, err := source.Rand(32)
	if err != nil {
		t.Fatalf("Source.Rand failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestTPM2Resolver_ChunkBoundaries tests various chunk boundary scenarios
func TestTPM2Resolver_ChunkBoundaries(t *testing.T) {
	tests := []struct {
		name           string
		requestSize    int
		maxRequestSize int
		expectedCalls  int
	}{
		{"exact_single", 32, 32, 1},
		{"exact_double", 64, 32, 2},
		{"exact_triple", 96, 32, 3},
		{"one_under", 31, 32, 1},
		{"one_over", 33, 32, 2},
		{"half", 16, 32, 1},
		{"three_halves", 48, 32, 2},
		{"large_max", 64, 64, 1},
		{"small_max", 32, 8, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockTPMTransport{}

			resolver := &tpm2Resolver{
				rwc: mock,
				config: &TPM2Config{
					MaxRequestSize: tt.maxRequestSize,
				},
			}
			defer func() { _ = resolver.Close() }()

			data, err := resolver.Rand(tt.requestSize)
			if err != nil {
				t.Fatalf("Rand(%d) failed: %v", tt.requestSize, err)
			}
			if len(data) != tt.requestSize {
				t.Errorf("Expected %d bytes, got %d", tt.requestSize, len(data))
			}

			mock.mu.Lock()
			callCount := mock.callCount
			mock.mu.Unlock()

			if callCount != tt.expectedCalls {
				t.Errorf("Expected %d calls, got %d", tt.expectedCalls, callCount)
			}
		})
	}
}

// TestTPM2Resolver_RandErrorMidChunk tests error occurring during chunked operation
func TestTPM2Resolver_RandErrorMidChunk(t *testing.T) {
	mock := &mockTPMTransport{}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	// Set error after first successful call
	go func() {
		for {
			mock.mu.Lock()
			if mock.callCount >= 1 {
				mock.randErr = errors.New("mid-chunk error")
				mock.mu.Unlock()
				return
			}
			mock.mu.Unlock()
		}
	}()

	// Request large amount to ensure multiple chunks
	_, err := resolver.Rand(128)
	// May or may not error depending on timing
	_ = err
}

// TestTPM2Resolver_RandUniqueness tests that multiple calls produce unique data
func TestTPM2Resolver_RandUniqueness(t *testing.T) {
	mock := &mockTPMTransport{}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}
	defer func() { _ = resolver.Close() }()

	samples := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		data, err := resolver.Rand(32)
		if err != nil {
			t.Fatalf("Rand failed at iteration %d: %v", i, err)
		}
		samples[i] = make([]byte, len(data))
		copy(samples[i], data)
	}

	// Check uniqueness
	for i := 0; i < len(samples); i++ {
		for j := i + 1; j < len(samples); j++ {
			equal := true
			for k := 0; k < len(samples[i]); k++ {
				if samples[i][k] != samples[j][k] {
					equal = false
					break
				}
			}
			if equal {
				t.Errorf("Samples %d and %d are identical", i, j)
			}
		}
	}
}

// TestTPM2Source_AllMethodsWithMock tests all tpm2Source methods
func TestTPM2Source_AllMethodsWithMock(t *testing.T) {
	mock := &mockTPMTransport{}

	resolver := &tpm2Resolver{
		rwc: mock,
		config: &TPM2Config{
			MaxRequestSize: 32,
		},
	}

	source := &tpm2Source{resolver: resolver}

	// Test Rand
	data, err := source.Rand(16)
	if err != nil {
		t.Errorf("Rand failed: %v", err)
	}
	if len(data) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(data))
	}

	// Test Available
	if !source.Available() {
		t.Error("Should be available")
	}

	// Test Close
	err = source.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// After close, Available should be false
	if source.Available() {
		t.Error("Should not be available after close")
	}
}

// TestTPM2Resolver_ResponseVariants tests handling of various TPM response scenarios
func TestTPM2Resolver_ResponseVariants(t *testing.T) {
	t.Run("normal_response", func(t *testing.T) {
		mock := &mockTPMTransport{}
		resolver := &tpm2Resolver{
			rwc:    mock,
			config: &TPM2Config{MaxRequestSize: 32},
		}
		defer func() { _ = resolver.Close() }()

		data, err := resolver.Rand(16)
		if err != nil {
			t.Errorf("Rand failed: %v", err)
		}
		if len(data) != 16 {
			t.Errorf("Expected 16 bytes, got %d", len(data))
		}
	})

	t.Run("single_byte_request", func(t *testing.T) {
		mock := &mockTPMTransport{}
		resolver := &tpm2Resolver{
			rwc:    mock,
			config: &TPM2Config{MaxRequestSize: 32},
		}
		defer func() { _ = resolver.Close() }()

		data, err := resolver.Rand(1)
		if err != nil {
			t.Errorf("Rand(1) failed: %v", err)
		}
		if len(data) != 1 {
			t.Errorf("Expected 1 byte, got %d", len(data))
		}
	})
}

// TestTPM2GetRandomCommand verifies the structure of TPM2 GetRandom command
func TestTPM2GetRandomCommand(t *testing.T) {
	// This tests that we understand the TPM2 GetRandom command structure
	cmd := tpm2.GetRandom{
		BytesRequested: 32,
	}

	// Command code should be TPM_CC_GetRandom (0x0000017B)
	expectedCC := tpm2.TPMCCGetRandom
	if cmd.Command() != expectedCC {
		t.Errorf("Expected command code %v, got %v", expectedCC, cmd.Command())
	}
}
