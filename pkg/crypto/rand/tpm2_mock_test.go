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

package rand

import (
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// mockTPM2Closer simulates the TPM transport closer interface for testing
// nil-state and close lifecycle behavior.
type mockTPM2Closer struct {
	closeErr error
	closed   bool
	mu       sync.Mutex
}

func (m *mockTPM2Closer) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return m.closeErr
}

func (m *mockTPM2Closer) Send([]byte) ([]byte, error) {
	return nil, errors.New("mock TPM: not implemented")
}

// mockTPMTransport implements transport.TPMCloser for testing TPM2 random
// operations. It simulates TPM GetRandom command responses with proper
// TPM2 protocol framing.
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

	actualBytes := int(bytesRequested)
	if m.returnPartial && actualBytes > 8 {
		actualBytes = 8
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

	// Build TPM2 GetRandom response:
	// - 2 bytes: tag (TPM_ST_NO_SESSIONS = 0x8001)
	// - 4 bytes: response size
	// - 4 bytes: response code (TPM_RC_SUCCESS = 0x00000000)
	// - 2 bytes: size of random bytes (TPM2B_DIGEST size)
	// - N bytes: random data
	responseSize := uint32(12 + actualBytes)
	response := make([]byte, responseSize)

	binary.BigEndian.PutUint16(response[0:2], 0x8001)
	binary.BigEndian.PutUint32(response[2:6], responseSize)
	binary.BigEndian.PutUint32(response[6:10], 0x00000000)
	binary.BigEndian.PutUint16(response[10:12], uint16(actualBytes))
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

// ---------------------------------------------------------------------------
// Tests: tpm2Resolver nil/closed state behavior (using mockTPM2Closer)
// ---------------------------------------------------------------------------

// TestTPM2Resolver_RandWithNilRWC tests Rand when rwc is nil
func TestTPM2Resolver_RandWithNilRWC(t *testing.T) {
	resolver := &tpm2Resolver{
		rwc:    nil,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	_, err := resolver.Rand(32)
	if err == nil {
		t.Error("Expected error when rwc is nil")
	}
	if err.Error() != "TPM2 resolver closed" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestTPM2Resolver_ReadWithNilRWC tests Read when rwc is nil
func TestTPM2Resolver_ReadWithNilRWC(t *testing.T) {
	resolver := &tpm2Resolver{
		rwc:    nil,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	buf := make([]byte, 32)
	n, err := resolver.Read(buf)
	if err == nil {
		t.Error("Expected error when rwc is nil")
	}
	if n != 0 {
		t.Errorf("Expected 0 bytes read, got %d", n)
	}
}

// TestTPM2Resolver_SourceWithNilRWC tests Source when rwc is nil
func TestTPM2Resolver_SourceWithNilRWC(t *testing.T) {
	resolver := &tpm2Resolver{
		rwc:    nil,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	source := resolver.Source()
	if source == nil {
		t.Error("Source should not return nil")
	}

	tpmSource, ok := source.(*tpm2Source)
	if !ok {
		t.Error("Source should return *tpm2Source")
	}

	if tpmSource != nil {
		if tpmSource.Available() {
			t.Error("tpm2Source.Available() should return false when rwc is nil")
		}

		_, err := tpmSource.Rand(32)
		if err == nil {
			t.Error("tpm2Source.Rand() should error when rwc is nil")
		}

		err = tpmSource.Close()
		if err != nil {
			t.Errorf("tpm2Source.Close() should not error: %v", err)
		}
	}
}

// TestTPM2Resolver_AvailableWithNilRWC tests Available when rwc is nil
func TestTPM2Resolver_AvailableWithNilRWC(t *testing.T) {
	resolver := &tpm2Resolver{
		rwc:    nil,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	if resolver.Available() {
		t.Error("Available should return false when rwc is nil")
	}
}

// TestTPM2Resolver_CloseWithNilRWC tests Close when rwc is nil
func TestTPM2Resolver_CloseWithNilRWC(t *testing.T) {
	resolver := &tpm2Resolver{
		rwc:    nil,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	err := resolver.Close()
	if err != nil {
		t.Errorf("Close should not error when rwc is nil: %v", err)
	}
}

// TestTPM2Resolver_CloseWithMockRWC tests Close with a mock rwc
func TestTPM2Resolver_CloseWithMockRWC(t *testing.T) {
	mock := &mockTPM2Closer{}
	resolver := &tpm2Resolver{
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	err := resolver.Close()
	if err != nil {
		t.Errorf("Close should not error: %v", err)
	}

	mock.mu.Lock()
	if !mock.closed {
		t.Error("Close should have called rwc.Close()")
	}
	mock.mu.Unlock()

	if resolver.rwc != nil {
		t.Error("rwc should be nil after Close()")
	}
}

// TestTPM2Resolver_CloseWithMockRWCError tests Close when mock rwc returns error
func TestTPM2Resolver_CloseWithMockRWCError(t *testing.T) {
	expectedErr := errors.New("close failed")
	mock := &mockTPM2Closer{closeErr: expectedErr}
	resolver := &tpm2Resolver{
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	err := resolver.Close()
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}

	if resolver.rwc != nil {
		t.Error("rwc should be nil after Close()")
	}
}

// TestTPM2Resolver_DoubleClose tests closing twice
func TestTPM2Resolver_DoubleClose(t *testing.T) {
	mock := &mockTPM2Closer{}
	resolver := &tpm2Resolver{
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	err := resolver.Close()
	if err != nil {
		t.Errorf("First Close should not error: %v", err)
	}

	err = resolver.Close()
	if err != nil {
		t.Errorf("Second Close should not error: %v", err)
	}
}

// TestTPM2Resolver_AvailableWithMockRWC tests Available with mock rwc
func TestTPM2Resolver_AvailableWithMockRWC(t *testing.T) {
	mock := &mockTPM2Closer{}
	resolver := &tpm2Resolver{
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	if !resolver.Available() {
		t.Error("Available should return true when rwc is not nil")
	}

	_ = resolver.Close()

	if resolver.Available() {
		t.Error("Available should return false after Close()")
	}
}

// TestTPM2Resolver_ConcurrentAccessNilRWC tests concurrent access with nil rwc
func TestTPM2Resolver_ConcurrentAccessNilRWC(t *testing.T) {
	resolver := &tpm2Resolver{
		rwc:    nil,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	var wg sync.WaitGroup
	numGoroutines := 20

	wg.Add(numGoroutines * 4)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = resolver.Available()
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = resolver.Source()
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = resolver.Rand(32)
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			buf := make([]byte, 32)
			_, _ = resolver.Read(buf)
		}()
	}

	wg.Wait()
}

// TestTPM2Source_AllMethods tests all tpm2Source methods with nil rwc
func TestTPM2Source_AllMethods(t *testing.T) {
	resolver := &tpm2Resolver{
		rwc:    nil,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	source := &tpm2Source{resolver: resolver}

	_, err := source.Rand(16)
	if err == nil {
		t.Error("tpm2Source.Rand should error when rwc is nil")
	}

	if source.Available() {
		t.Error("tpm2Source.Available should return false when rwc is nil")
	}

	err = source.Close()
	if err != nil {
		t.Errorf("tpm2Source.Close should not error: %v", err)
	}
}

// TestTPM2Source_WithMockRWC tests tpm2Source with a mock rwc
func TestTPM2Source_WithMockRWC(t *testing.T) {
	mock := &mockTPM2Closer{}
	resolver := &tpm2Resolver{
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	source := &tpm2Source{resolver: resolver}

	if !source.Available() {
		t.Error("tpm2Source.Available should return true when rwc is not nil")
	}

	err := source.Close()
	if err != nil {
		t.Errorf("tpm2Source.Close should not error: %v", err)
	}

	if source.Available() {
		t.Error("tpm2Source.Available should return false after Close()")
	}
}

// TestTPM2Resolver_ReadZeroBytesNilRWC tests Read with zero-length buffer and nil rwc
func TestTPM2Resolver_ReadZeroBytesNilRWC(t *testing.T) {
	resolver := &tpm2Resolver{
		rwc:    nil,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	buf := make([]byte, 0)
	n, err := resolver.Read(buf)
	if err == nil {
		t.Error("Expected error when rwc is nil")
	}
	if n != 0 {
		t.Errorf("Expected 0 bytes read, got %d", n)
	}
}

// TestTPM2Resolver_SourceReturnsConsistentType tests that Source always returns *tpm2Source
func TestTPM2Resolver_SourceReturnsConsistentType(t *testing.T) {
	resolver := &tpm2Resolver{
		rwc:    nil,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	for i := 0; i < 10; i++ {
		source := resolver.Source()
		if source == nil {
			t.Errorf("Source call %d returned nil", i)
			continue
		}

		_, ok := source.(*tpm2Source)
		if !ok {
			t.Errorf("Source call %d did not return *tpm2Source", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: tpm2Resolver with mock TPM transport (using mockTPMTransport)
// These tests exercise the actual Rand/Read logic with simulated TPM responses.
// ---------------------------------------------------------------------------

// TestTPM2Resolver_RandWithMockTransport tests basic random generation
func TestTPM2Resolver_RandWithMockTransport(t *testing.T) {
	mock := &mockTPMTransport{maxRequestSz: 32}
	resolver := &tpm2Resolver{
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
	}
	defer func() { _ = resolver.Close() }()

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
	mock := &mockTPMTransport{maxRequestSz: 32}
	resolver := &tpm2Resolver{
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
	}
	defer func() { _ = resolver.Close() }()

	data, err := resolver.Rand(100)
	if err != nil {
		t.Fatalf("Rand(100) failed: %v", err)
	}
	if len(data) != 100 {
		t.Errorf("Expected 100 bytes, got %d", len(data))
	}

	mock.mu.Lock()
	callCount := mock.callCount
	mock.mu.Unlock()

	if callCount < 4 {
		t.Errorf("Expected at least 4 TPM calls for 100 bytes with MaxRequestSize=32, got %d", callCount)
	}
}

// TestTPM2Resolver_RandSmallRequestNoChunking tests small requests don't chunk
func TestTPM2Resolver_RandSmallRequestNoChunking(t *testing.T) {
	mock := &mockTPMTransport{maxRequestSz: 32}
	resolver := &tpm2Resolver{
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
	}
	defer func() { _ = resolver.Close() }()

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

// TestTPM2Resolver_RandZeroBytesWithMock tests zero-byte request with mock transport
func TestTPM2Resolver_RandZeroBytesWithMock(t *testing.T) {
	mock := &mockTPMTransport{}
	resolver := &tpm2Resolver{
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
	}
	defer func() { _ = resolver.Close() }()

	data, err := resolver.Rand(0)
	if err != nil {
		t.Fatalf("Rand(0) failed: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("Expected 0 bytes, got %d", len(data))
	}

	mock.mu.Lock()
	callCount := mock.callCount
	mock.mu.Unlock()

	if callCount != 0 {
		t.Errorf("Should not call TPM for 0 bytes, got %d calls", callCount)
	}
}

// TestTPM2Resolver_RandTPMError tests error handling from TPM
func TestTPM2Resolver_RandTPMError(t *testing.T) {
	mock := &mockTPMTransport{
		randErr: errors.New("TPM hardware error"),
	}
	resolver := &tpm2Resolver{
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
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
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
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

// TestTPM2Resolver_RandConcurrentWithTransport tests concurrent Rand calls with mock transport
func TestTPM2Resolver_RandConcurrentWithTransport(t *testing.T) {
	mock := &mockTPMTransport{}
	resolver := &tpm2Resolver{
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
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

// TestTPM2Resolver_ChunkBoundaries tests various chunk boundary scenarios
// with a table-driven approach to verify the chunking algorithm.
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
				rwc:    mock,
				config: &TPM2Config{MaxRequestSize: tt.maxRequestSize},
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
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
	}
	defer func() { _ = resolver.Close() }()

	data, err := resolver.Rand(16)
	if err != nil {
		t.Fatalf("Rand failed: %v", err)
	}

	for i := 0; i < 16; i++ {
		if data[i] != fixedData[i] {
			t.Errorf("Byte %d mismatch: expected %d, got %d", i, fixedData[i], data[i])
		}
	}
}

// TestTPM2Resolver_SourceRandWithMockTransport tests tpm2Source.Rand via mock transport
func TestTPM2Resolver_SourceRandWithMockTransport(t *testing.T) {
	mock := &mockTPMTransport{}
	resolver := &tpm2Resolver{
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
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

// TestTPM2Source_AllMethodsWithMockTransport tests all tpm2Source methods
// using a full mock transport
func TestTPM2Source_AllMethodsWithMockTransport(t *testing.T) {
	mock := &mockTPMTransport{}
	resolver := &tpm2Resolver{
		rwc:    mock,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	source := &tpm2Source{resolver: resolver}

	data, err := source.Rand(16)
	if err != nil {
		t.Errorf("Rand failed: %v", err)
	}
	if len(data) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(data))
	}

	if !source.Available() {
		t.Error("Should be available")
	}

	err = source.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	if source.Available() {
		t.Error("Should not be available after close")
	}
}

// TestTPM2GetRandomCommand verifies the structure of TPM2 GetRandom command
func TestTPM2GetRandomCommand(t *testing.T) {
	cmd := tpm2.GetRandom{
		BytesRequested: 32,
	}

	expectedCC := tpm2.TPMCCGetRandom
	if cmd.Command() != expectedCC {
		t.Errorf("Expected command code %v, got %v", expectedCC, cmd.Command())
	}
}
