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
	"errors"
	"sync"
	"testing"
)

// mockTPM2Closer simulates the TPM transport closer interface for testing
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

	// The returned source should be a tpm2Source
	tpmSource, ok := source.(*tpm2Source)
	if !ok {
		t.Error("Source should return *tpm2Source")
	}

	// tpm2Source methods should work through the resolver
	if tpmSource != nil {
		// Available should return false since rwc is nil
		if tpmSource.Available() {
			t.Error("tpm2Source.Available() should return false when rwc is nil")
		}

		// Rand should error
		_, err := tpmSource.Rand(32)
		if err == nil {
			t.Error("tpm2Source.Rand() should error when rwc is nil")
		}

		// Close should not error even when already closed
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

	// rwc should be nil after close
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

	// rwc should still be nil after close attempt
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

	// Second close should be a no-op
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

	// Close and check again
	_ = resolver.Close()

	if resolver.Available() {
		t.Error("Available should return false after Close()")
	}
}

// TestTPM2Resolver_ConcurrentAccess tests concurrent access to tpm2Resolver methods
func TestTPM2Resolver_ConcurrentAccess(t *testing.T) {
	resolver := &tpm2Resolver{
		rwc:    nil,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	var wg sync.WaitGroup
	numGoroutines := 20

	wg.Add(numGoroutines * 4)

	// Concurrent Available calls
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = resolver.Available()
		}()
	}

	// Concurrent Source calls
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = resolver.Source()
		}()
	}

	// Concurrent Rand calls (will error)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = resolver.Rand(32)
		}()
	}

	// Concurrent Read calls (will error)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			buf := make([]byte, 32)
			_, _ = resolver.Read(buf)
		}()
	}

	wg.Wait()
}

// TestTPM2Source_AllMethods tests all tpm2Source methods
func TestTPM2Source_AllMethods(t *testing.T) {
	resolver := &tpm2Resolver{
		rwc:    nil,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	source := &tpm2Source{resolver: resolver}

	// Test Rand
	_, err := source.Rand(16)
	if err == nil {
		t.Error("tpm2Source.Rand should error when rwc is nil")
	}

	// Test Available
	if source.Available() {
		t.Error("tpm2Source.Available should return false when rwc is nil")
	}

	// Test Close
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

	// Available should be true
	if !source.Available() {
		t.Error("tpm2Source.Available should return true when rwc is not nil")
	}

	// Close should close the resolver
	err := source.Close()
	if err != nil {
		t.Errorf("tpm2Source.Close should not error: %v", err)
	}

	// Available should now be false
	if source.Available() {
		t.Error("tpm2Source.Available should return false after Close()")
	}
}

// TestTPM2Resolver_ReadZeroBytes tests Read with zero-length buffer
func TestTPM2Resolver_ReadZeroBytes(t *testing.T) {
	resolver := &tpm2Resolver{
		rwc:    nil,
		config: &TPM2Config{MaxRequestSize: 32},
	}

	buf := make([]byte, 0)
	n, err := resolver.Read(buf)
	// Even with empty buffer, should error because rwc is nil
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

	// Call Source multiple times
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
