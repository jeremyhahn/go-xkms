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

package ca

import (
	"errors"
	"math/big"
	"sync"
	"testing"
)

// =============================================================================
// NewSerialGenerator Tests
// =============================================================================

func TestNewSerialGenerator_CreatesValidGenerator(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	generator := NewSerialGenerator(storage)

	if generator == nil {
		t.Fatal("NewSerialGenerator() returned nil")
	}
}

// =============================================================================
// SerialGenerator.Generate Tests
// =============================================================================

func TestSerialGenerator_Generate_ReturnsUniqueSerials(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	generator := NewSerialGenerator(storage)

	serials := make(map[string]bool)
	const numSerials = 100

	for i := 0; i < numSerials; i++ {
		serial, err := generator.Generate()
		if err != nil {
			t.Fatalf("Generate() iteration %d: unexpected error: %v", i, err)
		}

		key := serial.Text(10)
		if serials[key] {
			t.Fatalf("Generate() returned duplicate serial: %s", key)
		}
		serials[key] = true
	}

	if len(serials) != numSerials {
		t.Errorf("expected %d unique serials, got %d", numSerials, len(serials))
	}
}

func TestSerialGenerator_Generate_ReturnsPositiveSerials(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	generator := NewSerialGenerator(storage)

	const numSerials = 50

	for i := 0; i < numSerials; i++ {
		serial, err := generator.Generate()
		if err != nil {
			t.Fatalf("Generate() iteration %d: unexpected error: %v", i, err)
		}

		if serial.Sign() <= 0 {
			t.Errorf("Generate() returned non-positive serial: %s", serial.Text(10))
		}
	}
}

func TestSerialGenerator_Generate_ReturnsCorrectBitLength(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	generator := NewSerialGenerator(storage)

	const numSerials = 50

	for i := 0; i < numSerials; i++ {
		serial, err := generator.Generate()
		if err != nil {
			t.Fatalf("Generate() iteration %d: unexpected error: %v", i, err)
		}

		bitLen := serial.BitLen()
		// Serial should be at most SerialNumberBits bits (with MSB cleared for positive encoding)
		// Minimum should be reasonably high (e.g., 100+ bits) for 128-bit random
		if bitLen > SerialNumberBits {
			t.Errorf("Generate() serial bit length %d exceeds max %d", bitLen, SerialNumberBits)
		}
		// Due to MSB being cleared, we expect at least 120 bits for a 128-bit random number
		// (very unlikely to have many leading zeros)
		if bitLen < 100 {
			t.Logf("Warning: Generate() serial bit length %d is unexpectedly low", bitLen)
		}
	}
}

func TestSerialGenerator_Generate_StoresSerial(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	generator := NewSerialGenerator(storage)

	serial, err := generator.Generate()
	if err != nil {
		t.Fatalf("Generate() unexpected error: %v", err)
	}

	// Verify serial is stored
	exists, err := storage.SerialExists(serial)
	if err != nil {
		t.Fatalf("SerialExists() unexpected error: %v", err)
	}
	if !exists {
		t.Error("Generate() did not store the serial in storage")
	}
}

// =============================================================================
// SerialGenerator.IsUsed Tests
// =============================================================================

func TestSerialGenerator_IsUsed_ReturnsTrueForUsedSerial(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	generator := NewSerialGenerator(storage)

	// Generate a serial (which marks it as used)
	serial, err := generator.Generate()
	if err != nil {
		t.Fatalf("Generate() unexpected error: %v", err)
	}

	// Check IsUsed
	used, err := generator.IsUsed(serial)
	if err != nil {
		t.Fatalf("IsUsed() unexpected error: %v", err)
	}
	if !used {
		t.Error("IsUsed() expected true for generated serial, got false")
	}
}

func TestSerialGenerator_IsUsed_ReturnsFalseForUnusedSerial(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	generator := NewSerialGenerator(storage)

	// Create a serial that was never generated
	unusedSerial := big.NewInt(999999)

	used, err := generator.IsUsed(unusedSerial)
	if err != nil {
		t.Fatalf("IsUsed() unexpected error: %v", err)
	}
	if used {
		t.Error("IsUsed() expected false for unused serial, got true")
	}
}

func TestSerialGenerator_IsUsed_Error_NilSerial(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	generator := NewSerialGenerator(storage)

	used, err := generator.IsUsed(nil)
	if err == nil {
		t.Fatal("IsUsed() expected error for nil serial, got nil")
	}
	if used {
		t.Error("IsUsed() should return false on error")
	}

	var validationErr *SerialValidationError
	if !errors.As(err, &validationErr) {
		t.Errorf("IsUsed() error type = %T, expected *SerialValidationError", err)
	}
}

// =============================================================================
// SerialGenerator.MarkUsed Tests
// =============================================================================

func TestSerialGenerator_MarkUsed_Success(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	generator := NewSerialGenerator(storage)

	serial := big.NewInt(123456789)

	err := generator.MarkUsed(serial)
	if err != nil {
		t.Fatalf("MarkUsed() unexpected error: %v", err)
	}

	// Verify it's now marked as used
	used, err := generator.IsUsed(serial)
	if err != nil {
		t.Fatalf("IsUsed() unexpected error: %v", err)
	}
	if !used {
		t.Error("MarkUsed() did not mark serial as used")
	}
}

func TestSerialGenerator_MarkUsed_Error_AlreadyUsed(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	generator := NewSerialGenerator(storage)

	serial := big.NewInt(123456789)

	// Mark once
	err := generator.MarkUsed(serial)
	if err != nil {
		t.Fatalf("MarkUsed() first call unexpected error: %v", err)
	}

	// Try to mark again
	err = generator.MarkUsed(serial)
	if err == nil {
		t.Fatal("MarkUsed() expected error for duplicate serial, got nil")
	}
	if !errors.Is(err, ErrSerialCollision) {
		t.Errorf("MarkUsed() error = %v, expected ErrSerialCollision", err)
	}
}

func TestSerialGenerator_MarkUsed_Error_NilSerial(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	generator := NewSerialGenerator(storage)

	err := generator.MarkUsed(nil)
	if err == nil {
		t.Fatal("MarkUsed() expected error for nil serial, got nil")
	}

	var validationErr *SerialValidationError
	if !errors.As(err, &validationErr) {
		t.Errorf("MarkUsed() error type = %T, expected *SerialValidationError", err)
	}
}

func TestSerialGenerator_MarkUsed_Error_NonPositiveSerial(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	generator := NewSerialGenerator(storage)

	tests := []struct {
		name   string
		serial *big.Int
	}{
		{name: "zero", serial: big.NewInt(0)},
		{name: "negative", serial: big.NewInt(-1)},
		{name: "large negative", serial: big.NewInt(-999999)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := generator.MarkUsed(tt.serial)
			if err == nil {
				t.Fatal("MarkUsed() expected error for non-positive serial, got nil")
			}

			var validationErr *SerialValidationError
			if !errors.As(err, &validationErr) {
				t.Errorf("MarkUsed() error type = %T, expected *SerialValidationError", err)
			}
		})
	}
}

// =============================================================================
// MemoryStorage Tests
// =============================================================================

func TestNewMemoryStorage_CreatesValidStorage(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	if storage == nil {
		t.Fatal("NewMemoryStorage() returned nil")
	}
}

func TestMemoryStorage_SerialExists_ReturnsFalseForUnknownSerial(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	serial := big.NewInt(12345)

	exists, err := storage.SerialExists(serial)
	if err != nil {
		t.Fatalf("SerialExists() unexpected error: %v", err)
	}
	if exists {
		t.Error("SerialExists() expected false for unknown serial, got true")
	}
}

func TestMemoryStorage_SerialExists_ReturnsTrueForStoredSerial(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	serial := big.NewInt(12345)

	err := storage.StoreSerial(serial)
	if err != nil {
		t.Fatalf("StoreSerial() unexpected error: %v", err)
	}

	exists, err := storage.SerialExists(serial)
	if err != nil {
		t.Fatalf("SerialExists() unexpected error: %v", err)
	}
	if !exists {
		t.Error("SerialExists() expected true for stored serial, got false")
	}
}

func TestMemoryStorage_SerialExists_Error_NilSerial(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()

	exists, err := storage.SerialExists(nil)
	if err == nil {
		t.Fatal("SerialExists() expected error for nil serial, got nil")
	}
	if exists {
		t.Error("SerialExists() should return false on error")
	}
}

func TestMemoryStorage_StoreSerial_Success(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()

	serials := []*big.Int{
		big.NewInt(1),
		big.NewInt(100),
		big.NewInt(999999),
	}

	for _, serial := range serials {
		err := storage.StoreSerial(serial)
		if err != nil {
			t.Fatalf("StoreSerial(%s) unexpected error: %v", serial.Text(10), err)
		}
	}

	// Verify all serials are stored
	for _, serial := range serials {
		exists, err := storage.SerialExists(serial)
		if err != nil {
			t.Fatalf("SerialExists(%s) unexpected error: %v", serial.Text(10), err)
		}
		if !exists {
			t.Errorf("Serial %s was not stored", serial.Text(10))
		}
	}
}

func TestMemoryStorage_StoreSerial_Error_NilSerial(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()

	err := storage.StoreSerial(nil)
	if err == nil {
		t.Fatal("StoreSerial() expected error for nil serial, got nil")
	}
}

// =============================================================================
// Concurrent Serial Generation Tests
// =============================================================================

func TestSerialGenerator_ConcurrentGeneration_ThreadSafe(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	generator := NewSerialGenerator(storage)

	const numGoroutines = 10
	const serialsPerGoroutine = 20

	var wg sync.WaitGroup
	serialsChan := make(chan *big.Int, numGoroutines*serialsPerGoroutine)
	errChan := make(chan error, numGoroutines*serialsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < serialsPerGoroutine; j++ {
				serial, err := generator.Generate()
				if err != nil {
					errChan <- err
					return
				}
				serialsChan <- serial
			}
		}()
	}

	wg.Wait()
	close(serialsChan)
	close(errChan)

	// Check for errors
	for err := range errChan {
		t.Fatalf("Generate() concurrent error: %v", err)
	}

	// Collect all serials and check for duplicates
	serials := make(map[string]bool)
	for serial := range serialsChan {
		key := serial.Text(10)
		if serials[key] {
			t.Fatalf("Generate() returned duplicate serial in concurrent execution: %s", key)
		}
		serials[key] = true
	}

	expected := numGoroutines * serialsPerGoroutine
	if len(serials) != expected {
		t.Errorf("expected %d unique serials, got %d", expected, len(serials))
	}
}

func TestMemoryStorage_ConcurrentAccess_ThreadSafe(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()

	const numGoroutines = 10
	const operationsPerGoroutine = 50

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines*operationsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				// Each goroutine uses its own range of serial numbers
				serial := big.NewInt(int64(goroutineID*1000 + j))

				err := storage.StoreSerial(serial)
				if err != nil {
					errChan <- err
					return
				}

				exists, err := storage.SerialExists(serial)
				if err != nil {
					errChan <- err
					return
				}
				if !exists {
					errChan <- errors.New("serial not found after store")
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		t.Fatalf("Concurrent storage operation error: %v", err)
	}
}

// =============================================================================
// Serial Error Types Tests
// =============================================================================

func TestSerialGenerationError_Error(t *testing.T) {
	t.Parallel()

	innerErr := errors.New("random source failure")
	err := &SerialGenerationError{Err: innerErr}

	expected := "ca: serial number generation failed: random source failure"
	if err.Error() != expected {
		t.Errorf("Error() = %q, expected %q", err.Error(), expected)
	}
}

func TestSerialGenerationError_Unwrap(t *testing.T) {
	t.Parallel()

	innerErr := errors.New("random source failure")
	err := &SerialGenerationError{Err: innerErr}

	if err.Unwrap() != innerErr {
		t.Errorf("Unwrap() = %v, expected %v", err.Unwrap(), innerErr)
	}
}

func TestSerialStorageError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		op       string
		innerErr error
		expected string
	}{
		{
			name:     "check operation",
			op:       "check",
			innerErr: errors.New("database error"),
			expected: "ca: serial storage check failed: database error",
		},
		{
			name:     "store operation",
			op:       "store",
			innerErr: errors.New("write failure"),
			expected: "ca: serial storage store failed: write failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := &SerialStorageError{Op: tt.op, Err: tt.innerErr}
			if err.Error() != tt.expected {
				t.Errorf("Error() = %q, expected %q", err.Error(), tt.expected)
			}
		})
	}
}

func TestSerialStorageError_Unwrap(t *testing.T) {
	t.Parallel()

	innerErr := errors.New("storage failure")
	err := &SerialStorageError{Op: "store", Err: innerErr}

	if err.Unwrap() != innerErr {
		t.Errorf("Unwrap() = %v, expected %v", err.Unwrap(), innerErr)
	}
}

func TestSerialValidationError_Error(t *testing.T) {
	t.Parallel()

	err := &SerialValidationError{Reason: "serial number is nil"}

	expected := "ca: serial validation failed: serial number is nil"
	if err.Error() != expected {
		t.Errorf("Error() = %q, expected %q", err.Error(), expected)
	}
}

// =============================================================================
// Storage Interface Mock for Error Testing
// =============================================================================

type failingStorage struct {
	failOnExists bool
	failOnStore  bool
	existsCount  int
}

func (f *failingStorage) SerialExists(serial *big.Int) (bool, error) {
	f.existsCount++
	if f.failOnExists {
		return false, errors.New("storage check failed")
	}
	return false, nil
}

func (f *failingStorage) StoreSerial(serial *big.Int) error {
	if f.failOnStore {
		return errors.New("storage write failed")
	}
	return nil
}

func TestSerialGenerator_Generate_Error_StorageExistsFails(t *testing.T) {
	t.Parallel()

	storage := &failingStorage{failOnExists: true}
	generator := NewSerialGenerator(storage)

	_, err := generator.Generate()
	if err == nil {
		t.Fatal("Generate() expected error when storage.SerialExists fails, got nil")
	}

	var storageErr *SerialStorageError
	if !errors.As(err, &storageErr) {
		t.Errorf("Generate() error type = %T, expected *SerialStorageError", err)
	}
}

func TestSerialGenerator_Generate_Error_StorageStoreFails(t *testing.T) {
	t.Parallel()

	storage := &failingStorage{failOnStore: true}
	generator := NewSerialGenerator(storage)

	_, err := generator.Generate()
	if err == nil {
		t.Fatal("Generate() expected error when storage.StoreSerial fails, got nil")
	}

	var storageErr *SerialStorageError
	if !errors.As(err, &storageErr) {
		t.Errorf("Generate() error type = %T, expected *SerialStorageError", err)
	}
}

// =============================================================================
// Collision Retry Testing
// =============================================================================

type collisionStorage struct {
	collisions int
	maxRetries int
	stored     map[string]bool
	mu         sync.Mutex
}

func newCollisionStorage(collisions int) *collisionStorage {
	return &collisionStorage{
		collisions: collisions,
		maxRetries: collisions,
		stored:     make(map[string]bool),
	}
}

func (c *collisionStorage) SerialExists(serial *big.Int) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := serial.Text(10)

	// Simulate collisions for the first N checks
	if c.collisions > 0 {
		c.collisions--
		return true, nil
	}

	return c.stored[key], nil
}

func (c *collisionStorage) StoreSerial(serial *big.Int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := serial.Text(10)
	c.stored[key] = true
	return nil
}

func TestSerialGenerator_Generate_RetriesOnCollision(t *testing.T) {
	t.Parallel()

	// Simulate 3 collisions then success
	storage := newCollisionStorage(3)
	generator := NewSerialGenerator(storage)

	serial, err := generator.Generate()
	if err != nil {
		t.Fatalf("Generate() unexpected error: %v", err)
	}

	if serial == nil {
		t.Error("Generate() returned nil serial")
	}
}

func TestSerialGenerator_Generate_Error_MaxRetriesExceeded(t *testing.T) {
	t.Parallel()

	// Simulate more collisions than max retries allows
	storage := newCollisionStorage(MaxSerialRetries + 5)
	generator := NewSerialGenerator(storage)

	_, err := generator.Generate()
	if err == nil {
		t.Fatal("Generate() expected error when max retries exceeded, got nil")
	}

	if !errors.Is(err, ErrSerialCollision) {
		t.Errorf("Generate() error = %v, expected ErrSerialCollision", err)
	}
}
