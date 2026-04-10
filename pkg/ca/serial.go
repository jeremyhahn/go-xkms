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

// Package ca provides serial number generation for X.509 certificates.
//
// # RFC 5280 Serial Number Requirements
//
// According to RFC 5280 Section 4.1.2.2, certificate serial numbers:
//   - MUST be a positive integer
//   - MUST be unique for each certificate issued by a given CA
//   - MUST NOT be longer than 20 octets
//   - SHOULD contain at least 64 bits of output from a CSPRNG
//
// # CAB Forum Baseline Requirements
//
// The CA/Browser Forum Baseline Requirements (Section 7.1) specify:
//   - Serial numbers MUST contain at least 64 bits of output from a CSPRNG
//   - The recommended practice is to use 128 bits for security margin
//   - The high-order bit MUST be 0 to ensure positive integer encoding
//
// # Security Considerations
//
// This implementation uses:
//   - 128 bits of entropy from crypto/rand for security
//   - Collision detection with configurable retries
//   - Persistent storage to prevent serial reuse across restarts
//   - Thread-safe operations for concurrent certificate issuance
//
// The 128-bit serial number provides approximately 2^64 birthday bound,
// which far exceeds the expected certificate issuance rate of any CA.
package ca

import (
	"crypto/rand"
	"math/big"
	"sync"
)

const (
	// SerialNumberBits is the bit length for serial numbers.
	// 128 bits is recommended by the CAB Forum Baseline Requirements
	// to provide sufficient entropy and collision resistance.
	// This value ensures compliance with RFC 5280's 20-octet maximum
	// while providing a significant security margin.
	SerialNumberBits = 128

	// MaxSerialRetries is the maximum number of attempts to generate
	// a unique serial number before returning an error.
	// With 128 bits of entropy, collisions are astronomically unlikely,
	// but this safeguard prevents infinite loops in pathological cases.
	MaxSerialRetries = 10
)

// Storage defines the interface for persisting serial numbers.
//
// Implementations must be thread-safe and provide durable storage
// to prevent serial number reuse across CA restarts. Serial numbers
// are stored as their string representation (base-10) for portability.
//
// Thread-safe: All implementations must be thread-safe.
type Storage interface {
	// SerialExists checks if a serial number has been used.
	//
	// Returns true if the serial number exists in storage, false otherwise.
	// Returns an error if the storage operation fails.
	//
	// The serial number is stored as its base-10 string representation.
	//
	// Thread-safe: Yes
	SerialExists(serial *big.Int) (bool, error)

	// StoreSerial persistently records a serial number as used.
	//
	// This operation must be atomic - either the serial is fully stored
	// or the operation fails without partial state. The implementation
	// should ensure durability before returning.
	//
	// Thread-safe: Yes
	StoreSerial(serial *big.Int) error
}

// SerialGenerator defines the interface for certificate serial number generation.
//
// Serial numbers are critical for certificate uniqueness and revocation.
// This interface provides cryptographically secure serial generation with
// collision detection and persistent tracking.
//
// Thread-safe: All implementations must be thread-safe.
type SerialGenerator interface {
	// Generate creates a new unique serial number.
	//
	// The generated serial number:
	//   - Is cryptographically random using crypto/rand
	//   - Contains 128 bits of entropy
	//   - Is guaranteed to be positive (MSB = 0)
	//   - Is unique within this CA's namespace
	//   - Is automatically marked as used in storage
	//
	// Returns ErrSerialGenerationFailed if crypto/rand fails.
	// Returns ErrSerialCollision if a unique serial cannot be generated
	// after MaxSerialRetries attempts (astronomically unlikely).
	//
	// Thread-safe: Yes
	Generate() (*big.Int, error)

	// IsUsed checks if a serial number has already been used.
	//
	// This is useful for validating externally-provided serial numbers
	// or for auditing purposes.
	//
	// Returns true if the serial has been used, false otherwise.
	// Returns an error if the storage lookup fails.
	//
	// Thread-safe: Yes
	IsUsed(serial *big.Int) (bool, error)

	// MarkUsed records a serial number as used without generating it.
	//
	// This is useful when importing existing certificates or when
	// the serial number is generated externally.
	//
	// Returns ErrSerialCollision if the serial is already used.
	// Returns storage errors if the operation fails.
	//
	// Thread-safe: Yes
	MarkUsed(serial *big.Int) error
}

// defaultSerialGenerator implements SerialGenerator with cryptographically
// secure random number generation and persistent storage.
type defaultSerialGenerator struct {
	storage Storage
	mu      sync.Mutex
}

// NewSerialGenerator creates a new SerialGenerator with the provided storage.
//
// The storage parameter must not be nil and is used to persist serial numbers
// for collision detection and to prevent reuse across CA restarts.
//
// Example usage:
//
//	storage := ca.NewMemoryStorage() // or persistent storage implementation
//	generator := ca.NewSerialGenerator(storage)
//	serial, err := generator.Generate()
func NewSerialGenerator(storage Storage) SerialGenerator {
	return &defaultSerialGenerator{
		storage: storage,
	}
}

// Generate creates a new unique serial number using crypto/rand.
//
// The implementation:
//  1. Generates 128 random bits from crypto/rand
//  2. Ensures the result is positive by clearing the MSB
//  3. Ensures the result is non-zero
//  4. Checks for collision against stored serials
//  5. Retries up to MaxSerialRetries times if collision detected
//  6. Stores the serial number before returning
//
// Thread-safe: Uses mutex to serialize generation and storage operations.
func (g *defaultSerialGenerator) Generate() (*big.Int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	for attempt := 0; attempt < MaxSerialRetries; attempt++ {
		serial, err := generateRandomSerial()
		if err != nil {
			return nil, err
		}

		exists, err := g.storage.SerialExists(serial)
		if err != nil {
			return nil, &SerialStorageError{Op: "check", Err: err}
		}

		if exists {
			continue
		}

		if err := g.storage.StoreSerial(serial); err != nil {
			return nil, &SerialStorageError{Op: "store", Err: err}
		}

		return serial, nil
	}

	return nil, ErrSerialCollision
}

// IsUsed checks if a serial number has already been used.
func (g *defaultSerialGenerator) IsUsed(serial *big.Int) (bool, error) {
	if serial == nil {
		return false, &SerialValidationError{Reason: "serial number is nil"}
	}

	exists, err := g.storage.SerialExists(serial)
	if err != nil {
		return false, &SerialStorageError{Op: "check", Err: err}
	}

	return exists, nil
}

// MarkUsed records a serial number as used without generating it.
func (g *defaultSerialGenerator) MarkUsed(serial *big.Int) error {
	if serial == nil {
		return &SerialValidationError{Reason: "serial number is nil"}
	}

	if serial.Sign() <= 0 {
		return &SerialValidationError{Reason: "serial number must be positive"}
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	exists, err := g.storage.SerialExists(serial)
	if err != nil {
		return &SerialStorageError{Op: "check", Err: err}
	}

	if exists {
		return ErrSerialCollision
	}

	if err := g.storage.StoreSerial(serial); err != nil {
		return &SerialStorageError{Op: "store", Err: err}
	}

	return nil
}

// generateRandomSerial generates a cryptographically random serial number.
//
// The function:
//   - Generates SerialNumberBits (128) random bits using crypto/rand
//   - Clears the most significant bit to ensure positive encoding per RFC 5280
//   - Validates the result is non-zero (regenerates if zero)
//
// This is an unexported function as serial generation should always go through
// the SerialGenerator interface to ensure proper collision detection.
func generateRandomSerial() (*big.Int, error) {
	// Calculate bytes needed for SerialNumberBits
	numBytes := SerialNumberBits / 8

	// Allocate buffer for random bytes
	serialBytes := make([]byte, numBytes)

	// Generate cryptographically random bytes
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, &SerialGenerationError{Err: err}
	}

	// Clear the MSB to ensure positive integer per RFC 5280 Section 4.1.2.2
	// Serial numbers must be positive integers, and ASN.1 INTEGER encoding
	// uses the MSB as the sign bit. Setting it to 0 ensures positive encoding.
	serialBytes[0] &= 0x7F

	// Convert to big.Int
	serial := new(big.Int).SetBytes(serialBytes)

	// Ensure non-zero (astronomically unlikely but required for correctness)
	// Zero is not a valid serial number per RFC 5280
	if serial.Sign() == 0 {
		// Set to 1 as a fallback (statistically impossible to reach with 128 bits)
		serial.SetInt64(1)
	}

	return serial, nil
}

// memoryStorage provides an in-memory Storage implementation.
//
// This implementation is suitable for testing and development but should
// NOT be used in production as serial numbers are lost on restart.
// For production use, implement Storage with a durable backend such as
// a database or the go-objstore abstraction.
//
// Thread-safe: Uses RWMutex for concurrent read access optimization.
type memoryStorage struct {
	serials map[string]bool
	mu      sync.RWMutex
}

// NewMemoryStorage creates a new in-memory Storage implementation.
//
// WARNING: This implementation does not persist data and should only be
// used for testing. Serial numbers will be lost on restart, potentially
// causing serial number collisions if the CA is restarted.
//
// For production use, implement the Storage interface with a durable
// backend such as:
//   - Database (PostgreSQL, SQLite)
//   - Key-value store (etcd, Consul)
//   - Object storage (via go-objstore)
func NewMemoryStorage() Storage {
	return &memoryStorage{
		serials: make(map[string]bool),
	}
}

// SerialExists checks if a serial number exists in memory.
func (m *memoryStorage) SerialExists(serial *big.Int) (bool, error) {
	if serial == nil {
		return false, &SerialValidationError{Reason: "serial number is nil"}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	key := serial.Text(10)
	return m.serials[key], nil
}

// StoreSerial stores a serial number in memory.
func (m *memoryStorage) StoreSerial(serial *big.Int) error {
	if serial == nil {
		return &SerialValidationError{Reason: "serial number is nil"}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := serial.Text(10)
	m.serials[key] = true
	return nil
}

// SerialGenerationError indicates that cryptographic random number
// generation failed during serial number creation.
type SerialGenerationError struct {
	Err error
}

func (e *SerialGenerationError) Error() string {
	return "ca: serial number generation failed: " + e.Err.Error()
}

func (e *SerialGenerationError) Unwrap() error {
	return e.Err
}

// SerialStorageError indicates a failure in serial number storage operations.
type SerialStorageError struct {
	Op  string // operation that failed: "check" or "store"
	Err error
}

func (e *SerialStorageError) Error() string {
	return "ca: serial storage " + e.Op + " failed: " + e.Err.Error()
}

func (e *SerialStorageError) Unwrap() error {
	return e.Err
}

// SerialValidationError indicates invalid input to serial number operations.
type SerialValidationError struct {
	Reason string
}

func (e *SerialValidationError) Error() string {
	return "ca: serial validation failed: " + e.Reason
}
