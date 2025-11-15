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

//go:build tpm2

package tpm2

import (
	"errors"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Session errors
var (
	ErrSessionCreationFailed = errors.New("tpm2: failed to create encrypted session")
	ErrSessionNotEncrypted   = errors.New("tpm2: session does not support encryption")
	ErrSessionClosed         = errors.New("tpm2: session already closed")
	ErrSessionPoolExhausted  = errors.New("tpm2: session pool exhausted")
	ErrInvalidSessionConfig  = errors.New("tpm2: invalid session configuration")
)

// SessionType defines the type of TPM session to create
type SessionType int

const (
	// SessionTypeHMAC uses HMAC-based sessions for command/response authentication
	SessionTypeHMAC SessionType = iota
	// SessionTypePolicy uses policy sessions for advanced authorization
	SessionTypePolicy
	// SessionTypeTrial uses trial sessions for policy calculation without execution
	SessionTypeTrial
)

// EncryptionMode defines the parameter encryption mode for sessions
type EncryptionMode int

const (
	// EncryptionModeNone disables parameter encryption (INSECURE - for debugging only)
	EncryptionModeNone EncryptionMode = iota
	// EncryptionModeIn encrypts only command parameters (TPM-bound data)
	EncryptionModeIn
	// EncryptionModeOut encrypts only response parameters (data from TPM)
	EncryptionModeOut
	// EncryptionModeInOut encrypts both command and response parameters (RECOMMENDED)
	EncryptionModeInOut
)

// SessionConfig defines configuration options for TPM sessions.
//
// Security Considerations:
//   - Parameter encryption protects sensitive data (keys, seeds, passwords) in transit
//   - Salted sessions provide stronger key derivation through ECDH with bind key
//   - Bound sessions tie session authorization to specific objects
//   - AES-128-CFB mode provides confidentiality (as per TPM 2.0 spec)
//   - HMAC sessions provide integrity and authentication
//
// Performance Impact:
//   - Encryption overhead: ~1-5% for typical operations
//   - Salted sessions: ~10-20ms additional latency on session creation
//   - Bidirectional encryption: minimal additional overhead vs unidirectional
//   - Session pooling amortizes creation costs across operations
//
// Compliance:
//   - Required for FIPS 140-2 Level 2+ deployments
//   - Required for Common Criteria EAL4+ evaluations
//   - Recommended for all production deployments
//
// Why Bidirectional Encryption Matters:
//   - EncryptIn: Protects keys/passwords sent TO the TPM
//   - EncryptOut: Protects decrypted data/keys coming FROM the TPM
//   - EncryptInOut: Protects both directions (defense in depth)
//   - Bus snooping can capture data in either direction
//   - Many attacks focus on capturing TPM responses (decrypted data, generated keys)
type SessionConfig struct {
	// Encrypted enables parameter encryption (default: true)
	// NEVER disable in production - only for debugging
	Encrypted bool

	// EncryptionMode specifies which parameters to encrypt (default: EncryptionModeInOut)
	// EncryptionModeInOut provides maximum protection for sensitive data
	EncryptionMode EncryptionMode

	// Salted enables salted sessions for stronger key derivation (default: false)
	// Uses ECDH with bind key for enhanced security
	Salted bool

	// Bound enables binding session to specific object (default: false)
	// Ties session authorization to a specific TPM object handle
	Bound bool

	// SessionType specifies the type of session (default: SessionTypeHMAC)
	SessionType SessionType

	// AESKeySize specifies AES key size in bits (default: 128)
	// Valid values: 128, 256. TPM 2.0 spec requires CFB mode.
	AESKeySize int

	// PoolSize specifies the number of pre-allocated sessions to maintain (default: 0, disabled)
	// Setting >0 enables session pooling for improved performance
	PoolSize int
}

// DefaultSessionConfig returns a SessionConfig with secure defaults.
//
// Default configuration provides:
//   - Bidirectional parameter encryption (EncryptInOut)
//   - AES-128-CFB encryption (TPM 2.0 standard)
//   - Salted sessions disabled by default (can be expensive)
//   - HMAC session type for general operations
//   - No session pooling (can be enabled with PoolSize > 0)
//
// This configuration is suitable for production deployments and provides
// strong protection for sensitive data with minimal performance overhead.
//
// For maximum security (at cost of ~10-20ms per session):
//
//	cfg := DefaultSessionConfig()
//	cfg.Salted = true
//
// For high-performance scenarios:
//
//	cfg := DefaultSessionConfig()
//	cfg.PoolSize = 4  // Pre-allocate 4 sessions
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		Encrypted:      true,
		EncryptionMode: EncryptionModeInOut,
		Salted:         false, // Can be expensive, enable explicitly if needed
		Bound:          false,
		SessionType:    SessionTypeHMAC,
		AESKeySize:     128,
		PoolSize:       0, // Disabled by default
	}
}

// Validate checks the SessionConfig for correctness
func (sc *SessionConfig) Validate() error {
	if sc.AESKeySize != 0 && sc.AESKeySize != 128 && sc.AESKeySize != 256 {
		return ErrInvalidSessionConfig
	}
	if sc.PoolSize < 0 {
		return ErrInvalidSessionConfig
	}
	return nil
}

// sessionPool manages a pool of reusable TPM sessions for improved performance.
//
// Session pooling amortizes the cost of session creation across multiple operations.
// This is particularly beneficial for:
//   - High-throughput workloads with frequent TPM operations
//   - Salted sessions which have higher creation overhead
//   - Scenarios where session setup time is significant vs operation time
//
// Thread Safety:
// All methods are thread-safe and can be called concurrently.
//
// Resource Management:
// Sessions in the pool consume TPM resources. The pool size should be tuned based on:
//   - Available TPM session slots (typically 3-64 depending on TPM)
//   - Concurrent operation requirements
//   - Memory constraints
type sessionPool struct {
	tpm      transport.TPM
	config   *SessionConfig
	sessions chan sessionHandle
	mu       sync.Mutex
	closed   bool
}

// sessionHandle wraps a TPM session with its cleanup function
type sessionHandle struct {
	session tpm2.Session
	cleanup func() error
}

// newSessionPool creates a new session pool with pre-allocated sessions
func newSessionPool(tpm transport.TPM, config *SessionConfig) (*sessionPool, error) {
	if config.PoolSize <= 0 {
		return nil, nil // Pooling disabled
	}

	pool := &sessionPool{
		tpm:      tpm,
		config:   config,
		sessions: make(chan sessionHandle, config.PoolSize),
	}

	// Pre-allocate sessions
	for i := 0; i < config.PoolSize; i++ {
		handle, err := pool.createSession()
		if err != nil {
			// Clean up any created sessions
			pool.Close()
			return nil, err
		}
		pool.sessions <- handle
	}

	return pool, nil
}

// createSession creates a new TPM session based on pool configuration
func (p *sessionPool) createSession() (sessionHandle, error) {
	var handle sessionHandle
	var err error

	// Get AES key size
	aesKeySize := p.config.AESKeySize
	if aesKeySize == 0 {
		aesKeySize = 128
	}

	// Get encryption mode
	encMode := tpm2.EncryptInOut
	if !p.config.Encrypted {
		encMode = tpm2.EncryptIn // Fallback to EncryptIn if not fully disabled
	} else {
		switch p.config.EncryptionMode {
		case EncryptionModeIn:
			encMode = tpm2.EncryptIn
		case EncryptionModeOut:
			encMode = tpm2.EncryptOut
		case EncryptionModeInOut:
			encMode = tpm2.EncryptInOut
		case EncryptionModeNone:
			// No encryption - create simple session
			handle.session, handle.cleanup, err = tpm2.HMACSession(
				p.tpm,
				tpm2.TPMAlgSHA256,
				16,
				tpm2.Auth(nil))
			return handle, err
		}
	}

	// Create encrypted HMAC session
	// Convert int to TPMKeyBits
	keyBits := tpm2.TPMKeyBits(aesKeySize)
	handle.session, handle.cleanup, err = tpm2.HMACSession(
		p.tpm,
		tpm2.TPMAlgSHA256,
		16,
		tpm2.Auth(nil),
		tpm2.AESEncryption(keyBits, encMode))

	if err != nil {
		return handle, ErrSessionCreationFailed
	}

	return handle, nil
}

// Get retrieves a session from the pool or creates a new one if pool is empty
func (p *sessionPool) Get() (session tpm2.Session, close func() error, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return session, nil, ErrSessionClosed
	}

	select {
	case handle := <-p.sessions:
		// Return session with a wrapper cleanup that returns it to pool
		cleanup := func() error {
			p.mu.Lock()
			defer p.mu.Unlock()
			if !p.closed {
				select {
				case p.sessions <- handle:
					return nil
				default:
					// Pool full, clean up session
					if handle.cleanup != nil {
						return handle.cleanup()
					}
					return nil
				}
			}
			// Pool closed, clean up session
			if handle.cleanup != nil {
				return handle.cleanup()
			}
			return nil
		}
		return handle.session, cleanup, nil
	default:
		// Pool empty, create new session on-demand
		handle, err := p.createSession()
		if err != nil {
			return session, nil, err
		}
		return handle.session, handle.cleanup, nil
	}
}

// Close closes all sessions in the pool
func (p *sessionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true

	// Close all sessions in pool
	close(p.sessions)
	var firstErr error
	for handle := range p.sessions {
		if handle.cleanup != nil {
			if err := handle.cleanup(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}

	return firstErr
}
