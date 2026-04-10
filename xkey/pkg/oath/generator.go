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

package oath

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"strings"
	"time"
)

// Generator errors.
var (
	ErrInvalidCode = errors.New("oath: invalid code")
	ErrCodeExpired = errors.New("oath: code expired")
)

// Generator generates and validates OTP codes for a credential.
type Generator struct {
	cred *Credential
}

// NewGenerator creates a new OTP generator for the given credential.
func NewGenerator(cred *Credential) (*Generator, error) {
	if err := cred.Validate(); err != nil {
		return nil, err
	}
	return &Generator{cred: cred}, nil
}

// Generate generates an OTP code for the current time (TOTP) or current counter (HOTP).
func (g *Generator) Generate() (string, error) {
	if g.cred.Type == TypeTOTP {
		return g.GenerateAt(time.Now())
	}
	return g.GenerateCounter(g.cred.Counter)
}

// GenerateAt generates a TOTP code for the specified time.
func (g *Generator) GenerateAt(t time.Time) (string, error) {
	if g.cred.Type != TypeTOTP {
		return "", fmt.Errorf("oath: GenerateAt only valid for TOTP credentials")
	}
	counter := uint64(t.Unix()) / uint64(g.cred.Period)
	return g.GenerateCounter(counter)
}

// GenerateCounter generates an OTP code for the specified counter value.
func (g *Generator) GenerateCounter(counter uint64) (string, error) {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(
		strings.ToUpper(g.cred.Secret),
	)
	if err != nil {
		return "", ErrInvalidSecret
	}

	// Get the appropriate hash function
	var h func() hash.Hash
	switch g.cred.Algorithm {
	case AlgorithmSHA1:
		h = sha1.New
	case AlgorithmSHA256:
		h = sha256.New
	case AlgorithmSHA512:
		h = sha512.New
	default:
		return "", ErrInvalidAlgorithm
	}

	// HOTP algorithm (RFC 4226)
	// Step 1: Generate HMAC-SHA hash
	mac := hmac.New(h, secret)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// Step 2: Dynamic truncation
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	// Step 3: Compute HOTP value
	code = code % uint32(math.Pow10(g.cred.Digits))

	// Format with leading zeros
	return fmt.Sprintf("%0*d", g.cred.Digits, code), nil
}

// Validate validates an OTP code.
// For TOTP, it checks the code against the current time with a skew window.
// For HOTP, it checks against the current counter.
// Returns nil if valid, or an error if invalid.
func (g *Generator) Validate(code string) error {
	return g.ValidateWithSkew(code, 1)
}

// ValidateWithSkew validates an OTP code with a custom skew window.
// For TOTP, skew is the number of time periods to check before/after current time.
// For HOTP, skew is the number of counter values to check ahead.
func (g *Generator) ValidateWithSkew(code string, skew int) error {
	if len(code) != g.cred.Digits {
		return ErrInvalidCode
	}

	if g.cred.Type == TypeTOTP {
		return g.validateTOTP(code, time.Now(), skew)
	}
	return g.validateHOTP(code, skew)
}

// validateTOTP validates a TOTP code against the given time with skew.
func (g *Generator) validateTOTP(code string, t time.Time, skew int) error {
	counter := uint64(t.Unix()) / uint64(g.cred.Period)

	// Check current and skew windows
	for i := -skew; i <= skew; i++ {
		expected, err := g.GenerateCounter(counter + uint64(i))
		if err != nil {
			return err
		}
		if hmac.Equal([]byte(code), []byte(expected)) {
			return nil
		}
	}

	return ErrInvalidCode
}

// validateHOTP validates an HOTP code against the current counter with look-ahead.
func (g *Generator) validateHOTP(code string, lookAhead int) error {
	for i := 0; i <= lookAhead; i++ {
		expected, err := g.GenerateCounter(g.cred.Counter + uint64(i))
		if err != nil {
			return err
		}
		if hmac.Equal([]byte(code), []byte(expected)) {
			// Update counter to next value after the matched one
			g.cred.Counter = g.cred.Counter + uint64(i) + 1
			return nil
		}
	}

	return ErrInvalidCode
}

// TimeRemaining returns the number of seconds remaining until the current TOTP code expires.
// Returns 0 for HOTP credentials.
func (g *Generator) TimeRemaining() int {
	if g.cred.Type != TypeTOTP {
		return 0
	}
	elapsed := time.Now().Unix() % int64(g.cred.Period)
	return g.cred.Period - int(elapsed)
}

// Counter returns the current counter value.
// For TOTP, this is the current time-based counter.
// For HOTP, this is the stored counter value.
func (g *Generator) Counter() uint64 {
	if g.cred.Type == TypeTOTP {
		return uint64(time.Now().Unix()) / uint64(g.cred.Period)
	}
	return g.cred.Counter
}

// IncrementCounter increments the HOTP counter.
// This should be called after successfully using an HOTP code.
// Has no effect on TOTP credentials.
func (g *Generator) IncrementCounter() {
	if g.cred.Type == TypeHOTP {
		g.cred.Counter++
	}
}
