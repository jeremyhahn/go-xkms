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
	"sync"
	"time"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// fipsMinSecretBytes is the shortest HMAC key crypto/hmac accepts under
// GODEBUG=fips140=only: 112 bits.
const fipsMinSecretBytes = 14

// shortHMACKeysRefused reports whether crypto/hmac in THIS process refuses a
// key shorter than fipsMinSecretBytes.
//
// It answers by trying one, with a throwaway key, and seeing whether the
// standard library panics. That is worth the oddity: the limit is enforced
// under GODEBUG=fips140=only but not fips140=on, both of which report the same
// crypto/fips140.Enabled(), and the setting can arrive from the environment, a
// //go:debug directive, or the GOFIPS140 build setting. Any rule derived from
// those inputs is a second implementation of a policy the library already
// holds, and getting it wrong costs either a process kill or a working
// credential refused. Asking cannot be wrong.
//
// Evaluated once; the mode cannot change during the life of the process.
var shortHMACKeysRefused = sync.OnceValue(func() (refused bool) {
	defer func() {
		if recover() != nil {
			refused = true
		}
	}()

	hmac.New(sha256.New, make([]byte, fipsMinSecretBytes-1)).Sum(nil)
	return false
})

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
		return "", &MessageError{Msg: "oath: GenerateAt only valid for TOTP credentials"}
	}
	counter := uint64(t.Unix()) / uint64(g.cred.Period)
	return g.GenerateCounter(counter)
}

// GenerateCounter generates an OTP code for the specified counter value.
func (g *Generator) GenerateCounter(counter uint64) (string, error) {
	// Select the hash BEFORE decoding the secret, so a request that is going
	// to be refused never materializes the key in the clear. A rejected call
	// should leave no plaintext behind to wipe.
	//
	// SHA-1 is refused BEFORE hmac.New rather than after: under
	// GODEBUG=fips140=only crypto/hmac rejects SHA-1 by PANICKING, so reaching
	// it turns a policy decision into a process kill on a path a user drives.
	// An error is the only outcome a caller can report.
	var h func() hash.Hash
	switch g.cred.Algorithm {
	case AlgorithmSHA1:
		if fipsMode() {
			return "", ErrAlgorithmNotFIPSApproved
		}
		h = sha1.New
	case AlgorithmSHA256:
		h = sha256.New
	case AlgorithmSHA512:
		h = sha512.New
	default:
		return "", ErrInvalidAlgorithm
	}

	// Canonicalised through the SAME helper Validate uses, so the two agree on
	// what this credential's secret is. They did not: Validate accepted a
	// secret written with grouping separators -- normalizeSecret strips them --
	// and this decode, seeing only strings.ToUpper, then failed on it. A
	// credential could be enrolled successfully and be unable to generate a
	// single code, which is the defect the FIPS gates above exist to prevent,
	// arriving by a different route.
	//
	// canonicalizeSecret rather than normalizeSecret because normalizeSecret
	// decodes in order to validate: calling it here would decode the secret
	// twice and leave a second plaintext copy of the key on the heap that the
	// wipe below does not reach.
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(
		canonicalizeSecret(g.cred.Secret),
	)
	if err != nil {
		return "", ErrInvalidSecret
	}
	// The decoded secret is the OATH key in the clear, so its residency is
	// bounded by this call rather than left to the collector.
	//
	// This wipe is deliberately PARTIAL, and the part it does not reach is
	// named here rather than left for a reader to find:
	//
	//   - hmac.New copies the key into its own ipad/opad blocks inside the
	//     validated module, and crypto/hmac exposes no way to clear them.
	//     That copy is NOT wipeable through any supported API.
	//   - g.cred.Secret is the Base32 source, an immutable string, which
	//     cannot be wiped at all and outlives this call by design -- it is
	//     what the credential store persists.
	//
	// The first is a resolved conflict, not an oversight. conventions/
	// security-review.md: when a FIPS-validated primitive conflicts with the
	// protected-memory mandate, the validated primitive wins and the mandate
	// yields -- the worked case is crypto/pbkdf2 copying the password inside
	// the module, ruled "accept the bounded transient copy, document it, do
	// NOT hand-roll over crypto/hmac to keep it wipeable". crypto/hmac is the
	// same boundary, and hand-rolling HMAC to keep the key wipeable would
	// forfeit validation in the exact code path this file exists to make
	// FIPS-safe.
	//
	// The second is a real gap and a pre-existing one: it is a property of
	// Credential's storage format, not of this function, and fixing it means
	// changing the persisted type. Tracked separately -- see the issue linked
	// from this PR -- because it is an architecture change, not a FIPS gate.
	defer secure.Wipe(secret)

	// The second FIPS panic, and the algorithm gate above does not prevent it:
	// crypto/hmac refuses a key below 112 bits by PANICKING, for SHA-256 and
	// SHA-512 just as much as SHA-1.
	//
	// Note this is deliberately NOT gated on fipsMode(). Measured against Go
	// 1.26, the limit applies under GODEBUG=fips140=only and NOT under
	// fips140=on, where a 10-byte secret still HMACs happily. Refusing
	// whenever FIPS is active would withdraw working credentials from
	// fips140=on deployments -- the opposite failure, and one every enrolment
	// in the field would hit, since the 16-character Base32 secret of every
	// TOTP worked example decodes to 10 bytes.
	//
	// So the condition is what the library will actually DO in this process,
	// which shortHMACKeysRefused establishes by asking it rather than by
	// inferring it from a mode name.
	if len(secret) < fipsMinSecretBytes && shortHMACKeysRefused() {
		return "", ErrSecretTooShortForFIPS
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
	code %= uint32(math.Pow10(g.cred.Digits))

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
