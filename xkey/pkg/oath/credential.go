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

// Package oath provides TOTP/HOTP one-time password support for go-xkms.
// It implements RFC 4226 (HOTP) and RFC 6238 (TOTP) for generating and
// validating one-time passwords.
package oath

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// OTP type constants.
const (
	TypeTOTP = "totp"
	TypeHOTP = "hotp"
)

// Algorithm constants.
const (
	AlgorithmSHA1   = "SHA1"
	AlgorithmSHA256 = "SHA256"
	AlgorithmSHA512 = "SHA512"
)

// Default values.
const (
	DefaultDigits    = 6
	DefaultPeriod    = 30
	DefaultAlgorithm = AlgorithmSHA1
)

// Credential errors.
var (
	ErrInvalidCredential = errors.New("oath: invalid credential")
	ErrInvalidSecret     = errors.New("oath: invalid secret")
	ErrInvalidType       = errors.New("oath: invalid OTP type (must be totp or hotp)")
	ErrInvalidAlgorithm  = errors.New("oath: invalid algorithm")

	// ErrAlgorithmNotFIPSApproved reports that the credential's OTP algorithm
	// is not permitted under FIPS 140.
	//
	// It exists so the refusal is an ERROR rather than a panic. Under
	// GODEBUG=fips140=only the standard library's crypto/hmac rejects SHA-1 by
	// panicking, so without this gate every default TOTP generation and
	// validation in a FIPS deployment is a process-killing panic on a path a
	// user drives -- not a validation failure it can report.
	//
	// SHA-1 remains the default OUTSIDE FIPS mode on purpose: RFC 6238 and
	// every mainstream authenticator (Google Authenticator, Authy, 1Password,
	// the otpauth:// URI default) assume it, and an enrolled credential only
	// keeps working with the algorithm it was enrolled under. Changing the
	// default is a product decision and is NOT what this error does; it
	// withdraws nothing from a non-FIPS deployment. Same shape this repo
	// already uses for X25519 and ChaCha20-Poly1305: supported, disabled in
	// FIPS mode.
	ErrAlgorithmNotFIPSApproved = errors.New("oath: algorithm is not FIPS 140 approved")

	// ErrSecretTooShortForFIPS reports that the credential's shared secret is
	// shorter than the minimum HMAC key length FIPS 140 permits.
	//
	// The same panic hazard as ErrAlgorithmNotFIPSApproved, reached by a
	// different route and NOT fixed by choosing an approved hash: under
	// GODEBUG=fips140=only crypto/hmac refuses keys below 112 bits by
	// PANICKING, whatever the digest. RFC 4226 recommends 160-bit secrets but
	// allows 128, and enrolment sources in the field routinely issue 80-bit
	// (16-character Base32) secrets -- the value in every worked example,
	// including the one this repo's own probe used. So a FIPS deployment can
	// import a perfectly ordinary SHA-256 credential and be killed by it.
	//
	// Narrower than it looks: measured against Go 1.26 the limit applies under
	// fips140=only and NOT under fips140=on, which report the same
	// crypto/fips140.Enabled(). This error is therefore raised from what the
	// standard library will actually do in the running process, not from FIPS
	// being active -- refusing these credentials wherever FIPS is on would
	// break working fips140=on deployments.
	ErrSecretTooShortForFIPS = errors.New("oath: secret is shorter than FIPS 140 permits for HMAC")
	ErrInvalidDigits         = errors.New("oath: invalid digits (must be 6, 7, or 8)")
	ErrInvalidPeriod         = errors.New("oath: invalid period (must be positive)")
	ErrInvalidURI            = errors.New("oath: invalid otpauth URI")
	ErrCredentialExists      = errors.New("oath: credential already exists")
	ErrCredentialNotFound    = errors.New("oath: credential not found")
)

// Credential represents an OATH TOTP/HOTP credential.
type Credential struct {
	// ID is a unique identifier for this credential.
	ID string `json:"id"`

	// Name is the display name (e.g., "GitHub", "AWS").
	Name string `json:"name"`

	// Issuer is the service provider name.
	Issuer string `json:"issuer"`

	// AccountName is the user's account identifier (e.g., email).
	AccountName string `json:"account_name"`

	// Secret is the base32-encoded shared secret.
	Secret string `json:"secret"`

	// Type is the OTP type: "totp" or "hotp".
	Type string `json:"type"`

	// Algorithm is the hash algorithm: SHA1, SHA256, or SHA512.
	Algorithm string `json:"algorithm"`

	// Digits is the number of digits in the OTP (6, 7, or 8).
	Digits int `json:"digits"`

	// Period is the time step in seconds (TOTP only, typically 30).
	Period int `json:"period"`

	// Counter is the current counter value (HOTP only).
	Counter uint64 `json:"counter"`

	// CreatedAt is when the credential was created.
	CreatedAt time.Time `json:"created_at"`

	// BackendID identifies which backend manages this credential.
	// Empty string means local/default (backward compatible).
	BackendID string `json:"backend_id,omitempty"`
}

// NewCredential creates a new OATH credential with the given parameters.
// It generates a random secret if none is provided.
func NewCredential(name, issuer, otpType string) (*Credential, error) {
	if name == "" {
		return nil, &DetailError{Err: ErrInvalidCredential, Detail: ": name is required"}
	}

	if otpType != TypeTOTP && otpType != TypeHOTP {
		return nil, ErrInvalidType
	}

	secret, err := GenerateSecret(20) // 160-bit secret
	if err != nil {
		return nil, err
	}

	cred := &Credential{
		ID:        generateCredentialID(issuer, name),
		Name:      name,
		Issuer:    issuer,
		Secret:    secret,
		Type:      otpType,
		Algorithm: defaultAlgorithmForMode(),
		Digits:    DefaultDigits,
		Period:    DefaultPeriod,
		CreatedAt: time.Now(),
	}

	return cred, nil
}

// defaultAlgorithmForMode returns the algorithm a NEWLY GENERATED credential
// should use.
//
// Substituting an approved hash is safe here and ONLY here: NewCredential
// generates the secret itself, so there is no counterparty that already
// decided which digest this credential uses. Doing the same in ParseURI or on
// an imported credential would be a correctness bug rather than a compliance
// improvement -- the issuer picked SHA-1, and a credential silently switched
// to SHA-256 computes codes the issuer will reject, which presents as "the
// codes are wrong" with nothing pointing at the cause. Imports are REFUSED
// under FIPS instead (Credential.Validate).
//
// DefaultAlgorithm itself is unchanged. Outside FIPS this still returns SHA-1,
// which RFC 6238 and every mainstream authenticator assume; changing that is a
// product decision (#22 option 2) and is not what this does.
func defaultAlgorithmForMode() string {
	if fipsMode() {
		return AlgorithmSHA256
	}
	return DefaultAlgorithm
}

// ParseURI parses an otpauth:// URI and returns a Credential.
// URI format: otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30
func ParseURI(uri string) (*Credential, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidURI, Cause: err}
	}

	if u.Scheme != "otpauth" {
		return nil, &DetailError{Err: ErrInvalidURI, Detail: ": scheme must be otpauth"}
	}

	otpType := u.Host
	if otpType != TypeTOTP && otpType != TypeHOTP {
		return nil, ErrInvalidType
	}

	// Parse label: /Issuer:account or /account
	label := strings.TrimPrefix(u.Path, "/")
	var issuer, accountName string
	if idx := strings.Index(label, ":"); idx != -1 {
		issuer = label[:idx]
		accountName = label[idx+1:]
	} else {
		accountName = label
	}

	query := u.Query()

	// Secret is required
	secret := query.Get("secret")
	if secret == "" {
		return nil, &DetailError{Err: ErrInvalidURI, Detail: ": secret is required"}
	}

	// Normalize and validate secret
	secret, err = normalizeSecret(secret)
	if err != nil {
		return nil, err
	}

	// Issuer from query overrides label
	if qIssuer := query.Get("issuer"); qIssuer != "" {
		issuer = qIssuer
	}

	// Algorithm (default SHA1)
	algorithm := DefaultAlgorithm
	if qAlg := query.Get("algorithm"); qAlg != "" {
		algorithm = strings.ToUpper(qAlg)
		if algorithm != AlgorithmSHA1 && algorithm != AlgorithmSHA256 && algorithm != AlgorithmSHA512 {
			return nil, ErrInvalidAlgorithm
		}
	}

	// Digits (default 6)
	digits := DefaultDigits
	if qDigits := query.Get("digits"); qDigits != "" {
		d, err := strconv.Atoi(qDigits)
		if err != nil || d < 6 || d > 8 {
			return nil, ErrInvalidDigits
		}
		digits = d
	}

	// Period (TOTP only, default 30)
	period := DefaultPeriod
	if otpType == TypeTOTP {
		if qPeriod := query.Get("period"); qPeriod != "" {
			p, err := strconv.Atoi(qPeriod)
			if err != nil || p <= 0 {
				return nil, ErrInvalidPeriod
			}
			period = p
		}
	}

	// Counter (HOTP only)
	var counter uint64
	if otpType == TypeHOTP {
		if qCounter := query.Get("counter"); qCounter != "" {
			c, err := strconv.ParseUint(qCounter, 10, 64)
			if err != nil {
				return nil, &DetailError{Err: ErrInvalidURI, Detail: ": invalid counter"}
			}
			counter = c
		}
	}

	// Generate name from issuer and account
	name := accountName
	if issuer != "" && !strings.HasPrefix(name, issuer) {
		name = issuer
		if accountName != "" {
			name = fmt.Sprintf("%s (%s)", issuer, accountName)
		}
	}

	cred := &Credential{
		ID:          generateCredentialID(issuer, accountName),
		Name:        name,
		Issuer:      issuer,
		AccountName: accountName,
		Secret:      strings.ToUpper(secret),
		Type:        otpType,
		Algorithm:   algorithm,
		Digits:      digits,
		Period:      period,
		Counter:     counter,
		CreatedAt:   time.Now(),
	}

	return cred, nil
}

// ToURI returns the otpauth:// URI for this credential.
func (c *Credential) ToURI() string {
	var label string
	if c.Issuer != "" {
		label = fmt.Sprintf("%s:%s", url.PathEscape(c.Issuer), url.PathEscape(c.AccountName))
	} else {
		label = url.PathEscape(c.AccountName)
	}

	u := url.URL{
		Scheme: "otpauth",
		Host:   c.Type,
		Path:   "/" + label,
	}

	q := u.Query()
	q.Set("secret", c.Secret)
	if c.Issuer != "" {
		q.Set("issuer", c.Issuer)
	}
	if c.Algorithm != DefaultAlgorithm {
		q.Set("algorithm", c.Algorithm)
	}
	if c.Digits != DefaultDigits {
		q.Set("digits", strconv.Itoa(c.Digits))
	}
	if c.Type == TypeTOTP && c.Period != DefaultPeriod {
		q.Set("period", strconv.Itoa(c.Period))
	}
	if c.Type == TypeHOTP {
		q.Set("counter", strconv.FormatUint(c.Counter, 10))
	}
	u.RawQuery = q.Encode()

	return u.String()
}

// Validate checks if the credential is valid.
func (c *Credential) Validate() error {
	if c.Name == "" {
		return &DetailError{Err: ErrInvalidCredential, Detail: ": name is required"}
	}
	if c.Secret == "" {
		return ErrInvalidSecret
	}
	if c.Type != TypeTOTP && c.Type != TypeHOTP {
		return ErrInvalidType
	}
	if c.Algorithm != AlgorithmSHA1 && c.Algorithm != AlgorithmSHA256 && c.Algorithm != AlgorithmSHA512 {
		return ErrInvalidAlgorithm
	}
	// Under FIPS the credential is refused HERE, at enrolment, rather than
	// silently accepted and then failing on every use. Validate gates the
	// write paths -- Add and Update in every store, and NewGenerator -- but
	// NOT Get, List or Delete, so a deployment that switches to FIPS with
	// SHA-1 credentials already stored can still see them and remove them.
	// That is the point of putting it here and not in the read paths.
	if c.Algorithm == AlgorithmSHA1 && fipsMode() {
		return ErrAlgorithmNotFIPSApproved
	}
	// Canonicalise BEFORE measuring. normalizeSecret strips separators,
	// whitespace and padding, so the raw string's length is not the secret's
	// length -- and the difference is attacker-controlled. A 12-byte secret is
	// 20 Base32 characters; written "MFRGG-ZDFMZ-TWQ2L-KNNWA" it is 23, and
	// DecodedLen(23) is 14, which clears a 14-byte minimum that the actual key
	// misses by two bytes. Measuring the raw string made this check fail OPEN
	// on exactly the input a human is most likely to type, since grouping
	// separators are why normalizeSecret exists.
	//
	// This is also the only decode: the base32 validity check below used to
	// call normalizeSecret a second time and discard the result, so measuring
	// the canonical value costs nothing that was not already being paid.
	normalized, err := normalizeSecret(c.Secret)
	if err != nil {
		return err
	}
	// The length half of the same contract. Refusing SHA-1 at enrolment while
	// letting a too-short secret through only moved the "created but can never
	// generate" defect from one dimension to the other: a 10-byte SHA-256
	// credential -- the length of every worked example -- passed here and then
	// failed on every GenerateCounter.
	//
	// Measured from the ENCODED length of the canonical form rather than by
	// decoding it. Base32 without padding is exactly five bits per character,
	// so the decoded size is arithmetic and the key itself is never
	// materialised here. Validate runs on every store write.
	if shortHMACKeysRefused() &&
		base32.StdEncoding.WithPadding(base32.NoPadding).DecodedLen(len(normalized)) < fipsMinSecretBytes {
		return ErrSecretTooShortForFIPS
	}
	if c.Digits < 6 || c.Digits > 8 {
		return ErrInvalidDigits
	}
	if c.Type == TypeTOTP && c.Period <= 0 {
		return ErrInvalidPeriod
	}

	return nil
}

// NewCredentialFromManualEntry creates a TOTP credential from manually entered
// parameters (account name, issuer, and base32-encoded secret key). This is the
// fallback when QR code scanning is unavailable. Standard TOTP defaults are
// applied (SHA1, 6 digits, 30-second period).
func NewCredentialFromManualEntry(accountName, issuer, secret string) (*Credential, error) {
	if accountName == "" && issuer == "" {
		return nil, &DetailError{Err: ErrInvalidCredential, Detail: ": account name or issuer required"}
	}
	if secret == "" {
		return nil, ErrInvalidSecret
	}

	normalizedSecret, err := normalizeSecret(secret)
	if err != nil {
		return nil, err
	}

	name := accountName
	if issuer != "" && !strings.HasPrefix(name, issuer) {
		name = issuer
		if accountName != "" {
			name = fmt.Sprintf("%s (%s)", issuer, accountName)
		}
	}

	cred := &Credential{
		ID:          generateCredentialID(issuer, accountName),
		Name:        name,
		Issuer:      issuer,
		AccountName: accountName,
		Secret:      normalizedSecret,
		Type:        TypeTOTP,
		Algorithm:   DefaultAlgorithm,
		Digits:      DefaultDigits,
		Period:      DefaultPeriod,
		CreatedAt:   time.Now(),
	}

	return cred, nil
}

// GenerateSecret generates a cryptographically random secret of the specified length in bytes.
// Returns the secret as a base32-encoded string without padding.
func GenerateSecret(length int) (string, error) {
	secret := make([]byte, length)
	if _, err := rand.Read(secret); err != nil {
		return "", &WrappedError{Msg: "oath: failed to generate secret", Err: err}
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// normalizeSecret cleans up a base32-encoded secret by:
// - Converting to uppercase
// - Removing spaces, dashes, and other separators
// - Applying typo corrections for commonly confused characters
// - Removing padding characters
// - Validating the result is valid base32
func normalizeSecret(secret string) (string, error) {
	secret = canonicalizeSecret(secret)

	if secret == "" {
		return "", &DetailError{Err: ErrInvalidSecret, Detail: ": empty secret"}
	}

	// Validate it's valid base32
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		return "", &DetailError{Err: ErrInvalidSecret, Detail: ": invalid base32 secret"}
	}

	return secret, nil
}

// canonicalizeSecret applies the textual half of normalizeSecret -- the case
// fold, separator removal, typo corrections and padding trim -- and nothing
// else.
//
// It is separate because the two callers need different halves. Validate wants
// the base32 check as well, and pays one decode for it. GenerateCounter is
// about to decode the secret anyway, and calling normalizeSecret there would
// decode it TWICE, leaving an extra plaintext copy of the key on the heap that
// nothing wipes -- the exact residue the wipe in GenerateCounter exists to
// bound. Sharing the mapping rather than duplicating it is what keeps the two
// paths agreeing on what a secret means.
//
// KNOWN LIMIT, tracked as go-xkms#210: every assignment below mints a new
// immutable Go string, so the intermediates hold key material that cannot be
// wiped. This function does not introduce that -- it is an extract-function
// refactor of a sequence normalizeSecret already performed, and Credential.Secret
// is itself a plain string the credential store persists. Fixing it properly
// means changing Credential.Secret to a protected-memory type, which is an
// architecture decision and is out of scope for a FIPS algorithm gate; #210
// carries it and flags the type change as the owner's call. Recorded here rather
// than left for the next reader to rediscover, per sdlc.md §4 -- document the
// limit at the call site and file the wider change.
func canonicalizeSecret(secret string) string {
	// Convert to uppercase
	secret = strings.ToUpper(secret)

	// Remove common separators and whitespace, and apply typo corrections
	// Standard base32 uses A-Z and 2-7 only. Common confusions:
	// - 0 (zero) often confused with O
	// - 1 (one) often confused with I or L
	// - 8 often confused with B
	secret = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '_', '\t', '\n', '\r':
			return -1 // Remove separators
		case '0':
			return 'O' // Zero -> O
		case '1':
			return 'I' // One -> I
		case '8':
			return 'B' // Eight -> B
		case '9':
			return -1 // Nine has no good substitute, remove it
		default:
			return r
		}
	}, secret)

	// Remove padding characters - we'll decode without padding
	return strings.TrimRight(secret, "=")
}

// generateCredentialID creates a unique ID from issuer and account name.
func generateCredentialID(issuer, accountName string) string {
	if issuer != "" && accountName != "" {
		return fmt.Sprintf("%s:%s", strings.ToLower(issuer), strings.ToLower(accountName))
	}
	if issuer != "" {
		return strings.ToLower(issuer)
	}
	if accountName != "" {
		return strings.ToLower(accountName)
	}
	// Fallback to random ID
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("oath-%x", b)
}
