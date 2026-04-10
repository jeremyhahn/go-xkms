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
	ErrInvalidCredential  = errors.New("oath: invalid credential")
	ErrInvalidSecret      = errors.New("oath: invalid secret")
	ErrInvalidType        = errors.New("oath: invalid OTP type (must be totp or hotp)")
	ErrInvalidAlgorithm   = errors.New("oath: invalid algorithm")
	ErrInvalidDigits      = errors.New("oath: invalid digits (must be 6, 7, or 8)")
	ErrInvalidPeriod      = errors.New("oath: invalid period (must be positive)")
	ErrInvalidURI         = errors.New("oath: invalid otpauth URI")
	ErrCredentialExists   = errors.New("oath: credential already exists")
	ErrCredentialNotFound = errors.New("oath: credential not found")
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
		return nil, fmt.Errorf("%w: name is required", ErrInvalidCredential)
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
		Algorithm: DefaultAlgorithm,
		Digits:    DefaultDigits,
		Period:    DefaultPeriod,
		CreatedAt: time.Now(),
	}

	return cred, nil
}

// ParseURI parses an otpauth:// URI and returns a Credential.
// URI format: otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30
func ParseURI(uri string) (*Credential, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidURI, err)
	}

	if u.Scheme != "otpauth" {
		return nil, fmt.Errorf("%w: scheme must be otpauth", ErrInvalidURI)
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
		return nil, fmt.Errorf("%w: secret is required", ErrInvalidURI)
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
				return nil, fmt.Errorf("%w: invalid counter", ErrInvalidURI)
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
	label := c.AccountName
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
		return fmt.Errorf("%w: name is required", ErrInvalidCredential)
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
	if c.Digits < 6 || c.Digits > 8 {
		return ErrInvalidDigits
	}
	if c.Type == TypeTOTP && c.Period <= 0 {
		return ErrInvalidPeriod
	}

	// Validate secret is valid base32 (normalize first)
	if _, err := normalizeSecret(c.Secret); err != nil {
		return err
	}

	return nil
}

// NewCredentialFromManualEntry creates a TOTP credential from manually entered
// parameters (account name, issuer, and base32-encoded secret key). This is the
// fallback when QR code scanning is unavailable. Standard TOTP defaults are
// applied (SHA1, 6 digits, 30-second period).
func NewCredentialFromManualEntry(accountName, issuer, secret string) (*Credential, error) {
	if accountName == "" && issuer == "" {
		return nil, fmt.Errorf("%w: account name or issuer required", ErrInvalidCredential)
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
		return "", fmt.Errorf("oath: failed to generate secret: %w", err)
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
	secret = strings.TrimRight(secret, "=")

	if secret == "" {
		return "", fmt.Errorf("%w: empty secret", ErrInvalidSecret)
	}

	// Validate it's valid base32
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		return "", fmt.Errorf("%w: invalid base32 secret", ErrInvalidSecret)
	}

	return secret, nil
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
