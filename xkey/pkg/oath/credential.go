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
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
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

	// ErrProtectedMemory reports that the shared secret could not be placed
	// in mlocked protected memory. The secret is never kept on the ordinary
	// heap as a fallback (go-xkms#210).
	ErrProtectedMemory = errors.New("oath: protected memory allocation failed")
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

	// secret holds the Base32-encoded shared secret in mlocked, guard-paged
	// protected memory (go-xkms#210). It is unexported so no consumer can
	// hold the key material as an unwipeable Go string; use SetSecret to
	// store it and Secret to export a copy at a serialization
	// boundary. nil means no secret is set. The persisted JSON form keeps
	// the historical "secret" key via MarshalJSON/UnmarshalJSON.
	secret *secure.Buffer

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

// SetSecret stores the Base32-encoded shared secret in protected memory,
// replacing (and destroying) any previous value. The value is stored verbatim
// — exactly what field assignment used to do — so normalization remains the
// business of the enrolment paths (ParseURI, NewCredentialFromManualEntry)
// and of the use-time canonicalization in Validate and GenerateCounter.
// An empty secret clears it.
//
// SetSecret copies secret; it stays the caller's, who wipes it.
//
// Returns ErrProtectedMemory (wrapped) when the protected allocation fails.
func (c *Credential) SetSecret(secret []byte) error {
	if len(secret) == 0 {
		return c.setSecretBytes(nil)
	}
	return c.setSecretBytes(bytes.Clone(secret))
}

// setSecretBytes adopts b — the Base32-encoded secret — into protected
// memory, replacing any previous value. b is wiped by the adoption; the
// caller must not reuse it. An empty b clears the secret.
func (c *Credential) setSecretBytes(b []byte) error {
	if len(b) == 0 {
		c.secret.Destroy()
		c.secret = nil
		return nil
	}
	buf, err := secure.NewBufferFromBytes(b)
	if err != nil {
		secure.Wipe(b)
		return &SentinelCauseError{Sentinel: ErrProtectedMemory, Cause: err}
	}
	c.secret.Destroy()
	c.secret = buf
	return nil
}

// secretCopy returns a heap copy of the Base32-encoded secret. The caller
// owns the copy and MUST wipe it (secure.Wipe) when done. Returns
// ErrInvalidSecret when no secret is set or the buffer has been destroyed.
func (c *Credential) secretCopy() ([]byte, error) {
	if c == nil || c.secret == nil {
		return nil, ErrInvalidSecret
	}
	var out []byte
	if err := c.secret.WithBytes(func(b []byte) error {
		out = make([]byte, len(b))
		copy(out, b)
		return nil
	}); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidSecret, Cause: err}
	}
	return out, nil
}

// Secret returns a caller-owned copy of the Base32-encoded shared secret, or
// nil when no secret is set. The caller MUST wipe it (secure.Wipe) as soon as
// it has been used. Returns ErrInvalidSecret (wrapped) when the protected
// buffer has been destroyed.
func (c *Credential) Secret() ([]byte, error) {
	if !c.HasSecret() {
		return nil, nil
	}
	return c.secretCopy()
}

// HasSecret reports whether the credential holds a shared secret.
func (c *Credential) HasSecret() bool {
	return c != nil && c.secret != nil
}

// credentialJSON is the persisted JSON form of Credential. It exists so the
// protected in-memory secret round-trips through the historical wire format
// unchanged: the "secret" key carries the Base32 string exactly as it did
// when Secret was an exported string field.
type credentialJSON struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Issuer      string           `json:"issuer"`
	AccountName string           `json:"account_name"`
	Secret      xkms.SecretBytes `json:"secret"`
	Type        string           `json:"type"`
	Algorithm   string           `json:"algorithm"`
	Digits      int              `json:"digits"`
	Period      int              `json:"period"`
	Counter     uint64           `json:"counter"`
	CreatedAt   time.Time        `json:"created_at"`
	BackendID   string           `json:"backend_id,omitempty"`
}

// MarshalJSON implements json.Marshaler, exporting the protected secret into
// the historical "secret" JSON key. Serialization necessarily materializes
// the secret on the heap; that residue belongs to the persistence boundary
// (the same bytes are about to be written to a store), not to this type.
func (c *Credential) MarshalJSON() ([]byte, error) {
	secret, err := c.Secret()
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(secret)
	wire := credentialJSON{
		ID:          c.ID,
		Name:        c.Name,
		Issuer:      c.Issuer,
		AccountName: c.AccountName,
		Secret:      secret,
		Type:        c.Type,
		Algorithm:   c.Algorithm,
		Digits:      c.Digits,
		Period:      c.Period,
		Counter:     c.Counter,
		CreatedAt:   c.CreatedAt,
		BackendID:   c.BackendID,
	}
	return json.Marshal(wire)
}

// UnmarshalJSON implements json.Unmarshaler, adopting the "secret" JSON key
// into protected memory.
func (c *Credential) UnmarshalJSON(data []byte) error {
	var aux credentialJSON
	defer aux.Secret.Wipe()
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.ID = aux.ID
	c.Name = aux.Name
	c.Issuer = aux.Issuer
	c.AccountName = aux.AccountName
	c.Type = aux.Type
	c.Algorithm = aux.Algorithm
	c.Digits = aux.Digits
	c.Period = aux.Period
	c.Counter = aux.Counter
	c.CreatedAt = aux.CreatedAt
	c.BackendID = aux.BackendID
	return c.SetSecret(aux.Secret)
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

	secret, err := generateSecretBase32(20) // 160-bit secret
	if err != nil {
		return nil, err
	}

	cred := &Credential{
		ID:        generateCredentialID(issuer, name),
		Name:      name,
		Issuer:    issuer,
		Type:      otpType,
		Algorithm: defaultAlgorithmForMode(),
		Digits:    DefaultDigits,
		Period:    DefaultPeriod,
		CreatedAt: time.Now(),
	}
	// setSecretBytes wipes secret on adoption; the Base32 form never
	// persists on the ordinary heap.
	if err := cred.setSecretBytes(secret); err != nil {
		return nil, err
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
		// url.Parse's returned *url.Error embeds the full input URI in its
		// message, including the query string -- and therefore the secret.
		// That text must never reach the returned error, so report a fixed
		// detail instead of wrapping the cause.
		return nil, &DetailError{Err: ErrInvalidURI, Detail: ": malformed URI"}
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

	// Normalize and validate the secret over a wipeable byte copy of the
	// query value. The url.Values string itself is an input-boundary residue
	// this package cannot wipe; every copy from here on is bytes.
	secretBytes, err := normalizeSecretBytes([]byte(secret))
	if err != nil {
		return nil, err
	}
	// Adoption wipes it too; this covers every refusal below, which return
	// before the secret reaches the credential.
	defer secure.Wipe(secretBytes)

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
		Type:        otpType,
		Algorithm:   algorithm,
		Digits:      digits,
		Period:      period,
		Counter:     counter,
		CreatedAt:   time.Now(),
	}
	// The normalized form is already upper-case; setSecretBytes wipes it on
	// adoption.
	if err := cred.setSecretBytes(secretBytes); err != nil {
		return nil, err
	}

	return cred, nil
}

// ToURI returns the otpauth:// URI for this credential. The URI embeds the
// shared secret, so it is as sensitive as the secret itself. Returns
// ErrInvalidSecret (wrapped) when the protected secret cannot be read.
func (c *Credential) ToURI() (string, error) {
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

	// An otpauth:// URI is a string by definition (it is rendered as a QR code
	// and a link), so the secret becomes a string here and only here.
	secret, err := c.Secret()
	if err != nil {
		return "", err
	}
	defer secure.Wipe(secret)
	q := u.Query()
	q.Set("secret", string(secret))
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

	return u.String(), nil
}

// Validate checks if the credential is valid.
func (c *Credential) Validate() error {
	if c.Name == "" {
		return &DetailError{Err: ErrInvalidCredential, Detail: ": name is required"}
	}
	if !c.HasSecret() {
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
	// Canonicalise BEFORE measuring. normalizeSecretBytes strips separators,
	// whitespace and padding, so the raw string's length is not the secret's
	// length -- and the difference is attacker-controlled. A 12-byte secret is
	// 20 Base32 characters; written "MFRGG-ZDFMZ-TWQ2L-KNNWA" it is 23, and
	// DecodedLen(23) is 14, which clears a 14-byte minimum that the actual key
	// misses by two bytes. Measuring the raw string made this check fail OPEN
	// on exactly the input a human is most likely to type, since grouping
	// separators are why normalizeSecretBytes exists.
	//
	// This is also the only decode: the base32 validity check below used to
	// call the normalization a second time and discard the result, so measuring
	// the canonical value costs nothing that was not already being paid.
	secretBytes, err := c.secretCopy()
	if err != nil {
		return err
	}
	defer secure.Wipe(secretBytes)
	normalized, err := normalizeSecretBytes(secretBytes)
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
	if fipsMode() &&
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

	normalizedSecret, err := normalizeSecretBytes([]byte(secret))
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
		Type:        TypeTOTP,
		Algorithm:   DefaultAlgorithm,
		Digits:      DefaultDigits,
		Period:      DefaultPeriod,
		CreatedAt:   time.Now(),
	}
	if err := cred.setSecretBytes(normalizedSecret); err != nil {
		return nil, err
	}

	return cred, nil
}

// GenerateSecret generates a cryptographically random secret of the specified length in bytes.
// Returns the secret as a base32-encoded string without padding.
//
// The returned string is for enrolment display and serialization boundaries;
// a caller storing it on a Credential should prefer NewCredential, which
// keeps the secret in wipeable memory throughout.
func GenerateSecret(length int) (string, error) {
	b, err := generateSecretBase32(length)
	if err != nil {
		return "", err
	}
	s := string(b)
	secure.Wipe(b)
	return s, nil
}

// generateSecretBase32 generates a cryptographically random secret and
// returns its Base32 (no padding) encoding as a wipeable byte slice. The raw
// key bytes are wiped before returning; the caller owns wiping the encoding
// (adoption via setSecretBytes does so).
func generateSecretBase32(length int) ([]byte, error) {
	raw := make([]byte, length)
	if _, err := rand.Read(raw); err != nil {
		return nil, &WrappedError{Msg: "oath: failed to generate secret", Err: err}
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	out := make([]byte, enc.EncodedLen(length))
	enc.Encode(out, raw)
	secure.Wipe(raw)
	return out, nil
}

// normalizeSecretBytes cleans up a base32-encoded secret by:
// - Converting to uppercase
// - Removing spaces, dashes, and other separators
// - Applying typo corrections for commonly confused characters
// - Removing padding characters
// - Validating the result is valid base32
//
// It works IN PLACE on secret and returns a prefix of the same backing array,
// so no intermediate copy of the key material is minted; the validation
// decode's scratch buffer is wiped before returning. The caller keeps
// ownership of secret's backing array — wiping the original slice wipes the
// canonical form too (go-xkms#210).
func normalizeSecretBytes(secret []byte) ([]byte, error) {
	secret = canonicalizeSecretBytes(secret)

	if len(secret) == 0 {
		return nil, &DetailError{Err: ErrInvalidSecret, Detail: ": empty secret"}
	}

	// Validate it's valid base32. The decode's output is the OATH key in the
	// clear, so it lands in a scratch buffer this function wipes.
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	scratch := make([]byte, enc.DecodedLen(len(secret)))
	_, err := enc.Decode(scratch, secret)
	secure.Wipe(scratch)
	if err != nil {
		return nil, &DetailError{Err: ErrInvalidSecret, Detail: ": invalid base32 secret"}
	}

	return secret, nil
}

// canonicalizeSecretBytes applies the textual half of normalizeSecretBytes —
// the case fold, separator removal, typo corrections and padding trim — and
// nothing else, IN PLACE, returning a prefix of secret's backing array.
//
// It is separate because the two callers need different halves. Validate
// wants the base32 check as well, and pays one decode for it (into a wiped
// scratch buffer). GenerateCounter is about to decode the secret anyway, and
// calling normalizeSecretBytes there would decode it twice. Sharing the
// mapping rather than duplicating it is what keeps the two paths agreeing on
// what a secret means.
//
// The Base32 alphabet is pure ASCII, so the fold is a byte-wise ASCII
// uppercase: no rune decoding, and — unlike the strings.ToUpper /
// strings.Map / strings.TrimRight sequence this replaces — no immutable
// intermediate copies of the key material that nothing can wipe. That
// unwipeable-intermediates residue was the defect go-xkms#210 tracked. (One
// deliberate divergence: a multi-byte rune whose Unicode uppercase is an
// ASCII base32 character, such as U+017F LATIN SMALL LETTER LONG S, no
// longer folds to it and is rejected as invalid base32 instead. No real
// enrolment source emits those.)
func canonicalizeSecretBytes(secret []byte) []byte {
	// Standard base32 uses A-Z and 2-7 only. Common confusions:
	// - 0 (zero) often confused with O
	// - 1 (one) often confused with I or L
	// - 8 often confused with B
	n := 0
	for _, ch := range secret {
		// ASCII uppercase fold.
		if ch >= 'a' && ch <= 'z' {
			ch -= 'a' - 'A'
		}
		switch ch {
		case ' ', '-', '_', '\t', '\n', '\r':
			continue // Remove separators
		case '9':
			continue // Nine has no good substitute, remove it
		case '0':
			ch = 'O' // Zero -> O
		case '1':
			ch = 'I' // One -> I
		case '8':
			ch = 'B' // Eight -> B
		}
		secret[n] = ch
		n++
	}
	// Wipe the tail the compaction left behind, then drop it.
	secure.Wipe(secret[n:])
	secret = secret[:n]

	// Remove padding characters - we'll decode without padding
	for len(secret) > 0 && secret[len(secret)-1] == '=' {
		secret = secret[:len(secret)-1]
	}
	return secret
}

// GenerateCredentialID returns the same ID a newly created credential would
// receive for the given issuer and account name. It is exported so a caller
// outside this package that builds a Credential from data with no ID of its
// own (e.g. the pairing bridge, assembling a Credential from an OATH
// credential handed over by a paired phone) mints IDs using the exact scheme
// every store already keys its entries by, instead of inventing a second one.
func GenerateCredentialID(issuer, accountName string) string {
	return generateCredentialID(issuer, accountName)
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
	// Fallback to a random ID. crypto/rand.Read failing means the platform's
	// entropy source itself is broken, not a transient condition this
	// function can retry around; fall back to a nanosecond timestamp so the
	// ID stays unique enough to avoid colliding with a sibling credential
	// created moments apart, rather than every failure returning "oath-0".
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("oath-%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("oath-%x", b)
}
