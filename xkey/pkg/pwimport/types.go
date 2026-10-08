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

// Package pwimport provides password import functionality from various formats
// including CSV, KeePass XML, and KDBX files.
package pwimport

import (
	"context"
	"errors"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Import format constants.
const (
	FormatCSV  = "csv"
	FormatXML  = "xml"
	FormatKDBX = "kdbx"
)

// Import errors.
var (
	ErrUnsupportedFormat   = errors.New("pwimport: unsupported format")
	ErrInvalidFile         = errors.New("pwimport: invalid file")
	ErrPasswordRequired    = errors.New("pwimport: password required for KDBX")
	ErrDecryptionFailed    = errors.New("pwimport: KDBX decryption failed")
	ErrParseError          = errors.New("pwimport: failed to parse file")
	ErrNoEntriesFound      = errors.New("pwimport: no entries found in file")
	ErrDuplicateEntry      = errors.New("pwimport: duplicate entry")
	ErrInvalidCSVHeader    = errors.New("pwimport: invalid CSV header")
	ErrInvalidXMLStructure = errors.New("pwimport: invalid XML structure")

	// ErrProtectedMemory reports that a parsed password could not be sealed
	// into mlocked protected memory. The password is never kept on the
	// ordinary heap as a fallback.
	ErrProtectedMemory = errors.New("pwimport: protected memory allocation failed")
)

// ImportOptions configures the import behavior.
type ImportOptions struct {
	// Format specifies the file format: "csv", "xml", or "kdbx".
	Format string `json:"format"`

	// FilePath is the path to the file to import.
	FilePath string `json:"file_path"`

	// Password is required for KDBX files.
	Password string `json:"password,omitempty"`

	// TargetFolder is the folder to import entries into (e.g., "Imported/KeePass").
	// If empty, entries preserve their original folder structure.
	TargetFolder string `json:"target_folder,omitempty"`

	// SkipDuplicates skips entries that already exist (by ID) instead of erroring.
	SkipDuplicates bool `json:"skip_duplicates"`

	// OverwriteDuplicates overwrites existing entries instead of skipping.
	OverwriteDuplicates bool `json:"overwrite_duplicates"`

	// ImportTOTP controls whether TOTP/OTP data is imported as OATH accounts.
	ImportTOTP bool `json:"import_totp"`
}

// ImportResult contains the result of an import operation.
type ImportResult struct {
	// Imported is the number of entries successfully imported.
	Imported int `json:"imported"`

	// Skipped is the number of entries skipped (e.g., duplicates).
	Skipped int `json:"skipped"`

	// Failed is the number of entries that failed to import.
	Failed int `json:"failed"`

	// Errors contains details about failed entries.
	Errors []ImportError `json:"errors,omitempty"`

	// TOTPImported is the number of TOTP accounts imported.
	TOTPImported int `json:"totp_imported,omitempty"`

	// Duration is how long the import took.
	Duration time.Duration `json:"duration"`
}

// ImportError describes a single import failure.
type ImportError struct {
	EntryName string `json:"entry_name"`
	Error     string `json:"error"`
}

// ParsedEntry represents a password entry parsed from an import file,
// with additional metadata that may not map directly to StaticPassword.
type ParsedEntry struct {
	// Core fields that map to StaticPassword.
	Title    string
	Username string

	// Password holds the entry's shared secret in protected memory. It is
	// never nil for an entry returned by a Parser — every parser skips
	// entries without a password before constructing a ParsedEntry.
	Password   *secure.Secret
	URL        string
	Notes      string
	FolderPath string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	ExpiresAt  time.Time

	// Additional metadata.
	Tags    []string
	TOTPURL string // otpauth:// URL for TOTP
	IconID  int
	HasTOTP bool
}

// newParsedPassword seals raw into a *secure.Secret for a ParsedEntry.
// Callers must not reuse raw afterward: the copy handed to the enclave is
// wiped on return, but the Go string itself cannot be.
func newParsedPassword(ctx context.Context, raw string) (*secure.Secret, error) {
	secret, err := secure.NewSecret(ctx, []byte(raw))
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrProtectedMemory, Cause: err}
	}
	return secret, nil
}

// passwordString returns a copy of the entry's password as a string, or ""
// when no password is set. It is the one place an imported password becomes a
// Go string: xkms.StaticPassword.Password is string-typed because the entry is
// bound to the GUI (whose generated TypeScript models type it as a string) and
// stored as JSON, so ToStaticPassword cannot take bytes. The byte copy the
// string is made from is wiped before this returns. Callers that only need to
// compare or hash the password borrow it via Password.Open/WithBytes instead.
func (p *ParsedEntry) passwordString(ctx context.Context) (string, error) {
	if p.Password == nil {
		return "", nil
	}
	buf, err := p.Password.Open(ctx)
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrProtectedMemory, Cause: err}
	}
	defer buf.Destroy()
	plain, err := secure.CopyOut(buf)
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrProtectedMemory, Cause: err}
	}
	defer secure.Wipe(plain)
	return string(plain), nil
}

// ToStaticPassword converts a ParsedEntry to a StaticPassword. Returns
// ErrProtectedMemory (wrapped) if the protected password cannot be opened.
func (p *ParsedEntry) ToStaticPassword(ctx context.Context) (*xkms.StaticPassword, error) {
	now := time.Now()

	createdAt := p.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}

	updatedAt := p.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = now
	}

	name := p.Title
	if name == "" {
		name = p.Username
	}
	if name == "" {
		name = "Unnamed Entry"
	}

	password, err := p.passwordString(ctx)
	if err != nil {
		return nil, err
	}

	sp := &xkms.StaticPassword{
		Name:       name,
		Title:      p.Title,
		Username:   p.Username,
		Password:   password,
		URL:        p.URL,
		Notes:      p.Notes,
		FolderPath: p.FolderPath,
		CreatedAt:  createdAt,
		UpdatedAt:  updatedAt,
		ExpiresAt:  p.ExpiresAt,
	}

	// Generate deterministic ID.
	sp.ID = xkms.GenerateStaticPasswordID(sp.Name, sp.FolderPath)

	return sp, nil
}

// Parser defines the interface for import file parsers.
type Parser interface {
	// Parse reads and parses the file at the given path, sealing each
	// entry's password under ctx.
	Parse(ctx context.Context, filePath string, opts *ImportOptions) ([]*ParsedEntry, error)

	// Format returns the format this parser handles.
	Format() string
}
