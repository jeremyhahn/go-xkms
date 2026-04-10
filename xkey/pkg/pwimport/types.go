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
	"errors"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
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
	Title      string
	Username   string
	Password   string
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

// ToStaticPassword converts a ParsedEntry to a StaticPassword.
func (p *ParsedEntry) ToStaticPassword() *staticpw.StaticPassword {
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

	sp := &staticpw.StaticPassword{
		Name:       name,
		Title:      p.Title,
		Username:   p.Username,
		Password:   p.Password,
		URL:        p.URL,
		Notes:      p.Notes,
		FolderPath: p.FolderPath,
		CreatedAt:  createdAt,
		UpdatedAt:  updatedAt,
		ExpiresAt:  p.ExpiresAt,
	}

	// Generate deterministic ID.
	sp.ID = staticpw.GenerateID(sp.Name, sp.FolderPath)

	return sp
}

// Parser defines the interface for import file parsers.
type Parser interface {
	// Parse reads and parses the file at the given path.
	Parse(filePath string, opts *ImportOptions) ([]*ParsedEntry, error)

	// Format returns the format this parser handles.
	Format() string
}
