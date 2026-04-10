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

package pwimport

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
)

// Importer handles importing passwords from various formats.
type Importer struct {
	parsers map[string]Parser
	store   staticpw.Store
}

// NewImporter creates a new importer with the given password store.
func NewImporter(store staticpw.Store) *Importer {
	imp := &Importer{
		parsers: make(map[string]Parser),
		store:   store,
	}

	// Register built-in parsers.
	imp.RegisterParser(NewCSVParser())
	imp.RegisterParser(NewXMLParser())
	imp.RegisterParser(NewKDBXParser())

	return imp
}

// RegisterParser registers a parser for a specific format.
func (i *Importer) RegisterParser(parser Parser) {
	i.parsers[parser.Format()] = parser
}

// DetectFormat attempts to detect the file format from the file extension.
func (i *Importer) DetectFormat(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".csv":
		return FormatCSV
	case ".xml":
		return FormatXML
	case ".kdbx":
		return FormatKDBX
	default:
		return ""
	}
}

// Import performs the import operation with the given options.
func (i *Importer) Import(opts *ImportOptions) (*ImportResult, error) {
	startTime := time.Now()

	result := &ImportResult{}

	// Auto-detect format if not specified.
	format := opts.Format
	if format == "" {
		format = i.DetectFormat(opts.FilePath)
		if format == "" {
			return nil, ErrUnsupportedFormat
		}
	}

	// Get the appropriate parser.
	parser, ok := i.parsers[format]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, format)
	}

	// Parse the file.
	entries, err := parser.Parse(opts.FilePath, opts)
	if err != nil {
		return nil, err
	}

	// Import each entry.
	for _, entry := range entries {
		sp := entry.ToStaticPassword()

		// Check for existing entry.
		existing, _ := i.store.Get(sp.ID)
		if existing != nil {
			if opts.SkipDuplicates {
				result.Skipped++
				continue
			}
			if !opts.OverwriteDuplicates {
				result.Failed++
				result.Errors = append(result.Errors, ImportError{
					EntryName: sp.Name,
					Error:     ErrDuplicateEntry.Error(),
				})
				continue
			}
			// Overwrite: delete existing first, then update.
			if err := i.store.ForceDelete(sp.ID); err != nil {
				result.Failed++
				result.Errors = append(result.Errors, ImportError{
					EntryName: sp.Name,
					Error:     fmt.Sprintf("failed to delete existing: %v", err),
				})
				continue
			}
		}

		// Add the new entry.
		if err := i.store.Add(sp); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, ImportError{
				EntryName: sp.Name,
				Error:     err.Error(),
			})
			continue
		}

		result.Imported++

		// Track TOTP imports.
		if entry.HasTOTP && opts.ImportTOTP {
			result.TOTPImported++
		}
	}

	result.Duration = time.Since(startTime)

	return result, nil
}

// Preview parses the file and returns the entries without storing them.
// This allows users to preview what will be imported.
func (i *Importer) Preview(opts *ImportOptions) ([]*ParsedEntry, error) {
	// Auto-detect format if not specified.
	format := opts.Format
	if format == "" {
		format = i.DetectFormat(opts.FilePath)
		if format == "" {
			return nil, ErrUnsupportedFormat
		}
	}

	// Get the appropriate parser.
	parser, ok := i.parsers[format]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, format)
	}

	return parser.Parse(opts.FilePath, opts)
}

// SupportedFormats returns a list of supported import formats.
func (i *Importer) SupportedFormats() []string {
	formats := make([]string, 0, len(i.parsers))
	for format := range i.parsers {
		formats = append(formats, format)
	}
	return formats
}
