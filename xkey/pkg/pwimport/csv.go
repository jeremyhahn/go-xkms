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
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"time"
)

// csvColumnIndex maps CSV column names to indices.
type csvColumnIndex struct {
	Group        int
	Title        int
	Username     int
	Password     int
	URL          int
	Notes        int
	TOTP         int
	Icon         int
	LastModified int
	Created      int
}

// CSVParser parses KeePassXC CSV export files.
type CSVParser struct{}

// NewCSVParser creates a new CSV parser.
func NewCSVParser() *CSVParser {
	return &CSVParser{}
}

// Format returns the format identifier.
func (p *CSVParser) Format() string {
	return FormatCSV
}

// Parse reads and parses a CSV file.
func (p *CSVParser) Parse(filePath string, opts *ImportOptions) ([]*ParsedEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFile, err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseError, err)
	}

	if len(records) < 2 {
		return nil, ErrNoEntriesFound
	}

	// Parse header to find column indices.
	colIdx, err := p.parseHeader(records[0])
	if err != nil {
		return nil, err
	}

	entries := make([]*ParsedEntry, 0, len(records)-1)

	for i := 1; i < len(records); i++ {
		row := records[i]
		entry, err := p.parseRow(row, colIdx, opts)
		if err != nil {
			continue // Skip invalid rows
		}
		if entry != nil {
			entries = append(entries, entry)
		}
	}

	if len(entries) == 0 {
		return nil, ErrNoEntriesFound
	}

	return entries, nil
}

// parseHeader identifies column indices from the CSV header.
func (p *CSVParser) parseHeader(header []string) (*csvColumnIndex, error) {
	idx := &csvColumnIndex{
		Group:        -1,
		Title:        -1,
		Username:     -1,
		Password:     -1,
		URL:          -1,
		Notes:        -1,
		TOTP:         -1,
		Icon:         -1,
		LastModified: -1,
		Created:      -1,
	}

	for i, col := range header {
		switch strings.ToLower(strings.TrimSpace(col)) {
		case "group", "folder", "path":
			idx.Group = i
		case "title", "name", "entry":
			idx.Title = i
		case "username", "user", "login":
			idx.Username = i
		case "password", "pass":
			idx.Password = i
		case "url", "website", "uri":
			idx.URL = i
		case "notes", "note", "comment", "comments":
			idx.Notes = i
		case "totp", "otp", "2fa":
			idx.TOTP = i
		case "icon", "iconid":
			idx.Icon = i
		case "last modified", "lastmodified", "modified", "updated":
			idx.LastModified = i
		case "created", "creation", "createdat":
			idx.Created = i
		}
	}

	// Password is required.
	if idx.Password == -1 {
		return nil, fmt.Errorf("%w: missing password column", ErrInvalidCSVHeader)
	}

	// At least one identifier (title or username) is required.
	if idx.Title == -1 && idx.Username == -1 {
		return nil, fmt.Errorf("%w: missing title or username column", ErrInvalidCSVHeader)
	}

	return idx, nil
}

// parseRow converts a CSV row to a ParsedEntry.
func (p *CSVParser) parseRow(row []string, idx *csvColumnIndex, opts *ImportOptions) (*ParsedEntry, error) {
	getField := func(i int) string {
		if i >= 0 && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}

	password := getField(idx.Password)
	if password == "" {
		return nil, nil // Skip entries without passwords
	}

	entry := &ParsedEntry{
		Title:    getField(idx.Title),
		Username: getField(idx.Username),
		Password: password,
		URL:      getField(idx.URL),
		Notes:    getField(idx.Notes),
		TOTPURL:  getField(idx.TOTP),
	}

	// Parse folder path.
	if idx.Group >= 0 {
		group := getField(idx.Group)
		if group != "" && group != "Root" {
			entry.FolderPath = group
		}
	}

	// Apply target folder prefix if specified.
	if opts != nil && opts.TargetFolder != "" {
		if entry.FolderPath != "" {
			entry.FolderPath = opts.TargetFolder + "/" + entry.FolderPath
		} else {
			entry.FolderPath = opts.TargetFolder
		}
	}

	// Parse timestamps.
	if idx.Created >= 0 {
		entry.CreatedAt = p.parseTimestamp(getField(idx.Created))
	}
	if idx.LastModified >= 0 {
		entry.UpdatedAt = p.parseTimestamp(getField(idx.LastModified))
	}

	// Check for TOTP.
	if entry.TOTPURL != "" && strings.HasPrefix(entry.TOTPURL, "otpauth://") {
		entry.HasTOTP = true
	}

	return entry, nil
}

// parseTimestamp attempts to parse various timestamp formats.
func (p *CSVParser) parseTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"01/02/2006 15:04:05",
		"01/02/2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}

	return time.Time{}
}

// Ensure CSVParser implements Parser.
var _ Parser = (*CSVParser)(nil)
