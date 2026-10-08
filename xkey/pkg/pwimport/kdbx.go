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
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

// KDBXParser parses KeePass KDBX database files directly.
type KDBXParser struct{}

// NewKDBXParser creates a new KDBX parser.
func NewKDBXParser() *KDBXParser {
	return &KDBXParser{}
}

// Format returns the format identifier.
func (p *KDBXParser) Format() string {
	return FormatKDBX
}

// Parse reads and parses a KDBX file.
func (p *KDBXParser) Parse(ctx context.Context, filePath string, opts *ImportOptions) ([]*ParsedEntry, error) {
	if opts == nil || opts.Password == "" {
		return nil, ErrPasswordRequired
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidFile, Cause: err}
	}
	defer func() { _ = file.Close() }()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(opts.Password)

	if err := gokeepasslib.NewDecoder(file).Decode(db); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDecryptionFailed, Cause: err}
	}

	// Unlock protected values (passwords are encrypted in memory by default).
	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, &DetailError{Err: ErrDecryptionFailed, Detail: fmt.Sprintf(": failed to unlock protected entries: %v", err)}
	}

	entries := make([]*ParsedEntry, 0)

	// Parse root group and all subgroups.
	if db.Content != nil && db.Content.Root != nil {
		for i := range db.Content.Root.Groups {
			if err := p.parseGroup(ctx, &db.Content.Root.Groups[i], "", opts, &entries); err != nil {
				return nil, err
			}
		}
	}

	if len(entries) == 0 {
		return nil, ErrNoEntriesFound
	}

	return entries, nil
}

// parseGroup recursively parses a group and its subgroups.
func (p *KDBXParser) parseGroup(ctx context.Context, group *gokeepasslib.Group, parentPath string, opts *ImportOptions, entries *[]*ParsedEntry) error {
	// Build current path.
	currentPath := parentPath
	if group.Name != "" && group.Name != "Root" {
		if currentPath != "" {
			currentPath = currentPath + "/" + group.Name
		} else {
			currentPath = group.Name
		}
	}

	// Parse entries in this group.
	for i := range group.Entries {
		entry, err := p.parseEntry(ctx, &group.Entries[i], currentPath, opts)
		if err != nil {
			return err
		}
		if entry != nil {
			*entries = append(*entries, entry)
		}
	}

	// Recursively parse subgroups.
	for i := range group.Groups {
		if err := p.parseGroup(ctx, &group.Groups[i], currentPath, opts, entries); err != nil {
			return err
		}
	}

	return nil
}

// parseEntry converts a gokeepasslib entry to a ParsedEntry.
func (p *KDBXParser) parseEntry(ctx context.Context, entry *gokeepasslib.Entry, folderPath string, opts *ImportOptions) (*ParsedEntry, error) {
	password := p.getValue(entry, "Password")
	if password == "" {
		return nil, nil // Skip entries without passwords
	}

	passwordSecret, err := newParsedPassword(ctx, password)
	if err != nil {
		return nil, err
	}

	parsed := &ParsedEntry{
		Title:    p.getValue(entry, "Title"),
		Username: p.getValue(entry, "UserName"),
		Password: passwordSecret,
		URL:      p.getValue(entry, "URL"),
		Notes:    p.getValue(entry, "Notes"),
		IconID:   int(entry.IconID),
	}

	// Check for TOTP (can be stored as "otp", "TOTP", "OTP", or "totp").
	for _, key := range []string{"otp", "TOTP", "OTP", "totp"} {
		totpURL := p.getValue(entry, key)
		if totpURL != "" {
			parsed.TOTPURL = totpURL
			if strings.HasPrefix(totpURL, "otpauth://") {
				parsed.HasTOTP = true
			}
			break
		}
	}

	// Parse tags.
	if entry.Tags != "" {
		tags := strings.Split(entry.Tags, ",")
		for i, tag := range tags {
			tags[i] = strings.TrimSpace(tag)
		}
		parsed.Tags = tags
	}

	// Build folder path with target prefix.
	if opts != nil && opts.TargetFolder != "" {
		if folderPath != "" {
			parsed.FolderPath = opts.TargetFolder + "/" + folderPath
		} else {
			parsed.FolderPath = opts.TargetFolder
		}
	} else {
		parsed.FolderPath = folderPath
	}

	// Parse timestamps.
	if entry.Times.CreationTime != nil {
		parsed.CreatedAt = p.parseTime(entry.Times.CreationTime)
	}
	if entry.Times.LastModificationTime != nil {
		parsed.UpdatedAt = p.parseTime(entry.Times.LastModificationTime)
	}

	// Parse expiry if enabled.
	if entry.Times.Expires.Bool {
		if entry.Times.ExpiryTime != nil {
			parsed.ExpiresAt = p.parseTime(entry.Times.ExpiryTime)
		}
	}

	return parsed, nil
}

// getValue retrieves a value from the entry's Values slice by key.
func (p *KDBXParser) getValue(entry *gokeepasslib.Entry, key string) string {
	val := entry.GetContent(key)
	return val
}

// parseTime converts a gokeepasslib time wrapper to time.Time.
func (p *KDBXParser) parseTime(t *wrappers.TimeWrapper) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.Time
}

// Ensure KDBXParser implements Parser.
var _ Parser = (*KDBXParser)(nil)
