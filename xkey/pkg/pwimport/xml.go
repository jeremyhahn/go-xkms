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
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"
)

// KeePass XML structures for parsing exported XML files.

// keePassFile is the root element of a KeePass XML export.
type keePassFile struct {
	XMLName xml.Name    `xml:"KeePassFile"`
	Meta    keePassMeta `xml:"Meta"`
	Root    keePassRoot `xml:"Root"`
}

type keePassMeta struct {
	Generator    string `xml:"Generator"`
	DatabaseName string `xml:"DatabaseName"`
}

type keePassRoot struct {
	Group          keePassGroup   `xml:"Group"`
	DeletedObjects keePassDeleted `xml:"DeletedObjects"`
}

type keePassDeleted struct {
	DeletedObject []keePassDeletedObject `xml:"DeletedObject"`
}

type keePassDeletedObject struct {
	UUID         string `xml:"UUID"`
	DeletionTime string `xml:"DeletionTime"`
}

type keePassGroup struct {
	UUID    string         `xml:"UUID"`
	Name    string         `xml:"Name"`
	Notes   string         `xml:"Notes"`
	IconID  int            `xml:"IconID"`
	Times   keePassTimes   `xml:"Times"`
	Groups  []keePassGroup `xml:"Group"`
	Entries []keePassEntry `xml:"Entry"`
}

type keePassEntry struct {
	UUID     string          `xml:"UUID"`
	IconID   int             `xml:"IconID"`
	Tags     string          `xml:"Tags"`
	Times    keePassTimes    `xml:"Times"`
	Strings  []keePassString `xml:"String"`
	AutoType keePassAutoType `xml:"AutoType"`
	History  keePassHistory  `xml:"History"`
}

type keePassTimes struct {
	LastModificationTime string `xml:"LastModificationTime"`
	CreationTime         string `xml:"CreationTime"`
	LastAccessTime       string `xml:"LastAccessTime"`
	ExpiryTime           string `xml:"ExpiryTime"`
	Expires              string `xml:"Expires"`
	UsageCount           int    `xml:"UsageCount"`
	LocationChanged      string `xml:"LocationChanged"`
}

type keePassString struct {
	Key   string       `xml:"Key"`
	Value keePassValue `xml:"Value"`
}

type keePassValue struct {
	Value           string `xml:",chardata"`
	ProtectInMemory string `xml:"ProtectInMemory,attr"`
}

type keePassAutoType struct {
	Enabled                 string `xml:"Enabled"`
	DataTransferObfuscation int    `xml:"DataTransferObfuscation"`
	DefaultSequence         string `xml:"DefaultSequence"`
}

type keePassHistory struct {
	Entries []keePassEntry `xml:"Entry"`
}

// XMLParser parses KeePass XML export files.
type XMLParser struct{}

// NewXMLParser creates a new XML parser.
func NewXMLParser() *XMLParser {
	return &XMLParser{}
}

// Format returns the format identifier.
func (p *XMLParser) Format() string {
	return FormatXML
}

// Parse reads and parses an XML file.
func (p *XMLParser) Parse(filePath string, opts *ImportOptions) ([]*ParsedEntry, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFile, err)
	}

	var kpFile keePassFile
	if err := xml.Unmarshal(data, &kpFile); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseError, err)
	}

	// Validate structure.
	if kpFile.Root.Group.UUID == "" {
		return nil, fmt.Errorf("%w: missing root group", ErrInvalidXMLStructure)
	}

	entries := make([]*ParsedEntry, 0)
	p.parseGroup(&kpFile.Root.Group, "", opts, &entries)

	if len(entries) == 0 {
		return nil, ErrNoEntriesFound
	}

	return entries, nil
}

// parseGroup recursively parses a group and its subgroups.
func (p *XMLParser) parseGroup(group *keePassGroup, parentPath string, opts *ImportOptions, entries *[]*ParsedEntry) {
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
		entry := p.parseEntry(&group.Entries[i], currentPath, opts)
		if entry != nil {
			*entries = append(*entries, entry)
		}
	}

	// Recursively parse subgroups.
	for i := range group.Groups {
		p.parseGroup(&group.Groups[i], currentPath, opts, entries)
	}
}

// parseEntry converts a KeePass entry to a ParsedEntry.
func (p *XMLParser) parseEntry(entry *keePassEntry, folderPath string, opts *ImportOptions) *ParsedEntry {
	// Build string map for easy access.
	stringMap := make(map[string]string)
	for _, s := range entry.Strings {
		stringMap[s.Key] = s.Value.Value
	}

	password := stringMap["Password"]
	if password == "" {
		return nil // Skip entries without passwords
	}

	parsed := &ParsedEntry{
		Title:    stringMap["Title"],
		Username: stringMap["UserName"],
		Password: password,
		URL:      stringMap["URL"],
		Notes:    stringMap["Notes"],
		IconID:   entry.IconID,
	}

	// Check for TOTP (can be stored as "otp", "TOTP", or "OTP").
	for _, key := range []string{"otp", "TOTP", "OTP", "totp"} {
		if totpURL, ok := stringMap[key]; ok && totpURL != "" {
			parsed.TOTPURL = totpURL
			if strings.HasPrefix(totpURL, "otpauth://") {
				parsed.HasTOTP = true
			}
			break
		}
	}

	// Parse tags.
	if entry.Tags != "" {
		// Tags are comma-separated in KeePass.
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
	parsed.CreatedAt = p.parseKeePassTime(entry.Times.CreationTime)
	parsed.UpdatedAt = p.parseKeePassTime(entry.Times.LastModificationTime)

	// Parse expiry if enabled.
	if strings.ToLower(entry.Times.Expires) == "true" {
		parsed.ExpiresAt = p.parseKeePassTime(entry.Times.ExpiryTime)
	}

	return parsed
}

// parseKeePassTime parses KeePass base64-encoded timestamps.
// KeePass stores timestamps as base64-encoded 8-byte little-endian integers
// representing 100-nanosecond intervals since 0001-01-01 00:00:00 UTC.
func (p *XMLParser) parseKeePassTime(encoded string) time.Time {
	if encoded == "" {
		return time.Time{}
	}

	// Try decoding as base64.
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try parsing as ISO 8601 format (some exports use this).
		if t, err := time.Parse(time.RFC3339, encoded); err == nil {
			return t
		}
		if t, err := time.Parse("2006-01-02T15:04:05Z", encoded); err == nil {
			return t
		}
		return time.Time{}
	}

	if len(decoded) < 8 {
		return time.Time{}
	}

	// Parse as 8-byte little-endian integer.
	ticks := binary.LittleEndian.Uint64(decoded)

	// KeePass epoch is 0001-01-01 00:00:00 UTC.
	// Convert from 100-nanosecond intervals to nanoseconds.
	// Then add to the epoch.
	// Note: Go's time.Time uses Unix epoch (1970-01-01), so we need to adjust.

	// Number of 100-nanosecond intervals from 0001-01-01 to 1970-01-01.
	// This is approximately 621355968000000000 ticks.
	const ticksToUnixEpoch uint64 = 621355968000000000

	if ticks < ticksToUnixEpoch {
		return time.Time{}
	}

	// Convert to Unix nanoseconds.
	unixNanos := int64((ticks - ticksToUnixEpoch) * 100)

	return time.Unix(0, unixNanos)
}

// Ensure XMLParser implements Parser.
var _ Parser = (*XMLParser)(nil)
