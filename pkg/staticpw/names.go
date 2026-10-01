// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package staticpw

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// personalNamesInfo is the HKDF info that derives a personal store's naming
// key from the user's DEK.
const personalNamesInfo = "xkms/staticpw/personal/v1/names"

// personalIDLength is the length, in bytes, of an opaque personal segment
// (128 bits, hex-encoded to 32 characters).
const personalIDLength = 16

// Kinds of name an entryNames maps, kept apart so that an entry, a folder
// marker and an alias with the same text never share a segment.
const (
	nameKindEntry  = "entry"
	nameKindFolder = "folder"
	nameKindAlias  = "alias"
)

// entryNames maps the names a store is given -- an entry's name and folder,
// a folder marker, an alias -- to the segments of the storage keys it
// writes.
//
// The zero value is the public scheme every shared and local store uses: an
// entry ID is GenerateID's hash of the name and folder, and a marker's
// segment is its text. A personal store is keyed with a secret derived from
// the user's DEK instead, so every segment is HMAC-SHA-256 under that key:
// whoever holds only the tenant barrier key sees neither names, folders, nor
// a hash of them anyone else could compute.
type entryNames struct {
	key []byte
}

// opaque reports whether the names are keyed.
func (n entryNames) opaque() bool { return n.key != nil }

// entryID returns the ID of the entry name in folderPath. Names are
// case-insensitive, as GenerateID's are.
func (n entryNames) entryID(name, folderPath string) string {
	if !n.opaque() {
		return GenerateID(name, folderPath)
	}
	path := name
	if folderPath != "" {
		path = folderPath + "/" + name
	}
	return n.mac(nameKindEntry, strings.ToLower(path))
}

// segment returns the storage-key segment of a marker of kind.
func (n entryNames) segment(kind, value string) string {
	if !n.opaque() {
		return value
	}
	return n.mac(kind, value)
}

func (n entryNames) mac(kind, value string) string {
	h := hmac.New(sha256.New, n.key)
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil)[:personalIDLength])
}

// newPersonalNames derives the personal naming key from dek. The caller
// zeroes the names' key with the DEK when the session ends.
func newPersonalNames(dek []byte) (entryNames, error) {
	key, err := hkdfKey(dek, nil, personalNamesInfo)
	if err != nil {
		return entryNames{}, err
	}
	return entryNames{key: key}, nil
}
