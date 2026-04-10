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

package secretservice

import (
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/godbus/dbus/v5"
)

// PathMapper handles conversion between D-Bus object paths and go-xkms identifiers.
type PathMapper struct {
	config *ServiceConfig
}

// NewPathMapper creates a new PathMapper with the given configuration.
func NewPathMapper(config *ServiceConfig) *PathMapper {
	return &PathMapper{config: config}
}

// CollectionPathFromFolder returns the D-Bus object path for a folder.
// Empty folder maps to the default collection.
func (m *PathMapper) CollectionPathFromFolder(folderPath string) dbus.ObjectPath {
	if folderPath == "" {
		return dbus.ObjectPath(CollectionPathPrefix + DefaultCollection)
	}
	// URL-encode the folder path for safe D-Bus path
	encoded := url.PathEscape(folderPath)
	// Replace any remaining problematic chars
	encoded = strings.ReplaceAll(encoded, "/", "_")
	return dbus.ObjectPath(CollectionPathPrefix + encoded)
}

// FolderFromCollectionPath returns the folder path for a collection D-Bus path.
// Returns empty string for default/login collections.
func (m *PathMapper) FolderFromCollectionPath(path dbus.ObjectPath) string {
	pathStr := string(path)

	// Handle alias paths
	if strings.HasPrefix(pathStr, AliasPathPrefix) {
		alias := strings.TrimPrefix(pathStr, AliasPathPrefix)
		return m.FolderFromAlias(alias)
	}

	if !strings.HasPrefix(pathStr, CollectionPathPrefix) {
		return ""
	}

	name := strings.TrimPrefix(pathStr, CollectionPathPrefix)

	// Check for default/login collections
	if name == DefaultCollection || name == LoginCollection {
		return m.config.DefaultCollectionFolder
	}

	// Check configured mappings
	for collName, folder := range m.config.CollectionFolderMap {
		if name == collName {
			return folder
		}
	}

	// URL-decode and convert underscores back to slashes
	name = strings.ReplaceAll(name, "_", "/")
	decoded, err := url.PathUnescape(name)
	if err != nil {
		return name
	}
	return decoded
}

// FolderFromAlias returns the folder path for a collection alias.
func (m *PathMapper) FolderFromAlias(alias string) string {
	if alias == DefaultCollection || alias == LoginCollection {
		return m.config.DefaultCollectionFolder
	}
	if folder, ok := m.config.CollectionFolderMap[alias]; ok {
		return folder
	}
	return alias
}

// ItemPathFromPassword returns the D-Bus object path for a password entry.
func (m *PathMapper) ItemPathFromPassword(collectionPath dbus.ObjectPath, passwordID string) dbus.ObjectPath {
	// Hex-encode the password ID for safe D-Bus path
	encoded := hex.EncodeToString([]byte(passwordID))
	return dbus.ObjectPath(string(collectionPath) + "/" + encoded)
}

// PasswordIDFromItemPath extracts the password ID from an item D-Bus path.
func (m *PathMapper) PasswordIDFromItemPath(path dbus.ObjectPath) (collectionPath dbus.ObjectPath, passwordID string, err error) {
	pathStr := string(path)

	// Find the last slash to split collection and item
	lastSlash := strings.LastIndex(pathStr, "/")
	if lastSlash == -1 || lastSlash == len(pathStr)-1 {
		return "", "", ErrItemNotFound
	}

	collectionPath = dbus.ObjectPath(pathStr[:lastSlash])
	encodedID := pathStr[lastSlash+1:]

	// Hex-decode the password ID
	decoded, err := hex.DecodeString(encodedID)
	if err != nil {
		return "", "", ErrItemNotFound
	}

	return collectionPath, string(decoded), nil
}

// SessionPath generates a D-Bus object path for a new session.
func (m *PathMapper) SessionPath(sessionID string) dbus.ObjectPath {
	return dbus.ObjectPath(SessionPathPrefix + sessionID)
}

// PromptPath generates a D-Bus object path for a new prompt.
func (m *PathMapper) PromptPath(promptID string) dbus.ObjectPath {
	return dbus.ObjectPath(PromptPathPrefix + promptID)
}

// CollectionNameFromPath extracts the collection name from a D-Bus path.
func (m *PathMapper) CollectionNameFromPath(path dbus.ObjectPath) string {
	pathStr := string(path)
	if strings.HasPrefix(pathStr, AliasPathPrefix) {
		return strings.TrimPrefix(pathStr, AliasPathPrefix)
	}
	if strings.HasPrefix(pathStr, CollectionPathPrefix) {
		return strings.TrimPrefix(pathStr, CollectionPathPrefix)
	}
	return ""
}

// IsDefaultCollection returns true if the path refers to the default collection.
func (m *PathMapper) IsDefaultCollection(path dbus.ObjectPath) bool {
	name := m.CollectionNameFromPath(path)
	return name == DefaultCollection || name == LoginCollection
}

// AttributesToSearchCriteria converts D-Bus item attributes to search criteria
// that can be used with the password store.
func AttributesToSearchCriteria(attrs ItemAttributes) map[string]string {
	// Copy attributes, normalizing common variations
	result := make(map[string]string, len(attrs))
	for k, v := range attrs {
		// Normalize common attribute names
		switch strings.ToLower(k) {
		case "service", "application":
			result["service"] = v
		case "username", "user", "account":
			result["username"] = v
		case "url", "uri", "server", "host":
			result["url"] = v
		default:
			result[k] = v
		}
	}
	return result
}

// PasswordToItemAttributes converts a password entry to D-Bus item attributes.
func PasswordToItemAttributes(name, username, url string) ItemAttributes {
	attrs := make(ItemAttributes)
	if name != "" {
		attrs["service"] = name
	}
	if username != "" {
		attrs["username"] = username
	}
	if url != "" {
		attrs["url"] = url
	}
	// Add schema identifier
	attrs["xdg:schema"] = "org.freedesktop.Secret.Generic"
	return attrs
}

// MatchAttributes returns true if the item attributes match the search criteria.
// An empty search matches all items.
func MatchAttributes(itemAttrs, searchAttrs ItemAttributes) bool {
	if len(searchAttrs) == 0 {
		return true
	}

	for key, searchVal := range searchAttrs {
		itemVal, exists := itemAttrs[key]
		if !exists || itemVal != searchVal {
			return false
		}
	}
	return true
}
