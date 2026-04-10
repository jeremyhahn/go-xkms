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

package staticpw

import (
	"regexp"
	"strings"
)

const (
	// MaxFolderDepth is the maximum allowed nesting depth for folder paths.
	MaxFolderDepth = 10

	// MaxFolderNameLength is the maximum length for a single folder name segment.
	MaxFolderNameLength = 64
)

// folderNameRegex validates individual folder name segments.
// Allows alphanumeric characters, hyphens, underscores, and spaces.
// Must not start or end with whitespace.
var folderNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_\- ]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$`)

// ValidateFolderPath validates a folder path string.
// An empty path is valid (represents root).
// Returns ErrInvalidFolderPath if the path contains invalid characters or empty segments.
// Returns ErrFolderPathTooDeep if the path exceeds MaxFolderDepth levels.
func ValidateFolderPath(path string) error {
	// Empty path is valid (root folder)
	if path == "" {
		return nil
	}

	// Check for leading/trailing slashes
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return ErrInvalidFolderPath
	}

	parts := strings.Split(path, "/")

	// Check depth
	if len(parts) > MaxFolderDepth {
		return ErrFolderPathTooDeep
	}

	// Validate each segment
	for _, part := range parts {
		if err := validateFolderName(part); err != nil {
			return err
		}
	}

	return nil
}

// validateFolderName validates a single folder name segment.
func validateFolderName(name string) error {
	// Empty segment is invalid
	if name == "" {
		return ErrInvalidFolderPath
	}

	// Check length
	if len(name) > MaxFolderNameLength {
		return ErrInvalidFolderPath
	}

	// Check pattern
	if !folderNameRegex.MatchString(name) {
		return ErrInvalidFolderPath
	}

	return nil
}

// NormalizeFolderPath normalizes a folder path by trimming whitespace from segments
// and removing duplicate slashes. Returns the normalized path.
func NormalizeFolderPath(path string) string {
	if path == "" {
		return ""
	}

	parts := strings.Split(path, "/")
	normalized := make([]string, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}

	return strings.Join(normalized, "/")
}

// IsSubfolder returns true if childPath is a direct or nested subfolder of parentPath.
// Returns false if childPath equals parentPath (use exact comparison for that).
func IsSubfolder(parentPath, childPath string) bool {
	if parentPath == "" {
		// Everything is under root (except root itself)
		return childPath != ""
	}

	return strings.HasPrefix(childPath, parentPath+"/")
}

// IsDirectChild returns true if childPath is a direct (immediate) child of parentPath.
func IsDirectChild(parentPath, childPath string) bool {
	if !IsSubfolder(parentPath, childPath) {
		return false
	}

	// Get the relative path
	var relative string
	if parentPath == "" {
		relative = childPath
	} else {
		relative = strings.TrimPrefix(childPath, parentPath+"/")
	}

	// Direct child has no slashes in the relative path
	return !strings.Contains(relative, "/")
}

// GetParentFolder returns the parent folder path, or empty string if at root.
func GetParentFolder(path string) string {
	if path == "" {
		return ""
	}

	lastSlash := strings.LastIndex(path, "/")
	if lastSlash == -1 {
		return "" // Direct child of root
	}

	return path[:lastSlash]
}

// GetFolderName returns the name of the folder (last segment of the path).
func GetFolderName(path string) string {
	if path == "" {
		return ""
	}

	lastSlash := strings.LastIndex(path, "/")
	if lastSlash == -1 {
		return path
	}

	return path[lastSlash+1:]
}
