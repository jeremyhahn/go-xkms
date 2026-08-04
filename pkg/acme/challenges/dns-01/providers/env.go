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

package providers

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// EnvFileNotFoundError is returned when an environment variable file cannot be read.
type EnvFileNotFoundError struct {
	EnvVar   string
	FilePath string
	Err      error
}

func (e *EnvFileNotFoundError) Error() string {
	return "env file not found: " + e.EnvVar + "_FILE=" + e.FilePath + ": " + e.Err.Error()
}

func (e *EnvFileNotFoundError) Unwrap() error {
	return e.Err
}

// GetEnvOrFile returns the value from the environment variable, or if VAR_FILE
// is set, reads from that file path. This supports the Docker secrets pattern
// where secrets are mounted as files.
//
// The lookup order is:
//  1. Check if envVar is set and non-empty, return its value
//  2. Check if envVar_FILE is set, read and return file contents
//  3. Return empty string and nil error if neither is set
//
// Returns an error if envVar_FILE is set but the file cannot be read.
func GetEnvOrFile(envVar string) (string, error) {
	// Check direct environment variable first
	if value := os.Getenv(envVar); value != "" {
		return value, nil
	}

	// Check for _FILE variant (Docker secrets pattern)
	// This is a standard pattern for reading secrets from mounted files
	fileEnvVar := envVar + "_FILE"
	if filePath := os.Getenv(fileEnvVar); filePath != "" {
		// #nosec G304 - file path is administrator-controlled via environment variable
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", &EnvFileNotFoundError{
				EnvVar:   envVar,
				FilePath: filePath,
				Err:      err,
			}
		}
		return strings.TrimSpace(string(data)), nil
	}

	return "", nil
}

// GetEnvOrDefault returns the value of the environment variable if set,
// otherwise returns the default value.
func GetEnvOrDefault(envVar, defaultValue string) string {
	if value := os.Getenv(envVar); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvDuration parses a duration from the environment variable.
// If the variable is not set or cannot be parsed, returns the default value.
//
// Accepted formats are those supported by time.ParseDuration:
// "300ms", "1.5h", "2h45m", etc.
func GetEnvDuration(envVar string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(envVar)
	if value == "" {
		return defaultValue
	}

	duration, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue
	}
	return duration
}

// GetEnvInt parses an integer from the environment variable.
// If the variable is not set or cannot be parsed, returns the default value.
func GetEnvInt(envVar string, defaultValue int) int {
	value := os.Getenv(envVar)
	if value == "" {
		return defaultValue
	}

	intValue, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return intValue
}

// GetEnvBool parses a boolean from the environment variable.
// If the variable is not set or cannot be parsed, returns the default value.
//
// Accepted values (case-insensitive):
//   - True: "1", "t", "true", "yes", "on"
//   - False: "0", "f", "false", "no", "off"
func GetEnvBool(envVar string, defaultValue bool) bool {
	value := os.Getenv(envVar)
	if value == "" {
		return defaultValue
	}

	boolValue, err := strconv.ParseBool(value)
	if err != nil {
		// Handle additional common boolean representations
		switch strings.ToLower(value) {
		case "yes", "on":
			return true
		case "no", "off":
			return false
		default:
			return defaultValue
		}
	}
	return boolValue
}
