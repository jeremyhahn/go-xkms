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

package handlers

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DefaultAWSCredentialsPath is the default path for AWS credentials file.
	DefaultAWSCredentialsPath = "~/.aws/credentials"

	// DefaultAWSProfile is the default AWS profile name.
	DefaultAWSProfile = "default"
)

// AWSCredentialsHandler writes AWS credentials to the credentials file.
type AWSCredentialsHandler struct {
	// CredentialsPath is the path to the credentials file.
	CredentialsPath string

	// Profile is the AWS profile name to write to.
	Profile string

	// Region is the region to set (optional).
	Region string

	// IncludeExpiration includes the expiration timestamp in the credentials file.
	IncludeExpiration bool
}

// NewAWSCredentialsHandler creates a new AWS credentials handler.
func NewAWSCredentialsHandler(profile string) *AWSCredentialsHandler {
	return &AWSCredentialsHandler{
		CredentialsPath:   DefaultAWSCredentialsPath,
		Profile:           profile,
		IncludeExpiration: true,
	}
}

// Handle writes AWS credentials to the credentials file.
func (h *AWSCredentialsHandler) Handle(ctx context.Context, data *TokenData) error {
	if err := ValidateTokenData(data); err != nil {
		return err
	}

	if data.AWSCredentials == nil {
		return ErrAWSResponseMissingCredentials
	}

	creds := data.AWSCredentials

	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return ErrAWSResponseMissingCredentials
	}

	profile := h.Profile
	if profile == "" {
		return ErrAWSProfileRequired
	}

	credPath := h.CredentialsPath
	if credPath == "" {
		return ErrAWSCredentialsPathRequired
	}

	// Expand home directory
	credPath = expandPath(credPath)

	// Ensure directory exists
	dir := filepath.Dir(credPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("%w: %v", ErrAWSCredentialsWrite, err)
	}

	// Read existing credentials file
	sections, err := h.readCredentialsFile(credPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("%w: %v", ErrAWSCredentialsRead, err)
	}

	// Build profile section
	profileSection := h.buildProfileSection(creds)

	// Update or add the profile
	sections[profile] = profileSection

	// Write back the credentials file
	if err := h.writeCredentialsFile(credPath, sections); err != nil {
		return fmt.Errorf("%w: %v", ErrAWSCredentialsWrite, err)
	}

	return nil
}

// Name returns the handler's identifier.
func (h *AWSCredentialsHandler) Name() string {
	return "aws-credentials"
}

// buildProfileSection creates the profile section content.
func (h *AWSCredentialsHandler) buildProfileSection(creds *AWSCredentials) map[string]string {
	section := map[string]string{
		"aws_access_key_id":     creds.AccessKeyID,
		"aws_secret_access_key": creds.SecretAccessKey,
	}

	if creds.SessionToken != "" {
		section["aws_session_token"] = creds.SessionToken
	}

	if h.Region != "" {
		section["region"] = h.Region
	} else if creds.Region != "" {
		section["region"] = creds.Region
	}

	if h.IncludeExpiration && !creds.Expiration.IsZero() {
		section["aws_credential_expiration"] = creds.Expiration.Format("2006-01-02T15:04:05Z")
	}

	return section
}

// readCredentialsFile reads and parses the AWS credentials file.
func (h *AWSCredentialsHandler) readCredentialsFile(path string) (map[string]map[string]string, error) {
	sections := make(map[string]map[string]string)

	file, err := os.Open(path)
	if err != nil {
		return sections, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Check for section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.TrimPrefix(strings.TrimSuffix(line, "]"), "[")
			if _, exists := sections[currentSection]; !exists {
				sections[currentSection] = make(map[string]string)
			}
			continue
		}

		// Parse key-value pair
		if currentSection != "" {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				sections[currentSection][key] = value
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return sections, nil
}

// writeCredentialsFile writes the credentials file.
func (h *AWSCredentialsHandler) writeCredentialsFile(path string, sections map[string]map[string]string) error {
	// Create temporary file in the same directory
	dir := filepath.Dir(path)
	tempFile, err := os.CreateTemp(dir, ".aws-credentials-*")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath) // Clean up if we fail

	writer := bufio.NewWriter(tempFile)

	// Define key order for consistent output
	keyOrder := []string{
		"aws_access_key_id",
		"aws_secret_access_key",
		"aws_session_token",
		"region",
		"aws_credential_expiration",
	}

	first := true
	for profile, section := range sections {
		if !first {
			writer.WriteString("\n")
		}
		first = false

		fmt.Fprintf(writer, "[%s]\n", profile)

		// Write keys in order
		written := make(map[string]bool)
		for _, key := range keyOrder {
			if value, exists := section[key]; exists {
				fmt.Fprintf(writer, "%s = %s\n", key, value)
				written[key] = true
			}
		}

		// Write any remaining keys not in our predefined order
		for key, value := range section {
			if !written[key] {
				fmt.Fprintf(writer, "%s = %s\n", key, value)
			}
		}
	}

	if err := writer.Flush(); err != nil {
		tempFile.Close()
		return err
	}

	if err := tempFile.Close(); err != nil {
		return err
	}

	// Set permissions before rename
	if err := os.Chmod(tempPath, 0600); err != nil {
		return err
	}

	// Atomic rename
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}

	return nil
}

// expandPath expands ~ to the home directory.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

// WithPath sets the credentials file path.
func (h *AWSCredentialsHandler) WithPath(path string) *AWSCredentialsHandler {
	h.CredentialsPath = path
	return h
}

// WithRegion sets the region.
func (h *AWSCredentialsHandler) WithRegion(region string) *AWSCredentialsHandler {
	h.Region = region
	return h
}

// WithExpiration enables/disables expiration timestamp.
func (h *AWSCredentialsHandler) WithExpiration(include bool) *AWSCredentialsHandler {
	h.IncludeExpiration = include
	return h
}
