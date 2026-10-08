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
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
)

const (
	// DefaultAWSCredentialsPath is the default path for AWS credentials file.
	DefaultAWSCredentialsPath = "~/.aws/credentials"

	// DefaultAWSProfile is the default AWS profile name.
	DefaultAWSProfile = "default"

	// awsCredentialsFileMode is the permission set on the credentials file.
	awsCredentialsFileMode os.FileMode = 0600
)

// awsKeyOrder is the order known keys are written in within a profile.
var awsKeyOrder = []string{
	"aws_access_key_id",
	"aws_secret_access_key",
	"aws_session_token",
	"region",
	"aws_credential_expiration",
}

// awsValueRule constrains one value written to the credentials file. Every
// byte must satisfy allowed and the length must fall within [minLen, maxLen];
// a zero maxLen means unbounded.
type awsValueRule struct {
	sentinel error
	minLen   int
	maxLen   int
	allowed  func(c byte) bool
}

// The rules refuse, rather than sanitise, any value that could end its
// line or open a section: none of them admits a newline, carriage return,
// NUL or other control byte, and only the secret admits '[' or '='.
var (
	awsAccessKeyIDRule = awsValueRule{
		sentinel: ErrAWSInvalidAccessKeyID,
		minLen:   16,
		maxLen:   128,
		allowed:  func(c byte) bool { return isUpper(c) || isDigit(c) },
	}
	awsSecretAccessKeyRule = awsValueRule{
		sentinel: ErrAWSInvalidSecretAccessKey,
		minLen:   1,
		allowed:  func(c byte) bool { return c > ' ' && c < 0x7f },
	}
	awsSessionTokenRule = awsValueRule{
		sentinel: ErrAWSInvalidSessionToken,
		minLen:   1,
		allowed: func(c byte) bool {
			return isUpper(c) || isLower(c) || isDigit(c) || c == '+' || c == '/' || c == '='
		},
	}
	awsProfileRule = awsValueRule{
		sentinel: ErrAWSInvalidProfile,
		minLen:   1,
		allowed: func(c byte) bool {
			return isUpper(c) || isLower(c) || isDigit(c) || strings.IndexByte("._-@+:/", c) >= 0
		},
	}
	awsRegionRule = awsValueRule{
		sentinel: ErrAWSInvalidRegion,
		minLen:   1,
		allowed:  func(c byte) bool { return isLower(c) || isDigit(c) || c == '-' },
	}
)

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// check returns nil when value satisfies the rule. The error names the
// failing length or byte offset but never echoes the value, which may be
// a secret.
func (r awsValueRule) check(value string) error {
	if len(value) < r.minLen || (r.maxLen > 0 && len(value) > r.maxLen) {
		return &DetailError{Err: r.sentinel, Detail: ": length " + strconv.Itoa(len(value)) + " out of range"}
	}
	for i := range len(value) {
		if !r.allowed(value[i]) {
			return &DetailError{Err: r.sentinel, Detail: ": disallowed byte at offset " + strconv.Itoa(i)}
		}
	}
	return nil
}

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

// Handle writes AWS credentials to the credentials file. It replaces the
// handler's profile section and preserves every other profile. Every value
// written is validated first; an invalid value is refused with a typed error
// and the file is left untouched.
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

	if err := h.validate(creds); err != nil {
		return err
	}

	// Expand home directory
	credPath = expandPath(credPath)

	// Ensure directory exists
	dir := filepath.Dir(credPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return &SentinelCauseError{Sentinel: ErrAWSCredentialsWrite, Cause: err}
	}

	// Read existing credentials file
	sections, err := h.readCredentialsFile(credPath)
	if err != nil && !os.IsNotExist(err) {
		return &SentinelCauseError{Sentinel: ErrAWSCredentialsRead, Cause: err}
	}

	// Update or add the profile
	sections[profile] = h.buildProfileSection(creds)

	// Write back the credentials file
	if err := h.writeCredentialsFile(credPath, sections); err != nil {
		return &SentinelCauseError{Sentinel: ErrAWSCredentialsWrite, Cause: err}
	}

	return nil
}

// Name returns the handler's identifier.
func (h *AWSCredentialsHandler) Name() string {
	return "aws-credentials"
}

// validate checks the profile name and every credential value that
// buildProfileSection would write.
func (h *AWSCredentialsHandler) validate(creds *AWSCredentials) error {
	if err := awsProfileRule.check(h.Profile); err != nil {
		return err
	}
	if err := awsAccessKeyIDRule.check(creds.AccessKeyID); err != nil {
		return err
	}
	if err := awsSecretAccessKeyRule.check(creds.SecretAccessKey); err != nil {
		return err
	}
	if creds.SessionToken != "" {
		if err := awsSessionTokenRule.check(creds.SessionToken); err != nil {
			return err
		}
	}
	if region := h.region(creds); region != "" {
		if err := awsRegionRule.check(region); err != nil {
			return err
		}
	}
	return nil
}

// region returns the configured region, falling back to the one in creds.
func (h *AWSCredentialsHandler) region(creds *AWSCredentials) string {
	if h.Region != "" {
		return h.Region
	}
	return creds.Region
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

	if region := h.region(creds); region != "" {
		section["region"] = region
	}

	if h.IncludeExpiration && !creds.Expiration.IsZero() {
		section["aws_credential_expiration"] = creds.Expiration.UTC().Format("2006-01-02T15:04:05Z")
	}

	return section
}

// readCredentialsFile reads and parses the AWS credentials file.
func (h *AWSCredentialsHandler) readCredentialsFile(path string) (sections map[string]map[string]string, err error) {
	sections = make(map[string]map[string]string)

	file, err := os.Open(path)
	if err != nil {
		return sections, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()

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

// formatCredentialsFile renders sections as INI text. Profiles are written
// in name order; within a profile the known keys come first in awsKeyOrder,
// then any other keys in name order.
func formatCredentialsFile(sections map[string]map[string]string) []byte {
	var b strings.Builder
	for i, profile := range slices.Sorted(maps.Keys(sections)) {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("[" + profile + "]\n")

		section := sections[profile]
		for _, key := range awsKeyOrder {
			if value, exists := section[key]; exists {
				b.WriteString(key + " = " + value + "\n")
			}
		}
		for _, key := range slices.Sorted(maps.Keys(section)) {
			if !slices.Contains(awsKeyOrder, key) {
				b.WriteString(key + " = " + section[key] + "\n")
			}
		}
	}
	return []byte(b.String())
}

// writeCredentialsFile replaces the credentials file atomically with mode
// awsCredentialsFileMode. A failure before the rename leaves the existing file
// untouched.
func (h *AWSCredentialsHandler) writeCredentialsFile(path string, sections map[string]map[string]string) error {
	return fsutil.WriteFileAtomic(path, formatCredentialsFile(sections), awsCredentialsFileMode)
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
