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
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Real-shaped STS credentials: a 20-character temporary access key ID, a
// 40-character secret using '/' and '+', and a padded base64 session token.
const (
	realAccessKeyID     = "ASIAY34FZKBOKMUTVV7A"
	realSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY+EXAMPLEKE"
	realSessionToken    = "IQoJb3JpZ2luX2VjEHcaCXVzLWVhc3QtMSJHMEUCIQD6m+H/2Zexample/9Tu0Gr8sPWfnbfOaQ7ss4X8L3MgIgaw=="
)

// existingCredentials is the file a user already has before xkey runs.
const existingCredentials = `[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = defaultsecret

[work]
aws_access_key_id = AKIAWORKWORKWORK0001
aws_secret_access_key = worksecret
region = eu-west-1
`

// sandboxHome points HOME and AWS_SHARED_CREDENTIALS_FILE into a fresh
// temporary directory, so a handler using DefaultAWSCredentialsPath can
// never reach the real home, and returns the credentials path inside it.
func sandboxHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	credPath := filepath.Join(home, ".aws", "credentials")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credPath)
	if got := expandPath(DefaultAWSCredentialsPath); got != credPath {
		t.Fatalf("default path expands to %q, want %q inside the sandbox", got, credPath)
	}
	return credPath
}

// writeExisting creates the pre-existing credentials file at credPath.
func writeExisting(t *testing.T, credPath string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(credPath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(credPath, []byte(existingCredentials), 0600); err != nil {
		t.Fatalf("write existing credentials: %v", err)
	}
}

// dirEntries lists the names in dir, to detect leftover temporary files.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func validCredentials() *AWSCredentials {
	return &AWSCredentials{
		AccessKeyID:     realAccessKeyID,
		SecretAccessKey: realSecretAccessKey,
		SessionToken:    realSessionToken,
		Region:          "us-east-1",
	}
}

func TestAWSCredentialsHandler_RefusesInjection(t *testing.T) {
	tests := []struct {
		name     string
		profile  string
		region   string
		mutate   func(c *AWSCredentials)
		sentinel error
	}{
		{
			name:     "access key ID with newline injects credential_process",
			mutate:   func(c *AWSCredentials) { c.AccessKeyID = realAccessKeyID + "\ncredential_process = /bin/sh -c id" },
			sentinel: ErrAWSInvalidAccessKeyID,
		},
		{
			name:     "access key ID with carriage return",
			mutate:   func(c *AWSCredentials) { c.AccessKeyID = realAccessKeyID + "\rX" },
			sentinel: ErrAWSInvalidAccessKeyID,
		},
		{
			name:     "access key ID with NUL",
			mutate:   func(c *AWSCredentials) { c.AccessKeyID = "ASIAY34FZKBO\x00KMUTVV7A" },
			sentinel: ErrAWSInvalidAccessKeyID,
		},
		{
			name:     "access key ID shaped as a key assignment",
			mutate:   func(c *AWSCredentials) { c.AccessKeyID = "CREDENTIALPROCESS=CALC" },
			sentinel: ErrAWSInvalidAccessKeyID,
		},
		{
			name:     "secret with newline injects a profile",
			mutate:   func(c *AWSCredentials) { c.SecretAccessKey = "abc\n[evil]\ncredential_process = /bin/sh" },
			sentinel: ErrAWSInvalidSecretAccessKey,
		},
		{
			name:     "secret with carriage return",
			mutate:   func(c *AWSCredentials) { c.SecretAccessKey = "abc\rcredential_process=x" },
			sentinel: ErrAWSInvalidSecretAccessKey,
		},
		{
			name:     "secret with NUL",
			mutate:   func(c *AWSCredentials) { c.SecretAccessKey = "abc\x00def" },
			sentinel: ErrAWSInvalidSecretAccessKey,
		},
		{
			name:     "session token with newline",
			mutate:   func(c *AWSCredentials) { c.SessionToken = "abc\ncredential_process=/bin/sh" },
			sentinel: ErrAWSInvalidSessionToken,
		},
		{
			name:     "session token with section bracket",
			mutate:   func(c *AWSCredentials) { c.SessionToken = "abc[evil]" },
			sentinel: ErrAWSInvalidSessionToken,
		},
		{
			name:     "session token with NUL",
			mutate:   func(c *AWSCredentials) { c.SessionToken = "abc\x00" },
			sentinel: ErrAWSInvalidSessionToken,
		},
		{
			name:     "profile closing the section and opening another",
			profile:  "default]\n[evil",
			sentinel: ErrAWSInvalidProfile,
		},
		{
			name:     "profile with opening bracket",
			profile:  "[evil",
			sentinel: ErrAWSInvalidProfile,
		},
		{
			name:     "profile shaped as a key assignment",
			profile:  "credential_process=/bin/sh",
			sentinel: ErrAWSInvalidProfile,
		},
		{
			name:     "profile with carriage return",
			profile:  "work\r",
			sentinel: ErrAWSInvalidProfile,
		},
		{
			name:     "profile with NUL",
			profile:  "work\x00",
			sentinel: ErrAWSInvalidProfile,
		},
		{
			name:     "region from the response with newline",
			mutate:   func(c *AWSCredentials) { c.Region = "us-east-1\ncredential_process=/bin/sh" },
			sentinel: ErrAWSInvalidRegion,
		},
		{
			name:     "configured region with key assignment",
			region:   "us-east-1 = x",
			sentinel: ErrAWSInvalidRegion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credPath := sandboxHome(t)
			writeExisting(t, credPath)
			before := dirEntries(t, filepath.Dir(credPath))

			profile := tt.profile
			if profile == "" {
				profile = "session"
			}
			creds := validCredentials()
			if tt.mutate != nil {
				tt.mutate(creds)
			}
			handler := NewAWSCredentialsHandler(profile).WithRegion(tt.region)

			err := handler.Handle(context.Background(), &TokenData{AWSCredentials: creds})
			if !errors.Is(err, tt.sentinel) {
				t.Fatalf("Handle() error = %v, want %v", err, tt.sentinel)
			}
			var detail *DetailError
			if !errors.As(err, &detail) {
				t.Fatalf("Handle() error = %T, want *DetailError", err)
			}
			if strings.Contains(err.Error(), "credential_process") || strings.Contains(err.Error(), "evil") {
				t.Errorf("error %q echoes the refused value", err)
			}

			got, readErr := os.ReadFile(credPath)
			if readErr != nil {
				t.Fatalf("read credentials: %v", readErr)
			}
			if !bytes.Equal(got, []byte(existingCredentials)) {
				t.Errorf("credentials file changed after refusal:\n%s", got)
			}
			if after := dirEntries(t, filepath.Dir(credPath)); !slices.Equal(before, after) {
				t.Errorf("directory entries = %v, want %v", after, before)
			}
		})
	}
}

func TestAWSCredentialsHandler_RefusesBeforeCreatingFile(t *testing.T) {
	credPath := sandboxHome(t)
	creds := validCredentials()
	creds.SecretAccessKey = "abc\ncredential_process=/bin/sh"

	err := NewAWSCredentialsHandler("default").Handle(context.Background(), &TokenData{AWSCredentials: creds})
	if !errors.Is(err, ErrAWSInvalidSecretAccessKey) {
		t.Fatalf("Handle() error = %v, want ErrAWSInvalidSecretAccessKey", err)
	}
	if _, statErr := os.Stat(filepath.Dir(credPath)); !os.IsNotExist(statErr) {
		t.Errorf("~/.aws was created for a refused write: stat error = %v", statErr)
	}
}

func TestAWSCredentialsHandler_RoundTrip(t *testing.T) {
	credPath := sandboxHome(t)
	writeExisting(t, credPath)
	// A loose mode on the existing file must not survive the rewrite.
	if err := os.Chmod(credPath, 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	creds := validCredentials()
	creds.Expiration = time.Date(2026, 9, 25, 14, 30, 0, 0, time.FixedZone("UTC+2", 2*60*60))

	if err := NewAWSCredentialsHandler("session").Handle(context.Background(), &TokenData{AWSCredentials: creds}); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	sections, err := NewAWSCredentialsHandler("session").readCredentialsFile(credPath)
	if err != nil {
		t.Fatalf("readCredentialsFile() error = %v", err)
	}

	want := map[string]map[string]string{
		"default": {
			"aws_access_key_id":     "AKIAIOSFODNN7EXAMPLE",
			"aws_secret_access_key": "defaultsecret",
		},
		"work": {
			"aws_access_key_id":     "AKIAWORKWORKWORK0001",
			"aws_secret_access_key": "worksecret",
			"region":                "eu-west-1",
		},
		"session": {
			"aws_access_key_id":         realAccessKeyID,
			"aws_secret_access_key":     realSecretAccessKey,
			"aws_session_token":         realSessionToken,
			"region":                    "us-east-1",
			"aws_credential_expiration": "2026-09-25T12:30:00Z",
		},
	}
	if !maps.EqualFunc(sections, want, maps.Equal) {
		t.Errorf("round-tripped sections = %v, want %v", sections, want)
	}

	info, err := os.Stat(credPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("credentials file mode = %o, want 0600", perm)
	}
	if entries := dirEntries(t, filepath.Dir(credPath)); !slices.Equal(entries, []string{"credentials"}) {
		t.Errorf("directory entries = %v, want only credentials", entries)
	}
}

func TestAWSValueRule_Check(t *testing.T) {
	tests := []struct {
		name  string
		rule  awsValueRule
		value string
		ok    bool
	}{
		{"access key 16 chars", awsAccessKeyIDRule, strings.Repeat("A", 16), true},
		{"access key 128 chars", awsAccessKeyIDRule, strings.Repeat("9", 128), true},
		{"access key 15 chars", awsAccessKeyIDRule, strings.Repeat("A", 15), false},
		{"access key 129 chars", awsAccessKeyIDRule, strings.Repeat("A", 129), false},
		{"access key lowercase", awsAccessKeyIDRule, "asiay34fzkbokmutvv7a", false},
		{"secret with every printable symbol", awsSecretAccessKeyRule, "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", true},
		{"secret with space", awsSecretAccessKeyRule, "abc def", false},
		{"secret with tab", awsSecretAccessKeyRule, "abc\tdef", false},
		{"secret with DEL", awsSecretAccessKeyRule, "abc\x7f", false},
		{"secret with non-ASCII", awsSecretAccessKeyRule, "abcé", false},
		{"secret empty", awsSecretAccessKeyRule, "", false},
		{"session token base64", awsSessionTokenRule, realSessionToken, true},
		{"session token base64url dash", awsSessionTokenRule, "abc-def", false},
		{"session token base64url underscore", awsSessionTokenRule, "abc_def", false},
		{"profile with allowed punctuation", awsProfileRule, "Admin-123456789012_role.dev@org+x:y/z", true},
		{"profile with space", awsProfileRule, "my profile", false},
		{"profile with closing bracket", awsProfileRule, "evil]", false},
		{"profile starting with comment", awsProfileRule, "#evil", false},
		{"profile empty", awsProfileRule, "", false},
		{"region", awsRegionRule, "ap-southeast-2", true},
		{"region uppercase", awsRegionRule, "US-EAST-1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.check(tt.value)
			if tt.ok && err != nil {
				t.Errorf("check() error = %v, want nil", err)
			}
			if !tt.ok && !errors.Is(err, tt.rule.sentinel) {
				t.Errorf("check() error = %v, want %v", err, tt.rule.sentinel)
			}
		})
	}
}

func TestAWSValueRule_CheckReportsPositionNotValue(t *testing.T) {
	err := awsSecretAccessKeyRule.check("topsecret\nmore")
	if err == nil {
		t.Fatal("check() error = nil, want refusal")
	}
	if got, want := err.Error(), "handlers: invalid AWS secret access key: disallowed byte at offset 9"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}

	err = awsAccessKeyIDRule.check("SHORT")
	if got, want := err.Error(), "handlers: invalid AWS access key ID: length 5 out of range"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

func TestFormatCredentialsFile(t *testing.T) {
	sections := map[string]map[string]string{
		"work": {
			"zeta":                  "last",
			"region":                "eu-west-1",
			"aws_access_key_id":     "AKIAWORKWORKWORK0001",
			"alpha":                 "first",
			"aws_secret_access_key": "worksecret",
		},
		"default": {
			"aws_secret_access_key": "defaultsecret",
			"aws_access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		},
	}

	want := `[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = defaultsecret

[work]
aws_access_key_id = AKIAWORKWORKWORK0001
aws_secret_access_key = worksecret
region = eu-west-1
alpha = first
zeta = last
`
	if got := string(formatCredentialsFile(sections)); got != want {
		t.Errorf("formatCredentialsFile() =\n%s\nwant\n%s", got, want)
	}
	if got := formatCredentialsFile(map[string]map[string]string{}); len(got) != 0 {
		t.Errorf("formatCredentialsFile(empty) = %q, want empty", got)
	}
}

func TestAWSCredentialsHandler_writeCredentialsFileErrors(t *testing.T) {
	sections := map[string]map[string]string{"default": {"aws_access_key_id": realAccessKeyID}}
	handler := NewAWSCredentialsHandler("default")

	t.Run("missing directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "absent", "credentials")
		if err := handler.writeCredentialsFile(path, sections); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("writeCredentialsFile() error = %v, want os.ErrNotExist", err)
		}
	})

	t.Run("rename onto a directory removes the temporary file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "credentials")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := handler.writeCredentialsFile(path, sections); err == nil {
			t.Fatal("writeCredentialsFile() error = nil, want rename failure")
		}
		if entries := dirEntries(t, dir); !slices.Equal(entries, []string{"credentials"}) {
			t.Errorf("directory entries = %v, want only credentials", entries)
		}
	})
}

func TestSyncDir(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Errorf("syncDir() error = %v, want nil", err)
	}
	if err := syncDir(filepath.Join(t.TempDir(), "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("syncDir(absent) error = %v, want os.ErrNotExist", err)
	}
}
