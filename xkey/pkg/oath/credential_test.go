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

package oath

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewCredential_Success(t *testing.T) {
	tests := []struct {
		name     string
		credName string
		issuer   string
		otpType  string
	}{
		{
			name:     "TOTP with issuer",
			credName: "user@example.com",
			issuer:   "GitHub",
			otpType:  TypeTOTP,
		},
		{
			name:     "HOTP with issuer",
			credName: "admin@test.com",
			issuer:   "AWS",
			otpType:  TypeHOTP,
		},
		{
			name:     "TOTP without issuer",
			credName: "myaccount",
			issuer:   "",
			otpType:  TypeTOTP,
		},
		{
			name:     "HOTP without issuer",
			credName: "testuser",
			issuer:   "",
			otpType:  TypeHOTP,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := NewCredential(tc.credName, tc.issuer, tc.otpType)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cred.Name != tc.credName {
				t.Errorf("expected name %q, got %q", tc.credName, cred.Name)
			}
			if cred.Issuer != tc.issuer {
				t.Errorf("expected issuer %q, got %q", tc.issuer, cred.Issuer)
			}
			if cred.Type != tc.otpType {
				t.Errorf("expected type %q, got %q", tc.otpType, cred.Type)
			}
			if cred.Secret == "" {
				t.Error("expected non-empty secret")
			}
			if cred.Algorithm != DefaultAlgorithm {
				t.Errorf("expected algorithm %q, got %q", DefaultAlgorithm, cred.Algorithm)
			}
			if cred.Digits != DefaultDigits {
				t.Errorf("expected digits %d, got %d", DefaultDigits, cred.Digits)
			}
			if cred.Period != DefaultPeriod {
				t.Errorf("expected period %d, got %d", DefaultPeriod, cred.Period)
			}
			if cred.ID == "" {
				t.Error("expected non-empty ID")
			}
			if cred.CreatedAt.IsZero() {
				t.Error("expected non-zero CreatedAt")
			}
		})
	}
}

func TestNewCredential_Errors(t *testing.T) {
	tests := []struct {
		name     string
		credName string
		issuer   string
		otpType  string
		wantErr  error
	}{
		{
			name:     "empty name",
			credName: "",
			issuer:   "GitHub",
			otpType:  TypeTOTP,
			wantErr:  ErrInvalidCredential,
		},
		{
			name:     "invalid type",
			credName: "user@example.com",
			issuer:   "GitHub",
			otpType:  "invalid",
			wantErr:  ErrInvalidType,
		},
		{
			name:     "empty type",
			credName: "user@example.com",
			issuer:   "GitHub",
			otpType:  "",
			wantErr:  ErrInvalidType,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewCredential(tc.credName, tc.issuer, tc.otpType)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr.Error()) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr.Error(), err.Error())
			}
		})
	}
}

func TestParseURI_Success(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		wantType    string
		wantIssuer  string
		wantAccount string
		wantAlgo    string
		wantDigits  int
		wantPeriod  int
		wantCounter uint64
	}{
		{
			name:        "standard TOTP URI",
			uri:         "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
			wantType:    TypeTOTP,
			wantIssuer:  "GitHub",
			wantAccount: "user@example.com",
			wantAlgo:    AlgorithmSHA1,
			wantDigits:  6,
			wantPeriod:  30,
		},
		{
			name:        "TOTP with SHA256",
			uri:         "otpauth://totp/AWS:admin?secret=JBSWY3DPEHPK3PXP&issuer=AWS&algorithm=SHA256&digits=8&period=60",
			wantType:    TypeTOTP,
			wantIssuer:  "AWS",
			wantAccount: "admin",
			wantAlgo:    AlgorithmSHA256,
			wantDigits:  8,
			wantPeriod:  60,
		},
		{
			name:        "TOTP with SHA512",
			uri:         "otpauth://totp/Google:test@gmail.com?secret=JBSWY3DPEHPK3PXP&algorithm=sha512",
			wantType:    TypeTOTP,
			wantIssuer:  "Google",
			wantAccount: "test@gmail.com",
			wantAlgo:    AlgorithmSHA512,
			wantDigits:  6,
			wantPeriod:  30,
		},
		{
			name:        "HOTP with counter",
			uri:         "otpauth://hotp/Service:user?secret=JBSWY3DPEHPK3PXP&counter=42",
			wantType:    TypeHOTP,
			wantIssuer:  "Service",
			wantAccount: "user",
			wantAlgo:    AlgorithmSHA1,
			wantDigits:  6,
			wantCounter: 42,
		},
		{
			name:        "TOTP without issuer in label",
			uri:         "otpauth://totp/myaccount?secret=JBSWY3DPEHPK3PXP&issuer=MyService",
			wantType:    TypeTOTP,
			wantIssuer:  "MyService",
			wantAccount: "myaccount",
			wantAlgo:    AlgorithmSHA1,
			wantDigits:  6,
			wantPeriod:  30,
		},
		{
			name:        "TOTP with 7 digits",
			uri:         "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&digits=7",
			wantType:    TypeTOTP,
			wantIssuer:  "Test",
			wantAccount: "user",
			wantAlgo:    AlgorithmSHA1,
			wantDigits:  7,
			wantPeriod:  30,
		},
		{
			name:        "HOTP without counter",
			uri:         "otpauth://hotp/MyApp:user?secret=JBSWY3DPEHPK3PXP",
			wantType:    TypeHOTP,
			wantIssuer:  "MyApp",
			wantAccount: "user",
			wantAlgo:    AlgorithmSHA1,
			wantDigits:  6,
			wantCounter: 0,
		},
		{
			name:        "lowercase secret",
			uri:         "otpauth://totp/Test:user?secret=jbswy3dpehpk3pxp",
			wantType:    TypeTOTP,
			wantIssuer:  "Test",
			wantAccount: "user",
			wantAlgo:    AlgorithmSHA1,
			wantDigits:  6,
			wantPeriod:  30,
		},
		{
			name:        "secret with spaces",
			uri:         "otpauth://totp/Test:user?secret=JBSW Y3DP EHPK 3PXP",
			wantType:    TypeTOTP,
			wantIssuer:  "Test",
			wantAccount: "user",
			wantAlgo:    AlgorithmSHA1,
			wantDigits:  6,
			wantPeriod:  30,
		},
		{
			name:        "secret with dashes",
			uri:         "otpauth://totp/Test:user?secret=JBSW-Y3DP-EHPK-3PXP",
			wantType:    TypeTOTP,
			wantIssuer:  "Test",
			wantAccount: "user",
			wantAlgo:    AlgorithmSHA1,
			wantDigits:  6,
			wantPeriod:  30,
		},
		{
			name:        "secret with padding",
			uri:         "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP====",
			wantType:    TypeTOTP,
			wantIssuer:  "Test",
			wantAccount: "user",
			wantAlgo:    AlgorithmSHA1,
			wantDigits:  6,
			wantPeriod:  30,
		},
		{
			name:        "secret with mixed case spaces and dashes",
			uri:         "otpauth://totp/Test:user?secret=jbsw-y3dp%20EHPK%203pxp",
			wantType:    TypeTOTP,
			wantIssuer:  "Test",
			wantAccount: "user",
			wantAlgo:    AlgorithmSHA1,
			wantDigits:  6,
			wantPeriod:  30,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := ParseURI(tc.uri)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cred.Type != tc.wantType {
				t.Errorf("expected type %q, got %q", tc.wantType, cred.Type)
			}
			if cred.Issuer != tc.wantIssuer {
				t.Errorf("expected issuer %q, got %q", tc.wantIssuer, cred.Issuer)
			}
			if cred.AccountName != tc.wantAccount {
				t.Errorf("expected account %q, got %q", tc.wantAccount, cred.AccountName)
			}
			if cred.Algorithm != tc.wantAlgo {
				t.Errorf("expected algorithm %q, got %q", tc.wantAlgo, cred.Algorithm)
			}
			if cred.Digits != tc.wantDigits {
				t.Errorf("expected digits %d, got %d", tc.wantDigits, cred.Digits)
			}
			if tc.wantType == TypeTOTP && cred.Period != tc.wantPeriod {
				t.Errorf("expected period %d, got %d", tc.wantPeriod, cred.Period)
			}
			if tc.wantType == TypeHOTP && cred.Counter != tc.wantCounter {
				t.Errorf("expected counter %d, got %d", tc.wantCounter, cred.Counter)
			}
			if cred.Secret == "" {
				t.Error("expected non-empty secret")
			}
		})
	}
}

func TestParseURI_Errors(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr error
	}{
		{
			name:    "invalid URL",
			uri:     "not a valid url\x00",
			wantErr: ErrInvalidURI,
		},
		{
			name:    "wrong scheme",
			uri:     "https://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP",
			wantErr: ErrInvalidURI,
		},
		{
			name:    "invalid OTP type",
			uri:     "otpauth://invalid/GitHub:user?secret=JBSWY3DPEHPK3PXP",
			wantErr: ErrInvalidType,
		},
		{
			name:    "missing secret",
			uri:     "otpauth://totp/GitHub:user?issuer=GitHub",
			wantErr: ErrInvalidURI,
		},
		{
			name:    "invalid base32 secret",
			uri:     "otpauth://totp/GitHub:user?secret=invalid!!!base32",
			wantErr: ErrInvalidSecret,
		},
		{
			name:    "invalid algorithm",
			uri:     "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
			wantErr: ErrInvalidAlgorithm,
		},
		{
			name:    "digits too low",
			uri:     "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&digits=5",
			wantErr: ErrInvalidDigits,
		},
		{
			name:    "digits too high",
			uri:     "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&digits=9",
			wantErr: ErrInvalidDigits,
		},
		{
			name:    "invalid digits string",
			uri:     "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&digits=abc",
			wantErr: ErrInvalidDigits,
		},
		{
			name:    "invalid period zero",
			uri:     "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&period=0",
			wantErr: ErrInvalidPeriod,
		},
		{
			name:    "invalid period negative",
			uri:     "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&period=-1",
			wantErr: ErrInvalidPeriod,
		},
		{
			name:    "invalid period string",
			uri:     "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&period=abc",
			wantErr: ErrInvalidPeriod,
		},
		{
			name:    "invalid counter string",
			uri:     "otpauth://hotp/GitHub:user?secret=JBSWY3DPEHPK3PXP&counter=abc",
			wantErr: ErrInvalidURI,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseURI(tc.uri)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr.Error()) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr.Error(), err.Error())
			}
		})
	}
}

func TestCredential_ToURI_Success(t *testing.T) {
	tests := []struct {
		name      string
		cred      *Credential
		wantParts []string
	}{
		{
			name: "TOTP with defaults",
			cred: &Credential{
				Type:        TypeTOTP,
				Issuer:      "GitHub",
				AccountName: "user@example.com",
				Secret:      "JBSWY3DPEHPK3PXP",
				Algorithm:   AlgorithmSHA1,
				Digits:      6,
				Period:      30,
			},
			wantParts: []string{
				"otpauth://totp/",
				"GitHub",
				"user@example.com",
				"secret=JBSWY3DPEHPK3PXP",
				"issuer=GitHub",
			},
		},
		{
			name: "TOTP with non-default values",
			cred: &Credential{
				Type:        TypeTOTP,
				Issuer:      "AWS",
				AccountName: "admin",
				Secret:      "JBSWY3DPEHPK3PXP",
				Algorithm:   AlgorithmSHA256,
				Digits:      8,
				Period:      60,
			},
			wantParts: []string{
				"otpauth://totp/",
				"algorithm=SHA256",
				"digits=8",
				"period=60",
			},
		},
		{
			name: "HOTP with counter",
			cred: &Credential{
				Type:        TypeHOTP,
				Issuer:      "Service",
				AccountName: "user",
				Secret:      "JBSWY3DPEHPK3PXP",
				Algorithm:   AlgorithmSHA1,
				Digits:      6,
				Counter:     42,
			},
			wantParts: []string{
				"otpauth://hotp/",
				"counter=42",
			},
		},
		{
			name: "TOTP without issuer",
			cred: &Credential{
				Type:        TypeTOTP,
				Issuer:      "",
				AccountName: "myaccount",
				Secret:      "JBSWY3DPEHPK3PXP",
				Algorithm:   AlgorithmSHA1,
				Digits:      6,
				Period:      30,
			},
			wantParts: []string{
				"otpauth://totp/myaccount",
				"secret=JBSWY3DPEHPK3PXP",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uri := tc.cred.ToURI()
			for _, part := range tc.wantParts {
				if !strings.Contains(uri, part) {
					t.Errorf("expected URI to contain %q, got %q", part, uri)
				}
			}
		})
	}
}

func TestCredential_ToURI_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{
			name: "standard TOTP",
			uri:  "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
		},
		{
			name: "TOTP with SHA256",
			uri:  "otpauth://totp/AWS:admin?secret=JBSWY3DPEHPK3PXP&issuer=AWS&algorithm=SHA256&digits=8&period=60",
		},
		{
			name: "HOTP with counter",
			uri:  "otpauth://hotp/Service:user?secret=JBSWY3DPEHPK3PXP&issuer=Service&counter=42",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := ParseURI(tc.uri)
			if err != nil {
				t.Fatalf("failed to parse URI: %v", err)
			}

			generatedURI := cred.ToURI()

			// Parse the generated URI and compare fields
			cred2, err := ParseURI(generatedURI)
			if err != nil {
				t.Fatalf("failed to parse generated URI: %v", err)
			}

			if cred.Type != cred2.Type {
				t.Errorf("type mismatch: %q vs %q", cred.Type, cred2.Type)
			}
			if cred.Issuer != cred2.Issuer {
				t.Errorf("issuer mismatch: %q vs %q", cred.Issuer, cred2.Issuer)
			}
			if cred.AccountName != cred2.AccountName {
				t.Errorf("account mismatch: %q vs %q", cred.AccountName, cred2.AccountName)
			}
			if cred.Secret != cred2.Secret {
				t.Errorf("secret mismatch: %q vs %q", cred.Secret, cred2.Secret)
			}
			if cred.Algorithm != cred2.Algorithm {
				t.Errorf("algorithm mismatch: %q vs %q", cred.Algorithm, cred2.Algorithm)
			}
			if cred.Digits != cred2.Digits {
				t.Errorf("digits mismatch: %d vs %d", cred.Digits, cred2.Digits)
			}
			if cred.Period != cred2.Period {
				t.Errorf("period mismatch: %d vs %d", cred.Period, cred2.Period)
			}
			if cred.Counter != cred2.Counter {
				t.Errorf("counter mismatch: %d vs %d", cred.Counter, cred2.Counter)
			}
		})
	}
}

func TestCredential_Validate_Success(t *testing.T) {
	tests := []struct {
		name string
		cred *Credential
	}{
		{
			name: "valid TOTP credential",
			cred: &Credential{
				Name:      "test",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      TypeTOTP,
				Algorithm: AlgorithmSHA1,
				Digits:    6,
				Period:    30,
			},
		},
		{
			name: "valid HOTP credential",
			cred: &Credential{
				Name:      "test",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      TypeHOTP,
				Algorithm: AlgorithmSHA256,
				Digits:    8,
				Counter:   0,
			},
		},
		{
			name: "valid with SHA512",
			cred: &Credential{
				Name:      "test",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      TypeTOTP,
				Algorithm: AlgorithmSHA512,
				Digits:    7,
				Period:    60,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cred.Validate(); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestCredential_Validate_Errors(t *testing.T) {
	tests := []struct {
		name    string
		cred    *Credential
		wantErr error
	}{
		{
			name: "empty name",
			cred: &Credential{
				Name:      "",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      TypeTOTP,
				Algorithm: AlgorithmSHA1,
				Digits:    6,
				Period:    30,
			},
			wantErr: ErrInvalidCredential,
		},
		{
			name: "empty secret",
			cred: &Credential{
				Name:      "test",
				Secret:    "",
				Type:      TypeTOTP,
				Algorithm: AlgorithmSHA1,
				Digits:    6,
				Period:    30,
			},
			wantErr: ErrInvalidSecret,
		},
		{
			name: "invalid type",
			cred: &Credential{
				Name:      "test",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      "invalid",
				Algorithm: AlgorithmSHA1,
				Digits:    6,
				Period:    30,
			},
			wantErr: ErrInvalidType,
		},
		{
			name: "invalid algorithm",
			cred: &Credential{
				Name:      "test",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      TypeTOTP,
				Algorithm: "MD5",
				Digits:    6,
				Period:    30,
			},
			wantErr: ErrInvalidAlgorithm,
		},
		{
			name: "digits too low",
			cred: &Credential{
				Name:      "test",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      TypeTOTP,
				Algorithm: AlgorithmSHA1,
				Digits:    5,
				Period:    30,
			},
			wantErr: ErrInvalidDigits,
		},
		{
			name: "digits too high",
			cred: &Credential{
				Name:      "test",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      TypeTOTP,
				Algorithm: AlgorithmSHA1,
				Digits:    9,
				Period:    30,
			},
			wantErr: ErrInvalidDigits,
		},
		{
			name: "TOTP with zero period",
			cred: &Credential{
				Name:      "test",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      TypeTOTP,
				Algorithm: AlgorithmSHA1,
				Digits:    6,
				Period:    0,
			},
			wantErr: ErrInvalidPeriod,
		},
		{
			name: "TOTP with negative period",
			cred: &Credential{
				Name:      "test",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      TypeTOTP,
				Algorithm: AlgorithmSHA1,
				Digits:    6,
				Period:    -1,
			},
			wantErr: ErrInvalidPeriod,
		},
		{
			name: "invalid base32 secret",
			cred: &Credential{
				Name:      "test",
				Secret:    "invalid!!!secret",
				Type:      TypeTOTP,
				Algorithm: AlgorithmSHA1,
				Digits:    6,
				Period:    30,
			},
			wantErr: ErrInvalidSecret,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cred.Validate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr.Error()) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr.Error(), err.Error())
			}
		})
	}
}

func TestGenerateSecret_Success(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{name: "10 bytes", length: 10},
		{name: "20 bytes", length: 20},
		{name: "32 bytes", length: 32},
		{name: "64 bytes", length: 64},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secret, err := GenerateSecret(tc.length)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if secret == "" {
				t.Error("expected non-empty secret")
			}

			// Verify it's valid base32
			cred := &Credential{
				Name:      "test",
				Secret:    secret,
				Type:      TypeTOTP,
				Algorithm: AlgorithmSHA1,
				Digits:    6,
				Period:    30,
			}
			if err := cred.Validate(); err != nil {
				t.Errorf("generated secret is not valid base32: %v", err)
			}
		})
	}
}

func TestGenerateSecret_Uniqueness(t *testing.T) {
	secrets := make(map[string]bool)
	for i := 0; i < 100; i++ {
		secret, err := GenerateSecret(20)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if secrets[secret] {
			t.Errorf("duplicate secret generated: %s", secret)
		}
		secrets[secret] = true
	}
}

func TestGenerateCredentialID(t *testing.T) {
	tests := []struct {
		name        string
		issuer      string
		accountName string
		wantPrefix  string
	}{
		{
			name:        "both issuer and account",
			issuer:      "GitHub",
			accountName: "user@example.com",
			wantPrefix:  "github:user@example.com",
		},
		{
			name:        "only issuer",
			issuer:      "AWS",
			accountName: "",
			wantPrefix:  "aws",
		},
		{
			name:        "only account",
			issuer:      "",
			accountName: "myaccount",
			wantPrefix:  "myaccount",
		},
		{
			name:        "uppercase issuer and account",
			issuer:      "GOOGLE",
			accountName: "USER@GMAIL.COM",
			wantPrefix:  "google:user@gmail.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := generateCredentialID(tc.issuer, tc.accountName)
			if !strings.HasPrefix(id, tc.wantPrefix) {
				t.Errorf("expected ID to start with %q, got %q", tc.wantPrefix, id)
			}
		})
	}
}

func TestGenerateCredentialID_RandomFallback(t *testing.T) {
	id1 := generateCredentialID("", "")
	id2 := generateCredentialID("", "")

	if !strings.HasPrefix(id1, "oath-") {
		t.Errorf("expected ID to start with 'oath-', got %q", id1)
	}
	if !strings.HasPrefix(id2, "oath-") {
		t.Errorf("expected ID to start with 'oath-', got %q", id2)
	}
	// Random IDs should be different
	if id1 == id2 {
		t.Error("expected different random IDs")
	}
}

func TestCredential_HOTP_ZeroPeriod(t *testing.T) {
	// HOTP credentials should not fail validation even with zero period
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    0, // HOTP doesn't use period
		Counter:   0,
	}

	// HOTP with zero period should still fail because period validation
	// only applies to TOTP. Let's check the actual behavior.
	err := cred.Validate()
	if err != nil {
		t.Errorf("HOTP should not require period, got error: %v", err)
	}
}

func TestParseURI_LabelParsing(t *testing.T) {
	// Test various label formats
	tests := []struct {
		name        string
		uri         string
		wantIssuer  string
		wantAccount string
	}{
		{
			name:        "issuer:account format",
			uri:         "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP",
			wantIssuer:  "GitHub",
			wantAccount: "user@example.com",
		},
		{
			name:        "only account name",
			uri:         "otpauth://totp/myaccount?secret=JBSWY3DPEHPK3PXP",
			wantIssuer:  "",
			wantAccount: "myaccount",
		},
		{
			name:        "issuer from query overrides label",
			uri:         "otpauth://totp/OldIssuer:user?secret=JBSWY3DPEHPK3PXP&issuer=NewIssuer",
			wantIssuer:  "NewIssuer",
			wantAccount: "user",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := ParseURI(tc.uri)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cred.Issuer != tc.wantIssuer {
				t.Errorf("expected issuer %q, got %q", tc.wantIssuer, cred.Issuer)
			}
			if cred.AccountName != tc.wantAccount {
				t.Errorf("expected account %q, got %q", tc.wantAccount, cred.AccountName)
			}
		})
	}
}

func TestParseURI_NameGeneration(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		wantName string
	}{
		{
			name:     "issuer and account combined",
			uri:      "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
			wantName: "GitHub (user@example.com)",
		},
		{
			name:     "only account",
			uri:      "otpauth://totp/myaccount?secret=JBSWY3DPEHPK3PXP",
			wantName: "myaccount",
		},
		{
			name:     "issuer only",
			uri:      "otpauth://totp/AWS:?secret=JBSWY3DPEHPK3PXP&issuer=AWS",
			wantName: "AWS",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := ParseURI(tc.uri)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cred.Name != tc.wantName {
				t.Errorf("expected name %q, got %q", tc.wantName, cred.Name)
			}
		})
	}
}

func TestNormalizeSecret(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantErr    bool
		wantResult string
	}{
		{
			name:       "standard uppercase",
			input:      "JBSWY3DPEHPK3PXP",
			wantErr:    false,
			wantResult: "JBSWY3DPEHPK3PXP",
		},
		{
			name:       "lowercase",
			input:      "jbswy3dpehpk3pxp",
			wantErr:    false,
			wantResult: "JBSWY3DPEHPK3PXP",
		},
		{
			name:       "mixed case",
			input:      "JbSwY3DpEhPk3PxP",
			wantErr:    false,
			wantResult: "JBSWY3DPEHPK3PXP",
		},
		{
			name:       "with spaces",
			input:      "JBSW Y3DP EHPK 3PXP",
			wantErr:    false,
			wantResult: "JBSWY3DPEHPK3PXP",
		},
		{
			name:       "with dashes",
			input:      "JBSW-Y3DP-EHPK-3PXP",
			wantErr:    false,
			wantResult: "JBSWY3DPEHPK3PXP",
		},
		{
			name:       "with underscores",
			input:      "JBSW_Y3DP_EHPK_3PXP",
			wantErr:    false,
			wantResult: "JBSWY3DPEHPK3PXP",
		},
		{
			name:       "with padding",
			input:      "JBSWY3DPEHPK3PXP====",
			wantErr:    false,
			wantResult: "JBSWY3DPEHPK3PXP",
		},
		{
			name:       "with tabs and newlines",
			input:      "JBSWY3DP\tEHPK\n3PXP",
			wantErr:    false,
			wantResult: "JBSWY3DPEHPK3PXP",
		},
		{
			name:       "mixed separators and case",
			input:      "jbsw-Y3DP ehpk_3PXP====",
			wantErr:    false,
			wantResult: "JBSWY3DPEHPK3PXP",
		},
		{
			name:    "empty after normalization",
			input:   "   - _ ",
			wantErr: true,
		},
		{
			name:    "completely empty",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid base32 characters",
			input:   "INVALID!!!BASE32",
			wantErr: true,
		},
		{
			name:       "contains 0 (typo corrected to O)",
			input:      "JBSWY0DPEHPK3PXP",
			wantErr:    false,
			wantResult: "JBSWYODPEHPK3PXP",
		},
		{
			name:       "contains 1 (typo corrected to I)",
			input:      "JBSWY1DPEHPK3PXP",
			wantErr:    false,
			wantResult: "JBSWYIDPEHPK3PXP",
		},
		{
			name:       "contains 8 (typo corrected to B)",
			input:      "JBSWY8DPEHPK3PXP",
			wantErr:    false,
			wantResult: "JBSWYBDPEHPK3PXP",
		},
		{
			name:       "contains 9 (removed)",
			input:      "JBSWY9DPEHPK3PXP",
			wantErr:    false,
			wantResult: "JBSWYDPEHPK3PXP",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := normalizeSecret(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tc.wantResult {
					t.Errorf("expected %q, got %q", tc.wantResult, result)
				}
			}
		})
	}
}

func TestConstants(t *testing.T) {
	// Verify constants have expected values
	if TypeTOTP != "totp" {
		t.Errorf("expected TypeTOTP to be 'totp', got %q", TypeTOTP)
	}
	if TypeHOTP != "hotp" {
		t.Errorf("expected TypeHOTP to be 'hotp', got %q", TypeHOTP)
	}
	if AlgorithmSHA1 != "SHA1" {
		t.Errorf("expected AlgorithmSHA1 to be 'SHA1', got %q", AlgorithmSHA1)
	}
	if AlgorithmSHA256 != "SHA256" {
		t.Errorf("expected AlgorithmSHA256 to be 'SHA256', got %q", AlgorithmSHA256)
	}
	if AlgorithmSHA512 != "SHA512" {
		t.Errorf("expected AlgorithmSHA512 to be 'SHA512', got %q", AlgorithmSHA512)
	}
	if DefaultDigits != 6 {
		t.Errorf("expected DefaultDigits to be 6, got %d", DefaultDigits)
	}
	if DefaultPeriod != 30 {
		t.Errorf("expected DefaultPeriod to be 30, got %d", DefaultPeriod)
	}
	if DefaultAlgorithm != AlgorithmSHA1 {
		t.Errorf("expected DefaultAlgorithm to be 'SHA1', got %q", DefaultAlgorithm)
	}
}

func TestErrorMessages(t *testing.T) {
	// Verify error messages are meaningful
	errors := []error{
		ErrInvalidCredential,
		ErrInvalidSecret,
		ErrInvalidType,
		ErrInvalidAlgorithm,
		ErrInvalidDigits,
		ErrInvalidPeriod,
		ErrInvalidURI,
		ErrCredentialExists,
		ErrCredentialNotFound,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("expected non-empty error message for %v", err)
		}
		if !strings.HasPrefix(err.Error(), "oath:") {
			t.Errorf("expected error to start with 'oath:', got %q", err.Error())
		}
	}
}

func TestNewCredentialFromManualEntry_Success(t *testing.T) {
	tests := []struct {
		name        string
		accountName string
		issuer      string
		secret      string
		wantName    string
		wantID      string
		wantIssuer  string
	}{
		{
			name:        "with account name and issuer",
			accountName: "user@example.com",
			issuer:      "Okta",
			secret:      "AENQRKXVV3NCGL73",
			wantName:    "Okta (user@example.com)",
			wantID:      "okta:user@example.com",
			wantIssuer:  "Okta",
		},
		{
			name:        "with only account name",
			accountName: "myaccount",
			issuer:      "",
			secret:      "JBSWY3DPEHPK3PXP",
			wantName:    "myaccount",
			wantID:      "myaccount",
			wantIssuer:  "",
		},
		{
			name:        "with only issuer",
			accountName: "",
			issuer:      "GitHub",
			secret:      "JBSWY3DPEHPK3PXP",
			wantName:    "GitHub",
			wantID:      "github",
			wantIssuer:  "GitHub",
		},
		{
			name:        "with lowercase secret",
			accountName: "user@test.com",
			issuer:      "Test",
			secret:      "jbswy3dpehpk3pxp",
			wantName:    "Test (user@test.com)",
			wantID:      "test:user@test.com",
			wantIssuer:  "Test",
		},
		{
			name:        "with spaces in secret",
			accountName: "user@test.com",
			issuer:      "Test",
			secret:      "JBSW Y3DP EHPK 3PXP",
			wantName:    "Test (user@test.com)",
			wantID:      "test:user@test.com",
			wantIssuer:  "Test",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := NewCredentialFromManualEntry(tc.accountName, tc.issuer, tc.secret)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cred.Name != tc.wantName {
				t.Errorf("expected name %q, got %q", tc.wantName, cred.Name)
			}
			if cred.ID != tc.wantID {
				t.Errorf("expected ID %q, got %q", tc.wantID, cred.ID)
			}
			if cred.Issuer != tc.wantIssuer {
				t.Errorf("expected issuer %q, got %q", tc.wantIssuer, cred.Issuer)
			}
			if cred.Type != TypeTOTP {
				t.Errorf("expected type %q, got %q", TypeTOTP, cred.Type)
			}
			if cred.Algorithm != AlgorithmSHA1 {
				t.Errorf("expected algorithm %q, got %q", AlgorithmSHA1, cred.Algorithm)
			}
			if cred.Digits != 6 {
				t.Errorf("expected digits 6, got %d", cred.Digits)
			}
			if cred.Period != 30 {
				t.Errorf("expected period 30, got %d", cred.Period)
			}
			if cred.CreatedAt.IsZero() {
				t.Error("expected non-zero CreatedAt")
			}
		})
	}
}

func TestNewCredentialFromManualEntry_Errors(t *testing.T) {
	tests := []struct {
		name        string
		accountName string
		issuer      string
		secret      string
		wantErr     error
	}{
		{
			name:        "empty account and issuer",
			accountName: "",
			issuer:      "",
			secret:      "JBSWY3DPEHPK3PXP",
			wantErr:     ErrInvalidCredential,
		},
		{
			name:        "empty secret",
			accountName: "user@example.com",
			issuer:      "Test",
			secret:      "",
			wantErr:     ErrInvalidSecret,
		},
		{
			name:        "invalid base32 secret",
			accountName: "user@example.com",
			issuer:      "Test",
			secret:      "!!!invalid!!!",
			wantErr:     ErrInvalidSecret,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewCredentialFromManualEntry(tc.accountName, tc.issuer, tc.secret)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr.Error()) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr.Error(), err.Error())
			}
		})
	}
}

func TestCredential_BackendID_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name          string
		backendID     string
		wantInJSON    bool
		wantBackendID string
	}{
		{
			name:          "with backend ID",
			backendID:     "yubikey-5c-nano",
			wantInJSON:    true,
			wantBackendID: "yubikey-5c-nano",
		},
		{
			name:          "empty backend ID omitted from JSON",
			backendID:     "",
			wantInJSON:    false,
			wantBackendID: "",
		},
		{
			name:          "tpm2 backend",
			backendID:     "tpm2-primary",
			wantInJSON:    true,
			wantBackendID: "tpm2-primary",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred := &Credential{
				ID:          "test:user",
				Name:        "Test (user)",
				Issuer:      "Test",
				AccountName: "user",
				Secret:      "JBSWY3DPEHPK3PXP",
				Type:        TypeTOTP,
				Algorithm:   AlgorithmSHA1,
				Digits:      DefaultDigits,
				Period:      DefaultPeriod,
				CreatedAt:   time.Now(),
				BackendID:   tc.backendID,
			}

			data, err := json.Marshal(cred)
			if err != nil {
				t.Fatalf("failed to marshal credential: %v", err)
			}

			// Verify omitempty behavior.
			hasBackendID := strings.Contains(string(data), "backend_id")
			if tc.wantInJSON && !hasBackendID {
				t.Error("expected backend_id in JSON output, but it was missing")
			}
			if !tc.wantInJSON && hasBackendID {
				t.Error("expected backend_id to be omitted from JSON, but it was present")
			}

			// Unmarshal and verify round-trip.
			var decoded Credential
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal credential: %v", err)
			}

			if decoded.BackendID != tc.wantBackendID {
				t.Errorf("expected BackendID %q after round-trip, got %q",
					tc.wantBackendID, decoded.BackendID)
			}

			// Verify other fields survived the round-trip.
			if decoded.ID != cred.ID {
				t.Errorf("ID mismatch: want %q, got %q", cred.ID, decoded.ID)
			}
			if decoded.Name != cred.Name {
				t.Errorf("Name mismatch: want %q, got %q", cred.Name, decoded.Name)
			}
			if decoded.Secret != cred.Secret {
				t.Errorf("Secret mismatch: want %q, got %q", cred.Secret, decoded.Secret)
			}
		})
	}
}

func TestCredential_BackendID_StoreRoundTrip(t *testing.T) {
	store := NewMemoryStore()

	cred := &Credential{
		ID:          "backend-test:user",
		Name:        "BackendTest (user)",
		Issuer:      "BackendTest",
		AccountName: "user",
		Secret:      "JBSWY3DPEHPK3PXP",
		Type:        TypeTOTP,
		Algorithm:   AlgorithmSHA1,
		Digits:      DefaultDigits,
		Period:      DefaultPeriod,
		CreatedAt:   time.Now(),
		BackendID:   "pkcs11-slot-3",
	}

	if err := store.Add(cred); err != nil {
		t.Fatalf("failed to add credential: %v", err)
	}

	retrieved, err := store.Get(cred.ID)
	if err != nil {
		t.Fatalf("failed to get credential: %v", err)
	}

	if retrieved.BackendID != "pkcs11-slot-3" {
		t.Errorf("expected BackendID %q, got %q", "pkcs11-slot-3", retrieved.BackendID)
	}

	// Verify all other fields are intact.
	if retrieved.ID != cred.ID {
		t.Errorf("ID mismatch: want %q, got %q", cred.ID, retrieved.ID)
	}
	if retrieved.Name != cred.Name {
		t.Errorf("Name mismatch: want %q, got %q", cred.Name, retrieved.Name)
	}
	if retrieved.Issuer != cred.Issuer {
		t.Errorf("Issuer mismatch: want %q, got %q", cred.Issuer, retrieved.Issuer)
	}
}

func TestCredential_BackendID_EmptyDefault(t *testing.T) {
	// Constructors should leave BackendID empty (set later by service layer).
	cred, err := NewCredential("user@example.com", "GitHub", TypeTOTP)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.BackendID != "" {
		t.Errorf("expected empty BackendID from constructor, got %q", cred.BackendID)
	}

	cred2, err := NewCredentialFromManualEntry("user@example.com", "GitHub", "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred2.BackendID != "" {
		t.Errorf("expected empty BackendID from manual entry, got %q", cred2.BackendID)
	}

	cred3, err := ParseURI("otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred3.BackendID != "" {
		t.Errorf("expected empty BackendID from ParseURI, got %q", cred3.BackendID)
	}
}
