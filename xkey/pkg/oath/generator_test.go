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
	"strings"
	"testing"
	"time"
)

// RFC 4226 test vectors
// Secret: "12345678901234567890" (base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ)
var rfcTestSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

var rfcTestVectors = []struct {
	counter uint64
	code    string
}{
	{0, "755224"},
	{1, "287082"},
	{2, "359152"},
	{3, "969429"},
	{4, "338314"},
	{5, "254676"},
	{6, "287922"},
	{7, "162583"},
	{8, "399871"},
	{9, "520489"},
}

func TestNewGenerator_Success(t *testing.T) {
	tests := []struct {
		name string
		cred *Credential
	}{
		{
			name: "TOTP credential",
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
			name: "HOTP credential",
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
			name: "SHA512 credential",
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
			gen, err := NewGenerator(tc.cred)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gen == nil {
				t.Error("expected non-nil generator")
			}
		})
	}
}

func TestNewGenerator_Errors(t *testing.T) {
	tests := []struct {
		name    string
		cred    *Credential
		wantErr error
	}{
		{
			name: "invalid credential - empty name",
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
			name: "invalid credential - empty secret",
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
			name: "invalid credential - bad type",
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewGenerator(tc.cred)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr.Error()) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr.Error(), err.Error())
			}
		})
	}
}

func TestGenerator_GenerateCounter_RFC4226(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    rfcTestSecret,
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	for _, tc := range rfcTestVectors {
		t.Run("counter_"+tc.code, func(t *testing.T) {
			code, err := gen.GenerateCounter(tc.counter)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if code != tc.code {
				t.Errorf("counter %d: expected %s, got %s", tc.counter, tc.code, code)
			}
		})
	}
}

func TestGenerator_GenerateCounter_DifferentAlgorithms(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{name: "SHA1", algorithm: AlgorithmSHA1},
		{name: "SHA256", algorithm: AlgorithmSHA256},
		{name: "SHA512", algorithm: AlgorithmSHA512},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred := &Credential{
				Name:      "test",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      TypeHOTP,
				Algorithm: tc.algorithm,
				Digits:    6,
			}

			gen, err := NewGenerator(cred)
			if err != nil {
				t.Fatalf("failed to create generator: %v", err)
			}

			code, err := gen.GenerateCounter(0)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(code) != 6 {
				t.Errorf("expected 6-digit code, got %d digits", len(code))
			}
		})
	}
}

func TestGenerator_GenerateCounter_DifferentDigits(t *testing.T) {
	tests := []struct {
		name   string
		digits int
	}{
		{name: "6 digits", digits: 6},
		{name: "7 digits", digits: 7},
		{name: "8 digits", digits: 8},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred := &Credential{
				Name:      "test",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      TypeHOTP,
				Algorithm: AlgorithmSHA1,
				Digits:    tc.digits,
			}

			gen, err := NewGenerator(cred)
			if err != nil {
				t.Fatalf("failed to create generator: %v", err)
			}

			code, err := gen.GenerateCounter(0)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(code) != tc.digits {
				t.Errorf("expected %d-digit code, got %d digits", tc.digits, len(code))
			}
		})
	}
}

func TestGenerator_GenerateCounter_Errors(t *testing.T) {
	// Test with invalid algorithm (should be caught by Validate, but test the generate path)
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Temporarily change algorithm to test error path
	gen.cred.Algorithm = "INVALID"
	_, err = gen.GenerateCounter(0)
	if err == nil {
		t.Error("expected error for invalid algorithm")
	}
	if err != ErrInvalidAlgorithm {
		t.Errorf("expected ErrInvalidAlgorithm, got %v", err)
	}
}

func TestGenerator_GenerateCounter_InvalidSecret(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Temporarily change secret to invalid base32
	gen.cred.Secret = "invalid!!!"
	_, err = gen.GenerateCounter(0)
	if err == nil {
		t.Error("expected error for invalid secret")
	}
	if err != ErrInvalidSecret {
		t.Errorf("expected ErrInvalidSecret, got %v", err)
	}
}

func TestGenerator_Generate_TOTP(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeTOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	code, err := gen.Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("expected 6-digit code, got %d digits", len(code))
	}
}

func TestGenerator_Generate_HOTP(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    rfcTestSecret,
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Counter:   0,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	code, err := gen.Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Counter 0 should produce "755224" per RFC 4226
	if code != "755224" {
		t.Errorf("expected 755224, got %s", code)
	}
}

func TestGenerator_GenerateAt_Success(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeTOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Generate at a specific time
	testTime := time.Unix(0, 0) // Unix epoch
	code, err := gen.GenerateAt(testTime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("expected 6-digit code, got %d digits", len(code))
	}

	// Same time should produce same code
	code2, err := gen.GenerateAt(testTime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != code2 {
		t.Errorf("same time should produce same code: %s != %s", code, code2)
	}
}

func TestGenerator_GenerateAt_Error_HOTP(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Counter:   0,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	_, err = gen.GenerateAt(time.Now())
	if err == nil {
		t.Error("expected error when calling GenerateAt on HOTP credential")
	}
}

func TestGenerator_Validate_TOTP_Success(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeTOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Generate current code and validate it
	code, err := gen.Generate()
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	err = gen.Validate(code)
	if err != nil {
		t.Errorf("expected valid code, got error: %v", err)
	}
}

func TestGenerator_Validate_TOTP_Invalid(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeTOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Test with invalid code
	err = gen.Validate("000000")
	if err == nil {
		t.Error("expected error for invalid code")
	}
	if err != ErrInvalidCode {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

func TestGenerator_Validate_WrongLength(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeTOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	tests := []string{
		"12345",    // too short
		"1234567",  // too long
		"12345678", // too long
		"",         // empty
	}

	for _, code := range tests {
		err = gen.Validate(code)
		if err == nil {
			t.Errorf("expected error for code %q", code)
		}
		if err != ErrInvalidCode {
			t.Errorf("expected ErrInvalidCode for code %q, got %v", code, err)
		}
	}
}

func TestGenerator_ValidateWithSkew_TOTP(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeTOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Generate current code and validate with skew
	code, err := gen.Generate()
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	// Should validate with various skew values
	err = gen.ValidateWithSkew(code, 0)
	if err != nil {
		t.Errorf("expected valid code with skew 0, got error: %v", err)
	}

	err = gen.ValidateWithSkew(code, 1)
	if err != nil {
		t.Errorf("expected valid code with skew 1, got error: %v", err)
	}

	err = gen.ValidateWithSkew(code, 5)
	if err != nil {
		t.Errorf("expected valid code with skew 5, got error: %v", err)
	}
}

func TestGenerator_Validate_HOTP_Success(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    rfcTestSecret,
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Counter:   0,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Validate first code from RFC test vectors
	err = gen.Validate("755224")
	if err != nil {
		t.Errorf("expected valid code, got error: %v", err)
	}

	// Counter should have been incremented
	if gen.cred.Counter != 1 {
		t.Errorf("expected counter to be 1, got %d", gen.cred.Counter)
	}
}

func TestGenerator_Validate_HOTP_LookAhead(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    rfcTestSecret,
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Counter:   0,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Validate code at counter 1 (skipping counter 0)
	err = gen.ValidateWithSkew("287082", 5)
	if err != nil {
		t.Errorf("expected valid code with look-ahead, got error: %v", err)
	}

	// Counter should have been incremented to 2
	if gen.cred.Counter != 2 {
		t.Errorf("expected counter to be 2, got %d", gen.cred.Counter)
	}
}

func TestGenerator_Validate_HOTP_Invalid(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    rfcTestSecret,
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Counter:   0,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	err = gen.Validate("000000")
	if err == nil {
		t.Error("expected error for invalid code")
	}
	if err != ErrInvalidCode {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}

	// Counter should not have been changed
	if gen.cred.Counter != 0 {
		t.Errorf("expected counter to remain 0, got %d", gen.cred.Counter)
	}
}

func TestGenerator_TimeRemaining_TOTP(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeTOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	remaining := gen.TimeRemaining()
	if remaining < 0 || remaining > 30 {
		t.Errorf("expected remaining time between 0 and 30, got %d", remaining)
	}
}

func TestGenerator_TimeRemaining_HOTP(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Counter:   0,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	remaining := gen.TimeRemaining()
	if remaining != 0 {
		t.Errorf("expected 0 for HOTP, got %d", remaining)
	}
}

func TestGenerator_Counter_TOTP(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeTOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	counter := gen.Counter()
	if counter == 0 {
		// This would only be true at Unix epoch, very unlikely
		t.Log("counter is 0 (possible if running at Unix epoch)")
	}
	// Counter should be based on current time
	expectedCounter := uint64(time.Now().Unix()) / 30
	if counter != expectedCounter {
		t.Errorf("expected counter %d, got %d", expectedCounter, counter)
	}
}

func TestGenerator_Counter_HOTP(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Counter:   42,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	counter := gen.Counter()
	if counter != 42 {
		t.Errorf("expected counter 42, got %d", counter)
	}
}

func TestGenerator_IncrementCounter_HOTP(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Counter:   0,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	gen.IncrementCounter()
	if gen.cred.Counter != 1 {
		t.Errorf("expected counter 1, got %d", gen.cred.Counter)
	}

	gen.IncrementCounter()
	if gen.cred.Counter != 2 {
		t.Errorf("expected counter 2, got %d", gen.cred.Counter)
	}
}

func TestGenerator_IncrementCounter_TOTP(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeTOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// IncrementCounter should have no effect on TOTP
	gen.IncrementCounter()
	if gen.cred.Counter != 0 {
		t.Errorf("expected counter 0 for TOTP, got %d", gen.cred.Counter)
	}
}

func TestGenerator_LeadingZeros(t *testing.T) {
	// Test that codes with leading zeros are properly formatted
	cred := &Credential{
		Name:      "test",
		Secret:    rfcTestSecret,
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Counter:   0,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Generate multiple codes and check formatting
	for i := uint64(0); i < 100; i++ {
		code, err := gen.GenerateCounter(i)
		if err != nil {
			t.Fatalf("failed to generate code for counter %d: %v", i, err)
		}
		if len(code) != 6 {
			t.Errorf("counter %d: expected 6-digit code, got %d digits: %s", i, len(code), code)
		}
	}
}

func TestGenerator_TimeBasedConsistency(t *testing.T) {
	cred := &Credential{
		Name:      "test",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeTOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	gen, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Generate code at specific time
	testTime := time.Unix(1000000000, 0) // Sep 9, 2001
	code1, err := gen.GenerateAt(testTime)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	// Same time should produce same code
	code2, err := gen.GenerateAt(testTime)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	if code1 != code2 {
		t.Errorf("same time should produce same code: %s != %s", code1, code2)
	}

	// Time within same 30-second period should produce same code
	code3, err := gen.GenerateAt(testTime.Add(15 * time.Second))
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	if code1 != code3 {
		t.Errorf("same period should produce same code: %s != %s", code1, code3)
	}
}

func TestGenerator_DifferentPeriods(t *testing.T) {
	tests := []struct {
		name   string
		period int
	}{
		{name: "30 second period", period: 30},
		{name: "60 second period", period: 60},
		{name: "15 second period", period: 15},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred := &Credential{
				Name:      "test",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      TypeTOTP,
				Algorithm: AlgorithmSHA1,
				Digits:    6,
				Period:    tc.period,
			}

			gen, err := NewGenerator(cred)
			if err != nil {
				t.Fatalf("failed to create generator: %v", err)
			}

			code, err := gen.Generate()
			if err != nil {
				t.Fatalf("failed to generate code: %v", err)
			}

			if len(code) != 6 {
				t.Errorf("expected 6-digit code, got %d digits", len(code))
			}

			// Verify TimeRemaining is within bounds
			remaining := gen.TimeRemaining()
			if remaining < 0 || remaining > tc.period {
				t.Errorf("expected remaining time between 0 and %d, got %d", tc.period, remaining)
			}
		})
	}
}

func TestGeneratorErrors(t *testing.T) {
	// Verify error messages are meaningful
	errors := []error{
		ErrInvalidCode,
		ErrCodeExpired,
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
