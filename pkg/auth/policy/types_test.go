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

package policy

import (
	"testing"
)

func TestMFALevel_String(t *testing.T) {
	tests := []struct {
		name     string
		level    MFALevel
		expected string
	}{
		{
			name:     "none level",
			level:    MFANone,
			expected: "none",
		},
		{
			name:     "fido2 level",
			level:    MFAFIDO2,
			expected: "fido2",
		},
		{
			name:     "fido2+oath level",
			level:    MFAFIDO2OATH,
			expected: "fido2+oath",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.level.String()
			if got != tc.expected {
				t.Errorf("MFALevel(%d).String() = %q, want %q", tc.level, got, tc.expected)
			}
		})
	}
}

func TestMFALevel_String_Unknown(t *testing.T) {
	unknown := MFALevel(99)
	got := unknown.String()
	if got != "unknown" {
		t.Errorf("MFALevel(99).String() = %q, want %q", got, "unknown")
	}
}

func TestParseMFALevel_Valid(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected MFALevel
	}{
		{
			name:     "parse none",
			input:    "none",
			expected: MFANone,
		},
		{
			name:     "parse fido2",
			input:    "fido2",
			expected: MFAFIDO2,
		},
		{
			name:     "parse fido2+oath",
			input:    "fido2+oath",
			expected: MFAFIDO2OATH,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseMFALevel(tc.input)
			if err != nil {
				t.Fatalf("ParseMFALevel(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.expected {
				t.Errorf("ParseMFALevel(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestParseMFALevel_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty string", input: ""},
		{name: "garbage", input: "banana"},
		{name: "uppercase FIDO2", input: "FIDO2"},
		{name: "partial match", input: "fido"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseMFALevel(tc.input)
			if err != ErrInvalidMFALevel {
				t.Errorf("ParseMFALevel(%q) error = %v, want %v", tc.input, err, ErrInvalidMFALevel)
			}
		})
	}
}

func TestMFALevel_SatisfiedBy(t *testing.T) {
	tests := []struct {
		name     string
		required MFALevel
		provided MFALevel
		expected bool
	}{
		{
			name:     "none satisfied by none",
			required: MFANone,
			provided: MFANone,
			expected: true,
		},
		{
			name:     "none satisfied by fido2",
			required: MFANone,
			provided: MFAFIDO2,
			expected: true,
		},
		{
			name:     "none satisfied by fido2+oath",
			required: MFANone,
			provided: MFAFIDO2OATH,
			expected: true,
		},
		{
			name:     "fido2 satisfied by fido2",
			required: MFAFIDO2,
			provided: MFAFIDO2,
			expected: true,
		},
		{
			name:     "fido2 satisfied by fido2+oath",
			required: MFAFIDO2,
			provided: MFAFIDO2OATH,
			expected: true,
		},
		{
			name:     "fido2 not satisfied by none",
			required: MFAFIDO2,
			provided: MFANone,
			expected: false,
		},
		{
			name:     "fido2+oath satisfied by fido2+oath",
			required: MFAFIDO2OATH,
			provided: MFAFIDO2OATH,
			expected: true,
		},
		{
			name:     "fido2+oath not satisfied by fido2",
			required: MFAFIDO2OATH,
			provided: MFAFIDO2,
			expected: false,
		},
		{
			name:     "fido2+oath not satisfied by none",
			required: MFAFIDO2OATH,
			provided: MFANone,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.required.SatisfiedBy(tc.provided)
			if got != tc.expected {
				t.Errorf("%s.SatisfiedBy(%s) = %v, want %v",
					tc.required, tc.provided, got, tc.expected)
			}
		})
	}
}

func TestOperationPolicy_Fields(t *testing.T) {
	op := &OperationPolicy{
		Operation:     OpKeyExport,
		RequiredLevel: MFAFIDO2OATH,
		Description:   "test description",
		Enforced:      true,
	}

	if op.Operation != OpKeyExport {
		t.Errorf("Operation = %q, want %q", op.Operation, OpKeyExport)
	}
	if op.RequiredLevel != MFAFIDO2OATH {
		t.Errorf("RequiredLevel = %v, want %v", op.RequiredLevel, MFAFIDO2OATH)
	}
	if op.Description != "test description" {
		t.Errorf("Description = %q, want %q", op.Description, "test description")
	}
	if !op.Enforced {
		t.Error("Enforced = false, want true")
	}
}

func TestOperationPolicy_FieldsDefault(t *testing.T) {
	op := &OperationPolicy{}

	if op.Operation != "" {
		t.Errorf("Operation zero value = %q, want empty", op.Operation)
	}
	if op.RequiredLevel != MFANone {
		t.Errorf("RequiredLevel zero value = %v, want %v", op.RequiredLevel, MFANone)
	}
	if op.Description != "" {
		t.Errorf("Description zero value = %q, want empty", op.Description)
	}
	if op.Enforced {
		t.Error("Enforced zero value = true, want false")
	}
}

func TestMFAPolicy_Fields(t *testing.T) {
	p := &MFAPolicy{
		DefaultLevel: MFAFIDO2,
		Operations: map[string]*OperationPolicy{
			OpLogin: {
				Operation:     OpLogin,
				RequiredLevel: MFAFIDO2,
				Enforced:      true,
			},
		},
	}

	if p.DefaultLevel != MFAFIDO2 {
		t.Errorf("DefaultLevel = %v, want %v", p.DefaultLevel, MFAFIDO2)
	}
	if len(p.Operations) != 1 {
		t.Fatalf("Operations length = %d, want 1", len(p.Operations))
	}
	if _, ok := p.Operations[OpLogin]; !ok {
		t.Error("Operations missing OpLogin entry")
	}
}

func TestMFAPolicy_FieldsEmpty(t *testing.T) {
	p := &MFAPolicy{}

	if p.DefaultLevel != MFANone {
		t.Errorf("DefaultLevel zero value = %v, want %v", p.DefaultLevel, MFANone)
	}
	if p.Operations != nil {
		t.Error("Operations zero value should be nil")
	}
}

func TestOperationConstants(t *testing.T) {
	// Verify all operation constants are non-empty and unique.
	ops := []string{
		OpBarrierUnseal, OpBarrierSeal, OpKeyExport, OpKeyImport,
		OpKeyGenerate, OpKeyDelete, OpTenantCreate, OpTenantDelete,
		OpUserCreate, OpUserDelete, OpCustodianInvite, OpShareProvide,
		OpShareReceive, OpEscrowKey, OpRecoverKey, OpCertRequest, OpLogin,
	}

	seen := make(map[string]struct{}, len(ops))
	for _, op := range ops {
		if op == "" {
			t.Error("operation constant is empty")
		}
		if _, exists := seen[op]; exists {
			t.Errorf("duplicate operation constant: %q", op)
		}
		seen[op] = struct{}{}
	}

	if len(seen) != len(ops) {
		t.Errorf("expected %d unique operations, got %d", len(ops), len(seen))
	}
}

func TestMFALevel_Ordering(t *testing.T) {
	// Verify that levels are ordered: None < FIDO2 < FIDO2OATH.
	if MFANone >= MFAFIDO2 {
		t.Error("MFANone should be less than MFAFIDO2")
	}
	if MFAFIDO2 >= MFAFIDO2OATH {
		t.Error("MFAFIDO2 should be less than MFAFIDO2OATH")
	}
}
