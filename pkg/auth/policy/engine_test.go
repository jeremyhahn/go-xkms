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
	"sync"
	"testing"
)

func TestNewEngine_NilPolicy(t *testing.T) {
	e := NewEngine(nil)
	if e == nil {
		t.Fatal("NewEngine(nil) returned nil")
	}

	// Should use default policy with FIDO2 as default level.
	level := e.RequiredLevel(OpLogin)
	if level != MFAFIDO2 {
		t.Errorf("default level for unknown op = %v, want %v", level, MFAFIDO2)
	}
}

func TestNewEngine_CustomPolicy(t *testing.T) {
	p := &MFAPolicy{
		DefaultLevel: MFANone,
		Operations: map[string]*OperationPolicy{
			OpLogin: {
				Operation:     OpLogin,
				RequiredLevel: MFAFIDO2,
				Enforced:      true,
			},
		},
	}

	e := NewEngine(p)
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}

	// Login should require FIDO2.
	level := e.RequiredLevel(OpLogin)
	if level != MFAFIDO2 {
		t.Errorf("RequiredLevel(OpLogin) = %v, want %v", level, MFAFIDO2)
	}

	// Unknown operation should use custom default (None).
	level = e.RequiredLevel("custom_op")
	if level != MFANone {
		t.Errorf("RequiredLevel(custom_op) = %v, want %v", level, MFANone)
	}
}

func TestEngine_Check_ExplicitPolicySatisfied(t *testing.T) {
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations: map[string]*OperationPolicy{
			OpKeyExport: {
				Operation:     OpKeyExport,
				RequiredLevel: MFAFIDO2,
				Enforced:      true,
			},
		},
	})

	// Provide exactly the required level.
	err := e.Check(OpKeyExport, MFAFIDO2)
	if err != nil {
		t.Errorf("Check with exact level: unexpected error: %v", err)
	}

	// Provide a higher level.
	err = e.Check(OpKeyExport, MFAFIDO2OATH)
	if err != nil {
		t.Errorf("Check with higher level: unexpected error: %v", err)
	}
}

func TestEngine_Check_ExplicitPolicyNotSatisfied(t *testing.T) {
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations: map[string]*OperationPolicy{
			OpKeyExport: {
				Operation:     OpKeyExport,
				RequiredLevel: MFAFIDO2OATH,
				Enforced:      true,
			},
		},
	})

	// Provide lower level.
	err := e.Check(OpKeyExport, MFAFIDO2)
	if err != ErrInsufficientMFA {
		t.Errorf("Check with lower level: error = %v, want %v", err, ErrInsufficientMFA)
	}

	// Provide no MFA at all.
	err = e.Check(OpKeyExport, MFANone)
	if err != ErrInsufficientMFA {
		t.Errorf("Check with no MFA: error = %v, want %v", err, ErrInsufficientMFA)
	}
}

func TestEngine_Check_DefaultLevelFallback(t *testing.T) {
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFAFIDO2,
		Operations:   map[string]*OperationPolicy{},
	})

	// Operation without explicit policy should use default level.
	err := e.Check("some_unknown_op", MFAFIDO2)
	if err != nil {
		t.Errorf("Check with default level satisfied: unexpected error: %v", err)
	}

	err = e.Check("some_unknown_op", MFANone)
	if err != ErrInsufficientMFA {
		t.Errorf("Check with default level not met: error = %v, want %v", err, ErrInsufficientMFA)
	}
}

func TestEngine_Check_NonEnforcedPolicy(t *testing.T) {
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations: map[string]*OperationPolicy{
			OpKeyExport: {
				Operation:     OpKeyExport,
				RequiredLevel: MFAFIDO2OATH,
				Enforced:      false, // advisory only
			},
		},
	})

	// Non-enforced policy should never return an error.
	err := e.Check(OpKeyExport, MFANone)
	if err != nil {
		t.Errorf("Check non-enforced with insufficient MFA: unexpected error: %v", err)
	}
}

func TestEngine_Check_EmptyOperation(t *testing.T) {
	e := NewEngine(nil)

	err := e.Check("", MFAFIDO2)
	if err != ErrInvalidOperation {
		t.Errorf("Check with empty operation: error = %v, want %v", err, ErrInvalidOperation)
	}
}

func TestEngine_RequiredLevel_ExplicitPolicy(t *testing.T) {
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations: map[string]*OperationPolicy{
			OpBarrierUnseal: {
				Operation:     OpBarrierUnseal,
				RequiredLevel: MFAFIDO2OATH,
				Enforced:      true,
			},
		},
	})

	level := e.RequiredLevel(OpBarrierUnseal)
	if level != MFAFIDO2OATH {
		t.Errorf("RequiredLevel(OpBarrierUnseal) = %v, want %v", level, MFAFIDO2OATH)
	}
}

func TestEngine_RequiredLevel_DefaultFallback(t *testing.T) {
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFAFIDO2,
		Operations:   map[string]*OperationPolicy{},
	})

	level := e.RequiredLevel("unknown_operation")
	if level != MFAFIDO2 {
		t.Errorf("RequiredLevel(unknown) = %v, want %v", level, MFAFIDO2)
	}
}

func TestEngine_SetPolicy_Valid(t *testing.T) {
	e := NewEngine(nil)

	newPolicy := &MFAPolicy{
		DefaultLevel: MFAFIDO2OATH,
		Operations:   map[string]*OperationPolicy{},
	}

	err := e.SetPolicy(newPolicy)
	if err != nil {
		t.Fatalf("SetPolicy: unexpected error: %v", err)
	}

	// Verify new default level is in effect.
	level := e.RequiredLevel("any_op")
	if level != MFAFIDO2OATH {
		t.Errorf("after SetPolicy, RequiredLevel = %v, want %v", level, MFAFIDO2OATH)
	}
}

func TestEngine_SetPolicy_Nil(t *testing.T) {
	e := NewEngine(nil)

	err := e.SetPolicy(nil)
	if err != ErrNilPolicy {
		t.Errorf("SetPolicy(nil) error = %v, want %v", err, ErrNilPolicy)
	}
}

func TestEngine_AddOperationPolicy_New(t *testing.T) {
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations:   map[string]*OperationPolicy{},
	})

	op := &OperationPolicy{
		Operation:     OpCertRequest,
		RequiredLevel: MFAFIDO2,
		Description:   "cert requests need 2FA",
		Enforced:      true,
	}

	err := e.AddOperationPolicy(op)
	if err != nil {
		t.Fatalf("AddOperationPolicy: unexpected error: %v", err)
	}

	level := e.RequiredLevel(OpCertRequest)
	if level != MFAFIDO2 {
		t.Errorf("after add, RequiredLevel(OpCertRequest) = %v, want %v", level, MFAFIDO2)
	}
}

func TestEngine_AddOperationPolicy_Replace(t *testing.T) {
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations: map[string]*OperationPolicy{
			OpCertRequest: {
				Operation:     OpCertRequest,
				RequiredLevel: MFAFIDO2,
				Enforced:      true,
			},
		},
	})

	// Replace with higher level.
	replacement := &OperationPolicy{
		Operation:     OpCertRequest,
		RequiredLevel: MFAFIDO2OATH,
		Description:   "upgraded to 3FA",
		Enforced:      true,
	}

	err := e.AddOperationPolicy(replacement)
	if err != nil {
		t.Fatalf("AddOperationPolicy (replace): unexpected error: %v", err)
	}

	level := e.RequiredLevel(OpCertRequest)
	if level != MFAFIDO2OATH {
		t.Errorf("after replace, RequiredLevel = %v, want %v", level, MFAFIDO2OATH)
	}
}

func TestEngine_AddOperationPolicy_NilPolicy(t *testing.T) {
	e := NewEngine(nil)

	err := e.AddOperationPolicy(nil)
	if err != ErrNilPolicy {
		t.Errorf("AddOperationPolicy(nil) error = %v, want %v", err, ErrNilPolicy)
	}
}

func TestEngine_AddOperationPolicy_EmptyOperation(t *testing.T) {
	e := NewEngine(nil)

	op := &OperationPolicy{
		Operation:     "",
		RequiredLevel: MFAFIDO2,
		Enforced:      true,
	}

	err := e.AddOperationPolicy(op)
	if err != ErrInvalidOperation {
		t.Errorf("AddOperationPolicy(empty op) error = %v, want %v", err, ErrInvalidOperation)
	}
}

func TestEngine_AddOperationPolicy_NilOperationsMap(t *testing.T) {
	// Test that AddOperationPolicy initializes a nil Operations map.
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations:   nil,
	})

	op := &OperationPolicy{
		Operation:     OpLogin,
		RequiredLevel: MFAFIDO2,
		Enforced:      true,
	}

	err := e.AddOperationPolicy(op)
	if err != nil {
		t.Fatalf("AddOperationPolicy on nil map: unexpected error: %v", err)
	}

	level := e.RequiredLevel(OpLogin)
	if level != MFAFIDO2 {
		t.Errorf("after add to nil map, RequiredLevel = %v, want %v", level, MFAFIDO2)
	}
}

func TestEngine_RemoveOperationPolicy_Success(t *testing.T) {
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations: map[string]*OperationPolicy{
			OpKeyExport: {
				Operation:     OpKeyExport,
				RequiredLevel: MFAFIDO2OATH,
				Enforced:      true,
			},
		},
	})

	err := e.RemoveOperationPolicy(OpKeyExport)
	if err != nil {
		t.Fatalf("RemoveOperationPolicy: unexpected error: %v", err)
	}

	// After removal, should fall back to default level (None).
	level := e.RequiredLevel(OpKeyExport)
	if level != MFANone {
		t.Errorf("after removal, RequiredLevel = %v, want %v", level, MFANone)
	}
}

func TestEngine_RemoveOperationPolicy_NotFound(t *testing.T) {
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations:   map[string]*OperationPolicy{},
	})

	err := e.RemoveOperationPolicy("nonexistent_op")
	if err != ErrPolicyNotFound {
		t.Errorf("RemoveOperationPolicy(nonexistent) error = %v, want %v", err, ErrPolicyNotFound)
	}
}

func TestEngine_RemoveOperationPolicy_EmptyOperation(t *testing.T) {
	e := NewEngine(nil)

	err := e.RemoveOperationPolicy("")
	if err != ErrInvalidOperation {
		t.Errorf("RemoveOperationPolicy(\"\") error = %v, want %v", err, ErrInvalidOperation)
	}
}

func TestEngine_ListPolicies(t *testing.T) {
	ops := map[string]*OperationPolicy{
		OpKeyExport: {
			Operation:     OpKeyExport,
			RequiredLevel: MFAFIDO2OATH,
			Enforced:      true,
		},
		OpLogin: {
			Operation:     OpLogin,
			RequiredLevel: MFAFIDO2,
			Enforced:      true,
		},
	}

	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations:   ops,
	})

	policies := e.ListPolicies()
	if len(policies) != 2 {
		t.Fatalf("ListPolicies length = %d, want 2", len(policies))
	}

	// Build a lookup for verification.
	found := make(map[string]*OperationPolicy, len(policies))
	for _, p := range policies {
		found[p.Operation] = p
	}

	if p, ok := found[OpKeyExport]; !ok {
		t.Error("ListPolicies missing OpKeyExport")
	} else if p.RequiredLevel != MFAFIDO2OATH {
		t.Errorf("OpKeyExport level = %v, want %v", p.RequiredLevel, MFAFIDO2OATH)
	}

	if p, ok := found[OpLogin]; !ok {
		t.Error("ListPolicies missing OpLogin")
	} else if p.RequiredLevel != MFAFIDO2 {
		t.Errorf("OpLogin level = %v, want %v", p.RequiredLevel, MFAFIDO2)
	}
}

func TestEngine_ListPolicies_Empty(t *testing.T) {
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations:   map[string]*OperationPolicy{},
	})

	policies := e.ListPolicies()
	if len(policies) != 0 {
		t.Errorf("ListPolicies on empty = %d, want 0", len(policies))
	}
}

func TestEngine_ListPolicies_ReturnsCopy(t *testing.T) {
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations: map[string]*OperationPolicy{
			OpLogin: {
				Operation:     OpLogin,
				RequiredLevel: MFAFIDO2,
				Enforced:      true,
			},
		},
	})

	policies := e.ListPolicies()
	// Mutate the returned copy.
	policies[0].RequiredLevel = MFAFIDO2OATH

	// Original should be unchanged.
	level := e.RequiredLevel(OpLogin)
	if level != MFAFIDO2 {
		t.Errorf("mutation of ListPolicies result affected engine: level = %v, want %v", level, MFAFIDO2)
	}
}

func TestDefaultPolicy_SensitiveOperationsRequire3FA(t *testing.T) {
	p := DefaultPolicy()

	sensitiveOps := []string{
		OpBarrierUnseal,
		OpKeyExport,
		OpTenantCreate,
		OpEscrowKey,
		OpRecoverKey,
	}

	for _, op := range sensitiveOps {
		pol, ok := p.Operations[op]
		if !ok {
			t.Errorf("DefaultPolicy missing policy for %q", op)
			continue
		}
		if pol.RequiredLevel != MFAFIDO2OATH {
			t.Errorf("DefaultPolicy[%q].RequiredLevel = %v, want %v",
				op, pol.RequiredLevel, MFAFIDO2OATH)
		}
		if !pol.Enforced {
			t.Errorf("DefaultPolicy[%q].Enforced = false, want true", op)
		}
	}
}

func TestDefaultPolicy_DefaultLevelIsFIDO2(t *testing.T) {
	p := DefaultPolicy()

	if p.DefaultLevel != MFAFIDO2 {
		t.Errorf("DefaultPolicy.DefaultLevel = %v, want %v", p.DefaultLevel, MFAFIDO2)
	}
}

func TestEngine_ConcurrentAccess(t *testing.T) {
	e := NewEngine(nil)

	var wg sync.WaitGroup
	const goroutines = 100

	// Concurrent reads.
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.RequiredLevel(OpLogin)
			_ = e.Check(OpLogin, MFAFIDO2)
			_ = e.ListPolicies()
		}()
	}

	// Concurrent writes.
	for i := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op := &OperationPolicy{
				Operation:     OpLogin,
				RequiredLevel: MFALevel(i % 3),
				Enforced:      true,
			}
			_ = e.AddOperationPolicy(op)
		}()
	}

	wg.Wait()
}

func TestEngine_Check_AllLevelCombinations(t *testing.T) {
	// Exhaustive check of all required vs provided combinations.
	tests := []struct {
		name     string
		required MFALevel
		provided MFALevel
		wantErr  bool
	}{
		{"none requires none", MFANone, MFANone, false},
		{"none requires fido2", MFANone, MFAFIDO2, false},
		{"none requires fido2+oath", MFANone, MFAFIDO2OATH, false},
		{"fido2 requires none", MFAFIDO2, MFANone, true},
		{"fido2 requires fido2", MFAFIDO2, MFAFIDO2, false},
		{"fido2 requires fido2+oath", MFAFIDO2, MFAFIDO2OATH, false},
		{"fido2+oath requires none", MFAFIDO2OATH, MFANone, true},
		{"fido2+oath requires fido2", MFAFIDO2OATH, MFAFIDO2, true},
		{"fido2+oath requires fido2+oath", MFAFIDO2OATH, MFAFIDO2OATH, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(&MFAPolicy{
				DefaultLevel: MFANone,
				Operations: map[string]*OperationPolicy{
					"test_op": {
						Operation:     "test_op",
						RequiredLevel: tc.required,
						Enforced:      true,
					},
				},
			})

			err := e.Check("test_op", tc.provided)
			if tc.wantErr && err != ErrInsufficientMFA {
				t.Errorf("expected ErrInsufficientMFA, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestEngine_SetPolicy_ThenCheck(t *testing.T) {
	e := NewEngine(nil)

	// Default policy requires FIDO2 for unknown ops.
	err := e.Check("custom_op", MFANone)
	if err != ErrInsufficientMFA {
		t.Errorf("before SetPolicy: error = %v, want %v", err, ErrInsufficientMFA)
	}

	// Replace with a permissive policy.
	err = e.SetPolicy(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations:   map[string]*OperationPolicy{},
	})
	if err != nil {
		t.Fatalf("SetPolicy: unexpected error: %v", err)
	}

	// Now custom_op should pass with MFANone.
	err = e.Check("custom_op", MFANone)
	if err != nil {
		t.Errorf("after SetPolicy: unexpected error: %v", err)
	}
}

func TestEngine_AddThenRemoveThenCheck(t *testing.T) {
	e := NewEngine(&MFAPolicy{
		DefaultLevel: MFANone,
		Operations:   map[string]*OperationPolicy{},
	})

	// Add a policy.
	err := e.AddOperationPolicy(&OperationPolicy{
		Operation:     OpKeyDelete,
		RequiredLevel: MFAFIDO2OATH,
		Enforced:      true,
	})
	if err != nil {
		t.Fatalf("AddOperationPolicy: %v", err)
	}

	// Verify it's enforced.
	err = e.Check(OpKeyDelete, MFAFIDO2)
	if err != ErrInsufficientMFA {
		t.Errorf("after add, Check with FIDO2: error = %v, want %v", err, ErrInsufficientMFA)
	}

	// Remove it.
	err = e.RemoveOperationPolicy(OpKeyDelete)
	if err != nil {
		t.Fatalf("RemoveOperationPolicy: %v", err)
	}

	// Now it should fall back to default (None) and pass.
	err = e.Check(OpKeyDelete, MFANone)
	if err != nil {
		t.Errorf("after remove, Check with None: unexpected error: %v", err)
	}
}
