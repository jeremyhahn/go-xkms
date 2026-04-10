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
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPCRReader returns configured PCR values filtered to requested indices.
type mockPCRReader struct {
	values map[int][]byte
	err    error
}

func (m *mockPCRReader) ReadPCRs(_ string, indices []int) (map[int][]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	result := make(map[int][]byte, len(indices))
	for _, idx := range indices {
		if v, ok := m.values[idx]; ok {
			result[idx] = v
		}
	}
	return result, nil
}

func testPCRValues() map[int][]byte {
	return map[int][]byte{
		0: {0xaa, 0xbb, 0xcc, 0xdd},
		1: {0x11, 0x22, 0x33, 0x44},
		2: {0x55, 0x66, 0x77, 0x88},
		7: {0x99, 0xaa, 0xbb, 0xcc},
	}
}

func newTestManager(t *testing.T) (*Manager, *mockPCRReader, *MemoryPolicyStore) {
	t.Helper()
	reader := &mockPCRReader{values: testPCRValues()}
	store := NewMemoryPolicyStore()
	mgr, err := NewManager(reader, store)
	require.NoError(t, err)
	return mgr, reader, store
}

// --- NewManager tests ---

func TestNewManager_Success(t *testing.T) {
	reader := &mockPCRReader{values: testPCRValues()}
	store := NewMemoryPolicyStore()

	mgr, err := NewManager(reader, store)
	require.NoError(t, err)
	assert.NotNil(t, mgr)
}

func TestNewManager_NilReader(t *testing.T) {
	store := NewMemoryPolicyStore()

	mgr, err := NewManager(nil, store)
	assert.Nil(t, mgr)
	assert.ErrorIs(t, err, ErrNilPCRReader)
}

func TestNewManager_NilStore(t *testing.T) {
	reader := &mockPCRReader{values: testPCRValues()}

	mgr, err := NewManager(reader, nil)
	assert.Nil(t, mgr)
	assert.ErrorIs(t, err, ErrNilPolicyStore)
}

// --- CreatePolicy tests ---

func TestCreatePolicy_Success(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	def, err := mgr.CreatePolicy("boot", "sha256", []int{0, 1, 7})
	require.NoError(t, err)
	require.NotNil(t, def)

	assert.Equal(t, "boot", def.Name)
	assert.Equal(t, "sha256", def.Bank)
	assert.Equal(t, []int{0, 1, 7}, def.PCRIndices)
	assert.Len(t, def.PCRValues, 3)
	assert.True(t, bytes.Equal([]byte{0xaa, 0xbb, 0xcc, 0xdd}, def.PCRValues[0]))
	assert.True(t, bytes.Equal([]byte{0x11, 0x22, 0x33, 0x44}, def.PCRValues[1]))
	assert.True(t, bytes.Equal([]byte{0x99, 0xaa, 0xbb, 0xcc}, def.PCRValues[7]))
	assert.False(t, def.CreatedAt.IsZero())
	assert.False(t, def.UpdatedAt.IsZero())
}

func TestCreatePolicy_EmptyName(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	def, err := mgr.CreatePolicy("", "sha256", []int{0})
	assert.Nil(t, def)
	assert.ErrorIs(t, err, ErrInvalidName)
}

func TestCreatePolicy_WhitespaceName(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	def, err := mgr.CreatePolicy("   ", "sha256", []int{0})
	assert.Nil(t, def)
	assert.ErrorIs(t, err, ErrInvalidName)
}

func TestCreatePolicy_EmptyBank(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	def, err := mgr.CreatePolicy("boot", "", []int{0})
	assert.Nil(t, def)
	assert.ErrorIs(t, err, ErrInvalidBank)
}

func TestCreatePolicy_WhitespaceBank(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	def, err := mgr.CreatePolicy("boot", "  ", []int{0})
	assert.Nil(t, def)
	assert.ErrorIs(t, err, ErrInvalidBank)
}

func TestCreatePolicy_NilPCRs(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	def, err := mgr.CreatePolicy("boot", "sha256", nil)
	assert.Nil(t, def)
	assert.ErrorIs(t, err, ErrNoPCRsSelected)
}

func TestCreatePolicy_EmptyPCRs(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	def, err := mgr.CreatePolicy("boot", "sha256", []int{})
	assert.Nil(t, def)
	assert.ErrorIs(t, err, ErrNoPCRsSelected)
}

func TestCreatePolicy_AlreadyExists(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	_, err := mgr.CreatePolicy("boot", "sha256", []int{0, 1})
	require.NoError(t, err)

	def, err := mgr.CreatePolicy("boot", "sha256", []int{0, 1})
	assert.Nil(t, def)
	assert.ErrorIs(t, err, ErrPolicyExists)
}

func TestCreatePolicy_ReaderError(t *testing.T) {
	readerErr := errors.New("hardware fault")
	reader := &mockPCRReader{err: readerErr}
	store := NewMemoryPolicyStore()
	mgr, err := NewManager(reader, store)
	require.NoError(t, err)

	def, err := mgr.CreatePolicy("boot", "sha256", []int{0})
	assert.Nil(t, def)
	assert.ErrorIs(t, err, readerErr)
}

// --- GetPolicy tests ---

func TestGetPolicy_Success(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	created, err := mgr.CreatePolicy("boot", "sha256", []int{0, 7})
	require.NoError(t, err)

	loaded, err := mgr.GetPolicy("boot")
	require.NoError(t, err)
	assert.Equal(t, created.Name, loaded.Name)
	assert.Equal(t, created.Bank, loaded.Bank)
	assert.Equal(t, created.PCRIndices, loaded.PCRIndices)
}

func TestGetPolicy_NotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	loaded, err := mgr.GetPolicy("nonexistent")
	assert.Nil(t, loaded)
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

// --- ListPolicies tests ---

func TestListPolicies_Empty(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	policies, err := mgr.ListPolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestListPolicies_ReturnsAll(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	_, err := mgr.CreatePolicy("boot", "sha256", []int{0, 1})
	require.NoError(t, err)

	_, err = mgr.CreatePolicy("firmware", "sha256", []int{0, 2, 7})
	require.NoError(t, err)

	policies, err := mgr.ListPolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 2)

	names := make(map[string]bool)
	for _, p := range policies {
		names[p.Name] = true
	}
	assert.True(t, names["boot"])
	assert.True(t, names["firmware"])
}

// --- DeletePolicy tests ---

func TestDeletePolicy_Success(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	_, err := mgr.CreatePolicy("boot", "sha256", []int{0})
	require.NoError(t, err)

	err = mgr.DeletePolicy("boot")
	require.NoError(t, err)

	// Verify it's gone.
	loaded, err := mgr.GetPolicy("boot")
	assert.Nil(t, loaded)
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestDeletePolicy_NotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	err := mgr.DeletePolicy("nonexistent")
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

// --- RefreshPolicy tests ---

func TestRefreshPolicy_Success(t *testing.T) {
	mgr, reader, _ := newTestManager(t)

	original, err := mgr.CreatePolicy("boot", "sha256", []int{0, 1})
	require.NoError(t, err)

	// Simulate PCR value change (e.g., kernel update).
	reader.values = map[int][]byte{
		0: {0xff, 0xee, 0xdd, 0xcc},
		1: {0x00, 0x11, 0x22, 0x33},
	}

	refreshed, err := mgr.RefreshPolicy("boot")
	require.NoError(t, err)

	// Values should be updated.
	assert.True(t, bytes.Equal([]byte{0xff, 0xee, 0xdd, 0xcc}, refreshed.PCRValues[0]))
	assert.True(t, bytes.Equal([]byte{0x00, 0x11, 0x22, 0x33}, refreshed.PCRValues[1]))

	// UpdatedAt should be at or after the original.
	assert.True(t, !refreshed.UpdatedAt.Before(original.UpdatedAt))

	// Name and bank should be unchanged.
	assert.Equal(t, "boot", refreshed.Name)
	assert.Equal(t, "sha256", refreshed.Bank)
}

func TestRefreshPolicy_NotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	refreshed, err := mgr.RefreshPolicy("nonexistent")
	assert.Nil(t, refreshed)
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestRefreshPolicy_ReaderError(t *testing.T) {
	mgr, reader, _ := newTestManager(t)

	_, err := mgr.CreatePolicy("boot", "sha256", []int{0})
	require.NoError(t, err)

	// Simulate reader failure on refresh.
	reader.err = errors.New("tpm communication error")

	refreshed, err := mgr.RefreshPolicy("boot")
	assert.Nil(t, refreshed)
	assert.Error(t, err)
	assert.ErrorIs(t, err, reader.err)
}

// --- VerifyPolicy tests ---

func TestVerifyPolicy_Match(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	_, err := mgr.CreatePolicy("boot", "sha256", []int{0, 1, 7})
	require.NoError(t, err)

	// PCR values haven't changed, so verification should pass.
	match, msg, err := mgr.VerifyPolicy("boot")
	require.NoError(t, err)
	assert.True(t, match)
	assert.Equal(t, "all PCR values match", msg)
}

func TestVerifyPolicy_Mismatch(t *testing.T) {
	mgr, reader, _ := newTestManager(t)

	_, err := mgr.CreatePolicy("boot", "sha256", []int{0, 1})
	require.NoError(t, err)

	// Simulate PCR drift.
	reader.values = map[int][]byte{
		0: {0xff, 0xff, 0xff, 0xff},
		1: {0x11, 0x22, 0x33, 0x44}, // unchanged
	}

	match, msg, err := mgr.VerifyPolicy("boot")
	require.NoError(t, err)
	assert.False(t, match)
	assert.Contains(t, msg, "mismatch")
}

func TestVerifyPolicy_NotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	match, msg, err := mgr.VerifyPolicy("nonexistent")
	assert.False(t, match)
	assert.Empty(t, msg)
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestVerifyPolicy_ReaderError(t *testing.T) {
	mgr, reader, _ := newTestManager(t)

	_, err := mgr.CreatePolicy("boot", "sha256", []int{0})
	require.NoError(t, err)

	// Simulate reader failure on verify.
	reader.err = errors.New("device removed")

	match, msg, err := mgr.VerifyPolicy("boot")
	assert.False(t, match)
	assert.Empty(t, msg)
	assert.Error(t, err)
	assert.ErrorIs(t, err, reader.err)
}

func TestVerifyPolicy_MissingPCRFromCurrentReadings(t *testing.T) {
	mgr, reader, _ := newTestManager(t)

	_, err := mgr.CreatePolicy("boot", "sha256", []int{0, 7})
	require.NoError(t, err)

	// Return values that omit PCR 7.
	reader.values = map[int][]byte{
		0: {0xaa, 0xbb, 0xcc, 0xdd},
	}

	match, msg, err := mgr.VerifyPolicy("boot")
	require.NoError(t, err)
	assert.False(t, match)
	assert.Contains(t, msg, "PCR 7")
	assert.Contains(t, msg, "missing from current readings")
}

// --- ExportPolicy tests ---

func TestExportPolicy_Success(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	_, err := mgr.CreatePolicy("boot", "sha256", []int{0, 7})
	require.NoError(t, err)

	exported, err := mgr.ExportPolicy("boot")
	require.NoError(t, err)
	assert.NotEmpty(t, exported)

	// Verify it's valid JSON that round-trips.
	var parsed PolicyDefinition
	err = json.Unmarshal([]byte(exported), &parsed)
	require.NoError(t, err)
	assert.Equal(t, "boot", parsed.Name)
	assert.Equal(t, "sha256", parsed.Bank)
	assert.Len(t, parsed.PCRIndices, 2)
}

func TestExportPolicy_NotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	exported, err := mgr.ExportPolicy("nonexistent")
	assert.Empty(t, exported)
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

// --- ValidatePCRIndices tests ---

func TestValidatePCRIndices_Valid(t *testing.T) {
	assert.NoError(t, ValidatePCRIndices([]int{0, 1, 7, 23}))
}

func TestValidatePCRIndices_SingleIndex(t *testing.T) {
	assert.NoError(t, ValidatePCRIndices([]int{0}))
}

func TestValidatePCRIndices_AllIndices(t *testing.T) {
	all := make([]int, 24)
	for i := range all {
		all[i] = i
	}
	assert.NoError(t, ValidatePCRIndices(all))
}

func TestValidatePCRIndices_Empty(t *testing.T) {
	assert.ErrorIs(t, ValidatePCRIndices([]int{}), ErrNoPCRsSelected)
}

func TestValidatePCRIndices_Nil(t *testing.T) {
	assert.ErrorIs(t, ValidatePCRIndices(nil), ErrNoPCRsSelected)
}

func TestValidatePCRIndices_NegativeIndex(t *testing.T) {
	assert.ErrorIs(t, ValidatePCRIndices([]int{0, -1}), ErrPCRIndexOutOfRange)
}

func TestValidatePCRIndices_TooHigh(t *testing.T) {
	assert.ErrorIs(t, ValidatePCRIndices([]int{0, 24}), ErrPCRIndexOutOfRange)
}

func TestValidatePCRIndices_WayTooHigh(t *testing.T) {
	assert.ErrorIs(t, ValidatePCRIndices([]int{100}), ErrPCRIndexOutOfRange)
}

func TestValidatePCRIndices_Duplicate(t *testing.T) {
	assert.ErrorIs(t, ValidatePCRIndices([]int{0, 1, 0}), ErrDuplicatePCRIndex)
}

// --- ValidateBank tests ---

func TestValidateBank_SHA256(t *testing.T) {
	assert.NoError(t, ValidateBank("sha256"))
}

func TestValidateBank_SHA1(t *testing.T) {
	assert.NoError(t, ValidateBank("sha1"))
}

func TestValidateBank_SHA384(t *testing.T) {
	assert.NoError(t, ValidateBank("sha384"))
}

func TestValidateBank_SHA512(t *testing.T) {
	assert.NoError(t, ValidateBank("sha512"))
}

func TestValidateBank_CaseInsensitive(t *testing.T) {
	assert.NoError(t, ValidateBank("SHA256"))
	assert.NoError(t, ValidateBank("Sha384"))
}

func TestValidateBank_Empty(t *testing.T) {
	assert.ErrorIs(t, ValidateBank(""), ErrInvalidBank)
}

func TestValidateBank_Whitespace(t *testing.T) {
	assert.ErrorIs(t, ValidateBank("  "), ErrInvalidBank)
}

func TestValidateBank_Unsupported(t *testing.T) {
	assert.ErrorIs(t, ValidateBank("md5"), ErrUnsupportedBank)
}

func TestValidateBank_UnsupportedSM3(t *testing.T) {
	assert.ErrorIs(t, ValidateBank("sm3"), ErrUnsupportedBank)
}

// --- CreatePolicy with validation tests ---

func TestCreatePolicy_PCRIndexOutOfRange(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	def, err := mgr.CreatePolicy("boot", "sha256", []int{0, 24})
	assert.Nil(t, def)
	assert.ErrorIs(t, err, ErrPCRIndexOutOfRange)
}

func TestCreatePolicy_NegativePCRIndex(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	def, err := mgr.CreatePolicy("boot", "sha256", []int{-1})
	assert.Nil(t, def)
	assert.ErrorIs(t, err, ErrPCRIndexOutOfRange)
}

func TestCreatePolicy_DuplicatePCRIndex(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	def, err := mgr.CreatePolicy("boot", "sha256", []int{0, 1, 0})
	assert.Nil(t, def)
	assert.ErrorIs(t, err, ErrDuplicatePCRIndex)
}

func TestCreatePolicy_UnsupportedBank(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	def, err := mgr.CreatePolicy("boot", "md5", []int{0})
	assert.Nil(t, def)
	assert.ErrorIs(t, err, ErrUnsupportedBank)
}

func TestCreatePolicy_BankCaseInsensitive(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	def, err := mgr.CreatePolicy("boot", "SHA256", []int{0})
	require.NoError(t, err)
	assert.NotNil(t, def)
}
