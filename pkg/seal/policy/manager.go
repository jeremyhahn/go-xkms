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
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Manager provides operations for creating, verifying, refreshing, and
// exporting PCR policies. It reads current PCR values through a PCRReader
// and persists policy definitions through a PolicyStore.
type Manager struct {
	reader PCRReader
	store  PolicyStore
}

// NewManager returns a Manager that uses the given PCRReader and PolicyStore.
// Both arguments must be non-nil.
func NewManager(reader PCRReader, store PolicyStore) (*Manager, error) {
	if reader == nil {
		return nil, ErrNilPCRReader
	}
	if store == nil {
		return nil, ErrNilPolicyStore
	}
	return &Manager{
		reader: reader,
		store:  store,
	}, nil
}

// CreatePolicy captures the current PCR values for the specified bank and
// indices and stores them as a named policy. Returns ErrPolicyExists if a
// policy with the same name already exists.
func (m *Manager) CreatePolicy(name, bank string, pcrs []int) (*PolicyDefinition, error) {
	if strings.TrimSpace(name) == "" {
		return nil, ErrInvalidName
	}
	if err := ValidateBank(bank); err != nil {
		return nil, err
	}
	if err := ValidatePCRIndices(pcrs); err != nil {
		return nil, err
	}

	// Check for existing policy.
	_, err := m.store.LoadPolicy(name)
	if err == nil {
		return nil, ErrPolicyExists
	}
	if !errors.Is(err, ErrPolicyNotFound) {
		return nil, err
	}

	// Read current PCR values.
	values, err := m.reader.ReadPCRs(bank, pcrs)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	def := &PolicyDefinition{
		Name:       name,
		Bank:       bank,
		PCRIndices: pcrs,
		PCRValues:  values,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := m.store.SavePolicy(name, def); err != nil {
		return nil, err
	}
	return def, nil
}

// GetPolicy loads a policy definition by name from the store.
func (m *Manager) GetPolicy(name string) (*PolicyDefinition, error) {
	return m.store.LoadPolicy(name)
}

// RefreshPolicy re-reads the PCR values for an existing policy and updates
// the stored definition. This is used after a legitimate system change
// (e.g., kernel update) to capture the new expected values.
func (m *Manager) RefreshPolicy(name string) (*PolicyDefinition, error) {
	def, err := m.store.LoadPolicy(name)
	if err != nil {
		return nil, err
	}

	values, err := m.reader.ReadPCRs(def.Bank, def.PCRIndices)
	if err != nil {
		return nil, err
	}

	def.PCRValues = values
	def.UpdatedAt = time.Now()

	if err := m.store.SavePolicy(name, def); err != nil {
		return nil, err
	}
	return def, nil
}

// VerifyPolicy reads the current PCR values and compares them against the
// stored policy. Returns true with an "ok" message if all PCR values match,
// or false with a descriptive mismatch message otherwise.
func (m *Manager) VerifyPolicy(name string) (bool, string, error) {
	def, err := m.store.LoadPolicy(name)
	if err != nil {
		return false, "", err
	}

	current, err := m.reader.ReadPCRs(def.Bank, def.PCRIndices)
	if err != nil {
		return false, "", err
	}

	for _, idx := range def.PCRIndices {
		expected, ok := def.PCRValues[idx]
		if !ok {
			return false, fmt.Sprintf("PCR %d: missing from policy", idx), nil
		}
		actual, ok := current[idx]
		if !ok {
			return false, fmt.Sprintf("PCR %d: missing from current readings", idx), nil
		}
		if subtle.ConstantTimeCompare(expected, actual) != 1 {
			return false, fmt.Sprintf("PCR %d: value mismatch", idx), nil
		}
	}
	return true, "all PCR values match", nil
}

// DeletePolicy removes a policy from the store.
func (m *Manager) DeletePolicy(name string) error {
	return m.store.DeletePolicy(name)
}

// ListPolicies returns all stored policy definitions.
func (m *Manager) ListPolicies() ([]*PolicyDefinition, error) {
	return m.store.ListPolicies()
}

// ExportPolicy serializes a named policy to a formatted JSON string.
func (m *Manager) ExportPolicy(name string) (string, error) {
	def, err := m.store.LoadPolicy(name)
	if err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(def, "", "  ")
	if err != nil {
		return "", ErrExportFailed
	}
	return string(data), nil
}
