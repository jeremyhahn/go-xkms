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

// Package policy manages PCR (Platform Configuration Register) policies for
// TPM-based sealing. It abstracts PCR reading and policy storage behind
// interfaces so it can work with any TPM implementation.
package policy

import (
	"strings"
	"time"
)

// PolicyDefinition captures a snapshot of PCR values bound to a name.
type PolicyDefinition struct {
	Name       string         `json:"name"`
	Bank       string         `json:"bank"`        // e.g., "sha256"
	PCRIndices []int          `json:"pcr_indices"` // e.g., [0, 1, 2, 3, 7]
	PCRValues  map[int][]byte `json:"pcr_values"`  // index -> digest
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// PCRReader reads PCR values from a platform.
type PCRReader interface {
	ReadPCRs(bank string, indices []int) (map[int][]byte, error)
}

// PolicyStore persists and retrieves policy definitions.
type PolicyStore interface {
	SavePolicy(name string, def *PolicyDefinition) error
	LoadPolicy(name string) (*PolicyDefinition, error)
	DeletePolicy(name string) error
	ListPolicies() ([]*PolicyDefinition, error)
}

// MaxPCRIndex is the highest valid TPM 2.0 PCR index.
const MaxPCRIndex = 23

// SupportedBanks contains the recognized TPM 2.0 PCR hash algorithms.
var SupportedBanks = map[string]struct{}{
	"sha1":   {},
	"sha256": {},
	"sha384": {},
	"sha512": {},
}

// ValidatePCRIndices checks that every index is in [0, MaxPCRIndex] and that
// there are no duplicates. Returns ErrNoPCRsSelected if the slice is empty,
// ErrPCRIndexOutOfRange for out-of-bounds values, or ErrDuplicatePCRIndex
// for repeated indices.
func ValidatePCRIndices(pcrs []int) error {
	if len(pcrs) == 0 {
		return ErrNoPCRsSelected
	}
	seen := make(map[int]struct{}, len(pcrs))
	for _, idx := range pcrs {
		if idx < 0 || idx > MaxPCRIndex {
			return ErrPCRIndexOutOfRange
		}
		if _, dup := seen[idx]; dup {
			return ErrDuplicatePCRIndex
		}
		seen[idx] = struct{}{}
	}
	return nil
}

// ValidateBank checks that the bank name (case-insensitive) is a recognized
// TPM 2.0 PCR hash algorithm. Returns ErrInvalidBank for empty input or
// ErrUnsupportedBank for unrecognized algorithms.
func ValidateBank(bank string) error {
	trimmed := strings.TrimSpace(bank)
	if trimmed == "" {
		return ErrInvalidBank
	}
	if _, ok := SupportedBanks[strings.ToLower(trimmed)]; !ok {
		return ErrUnsupportedBank
	}
	return nil
}
