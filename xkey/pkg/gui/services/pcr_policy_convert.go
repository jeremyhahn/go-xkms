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

package services

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	pcrpolicy "github.com/jeremyhahn/go-xkms/xkey/pkg/pcr_policy"
)

// pcrPolicyToEntity converts a GUI PCRPolicy DTO into a
// pcrpolicy.PCRPolicyEntity suitable for persistence in the canonical PCR
// policy store shared with the CLI and BarrierAutoUnsealService.
//
// All PCR selections in a policy must share a single hash bank because the
// store entity has one Bank field; this mirrors how the frontend always
// creates policies with one bank applied uniformly across all selected PCR
// indices (see TPM.svelte's newPolicyBank).
func pcrPolicyToEntity(p PCRPolicy) (*pcrpolicy.PCRPolicyEntity, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return nil, ErrTPMInvalidPolicyName
	}
	if len(p.PCRSelections) == 0 {
		return nil, ErrTPMInvalidPCRs
	}

	bank := strings.ToUpper(p.PCRSelections[0].Bank)
	pcrs := make(map[uint][]byte, len(p.PCRSelections))
	for _, sel := range p.PCRSelections {
		if !strings.EqualFold(sel.Bank, bank) {
			return nil, ErrTPMPolicyMixedBanks
		}

		// Digests are keyed "bank:index" (lowercase bank) as produced by
		// readPCRDigests. A missing or malformed digest leaves the PCR
		// value empty; it is filled in on the next RefreshPolicyPCRs call.
		var digest []byte
		key := fmt.Sprintf("%s:%d", strings.ToLower(sel.Bank), sel.Index)
		if hexDigest, ok := p.PCRDigests[key]; ok {
			if decoded, decErr := hex.DecodeString(hexDigest); decErr == nil {
				digest = decoded
			}
		}
		pcrs[uint(sel.Index)] = digest
	}

	entity := &pcrpolicy.PCRPolicyEntity{
		Name:             name,
		Description:      p.Description,
		Bank:             bank,
		PCRs:             pcrs,
		IsPlatformPolicy: p.IsPlatformPolicy,
	}
	if p.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, p.CreatedAt); err == nil {
			entity.CreatedAt = t
		}
	}
	if p.UpdatedAt != "" {
		if t, err := time.Parse(time.RFC3339, p.UpdatedAt); err == nil {
			entity.UpdatedAt = t
		}
	}

	return entity, nil
}

// entityToPCRPolicy converts a pcrpolicy.PCRPolicyEntity read from the
// canonical store into the GUI-facing PCRPolicy DTO. The Valid field is
// intentionally left nil: it is a point-in-time comparison against live TPM
// state computed by ListPoliciesWithDigests, not persisted data.
func entityToPCRPolicy(e *pcrpolicy.PCRPolicyEntity) PCRPolicy {
	bank := strings.ToLower(e.Bank)

	indices := make([]uint, 0, len(e.PCRs))
	for idx := range e.PCRs {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })

	selections := make([]PCRSelection, 0, len(indices))
	digests := make(map[string]string, len(indices))
	for _, idx := range indices {
		selections = append(selections, PCRSelection{Index: int(idx), Bank: bank})
		if val := e.PCRs[idx]; len(val) > 0 {
			digests[fmt.Sprintf("%s:%d", bank, idx)] = hex.EncodeToString(val)
		}
	}

	policy := PCRPolicy{
		Name:             e.Name,
		Description:      e.Description,
		PCRSelections:    selections,
		IsPlatformPolicy: e.IsPlatformPolicy,
	}
	if !e.CreatedAt.IsZero() {
		policy.CreatedAt = e.CreatedAt.Format(time.RFC3339)
	}
	if !e.UpdatedAt.IsZero() {
		policy.UpdatedAt = e.UpdatedAt.Format(time.RFC3339)
	}
	if len(digests) > 0 {
		policy.PCRDigests = digests
	}

	return policy
}
