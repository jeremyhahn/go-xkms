// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_UpdateBranchNeedsAReferenceSigner(t *testing.T) {
	svc, _ := newOfflineService(t)
	_, err := svc.UpdateBranch(context.Background(), "acme", "boot", "next", []byte("corim"))
	require.ErrorIs(t, err, ErrNoReferenceSigner)
}

func TestBranchPCRCondition(t *testing.T) {
	b := Branch{Conditions: []Condition{
		{Type: ConditionLocality, Localities: []uint{0}},
		{Type: ConditionPCR, Bank: "sha256", PCRs: []uint{testPCR}},
	}}
	c := branchPCRCondition(&b)
	require.NotNil(t, c)
	assert.Same(t, &b.Conditions[1], c, "the condition is returned in place, so the update edits the branch")
	assert.Nil(t, branchPCRCondition(&Branch{Conditions: []Condition{{Type: ConditionLocality, Localities: []uint{0}}}}))
}
