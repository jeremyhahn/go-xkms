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

package appraisaltest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestUnserved_RefusesEveryCall proves an embedding double never answers a
// Verifier call as if it had succeeded, with or without a request.
func TestUnserved_RefusesEveryCall(t *testing.T) {
	ctx := context.Background()
	calls := Calls(ctx, Unserved{})
	assert.Len(t, calls, 8)
	for name, call := range calls {
		assert.ErrorIs(t, call(), ErrUnserved, name)
	}
	for name, call := range NilRequestCalls(ctx, Unserved{}) {
		assert.ErrorIs(t, call(), ErrUnserved, name)
	}
}
