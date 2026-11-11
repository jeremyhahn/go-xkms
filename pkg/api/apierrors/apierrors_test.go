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

package apierrors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestClassOf_FirstMatchWins proves a single error satisfying errors.Is for
// more than one entry resolves to whichever entry is listed first, exactly
// like keyOpSentinelCodes in pkg/api/grpc and pkg/api/mcp.
func TestClassOf_FirstMatchWins(t *testing.T) {
	first := errors.New("first")
	second := errors.New("second")
	ordered := []SentinelClass{
		{first, ClassInvalidArgument},
		{second, ClassNotFound},
	}
	multi := fmt.Errorf("%w: %w", first, second)
	class, ok := ClassOf(ordered, multi)
	assert.True(t, ok)
	assert.Equal(t, ClassInvalidArgument, class)
}

// TestImportExportSentinelClasses_WrapTargetNotSymmetric proves a WrapKeyByID
// refusal of a non-symmetric target is an invalid argument (go-xkms#1634).
func TestImportExportSentinelClasses_WrapTargetNotSymmetric(t *testing.T) {
	err := &xkms.ErrWrapTarget{KeyID: "ecdsa-key", Err: xkms.ErrWrapTargetNotSymmetric}
	class, ok := ClassOf(ImportExportSentinelClasses, err)
	assert.True(t, ok)
	assert.Equal(t, ClassInvalidArgument, class)

	_, ok = ClassOf(ImportExportSentinelClasses, errors.New("unrelated"))
	assert.False(t, ok, "an unlisted error must not be classified")
}
