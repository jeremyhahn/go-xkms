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

//go:build !pkcs11

package pkcs11strategy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBuild_FailsClosedWithoutThePKCS11Tag proves a binary without PKCS#11
// support refuses a complete configuration instead of building nothing
// silently.
func TestBuild_FailsClosedWithoutThePKCS11Tag(t *testing.T) {
	strategy, closer, err := Build(context.Background(), validParams(t))
	require.ErrorIs(t, err, ErrNotCompiledIn)
	require.Nil(t, strategy)
	require.Nil(t, closer)
}
