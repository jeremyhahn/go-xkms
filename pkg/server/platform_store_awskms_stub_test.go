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

//go:build !awskms

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitializePlatformStore_AWSKMSNotCompiledIn proves the awskms
// credential strategy fails closed with the standard not-compiled-in error
// when the binary was built without the awskms tag. See
// platform_store_awskms_test.go for the real, working construction under
// that tag.
func TestInitializePlatformStore_AWSKMSNotCompiledIn(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig("awskms"))

	err := s.initializePlatformStore()
	require.Error(t, err)
	assert.Nil(t, s.platformStore)
	assert.ErrorIs(t, err, ErrBackendNotCompiled)
}
