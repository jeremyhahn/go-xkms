// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	assert.NotNil(t, opts, "DefaultOptions should not return nil")
	assert.Equal(t, "", opts.Path, "Default path should be empty")
	assert.Equal(t, 0600, int(opts.Permissions), "Default permissions should be 0600")
	assert.NotNil(t, opts.Metadata, "Metadata map should not be nil")
	assert.Empty(t, opts.Metadata, "Metadata map should be empty")
}

func TestDefaultOptions_MetadataNotShared(t *testing.T) {
	opts1 := DefaultOptions()
	opts2 := DefaultOptions()

	// Modify first options metadata
	opts1.Metadata["key1"] = "value1"

	// Second options should not be affected
	assert.Empty(t, opts2.Metadata, "Metadata should not be shared between instances")
	assert.NotContains(t, opts2.Metadata, "key1", "Metadata should be independent")
}

func TestOptions_Mutations(t *testing.T) {
	opts := DefaultOptions()

	// Test path mutation
	opts.Path = "/test/path"
	assert.Equal(t, "/test/path", opts.Path)

	// Test permissions mutation
	opts.Permissions = 0644
	assert.Equal(t, 0644, int(opts.Permissions))

	// Test metadata mutation
	opts.Metadata["test-key"] = "test-value"
	assert.Equal(t, "test-value", opts.Metadata["test-key"])
}
