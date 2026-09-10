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

package server

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
)

// TestBackendFactory_DefaultResolutionIsDeterministic covers the third site of
// the randomized-default defect.
//
// The factory computed its own default by ranging the backend map and taking
// the first entry, which reads Go's randomized iteration order. A deployment
// whose configured default was absent therefore got a different backend on
// each start, and keys written before a restart were looked for in another
// store after it. Because the factory computed a non-empty default before
// calling xkms.Initialize, Initialize's own deterministic rule never ran for
// this caller.
//
// The assertion is repetition: a randomized pick over three candidates
// survives a single comparison roughly a third of the time, so the property
// worth testing is that many resolutions agree.
func TestBackendFactory_DefaultResolutionIsDeterministic(t *testing.T) {
	backends := map[string]xkms.Backend{
		"aws-kms": nil,
		"pkcs11":  nil,
		"tpm2":    nil,
	}

	// A configured default that is not loaded must resolve the same way every
	// time rather than to whichever key the map happened to yield first.
	first := xkms.ResolveDefaultBackend("absent-backend", backends)
	for i := 0; i < 64; i++ {
		assert.Equal(t, first, xkms.ResolveDefaultBackend("absent-backend", backends),
			"an absent default must resolve identically on every call")
	}

	// A configured default that IS loaded is authoritative and must not be
	// replaced by the fallback rule.
	assert.Equal(t, "pkcs11", xkms.ResolveDefaultBackend("pkcs11", backends))

	// Software is preferred over the sorted fallback when it is present, so a
	// missing default does not silently promote a cloud KMS to hold every key
	// generated without an explicit backend.
	withSoftware := map[string]xkms.Backend{
		"aws-kms":  nil,
		"software": nil,
	}
	assert.Equal(t, "software", xkms.ResolveDefaultBackend("absent-backend", withSoftware))
}
