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

package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	pkgmcp "github.com/jeremyhahn/go-xkms/pkg/api/transport/mcp"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// TestErrIdentityCeremonyExcluded_ReExportsCanonical confirms the SDK error
// sentinel is the same value as the canonical pkg/api/transport/mcp error,
// not a re-declared lookalike that would defeat errors.Is for callers who
// compare against one package but receive an error from the other.
func TestErrIdentityCeremonyExcluded_ReExportsCanonical(t *testing.T) {
	assert.Same(t, pkgmcp.ErrIdentityCeremonyExcluded, ErrIdentityCeremonyExcluded)
}

// TestWebAuthnMethods_ExcludedByDesign confirms all four WebAuthn/FIDO2
// methods on the SDK's re-exported Transport fail with the typed exclusion
// error (issue #193), reachable via errors.Is through the SDK alias exactly
// as it is through the canonical implementation.
func TestWebAuthnMethods_ExcludedByDesign(t *testing.T) {
	tr := &Transport{}
	ctx := context.Background()

	_, err := tr.BeginRegistration(ctx, &transport.BeginRegistrationRequest{})
	assert.True(t, errors.Is(err, ErrIdentityCeremonyExcluded))

	_, err = tr.FinishRegistration(ctx, &transport.FinishRegistrationRequest{})
	assert.True(t, errors.Is(err, ErrIdentityCeremonyExcluded))

	_, err = tr.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{})
	assert.True(t, errors.Is(err, ErrIdentityCeremonyExcluded))

	_, err = tr.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{})
	assert.True(t, errors.Is(err, ErrIdentityCeremonyExcluded))
}
