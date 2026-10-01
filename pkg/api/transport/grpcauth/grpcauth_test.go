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


package grpcauth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBearer_Metadata(t *testing.T) {
	md, err := Bearer{token: "t"}.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"authorization": "Bearer t"}, md)
	assert.True(t, Bearer{}.RequireTransportSecurity(), "a bearer token never crosses plaintext")
}

func TestDialOptions(t *testing.T) {
	assert.Len(t, DialOptions("tok"), 1)
	assert.Nil(t, DialOptions(""), "no token, no authorization metadata")
}
