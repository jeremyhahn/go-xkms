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

package preseal

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

var errCause = errors.New("cause")

func TestErrors_NameTheSecretAndUnwrap(t *testing.T) {
	wrapping := map[string]error{
		"preseal: open store at /records: cause":           &OpenError{Dir: "/records", Err: errCause},
		"preseal: the Platform SRK is not enrolled: cause": &PlatformSRKError{Err: errCause},
		"preseal: seal pin: cause":                         &SealError{Name: "pin", Err: errCause},
		"preseal: the TPM refused to release pin: cause":   &RefusedError{Name: "pin", Err: errCause},
		"preseal: unseal pin: cause":                       &UnsealError{Name: "pin", Err: errCause},
	}
	for msg, err := range wrapping {
		require.EqualError(t, err, msg)
		require.ErrorIs(t, err, errCause)
	}
}

func TestErrors_WithoutCause(t *testing.T) {
	require.EqualError(t, &OpenError{Err: errCause}, "preseal: open store: cause")
	require.EqualError(t, &EmptySecretError{Name: "pin"}, "preseal: secret pin is empty")
	require.EqualError(t, &NotFoundError{Name: "pin"}, "preseal: no secret is sealed under pin")
}
