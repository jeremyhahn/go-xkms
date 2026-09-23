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

package backup

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestBackupKey_MarshalJSON_TPMAttributesWithSessionCloser proves a key whose
// TPM attributes carry a live session closer still backs up: the closer is a
// process-local func and must be left out of the JSON, not fail the encode.
func TestBackupKey_MarshalJSON_TPMAttributesWithSessionCloser(t *testing.T) {
	key := &BackupKey{
		Attributes: &types.KeyAttributes{
			CN: "tpm-key",
			TPMAttributes: &types.TPMAttributes{
				SessionCloser: func() error { return nil },
			},
		},
	}

	data, err := json.Marshal(key)
	require.NoError(t, err)
	require.NotContains(t, string(data), "SessionCloser")

	var decoded BackupKey
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.NotNil(t, decoded.Attributes.TPMAttributes)
	require.Nil(t, decoded.Attributes.TPMAttributes.SessionCloser)
}
