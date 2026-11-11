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

package grpc

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTimestampHelper(t *testing.T) {
	t.Run("returns nil for empty string", func(t *testing.T) {
		assert.Nil(t, parseTimestamp(""))
	})

	t.Run("returns nil for invalid format", func(t *testing.T) {
		assert.Nil(t, parseTimestamp("not-a-timestamp"))
	})

	t.Run("parses valid RFC3339 timestamp", func(t *testing.T) {
		ts := time.Now().UTC().Format(time.RFC3339)
		result := parseTimestamp(ts)
		require.NotNil(t, result)
	})
}

func TestPasswordEntryToProto(t *testing.T) {
	t.Run("converts entry with all fields", func(t *testing.T) {
		now := time.Now().UTC().Format(time.RFC3339)
		resp := &transport.PasswordGetResponse{
			ID:         "pw-3",
			Name:       "entry-test",
			Username:   "user",
			Password:   "pass",
			URL:        "https://example.com",
			Notes:      "notes",
			FolderPath: "root",
			BackendID:  "backend-1",
			ExpiresAt:  now,
			CreatedAt:  now,
			UpdatedAt:  now,
			ReadOnly:   true,
			Encrypted:  false,
			OwnerID:    "owner-1",
			Shared:     false,
		}

		pb := passwordEntryToProto(resp)
		require.NotNil(t, pb)
		assert.Equal(t, "pw-3", pb.Id)
		assert.Equal(t, "entry-test", pb.Name)
		assert.True(t, pb.ReadOnly)
		assert.False(t, pb.Encrypted)
		assert.NotNil(t, pb.ExpiresAt)
	})

	t.Run("converts entry with empty timestamps", func(t *testing.T) {
		resp := &transport.PasswordGetResponse{
			ID:   "pw-4",
			Name: "minimal-entry",
		}

		pb := passwordEntryToProto(resp)
		require.NotNil(t, pb)
		assert.Equal(t, "pw-4", pb.Id)
		assert.Nil(t, pb.ExpiresAt)
		assert.Nil(t, pb.CreatedAt)
		assert.Nil(t, pb.UpdatedAt)
	})
}
