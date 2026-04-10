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
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKDFAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected types.KDFAlgorithm
	}{
		{"empty defaults to HKDF", "", types.KDFAlgorithmHKDF},
		{"HKDF", "HKDF", types.KDFAlgorithmHKDF},
		{"hkdf lowercase", "hkdf", types.KDFAlgorithmHKDF},
		{"SP800-108-COUNTER", "SP800-108-COUNTER", types.KDFAlgorithmSP800108Counter},
		{"SP800-108-FEEDBACK", "SP800-108-FEEDBACK", types.KDFAlgorithmSP800108Feedback},
		{"SP800-56A", "SP800-56A", types.KDFAlgorithmSP80056A},
		{"X963", "X963", types.KDFAlgorithmX963},
		{"unknown defaults to HKDF", "unknown-algo", types.KDFAlgorithmHKDF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseKDFAlgorithm(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseKDFHash(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty defaults to SHA-256", "", "SHA-256"},
		{"SHA256", "SHA256", "SHA-256"},
		{"SHA-256 with dash", "SHA-256", "SHA-256"},
		{"SHA384", "SHA384", "SHA-384"},
		{"SHA512", "SHA512", "SHA-512"},
		{"SHA3256", "SHA3-256", "SHA3-256"},
		{"SHA3384", "SHA3-384", "SHA3-384"},
		{"SHA3512", "SHA3-512", "SHA3-512"},
		{"unknown returned as-is", "BLAKE2b", "BLAKE2b"},
		{"lowercase sha256", "sha256", "SHA-256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseKDFHash(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

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

func TestPasswordGetResponseToProto(t *testing.T) {
	t.Run("converts response with all fields", func(t *testing.T) {
		now := time.Now().UTC().Format(time.RFC3339)
		resp := &transport.PasswordGetResponse{
			ID:         "pw-1",
			Name:       "test-password",
			Username:   "admin",
			Password:   "secret123",
			URL:        "https://example.com",
			Notes:      "test notes",
			FolderPath: "folder/sub",
			BackendID:  "software",
			ExpiresAt:  now,
			CreatedAt:  now,
			UpdatedAt:  now,
			ReadOnly:   false,
			Encrypted:  true,
			OwnerID:    "user-1",
			Shared:     true,
		}

		pb := passwordGetResponseToProto(resp)
		require.NotNil(t, pb)
		require.NotNil(t, pb.Entry)
		assert.Equal(t, "pw-1", pb.Entry.Id)
		assert.Equal(t, "test-password", pb.Entry.Name)
		assert.Equal(t, "admin", pb.Entry.Username)
		assert.Equal(t, "secret123", pb.Entry.Password)
		assert.Equal(t, "https://example.com", pb.Entry.Url)
		assert.Equal(t, "test notes", pb.Entry.Notes)
		assert.Equal(t, "folder/sub", pb.Entry.FolderPath)
		assert.Equal(t, "software", pb.Entry.BackendId)
		assert.True(t, pb.Entry.Encrypted)
		assert.True(t, pb.Entry.Shared)
		assert.NotNil(t, pb.Entry.ExpiresAt)
		assert.NotNil(t, pb.Entry.CreatedAt)
		assert.NotNil(t, pb.Entry.UpdatedAt)
	})

	t.Run("converts response with empty timestamps", func(t *testing.T) {
		resp := &transport.PasswordGetResponse{
			ID:   "pw-2",
			Name: "minimal",
		}

		pb := passwordGetResponseToProto(resp)
		require.NotNil(t, pb)
		require.NotNil(t, pb.Entry)
		assert.Equal(t, "pw-2", pb.Entry.Id)
		assert.Nil(t, pb.Entry.ExpiresAt)
		assert.Nil(t, pb.Entry.CreatedAt)
		assert.Nil(t, pb.Entry.UpdatedAt)
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
