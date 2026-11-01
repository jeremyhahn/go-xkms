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
	"context"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPasswordUpdate_AllOptionalFields exercises every optional field branch
// in PasswordUpdate (Name, Username, Password, URL, Notes, FolderPath, ExpiresAt).
func TestPasswordUpdate_AllOptionalFields(t *testing.T) {
	service := setupTestWithPasswordStore(t)
	defer xkms.Reset()

	ctx := context.Background()

	// Create a password entry to update
	addResp, err := service.PasswordAdd(ctx, &pb.PasswordAddRequest{
		Name:     "All Fields Test",
		Username: "user1",
		Password: "pass1",
	})
	require.NoError(t, err)

	// Update with ALL optional fields set to exercise every branch
	newName := "Updated Name"
	newUsername := "newuser"
	newPassword := "newpass123"
	newURL := "https://example.com"
	newNotes := "updated notes"
	newFolder := "/updated/folder"
	newExpiry := "2030-01-01T00:00:00Z"

	updateResp, err := service.PasswordUpdate(ctx, &pb.PasswordUpdateRequest{
		Id:         addResp.Id,
		Name:       &newName,
		Username:   &newUsername,
		Password:   &newPassword,
		Url:        &newURL,
		Notes:      &newNotes,
		FolderPath: &newFolder,
		ExpiresAt:  &newExpiry,
	})
	require.NoError(t, err)
	// The rename and move re-key the entry: the response names the new ID.
	assert.NotEqual(t, addResp.Id, updateResp.Id)
	got, err := service.PasswordGet(ctx, &pb.PasswordGetRequest{Id: updateResp.Id})
	require.NoError(t, err)
	assert.Equal(t, newName, got.Entry.Name)
	assert.Contains(t, updateResp.Message, "updated")
}
