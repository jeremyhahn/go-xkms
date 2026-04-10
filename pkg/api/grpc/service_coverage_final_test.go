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

//go:build !frost

package grpc

import (
	"context"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	assert.Equal(t, addResp.Id, updateResp.Id)
	assert.Contains(t, updateResp.Message, "updated")
}

// TestPasswordUpdate_NilRequest exercises the nil request validation.
func TestPasswordUpdate_NilRequest(t *testing.T) {
	service := NewService(nil, nil)
	ctx := context.Background()

	_, err := service.PasswordUpdate(ctx, nil)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// TestPasswordList_WithEntries exercises PasswordList with entries in the store,
// covering the response building logic.
func TestPasswordList_WithEntries(t *testing.T) {
	service := setupTestWithPasswordStore(t)
	defer xkms.Reset()

	ctx := context.Background()

	// Add multiple entries to exercise the listing path
	_, err := service.PasswordAdd(ctx, &pb.PasswordAddRequest{
		Name: "Entry 1", Username: "u1", Password: "p1",
	})
	require.NoError(t, err)

	_, err = service.PasswordAdd(ctx, &pb.PasswordAddRequest{
		Name: "Entry 2", Username: "u2", Password: "p2",
	})
	require.NoError(t, err)

	// List passwords
	listResp, err := service.PasswordList(ctx, &pb.PasswordListRequest{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(listResp.GetPasswords()), 2)
}

// TestPasswordUpdate_EmptyID exercises the empty ID validation path.
func TestPasswordUpdate_EmptyID(t *testing.T) {
	service := setupTestWithPasswordStore(t)
	defer xkms.Reset()

	ctx := context.Background()

	_, err := service.PasswordUpdate(ctx, &pb.PasswordUpdateRequest{
		Id: "",
	})
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// TestPasswordDelete_NonExistentEntry exercises the not-found error path.
func TestPasswordDelete_NonExistentEntry(t *testing.T) {
	service := setupTestWithPasswordStore(t)
	defer xkms.Reset()

	ctx := context.Background()

	_, err := service.PasswordDelete(ctx, &pb.PasswordDeleteRequest{
		Id: "non-existent-id",
	})
	require.Error(t, err)
}
