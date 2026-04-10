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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createPasswordManager creates a real TenantPasswordStoreManager backed by
// in-memory storage for testing password handler happy paths.
func createPasswordManager(t *testing.T) *staticpw.TenantPasswordStoreManager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := storage.New()
	strategy := seal.NewSoftwareStrategy()
	barrier, err := seal.NewBarrier(logger, base, seal.BarrierConfig{}, strategy)
	require.NoError(t, err)
	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)
	store := staticpw.NewStore(storage.New())
	mgr, err := staticpw.NewTenantPasswordStoreManager(registry, store)
	require.NoError(t, err)
	return mgr
}

func TestHandlePasswordAdd(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("fails when password manager not configured", func(t *testing.T) {
		server.passwordManager = nil

		params := PasswordAddParams{Name: "test", Password: "secret"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.add", Params: paramsJSON, ID: 1}

		_, err := server.handlePasswordAdd(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPasswordStoreNotConfigured)
	})

	t.Run("fails with invalid JSON params", func(t *testing.T) {
		server.passwordManager = nil
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.add", Params: json.RawMessage(`invalid`), ID: 1}

		_, err := server.handlePasswordAdd(ctx, req)
		require.Error(t, err)
	})

	t.Run("adds password successfully", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)

		params := PasswordAddParams{Name: "my-service", Password: "s3cret!", Username: "admin"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.add", Params: paramsJSON, ID: 1}

		result, err := server.handlePasswordAdd(ctx, req)
		require.NoError(t, err)

		addResult, ok := result.(PasswordAddResult)
		require.True(t, ok)
		assert.Equal(t, "my-service", addResult.Name)
		assert.NotEmpty(t, addResult.ID)
		assert.Equal(t, "Password added successfully", addResult.Message)
	})

	t.Run("fails adding password with empty name", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)

		params := PasswordAddParams{Name: "", Password: "s3cret!"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.add", Params: paramsJSON, ID: 1}

		_, err := server.handlePasswordAdd(ctx, req)
		require.Error(t, err)
	})
}

func TestHandlePasswordGet(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("fails when password manager not configured", func(t *testing.T) {
		server.passwordManager = nil

		params := PasswordGetParams{ID: "some-id"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.get", Params: paramsJSON, ID: 1}

		_, err := server.handlePasswordGet(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPasswordStoreNotConfigured)
	})

	t.Run("fails when ID is empty", func(t *testing.T) {
		server.passwordManager = nil

		params := PasswordGetParams{ID: ""}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.get", Params: paramsJSON, ID: 1}

		_, err := server.handlePasswordGet(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPasswordIDRequired)
	})

	t.Run("fails with invalid JSON params", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.get", Params: json.RawMessage(`{bad`), ID: 1}
		_, err := server.handlePasswordGet(ctx, req)
		require.Error(t, err)
	})

	t.Run("gets password by name", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)

		// Add a password first
		addParams := PasswordAddParams{Name: "get-test", Password: "pw123", Username: "user1"}
		addJSON, _ := json.Marshal(addParams)
		addReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.add", Params: addJSON, ID: 1}
		_, err := server.handlePasswordAdd(ctx, addReq)
		require.NoError(t, err)

		// Get it by name
		getParams := PasswordGetParams{ID: "get-test"}
		getJSON, _ := json.Marshal(getParams)
		getReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.get", Params: getJSON, ID: 1}

		result, err := server.handlePasswordGet(ctx, getReq)
		require.NoError(t, err)

		detail, ok := result.(PasswordDetailResult)
		require.True(t, ok)
		assert.Equal(t, "get-test", detail.Name)
		assert.Equal(t, "pw123", detail.Password)
		assert.Equal(t, "user1", detail.Username)
	})

	t.Run("fails getting nonexistent password", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)

		params := PasswordGetParams{ID: "nonexistent"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.get", Params: paramsJSON, ID: 1}

		_, err := server.handlePasswordGet(ctx, req)
		require.Error(t, err)
	})
}

func TestHandlePasswordList(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("fails when password manager not configured", func(t *testing.T) {
		server.passwordManager = nil

		params := PasswordListParams{}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.list", Params: paramsJSON, ID: 1}

		_, err := server.handlePasswordList(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPasswordStoreNotConfigured)
	})

	t.Run("fails with invalid JSON params", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.list", Params: json.RawMessage(`{bad`), ID: 1}
		_, err := server.handlePasswordList(ctx, req)
		require.Error(t, err)
	})

	t.Run("lists passwords from system store", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)

		// Add some passwords
		for _, name := range []string{"alpha", "beta"} {
			addParams := PasswordAddParams{Name: name, Password: "pw"}
			addJSON, _ := json.Marshal(addParams)
			addReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.add", Params: addJSON, ID: 1}
			_, err := server.handlePasswordAdd(ctx, addReq)
			require.NoError(t, err)
		}

		params := PasswordListParams{}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.list", Params: paramsJSON, ID: 1}

		result, err := server.handlePasswordList(ctx, req)
		require.NoError(t, err)

		listResult, ok := result.(PasswordListResult)
		require.True(t, ok)
		assert.Equal(t, 2, listResult.Total)
		assert.Len(t, listResult.Passwords, 2)
	})

	t.Run("lists passwords by folder", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)

		// Add a password in a folder
		addParams := PasswordAddParams{Name: "in-folder", Password: "pw", FolderPath: "work"}
		addJSON, _ := json.Marshal(addParams)
		addReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.add", Params: addJSON, ID: 1}
		_, err := server.handlePasswordAdd(ctx, addReq)
		require.NoError(t, err)

		// Add one outside the folder
		addParams2 := PasswordAddParams{Name: "outside", Password: "pw"}
		addJSON2, _ := json.Marshal(addParams2)
		addReq2 := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.add", Params: addJSON2, ID: 1}
		_, err = server.handlePasswordAdd(ctx, addReq2)
		require.NoError(t, err)

		// List by folder
		params := PasswordListParams{Folder: "work"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.list", Params: paramsJSON, ID: 1}

		result, err := server.handlePasswordList(ctx, req)
		require.NoError(t, err)

		listResult, ok := result.(PasswordListResult)
		require.True(t, ok)
		assert.Equal(t, 1, listResult.Total)
	})

	t.Run("returns error for invalid scope", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)

		params := PasswordListParams{Scope: "invalid-scope"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.list", Params: paramsJSON, ID: 1}

		_, err := server.handlePasswordList(ctx, req)
		require.Error(t, err)
	})
}

func TestHandlePasswordUpdate(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("fails when password manager not configured", func(t *testing.T) {
		server.passwordManager = nil

		params := PasswordUpdateParams{ID: "some-id"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.update", Params: paramsJSON, ID: 1}

		_, err := server.handlePasswordUpdate(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPasswordStoreNotConfigured)
	})

	t.Run("fails when ID is empty", func(t *testing.T) {
		server.passwordManager = nil

		params := PasswordUpdateParams{ID: ""}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.update", Params: paramsJSON, ID: 1}

		_, err := server.handlePasswordUpdate(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPasswordIDRequired)
	})

	t.Run("fails with invalid JSON params", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.update", Params: json.RawMessage(`{bad`), ID: 1}
		_, err := server.handlePasswordUpdate(ctx, req)
		require.Error(t, err)
	})

	t.Run("updates password successfully", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)

		// Add a password first
		addParams := PasswordAddParams{Name: "update-me", Password: "oldpw"}
		addJSON, _ := json.Marshal(addParams)
		addReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.add", Params: addJSON, ID: 1}
		_, err := server.handlePasswordAdd(ctx, addReq)
		require.NoError(t, err)

		// Update it
		newName := "updated-name"
		newPW := "newpw"
		newTitle := "New Title"
		newURL := "https://example.com"
		newNotes := "some notes"
		newFolder := "updated"
		newUser := "admin2"
		params := PasswordUpdateParams{
			ID:         "update-me",
			Name:       &newName,
			Password:   &newPW,
			Title:      &newTitle,
			URL:        &newURL,
			Notes:      &newNotes,
			FolderPath: &newFolder,
			Username:   &newUser,
		}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.update", Params: paramsJSON, ID: 1}

		result, err := server.handlePasswordUpdate(ctx, req)
		require.NoError(t, err)

		updateResult, ok := result.(PasswordUpdateResult)
		require.True(t, ok)
		assert.Equal(t, "updated-name", updateResult.Name)
		assert.Equal(t, "Password updated successfully", updateResult.Message)
	})

	t.Run("fails updating nonexistent password", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)

		params := PasswordUpdateParams{ID: "nonexistent"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.update", Params: paramsJSON, ID: 1}

		_, err := server.handlePasswordUpdate(ctx, req)
		require.Error(t, err)
	})
}

func TestHandlePasswordDelete(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("fails when password manager not configured", func(t *testing.T) {
		server.passwordManager = nil

		params := PasswordDeleteParams{ID: "some-id"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.delete", Params: paramsJSON, ID: 1}

		_, err := server.handlePasswordDelete(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPasswordStoreNotConfigured)
	})

	t.Run("fails when ID is empty", func(t *testing.T) {
		server.passwordManager = nil

		params := PasswordDeleteParams{ID: ""}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.delete", Params: paramsJSON, ID: 1}

		_, err := server.handlePasswordDelete(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPasswordIDRequired)
	})

	t.Run("fails with invalid JSON params", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.delete", Params: json.RawMessage(`{bad`), ID: 1}
		_, err := server.handlePasswordDelete(ctx, req)
		require.Error(t, err)
	})

	t.Run("deletes password successfully", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)

		// Add a password first
		addParams := PasswordAddParams{Name: "delete-me", Password: "pw"}
		addJSON, _ := json.Marshal(addParams)
		addReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.add", Params: addJSON, ID: 1}
		_, err := server.handlePasswordAdd(ctx, addReq)
		require.NoError(t, err)

		// Delete it
		params := PasswordDeleteParams{ID: "delete-me"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.delete", Params: paramsJSON, ID: 1}

		result, err := server.handlePasswordDelete(ctx, req)
		require.NoError(t, err)

		deleteResult, ok := result.(PasswordDeleteResult)
		require.True(t, ok)
		assert.Equal(t, "Password deleted successfully", deleteResult.Message)
	})

	t.Run("fails deleting nonexistent password", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)

		params := PasswordDeleteParams{ID: "nonexistent"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.delete", Params: paramsJSON, ID: 1}

		_, err := server.handlePasswordDelete(ctx, req)
		require.Error(t, err)
	})
}

func TestHandlePasswordUnlock(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("fails when password manager not configured", func(t *testing.T) {
		server.passwordManager = nil
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.unlock", ID: 1}

		_, err := server.handlePasswordUnlock(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPasswordStoreNotConfigured)
	})

	t.Run("fails when identity has no tenant ID", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)
		// Identity with no TenantID
		ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "user1"})
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.unlock", ID: 1}

		_, err := server.handlePasswordUnlock(ctx, req)
		require.Error(t, err)
	})

	t.Run("fails when no identity", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.unlock", ID: 1}

		_, err := server.handlePasswordUnlock(ctx, req)
		require.Error(t, err)
	})
}

func TestHandlePasswordLock(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("fails when password manager not configured", func(t *testing.T) {
		server.passwordManager = nil
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.lock", ID: 1}

		_, err := server.handlePasswordLock(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPasswordStoreNotConfigured)
	})

	t.Run("fails when identity has no tenant ID", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)
		ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "user1"})
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.lock", ID: 1}

		_, err := server.handlePasswordLock(ctx, req)
		require.Error(t, err)
	})
}

func TestHandlePasswordStatus(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("returns not configured when manager is nil", func(t *testing.T) {
		server.passwordManager = nil
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.status", ID: 1}

		result, err := server.handlePasswordStatus(ctx, req)
		require.NoError(t, err)

		statusResult, ok := result.(PasswordStoreStatusResult)
		require.True(t, ok)
		assert.False(t, statusResult.Available)
		assert.Equal(t, "Password store not configured", statusResult.Message)
	})

	t.Run("returns system-level status when no tenant identity", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.status", ID: 1}

		result, err := server.handlePasswordStatus(ctx, req)
		require.NoError(t, err)

		statusResult, ok := result.(PasswordStoreStatusResult)
		require.True(t, ok)
		assert.True(t, statusResult.Available)
	})

	t.Run("returns tenant status with tenant identity", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)
		ctx := auth.WithIdentity(context.Background(), &auth.Identity{
			Subject:  "user1",
			TenantID: "tenant-1",
		})
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.status", ID: 1}

		// This will fail because tenant-1 isn't registered, returning ErrTenantNotFound
		_, err := server.handlePasswordStatus(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, seal.ErrTenantNotFound)
	})
}

func TestHandlePasswordGenerate(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("generates password with defaults", func(t *testing.T) {
		params := PasswordGenerateParams{}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.generate", Params: paramsJSON, ID: 1}

		result, err := server.handlePasswordGenerate(ctx, req)
		require.NoError(t, err)

		genResult, ok := result.(PasswordGenerateResult)
		require.True(t, ok)
		assert.NotEmpty(t, genResult.Password)
		assert.Equal(t, staticpw.DefaultLength, genResult.Length)
	})

	t.Run("generates password with custom length", func(t *testing.T) {
		params := PasswordGenerateParams{Length: 32}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.generate", Params: paramsJSON, ID: 1}

		result, err := server.handlePasswordGenerate(ctx, req)
		require.NoError(t, err)

		genResult, ok := result.(PasswordGenerateResult)
		require.True(t, ok)
		assert.Len(t, genResult.Password, 32)
		assert.Equal(t, 32, genResult.Length)
	})

	t.Run("generates password with custom charset", func(t *testing.T) {
		params := PasswordGenerateParams{Length: 16, Charset: staticpw.CharsetAlphanumeric}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.generate", Params: paramsJSON, ID: 1}

		result, err := server.handlePasswordGenerate(ctx, req)
		require.NoError(t, err)

		genResult, ok := result.(PasswordGenerateResult)
		require.True(t, ok)
		assert.NotEmpty(t, genResult.Password)
	})

	t.Run("fails with invalid JSON params", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.generate", Params: json.RawMessage(`{bad`), ID: 1}
		_, err := server.handlePasswordGenerate(ctx, req)
		require.Error(t, err)
	})
}

func TestMapPasswordError(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected error
	}{
		{"ErrInvalidName", staticpw.ErrInvalidName, ErrPasswordNameRequired},
		{"ErrEmptyPassword", staticpw.ErrEmptyPassword, ErrPasswordRequired},
		{"ErrPasswordExists", staticpw.ErrPasswordExists, staticpw.ErrPasswordExists},
		{"ErrStoreClosed", staticpw.ErrStoreClosed, staticpw.ErrStoreClosed},
		{"ErrPasswordNotFound", staticpw.ErrPasswordNotFound, staticpw.ErrPasswordNotFound},
		{"ErrPasswordReadOnly", staticpw.ErrPasswordReadOnly, staticpw.ErrPasswordReadOnly},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapPasswordError(tt.input)
			assert.ErrorIs(t, err, tt.expected)
		})
	}

	t.Run("returns unknown error as-is", func(t *testing.T) {
		unknownErr := errors.New("something else")
		err := mapPasswordError(unknownErr)
		assert.Equal(t, unknownErr, err)
	})
}

func TestMapPasswordStoreError(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected error
	}{
		{"ErrStoreLocked", staticpw.ErrStoreLocked, staticpw.ErrStoreLocked},
		{"ErrTenantSealed", seal.ErrTenantSealed, seal.ErrTenantSealed},
		{"ErrTenantNotFound", seal.ErrTenantNotFound, seal.ErrTenantNotFound},
		{"ErrNotConfigured", staticpw.ErrNotConfigured, ErrPasswordStoreNotConfigured},
		{"ErrInvalidUserID", staticpw.ErrInvalidUserID, staticpw.ErrInvalidUserID},
		{"ErrNotOwner", staticpw.ErrNotOwner, staticpw.ErrNotOwner},
		{"ErrInvalidScope", staticpw.ErrInvalidScope, staticpw.ErrInvalidScope},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapPasswordStoreError(tt.input)
			assert.ErrorIs(t, err, tt.expected)
		})
	}

	t.Run("returns unknown error as-is", func(t *testing.T) {
		unknownErr := errors.New("something else")
		err := mapPasswordStoreError(unknownErr)
		assert.Equal(t, unknownErr, err)
	})
}

func TestResolvePasswordStore(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("returns error when manager is nil", func(t *testing.T) {
		server.passwordManager = nil
		ctx := context.Background()

		_, err := server.resolvePasswordStore(ctx)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPasswordStoreNotConfigured)
	})

	t.Run("returns system store when no identity", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)
		ctx := context.Background()

		store, err := server.resolvePasswordStore(ctx)
		require.NoError(t, err)
		assert.NotNil(t, store)
	})

	t.Run("returns system store when identity has no tenant ID", func(t *testing.T) {
		server.passwordManager = createPasswordManager(t)
		ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "user1"})

		store, err := server.resolvePasswordStore(ctx)
		require.NoError(t, err)
		assert.NotNil(t, store)
	})
}
