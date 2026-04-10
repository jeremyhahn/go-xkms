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

package cmd

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
)

// --- Constants ---

func TestAuthConstants(t *testing.T) {
	t.Run("defaultAuthStoragePath", func(t *testing.T) {
		assert.Equal(t, "data/auth", defaultAuthStoragePath)
	})

	t.Run("defaultAuthTimeout", func(t *testing.T) {
		assert.Equal(t, 30*time.Second, defaultAuthTimeout)
	})
}

// --- Error sentinel tests ---

func TestAuthErrors(t *testing.T) {
	tests := []struct {
		err      error
		contains string
	}{
		{ErrAuthServerRequired, "auth: --server flag is required"},
		{ErrAuthStorageCreationFailed, "auth: failed to create storage backend"},
		{ErrAuthRegistryCreationFailed, "auth: failed to create server registry"},
		{ErrAuthTokenStoreCreationFailed, "auth: failed to create token store"},
		{ErrAuthClientCreationFailed, "auth: failed to create SDK client"},
		{ErrAuthConnectFailed, "auth: failed to connect to server"},
		{ErrAuthRegistrationFailed, "auth: failed to register server"},
		{ErrAuthServerLookupFailed, "auth: failed to look up server"},
		{ErrAuthTokenLoadFailed, "auth: failed to load token"},
		{ErrAuthServerListFailed, "auth: failed to list servers"},
		{ErrAuthTokenListFailed, "auth: failed to list tokens"},
	}

	for _, tc := range tests {
		t.Run(tc.contains, func(t *testing.T) {
			assert.NotNil(t, tc.err)
			assert.Equal(t, tc.contains, tc.err.Error())
			assert.True(t, strings.HasPrefix(tc.err.Error(), "auth:"))
		})
	}
}

func TestAuthErrors_AreDistinct(t *testing.T) {
	errs := []error{
		ErrAuthServerRequired,
		ErrAuthStorageCreationFailed,
		ErrAuthRegistryCreationFailed,
		ErrAuthTokenStoreCreationFailed,
		ErrAuthClientCreationFailed,
		ErrAuthConnectFailed,
		ErrAuthRegistrationFailed,
		ErrAuthServerLookupFailed,
		ErrAuthTokenLoadFailed,
		ErrAuthServerListFailed,
		ErrAuthTokenListFailed,
	}

	seen := make(map[string]bool, len(errs))
	for _, err := range errs {
		msg := err.Error()
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}
}

// --- Parent command structure ---

func TestAuthCmd_Exists(t *testing.T) {
	assert.NotNil(t, authCmd)
}

func TestAuthCmd_Properties(t *testing.T) {
	assert.Equal(t, "auth", authCmd.Use)
	assert.NotEmpty(t, authCmd.Short)
	assert.NotEmpty(t, authCmd.Long)
	assert.Contains(t, authCmd.Short, "authentication")
}

func TestAuthCmd_Subcommands(t *testing.T) {
	subcommands := authCmd.Commands()

	names := make(map[string]bool)
	for _, cmd := range subcommands {
		names[cmd.Name()] = true
	}

	assert.True(t, names["register"], "auth should have register subcommand")
	assert.True(t, names["login"], "auth should have login subcommand")
	assert.True(t, names["status"], "auth should have status subcommand")
	assert.True(t, names["token"], "auth should have token subcommand")
	assert.Len(t, subcommands, 4, "auth should have exactly 4 subcommands")
}

func TestAuthCmd_RegisteredOnRoot(t *testing.T) {
	found := false
	for _, cmd := range RootCmd.Commands() {
		if cmd.Name() == "auth" {
			found = true
			break
		}
	}
	assert.True(t, found, "auth command should be registered on root")
}

// --- Register command structure ---

func TestAuthRegisterCmd_Structure(t *testing.T) {
	assert.NotNil(t, authRegisterCmd)
	assert.Equal(t, "register", authRegisterCmd.Use)
	assert.NotEmpty(t, authRegisterCmd.Short)
	assert.NotEmpty(t, authRegisterCmd.Long)
	assert.NotNil(t, authRegisterCmd.RunE)
}

func TestAuthRegisterCmd_Flags(t *testing.T) {
	flags := []string{"server", "spki-pin", "setup-token"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := authRegisterCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "register command should have --%s flag", name)
		})
	}
}

func TestAuthRegisterCmd_FlagDefaults(t *testing.T) {
	t.Run("server_default_empty", func(t *testing.T) {
		flag := authRegisterCmd.Flags().Lookup("server")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("spki-pin_default_empty", func(t *testing.T) {
		flag := authRegisterCmd.Flags().Lookup("spki-pin")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("setup-token_default_empty", func(t *testing.T) {
		flag := authRegisterCmd.Flags().Lookup("setup-token")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})
}

// --- Login command structure ---

func TestAuthLoginCmd_Structure(t *testing.T) {
	assert.NotNil(t, authLoginCmd)
	assert.Equal(t, "login", authLoginCmd.Use)
	assert.NotEmpty(t, authLoginCmd.Short)
	assert.NotEmpty(t, authLoginCmd.Long)
	assert.NotNil(t, authLoginCmd.RunE)
}

func TestAuthLoginCmd_Flags(t *testing.T) {
	flag := authLoginCmd.Flags().Lookup("server")
	assert.NotNil(t, flag, "login command should have --server flag")
	assert.Equal(t, "", flag.DefValue)
}

// --- Status command structure ---

func TestAuthStatusCmd_Structure(t *testing.T) {
	assert.NotNil(t, authStatusCmd)
	assert.Equal(t, "status", authStatusCmd.Use)
	assert.NotEmpty(t, authStatusCmd.Short)
	assert.NotEmpty(t, authStatusCmd.Long)
	assert.NotNil(t, authStatusCmd.RunE)
}

func TestAuthStatusCmd_Flags(t *testing.T) {
	flag := authStatusCmd.Flags().Lookup("server")
	assert.NotNil(t, flag, "status command should have --server flag")
	assert.Equal(t, "", flag.DefValue)
}

// --- Token command structure ---

func TestAuthTokenCmd_Structure(t *testing.T) {
	assert.NotNil(t, authTokenCmd)
	assert.Equal(t, "token", authTokenCmd.Use)
	assert.NotEmpty(t, authTokenCmd.Short)
	assert.NotEmpty(t, authTokenCmd.Long)
	assert.NotNil(t, authTokenCmd.RunE)
}

func TestAuthTokenCmd_Flags(t *testing.T) {
	flag := authTokenCmd.Flags().Lookup("server")
	assert.NotNil(t, flag, "token command should have --server flag")
	assert.Equal(t, "", flag.DefValue)
}

// --- runAuthRegister tests ---

func TestRunAuthRegister_MissingServer(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	cmd.Flags().String("spki-pin", "", "")
	cmd.Flags().String("setup-token", "", "")

	err := runAuthRegister(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthServerRequired)
}

func TestRunAuthRegister_MissingServerEmptyString(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	cmd.Flags().String("spki-pin", "", "")
	cmd.Flags().String("setup-token", "", "")

	require.NoError(t, cmd.Flags().Set("server", ""))

	err := runAuthRegister(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthServerRequired)
}

func TestRunAuthRegister_WithServerFlag_ClientCreationFails(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	cmd.Flags().String("spki-pin", "", "")
	cmd.Flags().String("setup-token", "", "")

	// Use a valid URL but the SDK client will fail to connect (no real server).
	// The function should pass the server flag validation and attempt SDK creation.
	require.NoError(t, cmd.Flags().Set("server", "https://nonexistent.example.com:8443"))

	err := runAuthRegister(cmd, nil)
	assert.Error(t, err)
	// The error should be from client creation or connection, not from the server flag check.
	assert.NotErrorIs(t, err, ErrAuthServerRequired)
}

func TestRunAuthRegister_FlagsParsedCorrectly(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	cmd.Flags().String("spki-pin", "", "")
	cmd.Flags().String("setup-token", "", "")

	require.NoError(t, cmd.Flags().Set("server", "https://xkms.example.com:8443"))
	require.NoError(t, cmd.Flags().Set("spki-pin", "abc123def456"))
	require.NoError(t, cmd.Flags().Set("setup-token", "enrollment-token-xyz"))

	// Verify flags were set correctly
	serverURL, err := cmd.Flags().GetString("server")
	require.NoError(t, err)
	assert.Equal(t, "https://xkms.example.com:8443", serverURL)

	spkiPin, err := cmd.Flags().GetString("spki-pin")
	require.NoError(t, err)
	assert.Equal(t, "abc123def456", spkiPin)

	setupToken, err := cmd.Flags().GetString("setup-token")
	require.NoError(t, err)
	assert.Equal(t, "enrollment-token-xyz", setupToken)
}

// --- runAuthLogin tests ---

func TestRunAuthLogin_MissingServer(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")

	err := runAuthLogin(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthServerRequired)
}

func TestRunAuthLogin_MissingServerEmptyString(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")

	require.NoError(t, cmd.Flags().Set("server", ""))

	err := runAuthLogin(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthServerRequired)
}

func TestRunAuthLogin_WithServer_RegistryOpenSucceeds(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")

	require.NoError(t, cmd.Flags().Set("server", "https://nonexistent.example.com:8443"))

	err := runAuthLogin(cmd, nil)
	assert.Error(t, err)
	// Should fail at server lookup since the server is not registered.
	assert.ErrorIs(t, err, ErrAuthServerLookupFailed)
}

// --- runAuthToken tests ---

func TestRunAuthToken_MissingServer(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")

	err := runAuthToken(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthServerRequired)
}

func TestRunAuthToken_MissingServerEmptyString(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")

	require.NoError(t, cmd.Flags().Set("server", ""))

	err := runAuthToken(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthServerRequired)
}

func TestRunAuthToken_TokenNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")

	require.NoError(t, cmd.Flags().Set("server", "https://nonexistent.example.com:8443"))

	err := runAuthToken(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthTokenLoadFailed)
}

// --- runAuthStatus tests ---

func TestRunAuthStatus_NoServers(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")

	// Capture output by redirecting stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	runErr := runAuthStatus(cmd, nil)

	_ = w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	assert.NoError(t, runErr)
	assert.Contains(t, output, "No servers registered")
}

func TestRunAuthStatus_WithRegisteredServer(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Pre-register a server using the registry directly.
	logger := slog.Default()
	registry, cleanup, err := openServerRegistry(logger)
	require.NoError(t, err)
	defer cleanup()

	ctx := context.Background()
	entry := &serverregistry.ServerEntry{
		URL:      "https://test.example.com:8443",
		Name:     "test-server",
		Protocol: serverregistry.ProtocolREST,
	}
	require.NoError(t, registry.Register(ctx, entry))

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	os.Stdout = w

	runErr := runAuthStatus(cmd, nil)

	_ = w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	assert.NoError(t, runErr)
	assert.Contains(t, output, "Registered Servers (1)")
	assert.Contains(t, output, "https://test.example.com:8443")
	assert.Contains(t, output, "rest")
}

func TestRunAuthStatus_WithServerFilter(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Pre-register two servers.
	logger := slog.Default()
	registry, cleanup, err := openServerRegistry(logger)
	require.NoError(t, err)
	defer cleanup()

	ctx := context.Background()
	require.NoError(t, registry.Register(ctx, &serverregistry.ServerEntry{
		URL:      "https://server-a.example.com:8443",
		Name:     "server-a",
		Protocol: serverregistry.ProtocolREST,
	}))
	require.NoError(t, registry.Register(ctx, &serverregistry.ServerEntry{
		URL:      "https://server-b.example.com:8443",
		Name:     "server-b",
		Protocol: serverregistry.ProtocolGRPC,
	}))

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	require.NoError(t, cmd.Flags().Set("server", "https://server-a.example.com:8443"))

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	os.Stdout = w

	runErr := runAuthStatus(cmd, nil)

	_ = w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	assert.NoError(t, runErr)
	assert.Contains(t, output, "server-a.example.com")
	// server-b should not appear since we filtered to server-a
	assert.NotContains(t, output, "server-b.example.com")
}

func TestRunAuthStatus_TokenStatus(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	logger := slog.Default()

	// Register a server
	registry, registryCleanup, err := openServerRegistry(logger)
	require.NoError(t, err)
	defer registryCleanup()

	ctx := context.Background()
	require.NoError(t, registry.Register(ctx, &serverregistry.ServerEntry{
		URL:      "https://token-test.example.com:8443",
		Name:     "token-test",
		Protocol: serverregistry.ProtocolREST,
	}))

	// Store a valid (non-expired) token for that server
	tokens, tokenCleanup, err := openTokenStore(logger)
	require.NoError(t, err)
	defer tokenCleanup()

	require.NoError(t, tokens.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://token-test.example.com:8443",
		TokenType: tokenstore.TypeBearer,
		Source:    tokenstore.SourceFIDO2,
		Token:     "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.test",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
	}))

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")

	// Capture output
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	os.Stdout = w

	runErr := runAuthStatus(cmd, nil)

	_ = w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	assert.NoError(t, runErr)
	assert.Contains(t, output, "valid")
	assert.Contains(t, output, "fido2")
}

// --- authStoragePath tests ---

func TestAuthStoragePath(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	path, err := authStoragePath()
	require.NoError(t, err)

	assert.True(t, strings.HasSuffix(path, filepath.Join("data", "auth")),
		"path should end with data/auth, got: %s", path)
}

func TestAuthStoragePath_Format(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	path, err := authStoragePath()
	require.NoError(t, err)

	assert.Contains(t, path, ".xkey")
	assert.True(t, filepath.IsAbs(path), "path should be absolute")
}

func TestAuthStoragePath_UsesHomeDir(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	path, err := authStoragePath()
	require.NoError(t, err)

	expected := filepath.Join(tmpDir, ".xkey", "data", "auth")
	assert.Equal(t, expected, path)
}

func TestAuthStoragePath_DifferentHomes(t *testing.T) {
	tmpDir1 := t.TempDir()
	tmpDir2 := t.TempDir()

	t.Setenv("HOME", tmpDir1)
	path1, err1 := authStoragePath()
	require.NoError(t, err1)

	t.Setenv("HOME", tmpDir2)
	path2, err2 := authStoragePath()
	require.NoError(t, err2)

	assert.NotEqual(t, path1, path2, "different HOME dirs should produce different paths")
	assert.Contains(t, path1, tmpDir1)
	assert.Contains(t, path2, tmpDir2)
}

// --- openServerRegistry tests ---

func TestOpenServerRegistry_Success(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	logger := slog.Default()
	registry, cleanup, err := openServerRegistry(logger)
	require.NoError(t, err)
	require.NotNil(t, registry)
	require.NotNil(t, cleanup)

	defer cleanup()

	// Verify the registry is functional by registering and looking up a server
	ctx := context.Background()
	entry := &serverregistry.ServerEntry{
		URL:      "https://test.example.com:8443",
		Name:     "test",
		Protocol: serverregistry.ProtocolREST,
	}
	require.NoError(t, registry.Register(ctx, entry))

	found, err := registry.Lookup(ctx, "https://test.example.com:8443")
	require.NoError(t, err)
	assert.Equal(t, "https://test.example.com:8443", found.URL)
	assert.Equal(t, "test", found.Name)
}

func TestOpenServerRegistry_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	logger := slog.Default()
	registry, cleanup, err := openServerRegistry(logger)
	require.NoError(t, err)
	defer cleanup()

	// Verify the storage directory was created
	storagePath := filepath.Join(tmpDir, ".xkey", "data", "auth")
	info, err := os.Stat(storagePath)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	_ = registry
}

func TestOpenServerRegistry_CleanupClosesRegistry(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	logger := slog.Default()
	registry, cleanup, err := openServerRegistry(logger)
	require.NoError(t, err)

	// Call cleanup
	cleanup()

	// After cleanup, operations on the registry should fail (store closed)
	ctx := context.Background()
	_, err = registry.List(ctx)
	assert.Error(t, err)
}

func TestOpenServerRegistry_MultipleOpens(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	logger := slog.Default()

	// Open two separate registries (simulating separate invocations)
	reg1, cleanup1, err := openServerRegistry(logger)
	require.NoError(t, err)
	defer cleanup1()

	reg2, cleanup2, err := openServerRegistry(logger)
	require.NoError(t, err)
	defer cleanup2()

	// Register in the first, should be visible through the second
	ctx := context.Background()
	require.NoError(t, reg1.Register(ctx, &serverregistry.ServerEntry{
		URL:      "https://shared.example.com:8443",
		Name:     "shared",
		Protocol: serverregistry.ProtocolREST,
	}))

	found, err := reg2.Lookup(ctx, "https://shared.example.com:8443")
	require.NoError(t, err)
	assert.Equal(t, "https://shared.example.com:8443", found.URL)
}

// --- openTokenStore tests ---

func TestOpenTokenStore_Success(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	logger := slog.Default()
	store, cleanup, err := openTokenStore(logger)
	require.NoError(t, err)
	require.NotNil(t, store)
	require.NotNil(t, cleanup)

	defer cleanup()

	// Verify the store is functional
	ctx := context.Background()
	entry := &tokenstore.TokenEntry{
		ServerURL: "https://test.example.com:8443",
		TokenType: tokenstore.TypeBearer,
		Source:    tokenstore.SourceOIDC,
		Token:     "test-jwt-token",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
	}
	require.NoError(t, store.Save(ctx, entry))

	found, err := store.Load(ctx, "https://test.example.com:8443")
	require.NoError(t, err)
	assert.Equal(t, "test-jwt-token", found.Token)
	assert.Equal(t, tokenstore.SourceOIDC, found.Source)
}

func TestOpenTokenStore_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	logger := slog.Default()
	store, cleanup, err := openTokenStore(logger)
	require.NoError(t, err)
	defer cleanup()

	storagePath := filepath.Join(tmpDir, ".xkey", "data", "auth")
	info, err := os.Stat(storagePath)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	_ = store
}

func TestOpenTokenStore_CleanupClosesStore(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	logger := slog.Default()
	store, cleanup, err := openTokenStore(logger)
	require.NoError(t, err)

	// Call cleanup
	cleanup()

	// After cleanup, operations on the store should fail
	ctx := context.Background()
	_, err = store.List(ctx)
	assert.Error(t, err)
}

func TestOpenTokenStore_SaveAndLoadRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	logger := slog.Default()
	store, cleanup, err := openTokenStore(logger)
	require.NoError(t, err)
	defer cleanup()

	ctx := context.Background()

	// Save multiple tokens
	servers := []string{
		"https://alpha.example.com:8443",
		"https://beta.example.com:8443",
		"https://gamma.example.com:8443",
	}

	for _, serverURL := range servers {
		require.NoError(t, store.Save(ctx, &tokenstore.TokenEntry{
			ServerURL: serverURL,
			TokenType: tokenstore.TypeBearer,
			Source:    tokenstore.SourceFIDO2,
			Token:     "jwt-for-" + serverURL,
			ExpiresAt: time.Now().Add(1 * time.Hour),
			IssuedAt:  time.Now(),
		}))
	}

	// List all tokens
	entries, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, entries, 3)

	// Load each individually
	for _, serverURL := range servers {
		found, loadErr := store.Load(ctx, serverURL)
		require.NoError(t, loadErr)
		assert.Equal(t, "jwt-for-"+serverURL, found.Token)
	}
}

// --- runAuthToken with stored token ---

func TestRunAuthToken_LoadsStoredToken(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	logger := slog.Default()

	// Pre-store a token
	store, cleanup, err := openTokenStore(logger)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, store.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://stored.example.com:8443",
		TokenType: tokenstore.TypeBearer,
		Source:    tokenstore.SourceFIDO2,
		Token:     "valid-jwt-token-abc",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
	}))
	cleanup()

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	require.NoError(t, cmd.Flags().Set("server", "https://stored.example.com:8443"))

	// Capture stdout
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	os.Stdout = w

	runErr := runAuthToken(cmd, nil)

	_ = w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	assert.NoError(t, runErr)
	assert.Equal(t, "valid-jwt-token-abc", output)
}

func TestRunAuthToken_ExpiredTokenPrintsWarning(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	logger := slog.Default()

	// Pre-store an expired token
	store, cleanup, err := openTokenStore(logger)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, store.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://expired.example.com:8443",
		TokenType: tokenstore.TypeBearer,
		Source:    tokenstore.SourceOIDC,
		Token:     "expired-jwt-xyz",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // expired 1 hour ago
		IssuedAt:  time.Now().Add(-2 * time.Hour),
	}))
	cleanup()

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	require.NoError(t, cmd.Flags().Set("server", "https://expired.example.com:8443"))

	// Capture stdout and stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	rOut, wOut, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	os.Stdout = wOut

	rErr, wErr, pipeErr2 := os.Pipe()
	require.NoError(t, pipeErr2)
	os.Stderr = wErr

	runErr := runAuthToken(cmd, nil)

	_ = wOut.Close()
	_ = wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	outBuf := make([]byte, 4096)
	nOut, _ := rOut.Read(outBuf)
	stdoutOutput := string(outBuf[:nOut])

	errBuf := make([]byte, 4096)
	nErr, _ := rErr.Read(errBuf)
	stderrOutput := string(errBuf[:nErr])

	assert.NoError(t, runErr)
	assert.Equal(t, "expired-jwt-xyz", stdoutOutput)
	assert.Contains(t, stderrOutput, "Warning: token expired")
}

// --- runAuthRegister with existing server ---

func TestRunAuthRegister_ExistingServer_PrintsMessage(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	logger := slog.Default()

	// Pre-register a server
	registry, cleanup, err := openServerRegistry(logger)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, registry.Register(ctx, &serverregistry.ServerEntry{
		URL:      "https://existing.example.com:8443",
		Name:     "existing",
		Protocol: serverregistry.ProtocolREST,
	}))
	cleanup()

	// The runAuthRegister function first tries to connect via SDK before
	// checking the registry, so we cannot fully test the "already registered"
	// path without a real server. This test verifies the flag parsing path.
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	cmd.Flags().String("spki-pin", "", "")
	cmd.Flags().String("setup-token", "", "")

	require.NoError(t, cmd.Flags().Set("server", "https://existing.example.com:8443"))

	// This will fail at SDK connect, but we verify it gets past the server flag check
	err = runAuthRegister(cmd, nil)
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrAuthServerRequired)
}

// --- runAuthLogin with registered server ---

func TestRunAuthLogin_ServerNotRegistered(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	require.NoError(t, cmd.Flags().Set("server", "https://unregistered.example.com:8443"))

	err := runAuthLogin(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthServerLookupFailed)

	// The underlying error should indicate server not found
	assert.True(t, errors.Is(err, serverregistry.ErrServerNotFound) ||
		strings.Contains(err.Error(), "not found"),
		"error should indicate server not found")
}

// --- Long description content tests ---

func TestAuthCmd_LongDescriptionContent(t *testing.T) {
	assert.Contains(t, authCmd.Long, "register")
	assert.Contains(t, authCmd.Long, "login")
	assert.Contains(t, authCmd.Long, "status")
	assert.Contains(t, authCmd.Long, "token")
	assert.Contains(t, authCmd.Long, "xkey auth")
}

func TestAuthRegisterCmd_LongDescriptionContent(t *testing.T) {
	assert.Contains(t, authRegisterCmd.Long, "--server")
	assert.Contains(t, authRegisterCmd.Long, "--spki-pin")
	assert.Contains(t, authRegisterCmd.Long, "--setup-token")
}

func TestAuthLoginCmd_LongDescriptionContent(t *testing.T) {
	assert.Contains(t, authLoginCmd.Long, "WebAuthn")
	assert.Contains(t, authLoginCmd.Long, "--server")
}

func TestAuthStatusCmd_LongDescriptionContent(t *testing.T) {
	assert.Contains(t, authStatusCmd.Long, "status")
	assert.Contains(t, authStatusCmd.Long, "--server")
}

func TestAuthTokenCmd_LongDescriptionContent(t *testing.T) {
	assert.Contains(t, authTokenCmd.Long, "JWT")
	assert.Contains(t, authTokenCmd.Long, "--server")
}

// --- Error wrapping tests ---

func TestAuthErrors_ErrorJoinPreservesWrapping(t *testing.T) {
	innerErr := errors.New("connection refused")
	joined := errors.Join(ErrAuthConnectFailed, innerErr)

	assert.ErrorIs(t, joined, ErrAuthConnectFailed)
	assert.ErrorIs(t, joined, innerErr)
	assert.Contains(t, joined.Error(), "connection refused")
	assert.Contains(t, joined.Error(), "auth: failed to connect to server")
}

func TestAuthErrors_ErrorJoinClientCreationFailed(t *testing.T) {
	innerErr := errors.New("invalid TLS config")
	joined := errors.Join(ErrAuthClientCreationFailed, innerErr)

	assert.ErrorIs(t, joined, ErrAuthClientCreationFailed)
	assert.ErrorIs(t, joined, innerErr)
}

func TestAuthErrors_ErrorJoinRegistrationFailed(t *testing.T) {
	joined := errors.Join(ErrAuthRegistrationFailed, serverregistry.ErrServerExists)

	assert.ErrorIs(t, joined, ErrAuthRegistrationFailed)
	assert.ErrorIs(t, joined, serverregistry.ErrServerExists)
}

func TestAuthErrors_ErrorJoinTokenLoadFailed(t *testing.T) {
	joined := errors.Join(ErrAuthTokenLoadFailed, tokenstore.ErrTokenNotFound)

	assert.ErrorIs(t, joined, ErrAuthTokenLoadFailed)
	assert.ErrorIs(t, joined, tokenstore.ErrTokenNotFound)
}

func TestAuthErrors_ErrorJoinStorageCreationFailed(t *testing.T) {
	innerErr := errors.New("permission denied")
	joined := errors.Join(ErrAuthStorageCreationFailed, innerErr)

	assert.ErrorIs(t, joined, ErrAuthStorageCreationFailed)
	assert.Contains(t, joined.Error(), "permission denied")
}

// --- Edge case: registry and token store with same storage path ---

func TestOpenRegistryAndTokenStore_SharedStoragePath(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	logger := slog.Default()

	// Open both a registry and token store (they use the same base path
	// but different prefixes)
	registry, registryCleanup, err := openServerRegistry(logger)
	require.NoError(t, err)
	defer registryCleanup()

	store, storeCleanup, err := openTokenStore(logger)
	require.NoError(t, err)
	defer storeCleanup()

	ctx := context.Background()

	// Register a server
	require.NoError(t, registry.Register(ctx, &serverregistry.ServerEntry{
		URL:      "https://shared-path.example.com:8443",
		Name:     "shared",
		Protocol: serverregistry.ProtocolREST,
	}))

	// Store a token for the same server
	require.NoError(t, store.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://shared-path.example.com:8443",
		TokenType: tokenstore.TypeBearer,
		Source:    tokenstore.SourceBootstrap,
		Token:     "bootstrap-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IssuedAt:  time.Now(),
	}))

	// Both should be independently retrievable
	foundServer, err := registry.Lookup(ctx, "https://shared-path.example.com:8443")
	require.NoError(t, err)
	assert.Equal(t, "shared", foundServer.Name)

	foundToken, err := store.Load(ctx, "https://shared-path.example.com:8443")
	require.NoError(t, err)
	assert.Equal(t, "bootstrap-token", foundToken.Token)
}
