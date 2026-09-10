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
	"bytes"
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

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
)

// --- Constants ---

func TestAuthConstants(t *testing.T) {
	t.Run("defaultAuthStoragePath", func(t *testing.T) {
		assert.Equal(t, "auth", defaultAuthStoragePath,
			"the data segment belongs to the shared chain, not the feature constant")
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
	assert.True(t, names["refresh"], "auth should have refresh subcommand")
	assert.True(t, names["logout"], "auth should have logout subcommand")
	assert.Len(t, subcommands, 6, "auth should have exactly 6 subcommands")
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

func TestAuthLoginCmd_PIVFlags(t *testing.T) {
	pivFlag := authLoginCmd.Flags().Lookup("piv")
	require.NotNil(t, pivFlag, "login command should have --piv flag")
	assert.Equal(t, "false", pivFlag.DefValue)

	slotFlag := authLoginCmd.Flags().Lookup("slot")
	require.NotNil(t, slotFlag, "login command should have --slot flag")
	assert.Equal(t, "9a", slotFlag.DefValue)

	backendFlag := authLoginCmd.Flags().Lookup("backend")
	require.NotNil(t, backendFlag, "login command should have --backend flag")
	assert.Equal(t, "software", backendFlag.DefValue)
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

	// Built through the shared helper so the double carries every flag the
	// real command declares; a hand-rolled flag set silently goes stale the
	// next time one is added.
	cmd := newAuthLoginCmd(t, &bytes.Buffer{})
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
	cmd.Flags().String("email", "alice@example.com", "")

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
	isolateDataDirSources(t)
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	path, err := authStoragePath()
	require.NoError(t, err)

	assert.True(t, strings.HasSuffix(path, filepath.Join("data", "auth")),
		"path should end with data/auth, got: %s", path)
}

func TestAuthStoragePath_Format(t *testing.T) {
	isolateDataDirSources(t)
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	path, err := authStoragePath()
	require.NoError(t, err)

	assert.Contains(t, path, ".xkey")
	assert.True(t, filepath.IsAbs(path), "path should be absolute")
}

func TestAuthStoragePath_UsesHomeDir(t *testing.T) {
	isolateDataDirSources(t)
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	path, err := authStoragePath()
	require.NoError(t, err)

	expected := filepath.Join(tmpDir, ".xkey", "data", "auth")
	assert.Equal(t, expected, path)
}

func TestAuthStoragePath_DifferentHomes(t *testing.T) {
	isolateDataDirSources(t)
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

	cmd := newAuthLoginCmd(t, &bytes.Buffer{})
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

// --- WebAuthn ceremony test doubles ---

// fakeAuthClient is an AuthClientService double that records what the auth
// commands send and replays scripted server responses.
type fakeAuthClient struct {
	connectErr error
	closed     bool

	beginRegistrationResp *transport.BeginRegistrationResponse
	beginRegistrationErr  error
	beginRegistrationReq  *transport.BeginRegistrationRequest

	finishRegistrationResp *transport.FinishRegistrationResponse
	finishRegistrationErr  error
	finishRegistrationReq  *transport.FinishRegistrationRequest

	beginAuthenticationResp *transport.BeginAuthenticationResponse
	beginAuthenticationErr  error
	beginAuthenticationReq  *transport.BeginAuthenticationRequest

	finishAuthenticationResp *transport.FinishAuthenticationResponse
	finishAuthenticationErr  error
	finishAuthenticationReq  *transport.FinishAuthenticationRequest
}

func (f *fakeAuthClient) Connect(_ context.Context) error { return f.connectErr }

func (f *fakeAuthClient) Close() error {
	f.closed = true
	return nil
}

func (f *fakeAuthClient) BeginRegistration(_ context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	f.beginRegistrationReq = req
	return f.beginRegistrationResp, f.beginRegistrationErr
}

func (f *fakeAuthClient) FinishRegistration(_ context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	f.finishRegistrationReq = req
	return f.finishRegistrationResp, f.finishRegistrationErr
}

func (f *fakeAuthClient) BeginAuthentication(_ context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	f.beginAuthenticationReq = req
	return f.beginAuthenticationResp, f.beginAuthenticationErr
}

func (f *fakeAuthClient) FinishAuthentication(_ context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	f.finishAuthenticationReq = req
	return f.finishAuthenticationResp, f.finishAuthenticationErr
}

// fakeCeremony is a WebAuthnCeremony double standing in for an attached
// CTAP2 authenticator.
type fakeCeremony struct {
	registerJSON []byte
	registerErr  error
	registerOpts []byte

	assertJSON []byte
	assertErr  error
	assertOpts []byte

	origin string
	// pin records what the command passed to the authenticator, which is the
	// only way to prove the PIN survived the flag plumbing.
	pin    string
	closed bool
}

func (f *fakeCeremony) Register(_ context.Context, req CeremonyRequest) ([]byte, error) {
	f.registerOpts = req.OptionsJSON
	f.origin = req.Origin
	f.pin = req.PIN
	return f.registerJSON, f.registerErr
}

func (f *fakeCeremony) Assert(_ context.Context, req CeremonyRequest) ([]byte, error) {
	f.assertOpts = req.OptionsJSON
	f.origin = req.Origin
	f.pin = req.PIN
	return f.assertJSON, f.assertErr
}

func (f *fakeCeremony) Close() error {
	f.closed = true
	return nil
}

// installAuthDoubles points the auth commands at the supplied client and
// ceremony doubles for the duration of the test.
func installAuthDoubles(t *testing.T, client AuthClientService, ceremony WebAuthnCeremony, ceremonyErr error) {
	t.Helper()

	originalClient := authClientFactory
	originalCeremony := webauthnCeremonyFactory

	authClientFactory = func(authClientConfig) (AuthClientService, error) { return client, nil }
	webauthnCeremonyFactory = func() (WebAuthnCeremony, error) {
		if ceremonyErr != nil {
			return nil, ceremonyErr
		}
		return ceremony, nil
	}

	t.Cleanup(func() {
		authClientFactory = originalClient
		webauthnCeremonyFactory = originalCeremony
	})
}

// newAuthRegisterCmd builds a register command carrying the flags the real
// command declares, bound to an output buffer.
func newAuthRegisterCmd(t *testing.T, out *bytes.Buffer) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	cmd.Flags().String("spki-pin", "", "")
	cmd.Flags().String("setup-token", "", "")
	cmd.Flags().String("tls-ca", "", "")
	// The canonical login key is required; tests exercising the paths beyond
	// that guard supply one. TestRunAuthRegister_EmailRequired covers its
	// absence.
	cmd.Flags().String("email", "alice@example.com", "")
	cmd.Flags().String("username", "", "")
	cmd.Flags().String("display-name", "", "")
	// Declared through the same helper the real command uses, so the double
	// cannot drift from the flags resolvePINInput reads.
	addPINFlags(cmd)
	cmd.SetOut(out)
	return cmd
}

// newAuthLoginCmd builds a login command carrying the flags the real command
// declares, bound to an output buffer.
func newAuthLoginCmd(t *testing.T, out *bytes.Buffer) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	cmd.Flags().String("email", "alice@example.com", "")
	cmd.Flags().String("username", "", "")
	cmd.Flags().String("tls-ca", "", "")
	addPINFlags(cmd)
	cmd.SetOut(out)
	return cmd
}

// --- login key resolution (go-xkms #185) ---

// The ceremony is addressed by the canonical email login key, so a command
// that was given none must stop before it touches the network. It used to
// default to the current OS account name, which the server then resolved with
// GetUserByEmail: on a closed relying party that misses, and on an open one it
// enrolls the credential onto a second principal nobody created.
func TestRunAuthRegister_EmailRequired(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	client := &fakeAuthClient{}
	installAuthDoubles(t, client, &fakeCeremony{}, nil)

	cmd := newAuthRegisterCmd(t, &bytes.Buffer{})
	require.NoError(t, cmd.Flags().Set("server", "https://xkms.example.com:8443"))
	require.NoError(t, cmd.Flags().Set("email", ""))

	err := runAuthRegister(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthEmailRequired)
	assert.Nil(t, client.beginRegistrationReq, "no ceremony may be begun without a login key")
}

// The same guard on the login side.
func TestRunAuthLogin_EmailRequired(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	const serverURL = "https://xkms.example.com:8443"
	registerLoginServer(t, serverURL)

	client := &fakeAuthClient{}
	installAuthDoubles(t, client, &fakeCeremony{}, nil)

	cmd := newAuthLoginCmd(t, &bytes.Buffer{})
	require.NoError(t, cmd.Flags().Set("server", serverURL))
	require.NoError(t, cmd.Flags().Set("email", ""))

	err := runAuthLogin(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthEmailRequired)
	assert.Nil(t, client.beginAuthenticationReq, "no ceremony may be begun without a login key")
}

// The deprecated --username spelling still carries the login key end to end,
// so an operator already passing an email under it is not broken by the
// rename.
func TestRunAuthLogin_DeprecatedUsernameFlagStillCarriesTheLoginKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	const serverURL = "https://xkms.example.com:8443"
	registerLoginServer(t, serverURL)

	client := &fakeAuthClient{
		beginAuthenticationErr: errors.New("server said no"),
	}
	installAuthDoubles(t, client, &fakeCeremony{}, nil)

	cmd := newAuthLoginCmd(t, &bytes.Buffer{})
	require.NoError(t, cmd.Flags().Set("server", serverURL))
	require.NoError(t, cmd.Flags().Set("email", ""))
	require.NoError(t, cmd.Flags().Set("username", "alice@example.com"))

	err := runAuthLogin(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthBeginAuthenticationFailed)

	require.NotNil(t, client.beginAuthenticationReq)
	assert.Equal(t, "alice@example.com", client.beginAuthenticationReq.Email)
}

// --- runAuthRegister WebAuthn ceremony tests ---

// TestRunAuthRegister_CompletesCeremony verifies register drives the full
// WebAuthn registration ceremony - begin, authenticator attestation, finish -
// and reports the credential the server created. Before this was implemented
// the command printed "not yet implemented" and exited 0.
func TestRunAuthRegister_CompletesCeremony(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	client := &fakeAuthClient{
		beginRegistrationResp: &transport.BeginRegistrationResponse{
			SessionID:   "session-abc",
			OptionsJSON: `{"publicKey":{"challenge":"Y2hhbGxlbmdl","rp":{"id":"xkms.example.com"}}}`,
		},
		finishRegistrationResp: &transport.FinishRegistrationResponse{
			Success:      true,
			CredentialID: "cred-123",
		},
	}
	ceremony := &fakeCeremony{registerJSON: []byte(`{"id":"cred-123"}`)}
	installAuthDoubles(t, client, ceremony, nil)

	var out bytes.Buffer
	cmd := newAuthRegisterCmd(t, &out)
	require.NoError(t, cmd.Flags().Set("server", "https://xkms.example.com:8443"))
	require.NoError(t, cmd.Flags().Set("email", "alice@example.com"))
	require.NoError(t, cmd.Flags().Set("display-name", "Alice Example"))

	require.NoError(t, runAuthRegister(cmd, nil))

	// The server was asked to begin the ceremony for the canonical login key.
	require.NotNil(t, client.beginRegistrationReq)
	assert.Equal(t, "alice@example.com", client.beginRegistrationReq.Email)
	assert.Equal(t, "Alice Example", client.beginRegistrationReq.DisplayName)

	// The authenticator received the server's options and the server origin.
	assert.Equal(t, client.beginRegistrationResp.OptionsJSON, string(ceremony.registerOpts))
	assert.Equal(t, "https://xkms.example.com:8443", ceremony.origin)

	// The attestation went back with the correlating session id.
	require.NotNil(t, client.finishRegistrationReq)
	assert.Equal(t, "session-abc", client.finishRegistrationReq.SessionID)
	assert.Equal(t, `{"id":"cred-123"}`, client.finishRegistrationReq.AttestationJSON)

	assert.Contains(t, out.String(), "Server registered: https://xkms.example.com:8443")
	assert.Contains(t, out.String(), "Credential registered: cred-123")
	assert.True(t, ceremony.closed, "authenticator should be released")
	assert.True(t, client.closed, "transport client should be closed")

	// The server was recorded in the local registry.
	registry, cleanup, err := openServerRegistry(slog.Default())
	require.NoError(t, err)
	defer cleanup()
	entry, err := registry.Lookup(context.Background(), "https://xkms.example.com:8443")
	require.NoError(t, err)
	assert.Equal(t, "https://xkms.example.com:8443", entry.URL)
}

// TestRunAuthRegister_StoresIssuedToken verifies a token returned alongside
// registration is persisted in the token store.
func TestRunAuthRegister_StoresIssuedToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	client := &fakeAuthClient{
		beginRegistrationResp: &transport.BeginRegistrationResponse{SessionID: "s", OptionsJSON: "{}"},
		finishRegistrationResp: &transport.FinishRegistrationResponse{
			Success:      true,
			CredentialID: "cred-1",
			Token:        "issued-jwt",
		},
	}
	installAuthDoubles(t, client, &fakeCeremony{registerJSON: []byte("{}")}, nil)

	var out bytes.Buffer
	cmd := newAuthRegisterCmd(t, &out)
	require.NoError(t, cmd.Flags().Set("server", "https://xkms.example.com:8443"))
	require.NoError(t, cmd.Flags().Set("username", "alice"))

	require.NoError(t, runAuthRegister(cmd, nil))

	tokens, cleanup, err := openTokenStore(slog.Default())
	require.NoError(t, err)
	defer cleanup()

	entry, err := tokens.Load(context.Background(), "https://xkms.example.com:8443")
	require.NoError(t, err)
	assert.Equal(t, "issued-jwt", entry.Token)
	assert.Equal(t, tokenstore.SourceFIDO2, entry.Source)
}

// TestRunAuthRegister_ExistingServerStillEnrolls verifies an already
// registered server no longer short-circuits to a silent success: the
// credential ceremony still runs.
func TestRunAuthRegister_ExistingServerStillEnrolls(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	registry, cleanup, err := openServerRegistry(slog.Default())
	require.NoError(t, err)
	require.NoError(t, registry.Register(context.Background(), &serverregistry.ServerEntry{
		URL:      "https://existing.example.com:8443",
		Name:     "existing",
		Protocol: serverregistry.ProtocolREST,
	}))
	cleanup()

	client := &fakeAuthClient{
		beginRegistrationResp:  &transport.BeginRegistrationResponse{SessionID: "s", OptionsJSON: "{}"},
		finishRegistrationResp: &transport.FinishRegistrationResponse{Success: true, CredentialID: "cred-9"},
	}
	installAuthDoubles(t, client, &fakeCeremony{registerJSON: []byte("{}")}, nil)

	var out bytes.Buffer
	cmd := newAuthRegisterCmd(t, &out)
	require.NoError(t, cmd.Flags().Set("server", "https://existing.example.com:8443"))
	require.NoError(t, cmd.Flags().Set("username", "alice"))

	require.NoError(t, runAuthRegister(cmd, nil))

	assert.Contains(t, out.String(), "Server already registered")
	assert.Contains(t, out.String(), "Credential registered: cred-9")
	require.NotNil(t, client.finishRegistrationReq)
}

// TestRunAuthRegister_NoAuthenticator verifies the command fails closed when
// no CTAP2 authenticator can be opened.
func TestRunAuthRegister_NoAuthenticator(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	client := &fakeAuthClient{
		beginRegistrationResp: &transport.BeginRegistrationResponse{SessionID: "s", OptionsJSON: "{}"},
	}
	installAuthDoubles(t, client, nil, ErrWebAuthnAuthenticatorUnavailable)

	var out bytes.Buffer
	cmd := newAuthRegisterCmd(t, &out)
	require.NoError(t, cmd.Flags().Set("server", "https://xkms.example.com:8443"))

	err := runAuthRegister(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWebAuthnAuthenticatorUnavailable)
	assert.NotContains(t, out.String(), "Credential registered")
}

// TestRunAuthRegister_BeginRejected verifies a server that refuses to start
// the ceremony surfaces a typed error.
func TestRunAuthRegister_BeginRejected(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	client := &fakeAuthClient{beginRegistrationErr: errors.New("registration disabled")}
	installAuthDoubles(t, client, &fakeCeremony{}, nil)

	cmd := newAuthRegisterCmd(t, &bytes.Buffer{})
	require.NoError(t, cmd.Flags().Set("server", "https://xkms.example.com:8443"))

	err := runAuthRegister(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthBeginRegistrationFailed)
	assert.Contains(t, err.Error(), "registration disabled")
}

// TestRunAuthRegister_ServerRejectsAttestation verifies an unsuccessful
// finish is reported with the server's message instead of exiting 0.
func TestRunAuthRegister_ServerRejectsAttestation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	client := &fakeAuthClient{
		beginRegistrationResp:  &transport.BeginRegistrationResponse{SessionID: "s", OptionsJSON: "{}"},
		finishRegistrationResp: &transport.FinishRegistrationResponse{Success: false, Message: "attestation not trusted"},
	}
	installAuthDoubles(t, client, &fakeCeremony{registerJSON: []byte("{}")}, nil)

	cmd := newAuthRegisterCmd(t, &bytes.Buffer{})
	require.NoError(t, cmd.Flags().Set("server", "https://xkms.example.com:8443"))

	err := runAuthRegister(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthRegistrationRejected)
	assert.Contains(t, err.Error(), "attestation not trusted")
}

// TestRunAuthRegister_ConnectFails verifies an unreachable server is reported
// before anything is written to the registry.
func TestRunAuthRegister_ConnectFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	client := &fakeAuthClient{connectErr: errors.New("connection refused")}
	installAuthDoubles(t, client, &fakeCeremony{}, nil)

	cmd := newAuthRegisterCmd(t, &bytes.Buffer{})
	require.NoError(t, cmd.Flags().Set("server", "https://xkms.example.com:8443"))

	err := runAuthRegister(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthConnectFailed)

	registry, cleanup, regErr := openServerRegistry(slog.Default())
	require.NoError(t, regErr)
	defer cleanup()
	servers, listErr := registry.List(context.Background())
	require.NoError(t, listErr)
	assert.Empty(t, servers)
}

// --- runAuthLogin WebAuthn ceremony tests ---

// registerLoginServer pre-registers a server so login can look it up.
func registerLoginServer(t *testing.T, serverURL string) {
	t.Helper()

	registry, cleanup, err := openServerRegistry(slog.Default())
	require.NoError(t, err)
	defer cleanup()
	require.NoError(t, registry.Register(context.Background(), &serverregistry.ServerEntry{
		URL:      serverURL,
		Name:     serverURL,
		Protocol: serverregistry.ProtocolREST,
	}))
}

// TestRunAuthLogin_ObtainsAndStoresToken verifies login drives the assertion
// ceremony and persists the issued JWT with its claims. Before this was
// implemented the command printed "not yet implemented" and never obtained a
// token.
func TestRunAuthLogin_ObtainsAndStoresToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	const serverURL = "https://xkms.example.com:8443"
	registerLoginServer(t, serverURL)

	// HS256 JWT with iss/sub/exp claims; only the claims are read.
	const jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJpc3MiOiJ4a21zLmV4YW1wbGUuY29tIiwic3ViIjoiYWxpY2UiLCJleHAiOjQ4NzE1MTIwMDB9." +
		"c2lnbmF0dXJl"

	client := &fakeAuthClient{
		beginAuthenticationResp: &transport.BeginAuthenticationResponse{
			SessionID:   "login-session",
			OptionsJSON: `{"publicKey":{"challenge":"Y2hhbGxlbmdl","rpId":"xkms.example.com"}}`,
		},
		finishAuthenticationResp: &transport.FinishAuthenticationResponse{
			Success:  true,
			Token:    jwtToken,
			Username: "alice",
		},
	}
	ceremony := &fakeCeremony{assertJSON: []byte(`{"id":"cred-123"}`)}
	installAuthDoubles(t, client, ceremony, nil)

	var out bytes.Buffer
	cmd := newAuthLoginCmd(t, &out)
	require.NoError(t, cmd.Flags().Set("server", serverURL))
	require.NoError(t, cmd.Flags().Set("email", "alice@example.com"))

	require.NoError(t, runAuthLogin(cmd, nil))

	require.NotNil(t, client.beginAuthenticationReq)
	assert.Equal(t, "alice@example.com", client.beginAuthenticationReq.Email)
	assert.Equal(t, client.beginAuthenticationResp.OptionsJSON, string(ceremony.assertOpts))
	assert.Equal(t, serverURL, ceremony.origin)

	require.NotNil(t, client.finishAuthenticationReq)
	assert.Equal(t, "login-session", client.finishAuthenticationReq.SessionID)
	assert.Equal(t, "alice@example.com", client.finishAuthenticationReq.Email)
	assert.Equal(t, `{"id":"cred-123"}`, client.finishAuthenticationReq.AssertionJSON)

	tokens, cleanup, err := openTokenStore(slog.Default())
	require.NoError(t, err)
	defer cleanup()

	entry, err := tokens.Load(context.Background(), serverURL)
	require.NoError(t, err)
	assert.Equal(t, jwtToken, entry.Token)
	assert.Equal(t, tokenstore.TypeBearer, entry.TokenType)
	assert.Equal(t, tokenstore.SourceFIDO2, entry.Source)
	assert.Equal(t, "xkms.example.com", entry.Issuer)
	assert.Equal(t, "alice", entry.Subject)
	assert.False(t, entry.IsExpired())

	// The registry records the successful connection.
	registry, regCleanup, err := openServerRegistry(slog.Default())
	require.NoError(t, err)
	defer regCleanup()
	serverEntry, err := registry.Lookup(context.Background(), serverURL)
	require.NoError(t, err)
	assert.False(t, serverEntry.LastConnectedAt.IsZero(), "login should record the connection time")

	assert.Contains(t, out.String(), "Token stored")
	assert.True(t, ceremony.closed)
}

// TestRunAuthLogin_ServerRejectsAssertion verifies a rejected assertion is a
// failure, not a silent success.
func TestRunAuthLogin_ServerRejectsAssertion(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	const serverURL = "https://xkms.example.com:8443"
	registerLoginServer(t, serverURL)

	client := &fakeAuthClient{
		beginAuthenticationResp:  &transport.BeginAuthenticationResponse{SessionID: "s", OptionsJSON: "{}"},
		finishAuthenticationResp: &transport.FinishAuthenticationResponse{Success: false, Message: "unknown credential"},
	}
	installAuthDoubles(t, client, &fakeCeremony{assertJSON: []byte("{}")}, nil)

	cmd := newAuthLoginCmd(t, &bytes.Buffer{})
	require.NoError(t, cmd.Flags().Set("server", serverURL))

	err := runAuthLogin(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthLoginRejected)
	assert.Contains(t, err.Error(), "unknown credential")
}

// TestRunAuthLogin_NoTokenIssued verifies a success response without a token
// fails closed, since login exists to obtain a JWT.
func TestRunAuthLogin_NoTokenIssued(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	const serverURL = "https://xkms.example.com:8443"
	registerLoginServer(t, serverURL)

	client := &fakeAuthClient{
		beginAuthenticationResp:  &transport.BeginAuthenticationResponse{SessionID: "s", OptionsJSON: "{}"},
		finishAuthenticationResp: &transport.FinishAuthenticationResponse{Success: true},
	}
	installAuthDoubles(t, client, &fakeCeremony{assertJSON: []byte("{}")}, nil)

	cmd := newAuthLoginCmd(t, &bytes.Buffer{})
	require.NoError(t, cmd.Flags().Set("server", serverURL))

	err := runAuthLogin(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthNoToken)
}

// TestRunAuthLogin_AuthenticatorFails verifies a ceremony failure at the
// authenticator is surfaced.
func TestRunAuthLogin_AuthenticatorFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	const serverURL = "https://xkms.example.com:8443"
	registerLoginServer(t, serverURL)

	client := &fakeAuthClient{
		beginAuthenticationResp: &transport.BeginAuthenticationResponse{SessionID: "s", OptionsJSON: "{}"},
	}
	ceremony := &fakeCeremony{assertErr: &SentinelCauseError{
		Sentinel: ErrWebAuthnAssertionFailed,
		Cause:    errors.New("user presence timeout"),
	}}
	installAuthDoubles(t, client, ceremony, nil)

	cmd := newAuthLoginCmd(t, &bytes.Buffer{})
	require.NoError(t, cmd.Flags().Set("server", serverURL))

	err := runAuthLogin(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWebAuthnAssertionFailed)
	assert.Contains(t, err.Error(), "user presence timeout")
}

// TestRunAuthLogin_BeginRejected verifies a server that refuses to start the
// assertion ceremony surfaces a typed error.
func TestRunAuthLogin_BeginRejected(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	const serverURL = "https://xkms.example.com:8443"
	registerLoginServer(t, serverURL)

	client := &fakeAuthClient{beginAuthenticationErr: errors.New("no credentials enrolled")}
	installAuthDoubles(t, client, &fakeCeremony{}, nil)

	cmd := newAuthLoginCmd(t, &bytes.Buffer{})
	require.NoError(t, cmd.Flags().Set("server", serverURL))

	err := runAuthLogin(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthBeginAuthenticationFailed)
	assert.Contains(t, err.Error(), "no credentials enrolled")
}

// TestRunAuthLogin_ConnectFails verifies an unreachable registered server is
// reported before any ceremony work.
func TestRunAuthLogin_ConnectFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	const serverURL = "https://xkms.example.com:8443"
	registerLoginServer(t, serverURL)

	client := &fakeAuthClient{connectErr: errors.New("connection refused")}
	installAuthDoubles(t, client, &fakeCeremony{}, nil)

	cmd := newAuthLoginCmd(t, &bytes.Buffer{})
	require.NoError(t, cmd.Flags().Set("server", serverURL))

	err := runAuthLogin(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthConnectFailed)
	assert.Nil(t, client.beginAuthenticationReq)
}

// --- username resolution and token metadata ---

// TestResolveAuthLoginKey_EmailWins verifies --email is the login key and is
// preferred over the deprecated spelling.
func TestResolveAuthLoginKey_EmailWins(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("email", "", "")
	cmd.Flags().String("username", "", "")
	require.NoError(t, cmd.Flags().Set("email", "  alice@example.com  "))
	require.NoError(t, cmd.Flags().Set("username", "alice"))

	key, err := resolveAuthLoginKey(cmd)
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", key)
}

// TestResolveAuthLoginKey_DeprecatedUsernameStillCarriesTheKey verifies an
// operator already passing the email under the old flag keeps working.
func TestResolveAuthLoginKey_DeprecatedUsernameStillCarriesTheKey(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("email", "", "")
	cmd.Flags().String("username", "", "")
	require.NoError(t, cmd.Flags().Set("username", " alice@example.com "))

	key, err := resolveAuthLoginKey(cmd)
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", key)
}

// TestResolveAuthLoginKey_NoOSUserFallback verifies the environment-derived
// default is gone. An OS account name is not a login key: the server resolves
// the ceremony with GetUserByEmail, so defaulting to one could only miss --
// and on a relying party with public registration enabled a miss is a sign-up
// that enrolls the credential onto a principal nobody created.
func TestResolveAuthLoginKey_NoOSUserFallback(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("email", "", "")
	cmd.Flags().String("username", "", "")

	_, err := resolveAuthLoginKey(cmd)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthEmailRequired)
}

// TestApplyJWTClaims_PopulatesMetadata verifies registered claims are copied
// onto the stored token entry.
func TestApplyJWTClaims_PopulatesMetadata(t *testing.T) {
	const jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJpc3MiOiJ4a21zLmV4YW1wbGUuY29tIiwic3ViIjoiYWxpY2UiLCJleHAiOjQ4NzE1MTIwMDB9." +
		"c2lnbmF0dXJl"

	entry := &tokenstore.TokenEntry{}
	applyJWTClaims(entry, jwtToken)

	assert.Equal(t, "xkms.example.com", entry.Issuer)
	assert.Equal(t, "alice", entry.Subject)
	assert.Equal(t, int64(4871512000), entry.ExpiresAt.Unix())
}

// TestApplyJWTClaims_NonJWTLeavesMetadataUnset verifies an opaque token is
// stored without inventing metadata.
func TestApplyJWTClaims_NonJWTLeavesMetadataUnset(t *testing.T) {
	entry := &tokenstore.TokenEntry{}
	applyJWTClaims(entry, "not-a-jwt")

	assert.Empty(t, entry.Issuer)
	assert.Empty(t, entry.Subject)
	assert.True(t, entry.ExpiresAt.IsZero())
}

// TestAuthServerDetail verifies server messages are formatted as error detail
// only when present.
func TestAuthServerDetail(t *testing.T) {
	assert.Equal(t, "", authServerDetail(""))
	assert.Equal(t, ": denied", authServerDetail("denied"))
}

// TestDefaultAuthClientFactory_BuildsClient verifies the production factory
// returns a usable, unconnected SDK client.
func TestDefaultAuthClientFactory_BuildsClient(t *testing.T) {
	client, err := defaultAuthClientFactory(authClientConfig{ServerURL: "https://xkms.example.com:8443"})
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NoError(t, client.Close())
}

// TestDefaultAuthClientFactory_RejectsEmptyAddress verifies an unusable
// configuration is refused rather than producing a half-built client.
func TestDefaultAuthClientFactory_RejectsEmptyAddress(t *testing.T) {
	client, err := defaultAuthClientFactory(authClientConfig{})
	assert.Nil(t, client)
	assert.ErrorIs(t, err, ErrAuthClientCreationFailed)
}

// A non-email login key must be REFUSED, on either flag.
//
// resolveAuthLoginKey returned any non-empty string unchanged, so
// `xkey auth register --username alice` forwarded "alice" into the server's
// email-based lookup. On a closed relying party that fails to find the intended
// principal; on one with public registration enabled it silently enrols the
// credential onto a SECOND principal keyed by "alice" — the exact fail-open
// misrouting this change exists to eliminate. The doc comment claimed the
// deprecated path was safe because an operator "already passing an email keeps
// working"; the code did not check that (Codex, go-xkms #190).
func TestResolveAuthLoginKey_RefusesANonEmailKey(t *testing.T) {
	for _, tc := range []struct {
		name, flag, value string
	}{
		{"deprecated username flag", "username", "alice"},
		{"email flag", "email", "alice"},
		// A display-name form is not a bare address, and the server stores this
		// value verbatim as an index key.
		{"display-name form", "email", "Alice <alice@example.com>"},
		{"no domain", "email", "alice@"},
		{"os account name", "username", "jhahn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().String("email", "", "")
			cmd.Flags().String("username", "", "")
			require.NoError(t, cmd.Flags().Set(tc.flag, tc.value))

			_, err := resolveAuthLoginKey(cmd)
			require.Error(t, err, "a value that cannot address a principal must be refused")
			assert.ErrorIs(t, err, ErrAuthLoginKeyNotEmail)
		})
	}
}

// The deprecation must keep WORKING for the operator it was written for.
func TestResolveAuthLoginKey_DeprecatedFlagStillAcceptsARealEmail(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("email", "", "")
	cmd.Flags().String("username", "", "")
	require.NoError(t, cmd.Flags().Set("username", " operator@example.com "))

	key, err := resolveAuthLoginKey(cmd)
	require.NoError(t, err)
	assert.Equal(t, "operator@example.com", key)
}
