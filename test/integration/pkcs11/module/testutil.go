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

//go:build integration
// +build integration

// Package module provides integration tests for the PKCS#11 module implementation.
// These tests validate the go-xkms PKCS#11 module against the OASIS PKCS#11 v3.0
// specification using the embedded transport for direct in-process testing.
package module

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// TestEnvironment holds the test environment state including the PKCS#11 module
// and any resources that need cleanup.
type TestEnvironment struct {
	// Module is the PKCS#11 module instance under test.
	Module *module.Module

	// Config is the module configuration.
	Config *module.Config

	// mu protects concurrent access to the environment.
	mu sync.Mutex

	// cleanupFuncs holds functions to call during teardown.
	cleanupFuncs []func()
}

// DefaultTestConfig returns a default configuration for integration testing.
// It checks for environment variables to determine the transport:
//   - XKMS_PKCS11_TARGET: explicit target (e.g., "unix:///var/run/xkms/xkms.sock")
//   - XKMS_UNIX_SOCKET: Unix socket path (will be prefixed with "unix://")
//   - XKMS_GRPC_ADDR: gRPC server address (host:port)
//
// Storage configuration:
//   - XKMS_PKCS11_STORAGE_TYPE: "memory" or "file"
//   - XKMS_PKCS11_STORAGE_PATH: path for file-based storage
//
// Auto-initialization:
//   - XKMS_PKCS11_AUTO_INIT_TOKEN: enable auto-init
//   - XKMS_PKCS11_SO_PIN: SO PIN for auto-init
//   - XKMS_PKCS11_USER_PIN: User PIN for auto-init
//   - XKMS_PKCS11_TOKEN_LABEL: Token label for auto-init
func DefaultTestConfig() *module.Config {
	target := os.Getenv("XKMS_PKCS11_TARGET")
	if target == "" {
		if socketPath := os.Getenv("XKMS_UNIX_SOCKET"); socketPath != "" {
			target = "unix://" + socketPath
		} else if grpcAddr := os.Getenv("XKMS_GRPC_ADDR"); grpcAddr != "" {
			target = grpcAddr
		}
	}

	// If no target configured, use a sensible default for devcontainer
	if target == "" {
		target = "unix:///var/run/xkms/xkms.sock"
	}

	cfg := &module.Config{
		Target:  target,
		Timeout: 30 * time.Second,
	}

	// Read storage configuration from environment
	if storageType := os.Getenv("XKMS_PKCS11_STORAGE_TYPE"); storageType != "" {
		cfg.StorageType = storageType
	}
	if storagePath := os.Getenv("XKMS_PKCS11_STORAGE_PATH"); storagePath != "" {
		cfg.StoragePath = storagePath
	}

	// Read auto-initialization configuration from environment
	if autoInit := os.Getenv("XKMS_PKCS11_AUTO_INIT_TOKEN"); autoInit == "true" || autoInit == "1" {
		cfg.AutoInitToken = true
	}
	if soPin := os.Getenv("XKMS_PKCS11_SO_PIN"); soPin != "" {
		cfg.SOPIN = soPin
	}
	if userPin := os.Getenv("XKMS_PKCS11_USER_PIN"); userPin != "" {
		cfg.UserPIN = userPin
	}
	if tokenLabel := os.Getenv("XKMS_PKCS11_TOKEN_LABEL"); tokenLabel != "" {
		cfg.TokenLabel = tokenLabel
	}

	return cfg
}

// SetupTestEnvironment creates and initializes a new test environment.
// It creates a fresh PKCS#11 module instance with the provided configuration.
func SetupTestEnvironment(t *testing.T, cfg *module.Config) *TestEnvironment {
	t.Helper()

	if cfg == nil {
		cfg = DefaultTestConfig()
	}

	// Reset any global module state from previous tests
	module.ResetGlobalModule()

	// Create a new module instance
	mod, err := module.New(module.WithConfig(cfg))
	if err != nil {
		t.Fatalf("failed to create PKCS#11 module: %v", err)
	}

	env := &TestEnvironment{
		Module:       mod,
		Config:       cfg,
		cleanupFuncs: make([]func(), 0),
	}

	// Register cleanup to run when test completes
	t.Cleanup(func() {
		env.Teardown(t)
	})

	return env
}

// Teardown cleans up the test environment and releases all resources.
func (env *TestEnvironment) Teardown(t *testing.T) {
	t.Helper()

	env.mu.Lock()
	defer env.mu.Unlock()

	// Run cleanup functions in reverse order
	for i := len(env.cleanupFuncs) - 1; i >= 0; i-- {
		env.cleanupFuncs[i]()
	}
	env.cleanupFuncs = nil

	// Finalize the module if initialized
	if env.Module != nil && env.Module.IsInitialized() {
		if rv := env.Module.Finalize(); rv != module.CKR_OK {
			t.Logf("warning: module finalize returned %s", rv.String())
		}
	}

	// Reset global module state
	module.ResetGlobalModule()
}

// AddCleanup registers a function to be called during teardown.
func (env *TestEnvironment) AddCleanup(fn func()) {
	env.mu.Lock()
	defer env.mu.Unlock()
	env.cleanupFuncs = append(env.cleanupFuncs, fn)
}

// InitializeModule initializes the PKCS#11 module and returns the result.
func (env *TestEnvironment) InitializeModule(t *testing.T) module.CK_RV {
	t.Helper()
	return env.Module.Initialize(env.Config)
}

// MustInitializeModule initializes the module and fails the test if initialization fails.
func (env *TestEnvironment) MustInitializeModule(t *testing.T) {
	t.Helper()
	rv := env.InitializeModule(t)
	if rv != module.CKR_OK {
		t.Fatalf("module initialization failed: %s", rv.String())
	}
}

// InitializeToken initializes the default token with the given SO PIN and label.
func (env *TestEnvironment) InitializeToken(t *testing.T, soPin []byte, label string) module.CK_RV {
	t.Helper()
	return env.Module.InitToken(0, soPin, label)
}

// MustInitializeToken initializes the token and fails if initialization fails.
func (env *TestEnvironment) MustInitializeToken(t *testing.T, soPin []byte, label string) {
	t.Helper()
	rv := env.InitializeToken(t, soPin, label)
	if rv != module.CKR_OK {
		t.Fatalf("token initialization failed: %s", rv.String())
	}
}

// OpenSession opens a session with the default slot (0).
func (env *TestEnvironment) OpenSession(t *testing.T, flags module.SessionFlag) (module.SessionHandle, module.CK_RV) {
	t.Helper()
	return env.Module.OpenSession(0, flags)
}

// MustOpenSession opens a session and fails if opening fails.
func (env *TestEnvironment) MustOpenSession(t *testing.T, flags module.SessionFlag) module.SessionHandle {
	t.Helper()
	handle, rv := env.OpenSession(t, flags)
	if rv != module.CKR_OK {
		t.Fatalf("failed to open session: %s", rv.String())
	}
	return handle
}

// OpenRWSession opens a read-write session with the default slot.
func (env *TestEnvironment) OpenRWSession(t *testing.T) (module.SessionHandle, module.CK_RV) {
	t.Helper()
	return env.OpenSession(t, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
}

// MustOpenRWSession opens a read-write session and fails if opening fails.
func (env *TestEnvironment) MustOpenRWSession(t *testing.T) module.SessionHandle {
	t.Helper()
	return env.MustOpenSession(t, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
}

// OpenROSession opens a read-only session with the default slot.
func (env *TestEnvironment) OpenROSession(t *testing.T) (module.SessionHandle, module.CK_RV) {
	t.Helper()
	return env.OpenSession(t, module.CKF_SERIAL_SESSION)
}

// MustOpenROSession opens a read-only session and fails if opening fails.
func (env *TestEnvironment) MustOpenROSession(t *testing.T) module.SessionHandle {
	t.Helper()
	return env.MustOpenSession(t, module.CKF_SERIAL_SESSION)
}

// Login logs in to the token with the specified user type and PIN.
func (env *TestEnvironment) Login(t *testing.T, session module.SessionHandle, userType module.UserType, pin []byte) module.CK_RV {
	t.Helper()
	return env.Module.Login(session, userType, pin)
}

// MustLogin logs in and fails if login fails.
func (env *TestEnvironment) MustLogin(t *testing.T, session module.SessionHandle, userType module.UserType, pin []byte) {
	t.Helper()
	rv := env.Login(t, session, userType, pin)
	if rv != module.CKR_OK {
		t.Fatalf("login failed: %s", rv.String())
	}
}

// LoginSO logs in as Security Officer.
func (env *TestEnvironment) LoginSO(t *testing.T, session module.SessionHandle, pin []byte) module.CK_RV {
	t.Helper()
	return env.Login(t, session, module.CKU_SO, pin)
}

// MustLoginSO logs in as SO and fails if login fails.
func (env *TestEnvironment) MustLoginSO(t *testing.T, session module.SessionHandle, pin []byte) {
	t.Helper()
	env.MustLogin(t, session, module.CKU_SO, pin)
}

// LoginUser logs in as normal user.
func (env *TestEnvironment) LoginUser(t *testing.T, session module.SessionHandle, pin []byte) module.CK_RV {
	t.Helper()
	return env.Login(t, session, module.CKU_USER, pin)
}

// MustLoginUser logs in as user and fails if login fails.
func (env *TestEnvironment) MustLoginUser(t *testing.T, session module.SessionHandle, pin []byte) {
	t.Helper()
	env.MustLogin(t, session, module.CKU_USER, pin)
}

// TestPINs contains standard PINs used in tests.
var TestPINs = struct {
	SO   []byte
	User []byte
}{
	SO:   []byte("12345678"),
	User: []byte("87654321"),
}

// TestLabels contains standard labels used in tests.
var TestLabels = struct {
	Token string
}{
	Token: "test-token",
}

// SetupInitializedModule sets up a fully initialized module with token and user PIN.
func SetupInitializedModule(t *testing.T) (*TestEnvironment, module.SessionHandle) {
	t.Helper()
	return SetupInitializedModuleWithConfig(t, nil)
}

// SetupInitializedModuleWithConfig sets up a fully initialized module with custom config.
// It performs the full PKCS#11 token initialization flow:
// 1. Initialize module
// 2. InitToken with SO PIN
// 3. Login as SO
// 4. InitPIN to set user PIN
// 5. Logout SO
// 6. Return new session ready for user login
func SetupInitializedModuleWithConfig(t *testing.T, cfg *module.Config) (*TestEnvironment, module.SessionHandle) {
	t.Helper()

	env := SetupTestEnvironment(t, cfg)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

	// Open RW session to set user PIN
	session := env.MustOpenRWSession(t)

	// Login as SO to set user PIN
	env.MustLoginSO(t, session, TestPINs.SO)

	// Initialize user PIN
	rv := env.Module.InitPIN(session, TestPINs.User)
	if rv != module.CKR_OK {
		t.Fatalf("failed to initialize user PIN: %s", rv.String())
	}

	// Logout SO
	rv = env.Module.Logout(session)
	if rv != module.CKR_OK {
		t.Fatalf("failed to logout SO: %s", rv.String())
	}

	// Close session
	rv = env.Module.CloseSession(session)
	if rv != module.CKR_OK {
		t.Fatalf("failed to close session: %s", rv.String())
	}

	// Open a new RW session for the test
	session = env.MustOpenRWSession(t)

	return env, session
}

// SetupAuthenticatedModule sets up an initialized module with an authenticated user session.
func SetupAuthenticatedModule(t *testing.T) (*TestEnvironment, module.SessionHandle) {
	t.Helper()
	return SetupAuthenticatedModuleWithConfig(t, nil)
}

// SetupAuthenticatedModuleWithConfig sets up an initialized module with custom config
// and an authenticated user session.
func SetupAuthenticatedModuleWithConfig(t *testing.T, cfg *module.Config) (*TestEnvironment, module.SessionHandle) {
	t.Helper()

	env, session := SetupInitializedModuleWithConfig(t, cfg)
	env.MustLoginUser(t, session, TestPINs.User)

	return env, session
}

// RequireReturnValue checks that the return value matches the expected value.
func RequireReturnValue(t *testing.T, got, expected module.CK_RV, msg string) {
	t.Helper()
	if got != expected {
		t.Fatalf("%s: expected %s, got %s", msg, expected.String(), got.String())
	}
}

// RequireOK checks that the return value is CKR_OK.
func RequireOK(t *testing.T, rv module.CK_RV, msg string) {
	t.Helper()
	RequireReturnValue(t, rv, module.CKR_OK, msg)
}

// WithContext returns a context with the specified timeout.
func WithContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// DefaultContext returns a context with the default test timeout.
func DefaultContext() (context.Context, context.CancelFunc) {
	return WithContext(30 * time.Second)
}

// BuildRSAPublicKeyTemplate creates a template for RSA public key generation.
func BuildRSAPublicKeyTemplate(label string, modulusBits uint32) []module.Attribute {
	return []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewUint32Attribute(module.CKA_MODULUS_BITS, modulusBits),
		module.NewBoolAttribute(module.CKA_TOKEN, true),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_VERIFY, true),
		module.NewBoolAttribute(module.CKA_WRAP, true),
		// Standard RSA public exponent (65537)
		module.NewAttribute(module.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
	}
}

// BuildRSAPrivateKeyTemplate creates a template for RSA private key generation.
func BuildRSAPrivateKeyTemplate(label string) []module.Attribute {
	return []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_TOKEN, true),
		module.NewBoolAttribute(module.CKA_PRIVATE, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, true),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
		module.NewBoolAttribute(module.CKA_SIGN, true),
		module.NewBoolAttribute(module.CKA_UNWRAP, true),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, false),
	}
}

// BuildECPublicKeyTemplate creates a template for EC public key generation.
func BuildECPublicKeyTemplate(label string, curveOID []byte) []module.Attribute {
	return []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewAttribute(module.CKA_EC_PARAMS, curveOID),
		module.NewBoolAttribute(module.CKA_TOKEN, true),
		module.NewBoolAttribute(module.CKA_VERIFY, true),
		module.NewBoolAttribute(module.CKA_DERIVE, true),
	}
}

// BuildECPrivateKeyTemplate creates a template for EC private key generation.
func BuildECPrivateKeyTemplate(label string) []module.Attribute {
	return []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_TOKEN, true),
		module.NewBoolAttribute(module.CKA_PRIVATE, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, true),
		module.NewBoolAttribute(module.CKA_SIGN, true),
		module.NewBoolAttribute(module.CKA_DERIVE, true),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, false),
	}
}

// BuildAESKeyTemplate creates a template for AES key generation.
func BuildAESKeyTemplate(label string, keyLen uint32) []module.Attribute {
	return []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewUint32Attribute(module.CKA_VALUE_LEN, keyLen),
		module.NewBoolAttribute(module.CKA_TOKEN, true),
		module.NewBoolAttribute(module.CKA_PRIVATE, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, true),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, false),
	}
}

// EC curve OIDs (DER-encoded ASN.1 OID with tag and length).
var (
	// OID_P256 is the DER-encoded OID for P-256 (secp256r1, prime256v1).
	// OID: 1.2.840.10045.3.1.7
	OID_P256 = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

	// OID_P384 is the DER-encoded OID for P-384 (secp384r1).
	// OID: 1.3.132.0.34
	OID_P384 = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}

	// OID_P521 is the DER-encoded OID for P-521 (secp521r1).
	// OID: 1.3.132.0.35
	OID_P521 = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}

	// OID_Ed25519 is the DER-encoded OID for Ed25519 (Edwards curve).
	// OID: 1.3.101.112
	OID_Ed25519 = []byte{0x06, 0x03, 0x2b, 0x65, 0x70}

	// OID_Ed448 is the DER-encoded OID for Ed448 (Edwards curve).
	// OID: 1.3.101.113
	OID_Ed448 = []byte{0x06, 0x03, 0x2b, 0x65, 0x71}
)

// BuildEd25519PublicKeyTemplate creates a template for Ed25519 public key generation.
func BuildEd25519PublicKeyTemplate(label string) []module.Attribute {
	return []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC_EDWARDS)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewAttribute(module.CKA_EC_PARAMS, OID_Ed25519),
		module.NewBoolAttribute(module.CKA_TOKEN, true),
		module.NewBoolAttribute(module.CKA_VERIFY, true),
	}
}

// BuildEd25519PrivateKeyTemplate creates a template for Ed25519 private key generation.
func BuildEd25519PrivateKeyTemplate(label string) []module.Attribute {
	return []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC_EDWARDS)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_TOKEN, true),
		module.NewBoolAttribute(module.CKA_PRIVATE, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, true),
		module.NewBoolAttribute(module.CKA_SIGN, true),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, false),
	}
}

// FindKeyByLabel searches for a key object with the specified label.
func FindKeyByLabel(t *testing.T, env *TestEnvironment, session module.SessionHandle, label string) (module.ObjectHandle, bool) {
	t.Helper()

	template := []module.Attribute{
		module.NewStringAttribute(module.CKA_LABEL, label),
	}

	rv := env.Module.FindObjectsInit(session, template)
	if rv != module.CKR_OK {
		t.Fatalf("FindObjectsInit failed: %s", rv.String())
	}

	handles, rv := env.Module.FindObjects(session, 10)
	if rv != module.CKR_OK {
		t.Fatalf("FindObjects failed: %s", rv.String())
	}

	rv = env.Module.FindObjectsFinal(session)
	if rv != module.CKR_OK {
		t.Fatalf("FindObjectsFinal failed: %s", rv.String())
	}

	if len(handles) == 0 {
		return 0, false
	}

	return handles[0], true
}

// MustFindKeyByLabel finds a key by label or fails the test.
func MustFindKeyByLabel(t *testing.T, env *TestEnvironment, session module.SessionHandle, label string) module.ObjectHandle {
	t.Helper()

	handle, found := FindKeyByLabel(t, env, session, label)
	if !found {
		t.Fatalf("key with label %q not found", label)
	}

	return handle
}

// GetCurveOID returns the DER-encoded OID for the given curve name.
// Supported curves: P-256, P-384, P-521, Ed25519, Ed448
func GetCurveOID(curve string) []byte {
	switch curve {
	case "P-256", "secp256r1", "prime256v1":
		return OID_P256
	case "P-384", "secp384r1":
		return OID_P384
	case "P-521", "secp521r1":
		return OID_P521
	case "Ed25519":
		return OID_Ed25519
	case "Ed448":
		return OID_Ed448
	default:
		return nil
	}
}

// BuildECPublicKeyTemplateByName creates a template for EC public key using curve name.
func BuildECPublicKeyTemplateByName(label string, curveName string) []module.Attribute {
	return BuildECPublicKeyTemplate(label, GetCurveOID(curveName))
}

// setupTestModule creates a new module for testing and returns it with a cleanup function.
// This is used for tests that need direct module access without the full TestEnvironment setup.
func setupTestModule(t *testing.T) (*module.Module, func()) {
	t.Helper()

	// Reset any global module state from previous tests
	module.ResetGlobalModule()

	// Get configuration from environment (same as SetupTestEnvironment)
	cfg := DefaultTestConfig()

	m, err := module.New(module.WithConfig(cfg))
	if err != nil {
		t.Fatalf("Failed to create module: %v", err)
	}

	cleanup := func() {
		m.Finalize()
		module.ResetGlobalModule()
	}

	return m, cleanup
}

// loginAndInitToken initializes a token and logs in as user.
// This is a convenience function for tests that need an initialized and logged-in token.
// It handles the case where the token is already initialized by skipping InitToken.
// Returns the session handle to use (may be different from input if sessions were closed).
func loginAndInitToken(t *testing.T, m *module.Module, session module.SessionHandle, slotID module.SlotID) module.SessionHandle {
	t.Helper()

	soPIN := []byte("12345678")
	userPIN := []byte("87654321")

	// First try to login as user - if it works, token is already initialized
	rv := m.Login(session, module.CKU_USER, userPIN)
	if rv == module.CKR_OK || rv == module.CKR_USER_ALREADY_LOGGED_IN {
		// Token is already initialized and user PIN is set
		return session
	}

	// If user login failed with CKR_PIN_INCORRECT or CKR_USER_PIN_NOT_INITIALIZED,
	// we need to initialize the token. Close all sessions first (required for InitToken).
	m.CloseAllSessions(slotID)

	// Initialize token
	rv = m.InitToken(slotID, soPIN, "TestToken")
	if rv != module.CKR_OK && rv != module.CKR_PIN_INCORRECT {
		t.Logf("InitToken: %v (may already be initialized)", rv)
	}

	// Open a new RW session since we closed all sessions
	newSession, rv := m.OpenSession(slotID, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession after InitToken failed: %v", rv)
	}

	// Login as SO
	rv = m.Login(newSession, module.CKU_SO, soPIN)
	if rv != module.CKR_OK && rv != module.CKR_USER_ALREADY_LOGGED_IN {
		t.Fatalf("Login SO failed: %v", rv)
	}

	// Initialize user PIN
	rv = m.InitPIN(newSession, userPIN)
	if rv != module.CKR_OK {
		t.Logf("InitPIN: %v (may already be set)", rv)
	}

	// Logout SO
	rv = m.Logout(newSession)
	if rv != module.CKR_OK && rv != module.CKR_USER_NOT_LOGGED_IN {
		t.Logf("Logout SO: %v", rv)
	}

	// Login as user
	rv = m.Login(newSession, module.CKU_USER, userPIN)
	if rv != module.CKR_OK && rv != module.CKR_USER_ALREADY_LOGGED_IN {
		t.Fatalf("Login user failed: %v", rv)
	}

	return newSession
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS#7 padding.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

// pkcs7Unpad removes PKCS#7 padding from data.
func pkcs7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding > len(data) {
		return data
	}
	return data[:len(data)-padding]
}

// isFilePersistenceEnabled returns true if file-based persistence is configured.
// This is used to conditionally run tests that require persistent state across
// pkcs11-tool invocations.
func isFilePersistenceEnabled() bool {
	storageType := os.Getenv("XKMS_PKCS11_STORAGE_TYPE")
	storagePath := os.Getenv("XKMS_PKCS11_STORAGE_PATH")
	return storageType == "file" && storagePath != ""
}

// isAutoInitEnabled returns true if auto-initialization is configured.
// Auto-init allows the module to automatically initialize the token on load,
// which is useful for pkcs11-tool tests.
func isAutoInitEnabled() bool {
	autoInit := os.Getenv("XKMS_PKCS11_AUTO_INIT_TOKEN")
	return autoInit == "true" || autoInit == "1"
}

// skipIfNoFilePersistence skips the test if neither file persistence nor auto-init
// is configured. pkcs11-tool tests require one of these because each pkcs11-tool
// invocation loads a fresh library instance.
func skipIfNoFilePersistence(t *testing.T) {
	t.Helper()
	if !isFilePersistenceEnabled() && !isAutoInitEnabled() {
		t.Skip("Skipping: pkcs11-tool tests require file persistence or auto-init (set XKMS_PKCS11_STORAGE_TYPE=file or XKMS_PKCS11_AUTO_INIT_TOKEN=true)")
	}
}
