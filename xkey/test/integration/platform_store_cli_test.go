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

//go:build integration && linux

// Package xkey provides integration tests for the "xkey platform-store"
// command group (status / put / get / list / delete / reseal).
//
// Every platform-store subcommand builds a real SDK transport client from
// the resolved xkmsd endpoint (cmd/xkey/cmd/xkmsd_client.go): the
// --xkmsd-url flag, then XKMSD_URL / XKEY_XKMSD_URL, then the xkmsd_url
// config key, then xkmsd.address in the xkey config. The URL scheme selects
// the transport (unix, http(s), grpc(s), quic, mcp(s)).
//
// These tests do not require a live xkmsd. They assert the precise failure
// modes of the real client path: the missing-endpoint error, the transport's
// own connection error against an unreachable endpoint, the unsupported
// scheme error, and the TLS trust-material error. Success paths against a
// live daemon are covered by the server-backed suites.
package xkey

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubConnectMessage is the error text emitted by the removed platform-store
// client stub. No test may ever see it again.
const stubConnectMessage = "transport client creation requires a running xkmsd server"

// isolatePlatformStoreEnv gives the CLI a clean home and clears every
// ambient xkmsd endpoint source so tests observe only what they configure.
func isolatePlatformStoreEnv(t *testing.T) string {
	t.Helper()

	xkeyHome := SetupCleanEnvironment(t)
	t.Setenv("XKEY_HOME", xkeyHome)
	t.Setenv("HOME", xkeyHome)
	t.Setenv("XKMSD_URL", "")
	t.Setenv("XKEY_XKMSD_URL", "")
	t.Setenv("XKMSD_TOKEN", "")
	t.Setenv("XKMSD_TLS_CA", "")

	return xkeyHome
}

// unreachableSocketURL returns a unix:// URL for a socket that does not
// exist, so connecting fails immediately without any server.
func unreachableSocketURL(t *testing.T) string {
	t.Helper()
	return "unix://" + filepath.Join(t.TempDir(), "absent-xkmsd.sock")
}

// assertUnreachableServer asserts that output reports a real transport
// connection failure rather than the removed stub error.
func assertUnreachableServer(t *testing.T, output string) {
	t.Helper()

	assert.Contains(t, output, "connection failed")
	assert.Contains(t, output, "no such file or directory")
	assert.NotContains(t, output, stubConnectMessage)
}

// TestPlatformStoreCLI_Status_NoXkmsdURL verifies that "platform-store
// status" fails with the missing-endpoint error, naming every way to supply
// a server, when nothing is configured.
func TestPlatformStoreCLI_Status_NoXkmsdURL(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "", "platform-store", "status")

	assert.Contains(t, errOutput, "platform-store: failed to connect to xkmsd")
	assert.Contains(t, errOutput, "xkmsd: server URL is required")
	assert.Contains(t, errOutput, "--xkmsd-url")
	assert.NotContains(t, errOutput, stubConnectMessage)
}

// TestPlatformStoreCLI_Status_UnreachableServer verifies that supplying
// --xkmsd-url really constructs the transport: the failure comes from the
// connection attempt itself, not from a client that was never built.
func TestPlatformStoreCLI_Status_UnreachableServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"platform-store", "status", "--xkmsd-url", unreachableSocketURL(t))

	assert.Contains(t, errOutput, "platform-store: failed to connect to xkmsd")
	assertUnreachableServer(t, errOutput)
}

// TestPlatformStoreCLI_Status_URLFromEnvironment verifies that XKMSD_URL is
// honored when no flag is given: the command reaches the same connection
// attempt as the explicit flag.
func TestPlatformStoreCLI_Status_URLFromEnvironment(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolatePlatformStoreEnv(t)
	t.Setenv("XKMSD_URL", unreachableSocketURL(t))

	errOutput := RunXKeyExpectFailure(t, binary, "", "platform-store", "status")

	assert.Contains(t, errOutput, "platform-store: failed to connect to xkmsd")
	assertUnreachableServer(t, errOutput)
}

// TestPlatformStoreCLI_Status_ConnectionRefused verifies the REST transport
// is selected for https:// URLs and reports the refused TCP connection. An
// http:// URL is refused before dialing (ruling 152).
func TestPlatformStoreCLI_Status_ConnectionRefused(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"platform-store", "status", "--xkmsd-url", "https://127.0.0.1:1")

	assert.Contains(t, errOutput, "platform-store: failed to connect to xkmsd")
	assert.Contains(t, errOutput, "connection refused")
	assert.NotContains(t, errOutput, stubConnectMessage)
}

// TestPlatformStoreCLI_Status_UnsupportedScheme verifies that an unknown URL
// scheme is rejected with the supported-scheme list.
func TestPlatformStoreCLI_Status_UnsupportedScheme(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"platform-store", "status", "--xkmsd-url", "ftp://xkmsd.example.com:21")

	assert.Contains(t, errOutput, "xkmsd: unsupported server URL scheme")
	assert.Contains(t, errOutput, "unix://")
	assert.Contains(t, errOutput, "grpc://")
	assert.NotContains(t, errOutput, stubConnectMessage)
}

// TestPlatformStoreCLI_Status_UnreadableTLSCA verifies that a TLS-bearing
// URL with an unusable CA bundle fails while building the trust material,
// before any connection attempt.
func TestPlatformStoreCLI_Status_UnreadableTLSCA(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"platform-store", "status",
		"--xkmsd-url", "https://127.0.0.1:1",
		"--tls-ca", filepath.Join(xkeyHome, "absent-ca.pem"))

	assert.Contains(t, errOutput, "xkmsd: failed to build TLS configuration")
	assert.Contains(t, errOutput, "absent-ca.pem")
	assert.NotContains(t, errOutput, stubConnectMessage)
}

// TestPlatformStoreCLI_Put_MissingValueAndFile verifies that "put" is
// rejected locally, before any connection attempt, when neither --value
// nor --file is supplied.
func TestPlatformStoreCLI_Put_MissingValueAndFile(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "", "platform-store", "put", "my-secret")

	assert.Contains(t, errOutput, "--value or --file is required")
}

// TestPlatformStoreCLI_Put_ValueAndFileMutuallyExclusive verifies that
// "put" rejects --value and --file being supplied together, before any
// connection attempt.
func TestPlatformStoreCLI_Put_ValueAndFileMutuallyExclusive(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := isolatePlatformStoreEnv(t)

	tempFile := filepath.Join(xkeyHome, "secret-source.txt")
	require.NoError(t, os.WriteFile(tempFile, []byte("file-secret"), 0600))

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"platform-store", "put", "my-secret", "--value", "inline-secret", "--file", tempFile)

	assert.Contains(t, errOutput, "--value and --file are mutually exclusive")
}

// TestPlatformStoreCLI_Put_FileReadFailure verifies that "put --file" with
// a nonexistent source file fails with a clear error before any
// connection attempt.
func TestPlatformStoreCLI_Put_FileReadFailure(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"platform-store", "put", "my-secret", "--file", filepath.Join(xkeyHome, "does-not-exist.txt"))

	assert.Contains(t, errOutput, "platform-store: failed to read file")
}

// TestPlatformStoreCLI_Put_NoXkmsdURL verifies that a well-formed "put"
// invocation reports the missing-endpoint error once flag validation
// passes.
func TestPlatformStoreCLI_Put_NoXkmsdURL(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"platform-store", "put", "my-secret", "--value", "s3cret")

	assert.Contains(t, errOutput, "platform-store: failed to connect to xkmsd")
	assert.Contains(t, errOutput, "xkmsd: server URL is required")
	assert.NotContains(t, errOutput, stubConnectMessage)
}

// TestPlatformStoreCLI_Put_UnreachableServer verifies that "put" against a
// configured but unreachable server reports the transport's connection
// failure.
func TestPlatformStoreCLI_Put_UnreachableServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"platform-store", "put", "my-secret", "--value", "s3cret",
		"--xkmsd-url", unreachableSocketURL(t))

	assert.Contains(t, errOutput, "platform-store: failed to connect to xkmsd")
	assertUnreachableServer(t, errOutput)
}

// TestPlatformStoreCLI_Get_UnreachableServer verifies that "get" reaches the
// transport and reports its connection failure.
func TestPlatformStoreCLI_Get_UnreachableServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"platform-store", "get", "unknown-secret", "--xkmsd-url", unreachableSocketURL(t))

	assert.Contains(t, errOutput, "platform-store: failed to connect to xkmsd")
	assertUnreachableServer(t, errOutput)
}

// TestPlatformStoreCLI_Delete_UnreachableServer verifies that "delete"
// reaches the transport and reports its connection failure.
func TestPlatformStoreCLI_Delete_UnreachableServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"platform-store", "delete", "unknown-secret", "--xkmsd-url", unreachableSocketURL(t))

	assert.Contains(t, errOutput, "platform-store: failed to connect to xkmsd")
	assertUnreachableServer(t, errOutput)
}

// TestPlatformStoreCLI_List_UnreachableServer verifies that "list" reaches
// the transport and reports its connection failure.
func TestPlatformStoreCLI_List_UnreachableServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"platform-store", "list", "--xkmsd-url", unreachableSocketURL(t))

	assert.Contains(t, errOutput, "platform-store: failed to connect to xkmsd")
	assertUnreachableServer(t, errOutput)
}

// TestPlatformStoreCLI_Reseal_MissingNameAndAll verifies that "reseal" is
// rejected locally, before any connection attempt, when neither a name
// argument nor --all is supplied.
func TestPlatformStoreCLI_Reseal_MissingNameAndAll(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "", "platform-store", "reseal")

	assert.Contains(t, errOutput, "secret name is required")
}

// TestPlatformStoreCLI_Reseal_UnreachableServer verifies that a well-formed
// "reseal <name>" invocation reaches the transport and reports its
// connection failure.
func TestPlatformStoreCLI_Reseal_UnreachableServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolatePlatformStoreEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"platform-store", "reseal", "my-secret", "--xkmsd-url", unreachableSocketURL(t))

	assert.Contains(t, errOutput, "platform-store: failed to connect to xkmsd")
	assertUnreachableServer(t, errOutput)
}
