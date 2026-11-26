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

// Package xkey provides error-path integration test coverage for the
// server-dependent command groups ("auth", "ca", "cert", "device") when
// no xkmsd server is configured and no XKMSD_URL environment variable is
// set. Each subcommand is verified to fail (or, where the command is
// legitimately local-only, succeed) with a clear, non-panicking,
// deterministic message.
//
// Isolation note: unlike most xkey commands, "xkey auth" and "xkey device"
// resolve their local storage via os.UserHomeDir()/$HOME directly
// (authStoragePath in cmd/xkey/cmd/auth.go, getDevicesConfigPath in
// cmd/xkey/cmd/device.go) rather than through the XKEY_HOME-driven
// pkg/xhome resolver used everywhere else in the CLI. To keep these tests
// hermetic without touching the real host home directory, $HOME is
// overridden alongside XKEY_HOME for those two command groups. See the
// final task report for this as a flagged inconsistency.
package xkey

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateServerCmdEnv sets up a clean, isolated XKEY_HOME and also
// redirects $HOME to the same isolated directory so that commands which
// bypass pkg/xhome and call os.UserHomeDir() directly cannot read or
// write the real host home directory.
func isolateServerCmdEnv(t *testing.T) string {
	t.Helper()

	xkeyHome := SetupCleanEnvironment(t)
	t.Setenv("XKEY_HOME", xkeyHome)
	t.Setenv("HOME", xkeyHome)

	// Clear every ambient xkmsd endpoint source so these tests observe only
	// what they configure themselves.
	t.Setenv("XKMSD_URL", "")
	t.Setenv("XKEY_XKMSD_URL", "")
	t.Setenv("XKMSD_TOKEN", "")
	t.Setenv("XKMSD_TLS_CA", "")

	return xkeyHome
}

// ---------------------------------------------------------------------------
// xkey auth
// ---------------------------------------------------------------------------

// TestServerCmds_AuthStatus_NoServersRegistered verifies that "auth status"
// succeeds against an empty, freshly initialized server registry rather
// than failing outright, since having zero registered servers is a valid
// steady state.
func TestServerCmds_AuthStatus_NoServersRegistered(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	stdout := RunXKeyExpectSuccess(t, binary, "", "auth", "status")

	assert.Contains(t, stdout, "No servers registered.")
}

// TestServerCmds_AuthLogin_MissingServerFlag verifies that "auth login"
// without --server fails with a clear, local validation error before any
// I/O or network activity.
func TestServerCmds_AuthLogin_MissingServerFlag(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "", "auth", "login")

	assert.Contains(t, errOutput, "auth: --server flag is required")
}

// TestServerCmds_AuthLogin_UnregisteredServer verifies that "auth login
// --server <url>" fails with a clear error when the server was never
// registered, without attempting any network connection (the registry
// lookup happens before the SDK client is constructed).
func TestServerCmds_AuthLogin_UnregisteredServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"auth", "login", "--server", "https://xkms.example.invalid:8443")

	assert.Contains(t, errOutput, "auth: failed to look up server")
	assert.NotContains(t, errOutput, "not yet implemented")
}

// TestServerCmds_AuthRegister_MissingServerFlag verifies "auth register"
// without --server fails with a clear local validation error.
func TestServerCmds_AuthRegister_MissingServerFlag(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "", "auth", "register")

	assert.Contains(t, errOutput, "auth: --server flag is required")
}

// TestServerCmds_AuthRegister_UnreachableServer verifies "auth register"
// really dials the server and fails, rather than printing "WebAuthn
// registration not yet implemented" and exiting 0 as it did before the
// ceremony was wired up. Nothing is recorded in the local registry when the
// connection fails.
func TestServerCmds_AuthRegister_UnreachableServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"auth", "register", "--server", "https://127.0.0.1:1", "--username", "tester")

	assert.Contains(t, errOutput, "auth: failed to connect to server")
	assert.NotContains(t, errOutput, "not yet implemented")

	// A failed registration must not leave a server entry behind.
	stdout := RunXKeyExpectSuccess(t, binary, "", "auth", "status")
	assert.Contains(t, stdout, "No servers registered.")
}

// TestServerCmds_AuthRegister_HelpDescribesCeremony verifies the help text
// documents the WebAuthn ceremony and its authenticator requirement instead
// of only describing registry bookkeeping.
func TestServerCmds_AuthRegister_HelpDescribesCeremony(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	stdout := RunXKeyExpectSuccess(t, binary, "", "auth", "register", "--help")

	assert.Contains(t, stdout, "WebAuthn credential")
	assert.Contains(t, stdout, "--username")
	assert.NotContains(t, stdout, "not yet implemented")
}

// TestServerCmds_AuthLogin_HelpDescribesToken verifies "auth login" documents
// that it stores the issued JWT.
func TestServerCmds_AuthLogin_HelpDescribesToken(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	stdout := RunXKeyExpectSuccess(t, binary, "", "auth", "login", "--help")

	assert.Contains(t, stdout, "assertion ceremony")
	assert.Contains(t, stdout, "token store")
	assert.NotContains(t, stdout, "not yet implemented")
}

// ---------------------------------------------------------------------------
// xkey ca
// ---------------------------------------------------------------------------

// TestServerCmds_CAInfo_NoServerConfigured verifies that "ca info" reports
// the missing-endpoint error, naming every way to supply a server, when no
// xkmsd URL is configured.
func TestServerCmds_CAInfo_NoServerConfigured(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "", "ca", "info")

	assert.Contains(t, errOutput, "ca: failed to get CA info")
	assert.Contains(t, errOutput, "xkmsd: server URL is required")
	assert.Contains(t, errOutput, "--xkmsd-url")
	assert.NotContains(t, errOutput, "ca: client not initialized")
}

// TestServerCmds_CAInfo_UnreachableServer verifies that "ca info" against a
// configured but unreachable server really builds and dials the transport,
// surfacing the connection failure rather than a placeholder error.
func TestServerCmds_CAInfo_UnreachableServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := isolateServerCmdEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "", "ca", "info",
		"--xkmsd-url", "unix://"+filepath.Join(xkeyHome, "absent-xkmsd.sock"))

	assert.Contains(t, errOutput, "ca: failed to get CA info")
	assert.Contains(t, errOutput, "xkmsd: failed to connect to server")
	assert.Contains(t, errOutput, "no such file or directory")
	assert.NotContains(t, errOutput, "ca: client not initialized")
}

// TestServerCmds_CABundle_ConnectionRefused verifies that an https:// URL
// selects the REST transport and reports the refused TCP connection.
func TestServerCmds_CABundle_ConnectionRefused(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "", "ca", "bundle",
		"--xkmsd-url", "https://127.0.0.1:1")

	assert.Contains(t, errOutput, "ca: failed to get CA bundle")
	assert.Contains(t, errOutput, "connection refused")
}

// TestServerCmds_CARevoke_UnsupportedScheme verifies that an unknown URL
// scheme is rejected with the supported-scheme list before any dialing.
func TestServerCmds_CARevoke_UnsupportedScheme(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "", "ca", "revoke", "ABC123",
		"--xkmsd-url", "ftp://xkmsd.example.invalid:21")

	assert.Contains(t, errOutput, "ca: failed to revoke certificate")
	assert.Contains(t, errOutput, "xkmsd: unsupported server URL scheme")
	assert.Contains(t, errOutput, "grpcs://")
}

// ---------------------------------------------------------------------------
// xkey cert
// ---------------------------------------------------------------------------

// TestServerCmds_CertShow_NoCertificateInSlot verifies that "cert show"
// fails with a clear "not found" error against a clean, headless PIV file
// store with nothing enrolled in the default slot (9a).
//
// "cert show" reads from local PIV certificate storage (default: software
// backend, file storage) rather than a remote server. The file storage
// path resolves through the shared xkey data-directory chain
// (resolvePIVStoragePath, cmd/xkey/cmd/piv.go) to <XKEY_HOME>/data/piv,
// never a path relative to the process's working directory (go-xkms#929).
// The working directory is changed to an isolated temp directory distinct
// from XKEY_HOME for the duration of this test, so a regression back to a
// cwd-relative default would show up as a missing directory under
// XKEY_HOME rather than a directory left behind in the repository.
func TestServerCmds_CertShow_NoCertificateInSlot(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := isolateServerCmdEnv(t)

	workDir := t.TempDir()
	origWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(workDir))
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	errOutput := RunXKeyExpectFailure(t, binary, "", "cert", "show")

	assert.Contains(t, errOutput, "cert: no certificate found in slot")

	// The command must resolve PIV storage under XKEY_HOME, never under the
	// process's working directory (go-xkms#929).
	_, statErr := os.Stat(filepath.Join(xkeyHome, "data", "piv"))
	assert.NoError(t, statErr, "expected PIV storage under XKEY_HOME's data directory")

	_, cwdStatErr := os.Stat(filepath.Join(workDir, "data", "piv"))
	assert.True(t, os.IsNotExist(cwdStatErr), "PIV storage must not be created relative to the working directory")
}

// ---------------------------------------------------------------------------
// xkey device
// ---------------------------------------------------------------------------

// TestServerCmds_DeviceList_NoPairedDevices verifies that "device list"
// legitimately succeeds with an empty result against a clean, headless
// environment with no paired devices - it never dials a server.
func TestServerCmds_DeviceList_NoPairedDevices(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	stdout := RunXKeyExpectSuccess(t, binary, "", "device", "list")

	assert.Contains(t, stdout, "No paired devices.")
}

// TestServerCmds_DeviceEnroll_NoCertificateAuthority verifies "device enroll"
// fails when no xkmsd certificate authority is configured, instead of writing
// a key plus CSR and reporting an "enrollment request prepared" success as it
// did before the enrollment was completed.
func TestServerCmds_DeviceEnroll_NoCertificateAuthority(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := isolateServerCmdEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"device", "enroll", "--server", "master.example.invalid:9443")

	assert.Contains(t, errOutput, "agent: enrollment requires a reachable xkmsd certificate authority")
	assert.NotContains(t, errOutput, "Enrollment request prepared")

	// No agent key material may be left behind by a refused enrollment.
	_, statErr := os.Stat(filepath.Join(xkeyHome, "data", "agent", "certs", "agent-key.pem"))
	assert.True(t, os.IsNotExist(statErr), "a refused enrollment must not persist an agent key")
}

// TestServerCmds_DeviceEnroll_MissingServer verifies the master address is
// required.
func TestServerCmds_DeviceEnroll_MissingServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "", "device", "enroll")

	assert.Contains(t, errOutput, "device enroll: --server is required")
}

// TestServerCmds_DeviceEnroll_InvalidServer verifies a master address without
// a port is rejected up front.
func TestServerCmds_DeviceEnroll_InvalidServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"device", "enroll", "--server", "master.example.invalid")

	assert.Contains(t, errOutput, "device enroll: --server must be a host:port address")
}

// TestServerCmds_DeviceEnroll_OneTimeCodeFailsClosed verifies a one-time
// enrollment code is refused with an explanation rather than silently
// ignored.
func TestServerCmds_DeviceEnroll_OneTimeCodeFailsClosed(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateServerCmdEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"device", "enroll", "--server", "master.example.invalid:9443", "--code", "ABCD1234")

	assert.Contains(t, errOutput, "device enroll: one-time enrollment codes")
	assert.Contains(t, errOutput, "--xkmsd-url")
}
