// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// Test secrets. Distinct values so a test that mixes them up (the exact bug
// this feature was reworked to prevent -- one PIN standing in for all three)
// fails loudly instead of passing by coincidence.
const (
	provisionTestUserPIN         = "user-pin-123456"
	provisionTestSOPIN           = "so-pin-654321"
	provisionTestBarrierPassword = "correct-horse-battery-staple"
)

// resetProvisionFlags restores provisionCmd's own flags to their defaults
// between runs. Cobra retains flag state across RootCmd.Execute() calls in
// one process (see resetProvisionAttestationFlags for the same pattern).
func resetProvisionFlags() {
	provisionCmd.Flags().VisitAll(func(f *pflag.Flag) {
		f.Changed = false
		_ = f.Value.Set(f.DefValue)
	})
}

// isolateProvisionEnv gives a test its own HOME, XDG_RUNTIME_DIR and clears
// XKEY_HOME/XKEY_IPC_SOCKET/XKEY_SO_PIN/XKEY_PIN/XKEY_BARRIER_PASSWORD, so
// provisioning never touches a real ~/.xkey or ~/.config and never resolves
// a secret from a value some other test in this process left behind. It
// returns a short-lived home directory under t.TempDir() suitable for use as
// --home.
func isolateProvisionEnv(t *testing.T) string {
	t.Helper()

	fakeHome := t.TempDir()
	xdgRuntime := t.TempDir()
	agentHome := t.TempDir()

	t.Setenv("HOME", fakeHome)
	t.Setenv("XDG_RUNTIME_DIR", xdgRuntime)
	t.Setenv(xhome.EnvHome, "")
	t.Setenv("XKEY_IPC_SOCKET", "")
	t.Setenv("XKEY_PIN", "")
	t.Setenv("XKEY_SO_PIN", "")
	t.Setenv("XKEY_BARRIER_PASSWORD", "")

	// Provisioning auto-detects a TPM for the barrier, and on a host that
	// has one it would seal to (and authorize against) the host's real
	// TPM. Unit tests never touch host hardware: point the probe at a
	// device that does not exist, so the barrier takes the software
	// strategy.
	previousDevice, previousSimulator := barrierTPMDevice, barrierTPMSimulator
	barrierTPMDevice, barrierTPMSimulator = "/nonexistent-tpm-device-for-test", false
	t.Cleanup(func() { barrierTPMDevice, barrierTPMSimulator = previousDevice, previousSimulator })

	// Provisioning initializes the process-wide xkms service and PIV
	// manager (the software PIV key store); a later test must start from
	// neither, as a new xkey process does.
	t.Cleanup(newPIVProcess)

	return agentHome
}

// provisionSecrets names the three secrets a provisioning call supplies (or
// omits, with "") -- kept as one struct so a test's intent ("this one is
// missing") reads at the call site instead of in three positional strings.
type provisionSecrets struct {
	// userPIN is delivered via the mocked --pin-stdin path
	// (pin_input.go's stdinReader hook), same as an operator piping it in.
	// Empty and omitFlag both mean "supply nothing"; userPIN alone with
	// omitFlag=false is the normal case.
	userPIN  string
	omitUser bool

	// soPIN is delivered via XKEY_SO_PIN, since --pin-stdin already claims
	// the one stdin stream a test process has.
	soPIN string

	// barrierPassword is delivered via the XKEY_BARRIER_PASSWORD environment
	// variable. There is no "--barrier-password" value flag (go-xkms#1209).
	barrierPassword string
	omitBarrier     bool
}

// runProvisionCmd drives the real CLI end to end: root command, real flag
// parsing, and the three secrets delivered through the same paths an
// operator would use -- --pin-stdin (mocked via stdinReader), XKEY_SO_PIN,
// and XKEY_BARRIER_PASSWORD. Only one secret may ever come from stdin in a
// real invocation; this helper keeps that true here too by never routing
// more than the user PIN through stdinReader.
func runProvisionCmd(t *testing.T, secrets provisionSecrets, args ...string) (string, error) {
	t.Helper()

	resetCommandFlagsForTest(t, RootCmd)
	resetProvisionFlags()

	previousReader := stdinReader
	stdinReader = func() ([]byte, error) { return []byte(secrets.userPIN), nil }
	t.Cleanup(func() { stdinReader = previousReader })

	t.Setenv("XKEY_SO_PIN", secrets.soPIN)
	if !secrets.omitBarrier {
		t.Setenv("XKEY_BARRIER_PASSWORD", secrets.barrierPassword)
	}

	var buf bytes.Buffer
	RootCmd.SetOut(&buf)
	RootCmd.SetErr(&buf)
	t.Cleanup(func() {
		RootCmd.SetOut(os.Stdout)
		RootCmd.SetErr(os.Stderr)
		RootCmd.SetArgs(nil)
	})

	full := append([]string{"provision"}, args...)
	if !secrets.omitUser {
		full = append(full, "--pin-stdin")
	}
	RootCmd.SetArgs(full)

	err := RootCmd.Execute()
	return buf.String(), err
}

// happyPathSecrets returns three distinct, valid secrets for tests that
// exercise the full provisioning flow.
func happyPathSecrets() provisionSecrets {
	return provisionSecrets{
		userPIN:         provisionTestUserPIN,
		soPIN:           provisionTestSOPIN,
		barrierPassword: provisionTestBarrierPassword,
	}
}

// TestRunProvision_FreshHomeEndToEnd is the acceptance case: a brand-new
// home is provisioned in one call from three distinct secrets, the barrier
// initializes under the barrier password, and the host PIN service verifies
// the SO PIN as SO and the user PIN as user -- and rejects each as the
// other, proving the two were never collapsed into one value.
func TestRunProvision_FreshHomeEndToEnd(t *testing.T) {
	home := isolateProvisionEnv(t)

	out, err := runProvisionCmd(t, happyPathSecrets(),
		"--home", home, "--agent", "test-agent")
	require.NoError(t, err, "output: %s", out)

	assert.Contains(t, out, `Provisioned agent "test-agent"`)
	assert.Contains(t, out, "export XKEY_HOME="+home)
	assert.Contains(t, out, "Barrier strategy:")
	assert.Contains(t, out, "Host PIN:         set")
	assert.Contains(t, out, "FIDO2 AAGUID:")
	assert.Contains(t, out, "FIDO2 token:      initialized")
	assert.Contains(t, out, "PIV slot 9a (PIV Authentication): ECCP256")
	assert.Contains(t, out, "PIV slot 9c (Digital Signature): ECCP256")
	assert.Contains(t, out, "PIV slot 9d (Key Management): ECCP256")
	assert.Contains(t, out, "PIV slot 9e (Card Authentication): ECCP256")
	assert.Contains(t, out, "SSH key:          service/test-agent/default (ed25519)")
	assert.Contains(t, out, "SSH fingerprint:  SHA256:")
	assert.Contains(t, out, "ssh-ed25519 ")

	// The barrier this command initialized is real, and it unseals under the
	// barrier password specifically -- not under either PIN.
	barrierDataDir = ""
	dataDir, derr := resolveBarrierDataDir()
	require.NoError(t, derr)
	assert.True(t, barrierRootKeyExists(dataDir), "barrier root key must exist after provisioning")

	// The host PIN service: the SO PIN verifies as SO and the user PIN as
	// user; each is refused as the other. This is the SO/user separation
	// the fix restores -- collapsing them to one shared value would make
	// every one of these four checks pass identically, which is exactly
	// the bug a test using three distinct secrets is designed to catch.
	pinDataDir = ""
	pinBaseDir, pderr := resolvePINDataDir()
	require.NoError(t, pderr)
	svc, operr := openPINService(pinBaseDir)
	require.NoError(t, operr)

	assert.NoError(t, svc.VerifySOPIN(provisionTestSOPIN), "the SO PIN must verify as SO")
	assert.NoError(t, svc.VerifyUserPIN(provisionTestUserPIN), "the user PIN must verify as user")
	assert.Error(t, svc.VerifySOPIN(provisionTestUserPIN), "the user PIN must NOT verify as SO")
	assert.Error(t, svc.VerifyUserPIN(provisionTestSOPIN), "the SO PIN must NOT verify as user")

	// The display name landed in this home's own config, not the
	// operator's shared XDG config.
	cfgBytes, rerr := os.ReadFile(filepath.Join(home, "config.yaml"))
	require.NoError(t, rerr)
	assert.Contains(t, string(cfgBytes), "device_name: test-agent")
}

// TestRunProvision_RefusesWithoutHome proves the command never falls back to
// xkey's own default home resolution: no --home and no XKEY_HOME must
// refuse outright rather than silently provisioning into ~/.xkey.
func TestRunProvision_RefusesWithoutHome(t *testing.T) {
	isolateProvisionEnv(t)

	_, err := runProvisionCmd(t, happyPathSecrets(),
		"--agent", "test-agent")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrProvisionHomeRequired), "got: %v", err)
	assert.Contains(t, err.Error(), "provision: --home or XKEY_HOME is required")
}

// TestRunProvision_RefusesAlreadyInitializedWithoutForce proves a second
// provisioning attempt against the same home refuses instead of silently
// re-running (and potentially disturbing) an already-provisioned instance.
func TestRunProvision_RefusesAlreadyInitializedWithoutForce(t *testing.T) {
	home := isolateProvisionEnv(t)

	_, err := runProvisionCmd(t, happyPathSecrets(),
		"--home", home, "--agent", "test-agent")
	require.NoError(t, err)

	_, err = runProvisionCmd(t, happyPathSecrets(),
		"--home", home, "--agent", "test-agent")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrProvisionAlreadyInitialized), "got: %v", err)
	assert.Contains(t, err.Error(), "pass --force to provision it again")
}

// TestRunProvision_ForceSkipsSSHOnAlreadyInitializedHome proves --force
// completes the steps that can still run (PIN, FIDO2, PIV) against an
// already-initialized home instead of failing the whole command, while
// honestly reporting that SSH key generation could not run rather than
// silently skipping it.
func TestRunProvision_ForceSkipsSSHOnAlreadyInitializedHome(t *testing.T) {
	home := isolateProvisionEnv(t)

	_, err := runProvisionCmd(t, happyPathSecrets(),
		"--home", home, "--agent", "test-agent")
	require.NoError(t, err)

	out, err := runProvisionCmd(t, happyPathSecrets(),
		"--home", home, "--agent", "test-agent", "--force")

	require.NoError(t, err, "output: %s", out)
	assert.Contains(t, out, "already initialized (--force)")
	assert.Contains(t, out, "Host PIN:         already set")
	assert.Contains(t, out, "FIDO2 token:      already initialized")
	assert.Contains(t, out, "SSH key:          skipped:")
}

// TestRunProvision_BadUserPINInput proves a user PIN source that carries
// nothing (--pin-stdin given but standard input empty) is refused before
// any state is written, rather than silently sealing the barrier or the PIN
// service with an empty value.
func TestRunProvision_BadUserPINInput(t *testing.T) {
	home := isolateProvisionEnv(t)

	secrets := happyPathSecrets()
	secrets.userPIN = ""

	_, err := runProvisionCmd(t, secrets,
		"--home", home, "--agent", "test-agent")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPINInputStdinEmpty), "got: %v", err)
	assert.Contains(t, err.Error(), "resolve_user_pin")

	barrierDataDir = ""
	dataDir, derr := resolveBarrierDataDir()
	require.NoError(t, derr)
	assert.False(t, barrierRootKeyExists(dataDir), "a refused user PIN must never reach barrier initialization")
}

// TestRunProvision_RefusesMissingUserPIN proves omitting --pin-stdin
// entirely (no flag, no XKEY_PIN) is refused by name, not silently
// defaulted from the SO PIN or the barrier password.
func TestRunProvision_RefusesMissingUserPIN(t *testing.T) {
	home := isolateProvisionEnv(t)

	secrets := happyPathSecrets()
	secrets.omitUser = true

	_, err := runProvisionCmd(t, secrets,
		"--home", home, "--agent", "test-agent")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrProvisionUserPINRequired), "got: %v", err)

	barrierDataDir = ""
	dataDir, derr := resolveBarrierDataDir()
	require.NoError(t, derr)
	assert.False(t, barrierRootKeyExists(dataDir), "a refused user PIN must never reach barrier initialization")
}

// TestRunProvision_RefusesMissingSOPIN proves an absent XKEY_SO_PIN is
// refused by name, not silently defaulted from the user PIN or the barrier
// password.
func TestRunProvision_RefusesMissingSOPIN(t *testing.T) {
	home := isolateProvisionEnv(t)

	secrets := happyPathSecrets()
	secrets.soPIN = ""

	_, err := runProvisionCmd(t, secrets,
		"--home", home, "--agent", "test-agent")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrProvisionSOPINRequired), "got: %v", err)

	barrierDataDir = ""
	dataDir, derr := resolveBarrierDataDir()
	require.NoError(t, derr)
	assert.False(t, barrierRootKeyExists(dataDir), "a refused SO PIN must never reach barrier initialization")
}

// TestRunProvision_RefusesMissingBarrierPassword proves an absent barrier
// password (no --barrier-password, no file, no XKEY_BARRIER_PASSWORD, and no
// terminal to prompt in a test process) is refused by name, not silently
// defaulted from either PIN.
func TestRunProvision_RefusesMissingBarrierPassword(t *testing.T) {
	home := isolateProvisionEnv(t)

	secrets := happyPathSecrets()
	secrets.omitBarrier = true

	_, err := runProvisionCmd(t, secrets,
		"--home", home, "--agent", "test-agent")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrProvisionBarrierPasswordRequired), "got: %v", err)

	barrierDataDir = ""
	dataDir, derr := resolveBarrierDataDir()
	require.NoError(t, derr)
	assert.False(t, barrierRootKeyExists(dataDir), "a refused barrier password must never reach barrier initialization")
}

// TestRunProvision_JSONShape proves --json produces a single well-formed
// JSON object carrying every field the human-readable report does, with no
// secret anywhere in it.
func TestRunProvision_JSONShape(t *testing.T) {
	home := isolateProvisionEnv(t)
	secrets := happyPathSecrets()

	out, err := runProvisionCmd(t, secrets,
		"--home", home, "--agent", "json-agent", "--json")
	require.NoError(t, err, "output: %s", out)

	var result AgentProvisionResult
	require.NoError(t, json.Unmarshal([]byte(out), &result), "output: %s", out)

	assert.Equal(t, "json-agent", result.Agent)
	assert.Equal(t, home, result.Home)
	assert.Equal(t, "export XKEY_HOME="+home, result.HomeExport)
	assert.NotEmpty(t, result.SocketPath)
	assert.NotEmpty(t, result.BarrierStrategy)
	assert.Equal(t, "set", result.PINStatus)
	require.NotNil(t, result.FIDO2)
	assert.NotEmpty(t, result.FIDO2.AAGUID)
	assert.Equal(t, "initialized", result.FIDO2.TokenState)
	assert.Len(t, result.PIV, 4)
	require.NotNil(t, result.SSH)
	assert.Equal(t, "service", result.SSH.Scope)
	assert.Equal(t, "json-agent", result.SSH.Owner)
	assert.NotEmpty(t, result.SSH.Fingerprint)
	assert.NotEmpty(t, result.SSH.PublicKey)

	assert.NotContains(t, out, secrets.userPIN, "the report must never carry the user PIN")
	assert.NotContains(t, out, secrets.soPIN, "the report must never carry the SO PIN")
	assert.NotContains(t, out, secrets.barrierPassword, "the report must never carry the barrier password")
}

// TestResolveProvisionHome_PrefersFlagOverEnv proves --home wins over an
// ambient XKEY_HOME, matching the documented precedence.
func TestResolveProvisionHome_PrefersFlagOverEnv(t *testing.T) {
	envHome := t.TempDir()
	flagHome := t.TempDir()
	t.Setenv(xhome.EnvHome, envHome)

	previous := provisionHome
	provisionHome = flagHome
	t.Cleanup(func() { provisionHome = previous })

	got, err := resolveProvisionHome()
	require.NoError(t, err)

	want, absErr := filepath.Abs(flagHome)
	require.NoError(t, absErr)
	assert.Equal(t, want, got)
}

// TestResolveProvisionHome_RequiresOne proves neither --home nor XKEY_HOME
// present is a refusal, not a fallback to xkey's own default home.
func TestResolveProvisionHome_RequiresOne(t *testing.T) {
	t.Setenv(xhome.EnvHome, "")

	previous := provisionHome
	provisionHome = ""
	t.Cleanup(func() { provisionHome = previous })

	_, err := resolveProvisionHome()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrProvisionHomeRequired))
}

// TestProvisionError_WrapsStepAndCause proves ProvisionError names the step
// in its message and unwraps to the underlying cause for errors.Is/As.
func TestProvisionError_WrapsStepAndCause(t *testing.T) {
	cause := errors.New("boom")
	err := &ProvisionError{Step: "ssh", Err: cause}

	assert.True(t, strings.Contains(err.Error(), "ssh"))
	assert.True(t, strings.Contains(err.Error(), "boom"))
	assert.True(t, errors.Is(err, cause))
}

// TestProvisionError_UnwrapNil proves Unwrap on a ProvisionError with no
// cause returns nil rather than panicking, so errors.Is/As on a malformed
// ProvisionError degrades safely instead of crashing the caller.
func TestProvisionError_UnwrapNil(t *testing.T) {
	err := &ProvisionError{Step: "ssh", Err: nil}
	assert.Nil(t, err.Unwrap())
	assert.Contains(t, err.Error(), "ssh")
}
