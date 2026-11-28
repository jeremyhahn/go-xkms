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
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/authenticator"
)

// The Security Officer PINs these tests establish. They are never asserted on
// in command output: what is checked is that they authorize the SO role, not
// that they appear anywhere. sopinMinLength is 6 bytes.
const (
	testInitSOPIN    = "so-pin-init-1"
	testInitNewSOPIN = "so-pin-init-2"
)

// ---------------------------------------------------------------------------
// Command invocation
// ---------------------------------------------------------------------------

// resetTokenCmdFlags restores the token commands' flags between runs. Cobra
// retains flag state across Execute calls in one process.
func resetTokenCmdFlags() {
	for _, fs := range []*pflag.FlagSet{
		fido2Cmd.Flags(),
		fido2Cmd.PersistentFlags(),
		fido2InitTokenCmd.Flags(),
		fido2ChangeSOPINCmd.Flags(),
	} {
		fs.VisitAll(func(f *pflag.Flag) {
			f.Changed = false
			_ = f.Value.Set(f.DefValue)
		})
	}
}

// runTokenCommand drives the real CLI: root command, real argument parsing, the
// real PIN prompts fed from piped stdin, and the real user-presence handler fed
// from the command's own input stream.
//
// pinLines are consumed by the PIN prompts in order; presence is the answer the
// interactive presence handler reads. They come from different streams because
// the command reads them from different streams — the PIN through the shared
// no-echo PIN reader, presence through the command's input — and a test that
// merged them would not be exercising the wiring the operator meets.
func runTokenCommand(t *testing.T, args []string, pinLines []string, presence string) (string, error) {
	t.Helper()
	resetCommandFlagsForTest(t, RootCmd)

	resetTokenCmdFlags()

	restoreStdin := setPINStdin(strings.NewReader(strings.Join(pinLines, "\n") + "\n"))
	previousTerminal := pinInputIsTerminal
	pinInputIsTerminal = func() bool { return false }
	t.Cleanup(func() {
		restoreStdin()
		pinInputIsTerminal = previousTerminal
	})

	var buf bytes.Buffer
	RootCmd.SetOut(&buf)
	RootCmd.SetErr(&buf)
	RootCmd.SetIn(strings.NewReader(presence))
	t.Cleanup(func() {
		RootCmd.SetOut(os.Stdout)
		RootCmd.SetErr(os.Stderr)
		RootCmd.SetIn(os.Stdin)
		RootCmd.SetArgs(nil)
	})

	RootCmd.SetArgs(append(args, "--socket", absentSocketPath(t)))

	err := RootCmd.Execute()
	return buf.String(), err
}

// runInitToken establishes an SO PIN through the supported CLI path.
func runInitToken(t *testing.T, soPIN string) (string, error) {
	t.Helper()
	return runTokenCommand(t, []string{"fido2", "init-token"}, []string{soPIN, soPIN}, "y\n")
}

// runChangeSOPIN changes the SO PIN through the supported CLI path.
func runChangeSOPIN(t *testing.T, currentPIN, newPIN string) (string, error) {
	t.Helper()
	return runTokenCommand(t,
		[]string{"fido2", "change-so-pin"},
		[]string{currentPIN, newPIN, newPIN},
		"y\n")
}

// soPINAuthenticates reports whether the given PIN unlocks the Security Officer
// role on the device the CLI just wrote.
//
// This is the assertion that matters: IsSet is a boolean anything could set,
// while unlocking proves the SO key hierarchy was actually built under this PIN
// and can be reached with it. It goes through the CTAP vendor command, so it
// also proves the CLI's in-process establishment and the wire path agree on one
// credential.
func soPINAuthenticates(t *testing.T, pin string) bool {
	t.Helper()

	auth, storage := openTestDevice(t)
	defer func() {
		_ = auth.Close()
		_ = storage.Close()
	}()

	_, err := sendVendorCommand(auth, authenticator.VendorCmdUnlockWithSOPIN, map[string]interface{}{
		"pin": pin,
	})
	if err == nil {
		return true
	}
	if errors.Is(err, authenticator.ErrSOPINInvalid) ||
		errors.Is(err, authenticator.ErrTokenUninitialized) ||
		errors.Is(err, authenticator.ErrKeyManagerNoSOPIN) {
		return false
	}
	t.Fatalf("unlock SO: %v", err)
	return false
}

// tokenIsInitialized reports the device's persisted lifecycle state.
func tokenIsInitialized(t *testing.T) bool {
	t.Helper()

	auth, storage := openTestDevice(t)
	defer func() {
		_ = auth.Close()
		_ = storage.Close()
	}()
	return auth.IsTokenInitialized()
}

// ---------------------------------------------------------------------------
// Establishment — the supported path
// ---------------------------------------------------------------------------

// TestInitToken_EstablishesSOPINOnAnUninitializedDevice is the acceptance case
// for #233: before this command existed, InitializeToken had no caller a host
// could reach, so a device stayed permanently uninitialized and every SO-gated
// capability was unreachable. The operator now has one supported path to a
// Security Officer credential.
func TestInitToken_EstablishesSOPINOnAnUninitializedDevice(t *testing.T) {
	newProvisioningDevice(t)

	if tokenIsInitialized(t) {
		t.Fatal("a fresh device reports an initialized token")
	}

	output, err := runInitToken(t, testInitSOPIN)
	if err != nil {
		t.Fatalf("init-token: %v (output: %s)", err, output)
	}

	if !tokenIsInitialized(t) {
		t.Fatal("the token is still uninitialized after init-token reported success")
	}
	if !soPINAuthenticates(t, testInitSOPIN) {
		t.Fatal("the established SO PIN does not unlock the Security Officer role")
	}

	// The state survives the process that wrote it: a Security Officer
	// credential that lived only in memory would leave the daemon refusing every
	// SO-gated operation on the next start.
	if flags := deviceState(t).SOPINManager; flags == nil || !flags.IsSet {
		t.Fatal("the persisted state carries no Security Officer credential")
	}

	if !strings.Contains(output, "initialized") {
		t.Errorf("output does not report the token state, got:\n%s", output)
	}
	// The banner must name the control that actually applied. Reporting the
	// CTAP §6.9 bounds as though they constrained a local operator would be a
	// check that cannot fire, reported as one that held.
	if !strings.Contains(output, "file permissions") {
		t.Errorf("output does not name the enforcing control, got:\n%s", output)
	}
	// The SO PIN is the recovery credential for a forgotten user PIN. It must
	// never be echoed back to a terminal, a log or a transcript.
	if strings.Contains(output, testInitSOPIN) {
		t.Error("the SO PIN appears in the command's output")
	}
}

// TestInitToken_SOPINGatedCapabilityBecomesReachable proves the point of the
// issue rather than the mechanics: an SO-gated vendor command that refused with
// ErrTokenUninitialized before init-token succeeds after it.
func TestInitToken_SOPINGatedCapabilityBecomesReachable(t *testing.T) {
	newProvisioningDevice(t)

	func() {
		auth, storage := openTestDevice(t)
		defer func() {
			_ = auth.Close()
			_ = storage.Close()
		}()
		_, err := sendVendorCommand(auth, authenticator.VendorCmdReplaceAttestKey, nil)
		if !errors.Is(err, authenticator.ErrTokenUninitialized) {
			t.Fatalf("on an uninitialized device replaceAttestKey = %v, want %v",
				err, authenticator.ErrTokenUninitialized)
		}
	}()

	if output, err := runInitToken(t, testInitSOPIN); err != nil {
		t.Fatalf("init-token: %v (output: %s)", err, output)
	}

	auth, storage := openTestDevice(t)
	defer func() {
		_ = auth.Close()
		_ = storage.Close()
	}()
	if _, err := sendVendorCommand(auth, authenticator.VendorCmdUnlockWithSOPIN, map[string]interface{}{
		"pin": testInitSOPIN,
	}); err != nil {
		t.Fatalf("unlock SO after init-token: %v", err)
	}
	if _, err := sendVendorCommand(auth, authenticator.VendorCmdReplaceAttestKey, nil); err != nil {
		t.Fatalf("replaceAttestKey after init-token: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Establishment — refusals
// ---------------------------------------------------------------------------

// TestInitToken_RefusesWhenTokenAlreadyInitialized is the precondition an
// establishment verb must hold: it establishes, it never replaces. A second run
// must not silently rewrite the Security Officer credential — that would let
// anyone with write access to the state directory take the SO role from its
// holder without proving the current PIN.
func TestInitToken_RefusesWhenTokenAlreadyInitialized(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	output, err := runInitToken(t, testInitNewSOPIN)
	if !errors.Is(err, ErrTokenAlreadyInitialized) {
		t.Fatalf("init-token on an initialized token = %v, want %v (output: %s)",
			err, ErrTokenAlreadyInitialized, output)
	}

	// The refusal is settled before the operator is asked for anything. Nobody
	// should choose and confirm a PIN only to be told the device could never
	// have taken it, so the initialization banner must not have been printed.
	if strings.Contains(output, "Record the SO PIN") {
		t.Errorf("the operator was prompted before the refusal, got:\n%s", output)
	}

	// The refusal must have left the credential alone, not merely reported one.
	if !soPINAuthenticates(t, testProvisionSOPIN) {
		t.Error("the original SO PIN no longer unlocks the Security Officer role")
	}
	if soPINAuthenticates(t, testInitNewSOPIN) {
		t.Error("the refused SO PIN unlocks the Security Officer role")
	}
}

// TestInitToken_RefusesAPolicyViolatingPIN proves the length policy is enforced
// on the CLI path, not only on the wire path.
func TestInitToken_RefusesAPolicyViolatingPIN(t *testing.T) {
	newProvisioningDevice(t)

	output, err := runInitToken(t, "12345")
	if !errors.Is(err, authenticator.ErrSOPINPolicyViolation) {
		t.Fatalf("init-token with a short PIN = %v, want %v (output: %s)",
			err, authenticator.ErrSOPINPolicyViolation, output)
	}
	if !errors.Is(err, ErrTokenInitFailed) {
		t.Errorf("error = %v, want it to carry %v", err, ErrTokenInitFailed)
	}
	if tokenIsInitialized(t) {
		t.Error("a refused PIN initialized the token")
	}
}

// TestInitToken_RefusesWhenPresenceIsDenied proves the presence handler is a
// real gate on this path and not an auto-grant standing in for one.
func TestInitToken_RefusesWhenPresenceIsDenied(t *testing.T) {
	newProvisioningDevice(t)

	output, err := runTokenCommand(t,
		[]string{"fido2", "init-token"},
		[]string{testInitSOPIN, testInitSOPIN},
		"n\n")
	if !errors.Is(err, authenticator.ErrUserPresenceDenied) {
		t.Fatalf("init-token with presence denied = %v, want %v (output: %s)",
			err, authenticator.ErrUserPresenceDenied, output)
	}
	if tokenIsInitialized(t) {
		t.Error("the token was initialized although presence was denied")
	}
}

// TestInitToken_RefusesVolatileStorage proves the command does not report a
// Security Officer credential the device will lose when the process exits.
func TestInitToken_RefusesVolatileStorage(t *testing.T) {
	newProvisioningDevice(t)
	viper.Set("fido2.storage", string(FIDO2StorageTypeMemory))

	output, err := runInitToken(t, testInitSOPIN)
	if !errors.Is(err, ErrTokenVolatileStorage) {
		t.Fatalf("init-token on memory storage = %v, want %v (output: %s)",
			err, ErrTokenVolatileStorage, output)
	}
}

// TestInitToken_RefusesWhileTheDaemonIsRunning proves the command does not write
// state the running daemon would overwrite on its next save.
func TestInitToken_RefusesWhileTheDaemonIsRunning(t *testing.T) {
	resetCommandFlagsForTest(t, RootCmd)
	newProvisioningDevice(t)

	socketPath := startFakeFIDO2Daemon(t)

	resetTokenCmdFlags()
	restoreStdin := setPINStdin(strings.NewReader(testInitSOPIN + "\n" + testInitSOPIN + "\n"))
	previousTerminal := pinInputIsTerminal
	pinInputIsTerminal = func() bool { return false }
	t.Cleanup(func() {
		restoreStdin()
		pinInputIsTerminal = previousTerminal
	})

	var buf bytes.Buffer
	RootCmd.SetOut(&buf)
	RootCmd.SetErr(&buf)
	RootCmd.SetIn(strings.NewReader("y\n"))
	t.Cleanup(func() {
		RootCmd.SetOut(os.Stdout)
		RootCmd.SetErr(os.Stderr)
		RootCmd.SetIn(os.Stdin)
		RootCmd.SetArgs(nil)
	})
	RootCmd.SetArgs([]string{"fido2", "init-token", "--socket", socketPath})

	if err := RootCmd.Execute(); !errors.Is(err, ErrFIDO2DaemonRunning) {
		t.Fatalf("init-token with the daemon running = %v, want %v (output: %s)",
			err, ErrFIDO2DaemonRunning, buf.String())
	}
	if tokenIsInitialized(t) {
		t.Error("the token was initialized although the daemon owns the state")
	}
}

// ---------------------------------------------------------------------------
// Change
// ---------------------------------------------------------------------------

// TestChangeSOPIN_ReplacesTheCredentialWithTheCurrentPIN is the successor path:
// after initialization the SO PIN changes only here, and only for whoever
// already holds it.
func TestChangeSOPIN_ReplacesTheCredentialWithTheCurrentPIN(t *testing.T) {
	newProvisioningDevice(t)

	if output, err := runInitToken(t, testInitSOPIN); err != nil {
		t.Fatalf("init-token: %v (output: %s)", err, output)
	}

	output, err := runChangeSOPIN(t, testInitSOPIN, testInitNewSOPIN)
	if err != nil {
		t.Fatalf("change-so-pin: %v (output: %s)", err, output)
	}

	if !soPINAuthenticates(t, testInitNewSOPIN) {
		t.Error("the new SO PIN does not unlock the Security Officer role")
	}
	if soPINAuthenticates(t, testInitSOPIN) {
		t.Error("the replaced SO PIN still unlocks the Security Officer role")
	}
	if strings.Contains(output, testInitNewSOPIN) {
		t.Error("the SO PIN appears in the command's output")
	}
}

// TestChangeSOPIN_RefusesAWrongCurrentPIN proves the change is gated by the
// current credential and that a refused attempt leaves it intact.
func TestChangeSOPIN_RefusesAWrongCurrentPIN(t *testing.T) {
	newProvisioningDevice(t)

	if output, err := runInitToken(t, testInitSOPIN); err != nil {
		t.Fatalf("init-token: %v (output: %s)", err, output)
	}

	output, err := runChangeSOPIN(t, "not-the-so-pin", testInitNewSOPIN)
	if !errors.Is(err, ErrSOPINChangeFailed) {
		t.Fatalf("change-so-pin with a wrong current PIN = %v, want %v (output: %s)",
			err, ErrSOPINChangeFailed, output)
	}

	if !soPINAuthenticates(t, testInitSOPIN) {
		t.Error("the original SO PIN no longer unlocks the Security Officer role")
	}
	if soPINAuthenticates(t, testInitNewSOPIN) {
		t.Error("the refused new SO PIN unlocks the Security Officer role")
	}
}

// TestChangeSOPIN_RefusesAnUninitializedToken proves the two verbs do not
// overlap: change never establishes, so a device with no Security Officer is
// sent to init-token rather than quietly acquiring one here.
func TestChangeSOPIN_RefusesAnUninitializedToken(t *testing.T) {
	newProvisioningDevice(t)

	output, err := runChangeSOPIN(t, testInitSOPIN, testInitNewSOPIN)
	if !errors.Is(err, ErrSOPINChangeUninitialized) {
		t.Fatalf("change-so-pin on an uninitialized token = %v, want %v (output: %s)",
			err, ErrSOPINChangeUninitialized, output)
	}
	if tokenIsInitialized(t) {
		t.Error("change-so-pin initialized the token")
	}
}
