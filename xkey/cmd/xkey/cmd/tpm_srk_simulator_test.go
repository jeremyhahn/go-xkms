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

//go:build tpm_simulator

package cmd

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// testSRKUserPIN is a test-local literal; no real PIN is ever written.
const testSRKUserPIN = "test-user-pin-994"

// writeSRKPINFile writes pin plus a trailing newline to a 0600 file, as a
// systemd credential or an operator's echo would.
func writeSRKPINFile(t *testing.T, pin string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pin")
	require.NoError(t, os.WriteFile(path, []byte(pin+"\n"), 0o600))
	return path
}

// runSRKEnroll runs `xkey tpm srk enroll` with args and stdin and returns
// its output and error.
func runSRKEnroll(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	c := newTPMSRKCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&out)
	c.SetIn(strings.NewReader(stdin))
	c.SetArgs(append([]string{"enroll"}, args...))
	err := c.Execute()
	return out.String(), err
}

// installTPMForSRK points the data dir at a temp dir, so the TPM key store
// is file-backed there, and runs `xkey tpm install` on the simulator with
// no --auth, so the SO PIN is empty.
func installTPMForSRK(t *testing.T) *provisionedSimulator {
	t.Helper()
	t.Setenv("XKEY_DATA_DIR", t.TempDir())
	sim := withProvisionedSimulatorTPM(t)
	setVar(t, &tpmCfg.outputFormat, "text")
	setVar(t, &installHierarchyAuth, "")
	setVar(t, &installPCRBank, "sha256")
	setVar(t, &installGoldenPCRs, "0,7")
	setVar(t, &installPlatformPCRs, "")
	_, _, err := runTPMSubcommand(runTPMInstall)
	require.NoError(t, err)
	return sim
}

// sendOnlyTransport forwards commands to the shared simulator transport and
// never closes it, so a fresh TPM object can open and close over the
// simulator state an earlier TPM object left.
type sendOnlyTransport struct {
	tpm interface {
		Send(command []byte) ([]byte, error)
	}
}

func (s sendOnlyTransport) Send(command []byte) ([]byte, error) {
	return s.tpm.Send(command)
}

// openFreshSRKTPM opens a new TPM object, with the CLI's TPM params (and so
// its key store under the data dir), over the simulator, and routes openTPM
// and openTPMForDevice to it: the separate-process equivalent. No SRK auth
// or attributes carry over from the TPM object that enrolled.
func openFreshSRKTPM(t *testing.T, sim *provisionedSimulator) {
	t.Helper()
	config, err := newTPMConfig("", tpmCfg.useSimulator, ekCertHandleRSA)
	require.NoError(t, err)
	params, storage, err := newTPMParams(config)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, storage.Close()) })
	params.Transport = sendOnlyTransport{tpm: sim.tpm.Transport()}
	fresh, err := xkms.NewTPM2(params)
	if err != nil && !errors.Is(err, xkms.ErrTPMNotInitialized) {
		require.NoError(t, err)
	}
	require.NotNil(t, fresh)
	t.Cleanup(func() { assert.NoError(t, fresh.Close()) })
	shared := newSharedTPM(t, fresh)
	openTPM = func() (xkms.TrustedPlatformModule, error) { return shared, nil }
	openTPMForDevice = func(string) (xkms.TrustedPlatformModule, error) { return shared, nil }
}

// pipeSRKPINStdin makes os.Stdin a pipe carrying input, as `echo pin |
// xkey fido2 --pin-stdin` would, and restores it after the test.
func pipeSRKPINStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString(input)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	saved := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = saved
		assert.NoError(t, r.Close())
	})
}

// setViperForTest sets key for the test and restores it after.
func setViperForTest(t *testing.T, key string, value any) {
	t.Helper()
	prev := viper.Get(key)
	viper.Set(key, value)
	t.Cleanup(func() { viper.Set(key, prev) })
}

// createSRKCredential opens the fido2 tpm2 backend on a fresh TPM object
// and key store, with the Platform SRK PIN resolved the way `xkey fido2`
// resolves it (--pin-file, or --pin-stdin when stdin is not empty), and
// creates one credential key under the Platform SRK.
func createSRKCredential(t *testing.T, sim *provisionedSimulator, pinFile, stdin string) error {
	t.Helper()
	openFreshSRKTPM(t, sim)
	setViperForTest(t, "fido2.pin_file", pinFile)
	setViperForTest(t, "fido2.pin_stdin", stdin != "")
	if stdin != "" {
		pipeSRKPINStdin(t, stdin)
		restore := setPINStdin(strings.NewReader(stdin))
		defer restore()
	}
	cfg := &FIDO2Config{TPMDevice: ""}
	cfg.PlatformSRKPIN, cfg.PlatformSRKPINErr = resolveFIDO2PlatformSRKPIN()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend, err := createFIDO2TPM2KeyBackend(cfg, logger)
	if err != nil {
		return err
	}
	defer func() { assert.NoError(t, backend.Close()) }()
	const coseES256 = -7
	handle, publicKey, err := backend.GenerateCredentialKey(coseES256, []byte("ruling-993-credential"))
	if err != nil {
		return err
	}
	assert.NotEmpty(t, publicKey)
	assert.NotNil(t, handle)
	return nil
}

// srkPolicyRecords lists the records the persistent TPM key store under
// <dataDir>/tpm holds (its file names are content hashes; dot files are the
// store's own format and lock files). `tpm srk enroll` creates no key in it,
// so a record there is the Platform SRK's enrolment policy record.
func srkPolicyRecords(t *testing.T) []string {
	t.Helper()
	var records []string
	root := filepath.Join(os.Getenv("XKEY_DATA_DIR"), "tpm")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && path == root {
			return fs.SkipDir
		}
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && !strings.HasPrefix(d.Name(), ".") {
			records = append(records, path)
		}
		return nil
	})
	require.NoError(t, err)
	return records
}

// TestTPMSRKEnrollPINFileThenFIDO2 is rulings 993 and 994: after `tpm
// install` (no --auth, so an empty SO PIN), `tpm srk enroll --pin-file`
// enrols the Platform SRK and fido2 --backend tpm2, in a fresh process,
// creates a credential with the --pin-file PIN as the Platform SRK auth.
func TestTPMSRKEnrollPINFileThenFIDO2(t *testing.T) {
	sim := installTPMForSRK(t)
	pinFile := writeSRKPINFile(t, testSRKUserPIN)

	out, err := runSRKEnroll(t, "", "--pin-file", pinFile)
	require.NoError(t, err)
	assert.Contains(t, out, "enrolled")
	assert.NotContains(t, out, testSRKUserPIN)

	require.NoError(t, createSRKCredential(t, sim, pinFile, ""))
}

// TestTPMSRKEnrollPINStdin enrols with the user PIN on stdin, and fido2
// reads it from --pin-stdin.
func TestTPMSRKEnrollPINStdin(t *testing.T) {
	sim := installTPMForSRK(t)

	out, err := runSRKEnroll(t, testSRKUserPIN+"\n", "--pin-stdin")
	require.NoError(t, err)
	assert.NotContains(t, out, testSRKUserPIN)

	// After a PCR change only the PIN branch of the SRK policy is open, so
	// the key is created only if --pin-stdin's PIN became the SRK auth.
	update := sha256.Sum256([]byte("kernel-update"))
	require.NoError(t, sim.tpm.ExtendPCR(11, "sha256", update[:]))

	require.NoError(t, createSRKCredential(t, sim, "", testSRKUserPIN+"\n"))
}

// TestTPMSRKEnrollRecordsPolicyAndSurvivesPCRChange is ruling 1008 (1):
// the CLI enrolment records the Platform SRK's enrolment PCR digest in the
// persistent TPM key store, so after a PCR 11 change (a kernel update) a
// child key under the SRK still opens a session.
func TestTPMSRKEnrollRecordsPolicyAndSurvivesPCRChange(t *testing.T) {
	sim := installTPMForSRK(t)
	pinFile := writeSRKPINFile(t, testSRKUserPIN)

	_, err := runSRKEnroll(t, "", "--pin-file", pinFile)
	require.NoError(t, err)
	assert.NotEmpty(t, srkPolicyRecords(t), "enrolment records the Platform SRK policy in the TPM key store")

	update := sha256.Sum256([]byte("kernel-update"))
	require.NoError(t, sim.tpm.ExtendPCR(11, "sha256", update[:]))

	require.NoError(t, createSRKCredential(t, sim, pinFile, ""))
}

// TestTPMSRKEnrollIdempotent: a second enrol reports already enrolled and
// succeeds.
func TestTPMSRKEnrollIdempotent(t *testing.T) {
	installTPMForSRK(t)
	pinFile := writeSRKPINFile(t, testSRKUserPIN)

	_, err := runSRKEnroll(t, "", "--pin-file", pinFile)
	require.NoError(t, err)
	out, err := runSRKEnroll(t, "", "--pin-file", pinFile)
	require.NoError(t, err)
	assert.Contains(t, out, "already enrolled")
}

// TestTPMSRKEnrollFreshOpenIdempotent: enrolling again from a fresh open of
// an already-enrolled TPM (a second process) verifies the PIN and never
// re-creates the SRK; another PIN is refused.
func TestTPMSRKEnrollFreshOpenIdempotent(t *testing.T) {
	sim := installTPMForSRK(t)
	pinFile := writeSRKPINFile(t, testSRKUserPIN)

	_, err := runSRKEnroll(t, "", "--pin-file", pinFile)
	require.NoError(t, err)

	openFreshSRKTPM(t, sim)
	out, err := runSRKEnroll(t, "", "--pin-file", pinFile)
	require.NoError(t, err)
	assert.Contains(t, out, "already enrolled")

	openFreshSRKTPM(t, sim)
	_, err = runSRKEnroll(t, "", "--pin-file", writeSRKPINFile(t, "test-wrong-pin"))
	require.ErrorIs(t, err, ErrTPMSRKEnrolledOtherPIN)

	require.NoError(t, createSRKCredential(t, sim, pinFile, ""))
}

// TestTPMSRKEnrollConcurrentSerializesOnLock covers Codex review 6000753682
// (P1): two first enrolments race on one storage directory. The second blocks
// on the enrolment lock while the first enrols PIN A, then re-probes the SRK
// under the lock and refuses with ErrTPMSRKEnrolledOtherPIN; PIN A survives.
func TestTPMSRKEnrollConcurrentSerializesOnLock(t *testing.T) {
	sim := installTPMForSRK(t)
	pinFile := writeSRKPINFile(t, testSRKUserPIN)
	otherPINFile := writeSRKPINFile(t, "test-other-pin")

	unlock, err := lockSRKEnrollment()
	require.NoError(t, err)
	released := false
	t.Cleanup(func() {
		if !released {
			unlock()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, runErr := runSRKEnroll(t, "", "--pin-file", otherPINFile)
		done <- runErr
	}()

	select {
	case runErr := <-done:
		t.Fatalf("enrolment ran while another process held the enrolment lock: %v", runErr)
	case <-time.After(300 * time.Millisecond):
	}

	// The lock holder enrols first, as the winning process would.
	require.NoError(t, enrollPlatformSRKLocked(io.Discard, testSRKUserPIN, ""))
	unlock()
	released = true

	select {
	case runErr := <-done:
		require.ErrorIs(t, runErr, ErrTPMSRKEnrolledOtherPIN)
	case <-time.After(2 * time.Minute):
		t.Fatal("the second enrolment never acquired the released lock")
	}

	require.NoError(t, createSRKCredential(t, sim, pinFile, ""))
}

// TestTPMSRKEnrollWrongPINFailsFIDO2: fido2 with a PIN other than the
// enrolled one cannot use the Platform SRK.
func TestTPMSRKEnrollWrongPINFailsFIDO2(t *testing.T) {
	sim := installTPMForSRK(t)

	_, err := runSRKEnroll(t, "", "--pin-file", writeSRKPINFile(t, testSRKUserPIN))
	require.NoError(t, err)

	err = createSRKCredential(t, sim, writeSRKPINFile(t, "test-wrong-pin"), "")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "test-wrong-pin")
}
