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
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/internal/tpmpolicyfake"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// serverTPMPolicies points the tpm policy commands at a fake xkmsd for the
// test and returns it. PCR 7 reads 0xaa.
func serverTPMPolicies(t *testing.T) *tpmpolicyfake.Fake {
	t.Helper()
	fake := &tpmpolicyfake.Fake{}
	fake.SetPCR(7, []byte{0xaa})
	previous := tpmPolicySessionFactory
	tpmPolicySessionFactory = func(*cobra.Command) (*tpmPolicySession, error) {
		svc := services.NewTPMPolicyService()
		svc.SetClient(fake)
		return &tpmPolicySession{svc: svc}, nil
	}
	t.Cleanup(func() { tpmPolicySessionFactory = previous })
	return fake
}

// runTPMPolicyCommand runs a tpm policy command and returns its output.
func runTPMPolicyCommand(t *testing.T, run func(*cobra.Command, []string) error, args ...string) (string, error) {
	t.Helper()
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetContext(context.Background())
	err := run(cmd, args)
	return out.String(), err
}

// withTPMPolicyFlags sets the create/auto-unseal flags for a test.
func withTPMPolicyFlags(t *testing.T, pcrs, bank string, autoUnseal, off bool) {
	t.Helper()
	prevPCRs, prevBank, prevAuto, prevOff := tpmPolicyPCRs, tpmPolicyBank, tpmPolicyAutoUnseal, tpmPolicyOff
	tpmPolicyPCRs, tpmPolicyBank, tpmPolicyAutoUnseal, tpmPolicyOff = pcrs, bank, autoUnseal, off
	t.Cleanup(func() {
		tpmPolicyPCRs, tpmPolicyBank, tpmPolicyAutoUnseal, tpmPolicyOff = prevPCRs, prevBank, prevAuto, prevOff
	})
}

func TestTPMPolicyCreate_ServerModeCapturesAndRenders(t *testing.T) {
	serverTPMPolicies(t)
	withTPMPolicyFlags(t, "7", "sha256", false, false)
	out, err := runTPMPolicyCommand(t, runTPMPolicyCreate, "boot")
	require.NoError(t, err)
	assert.Contains(t, out, "Name:         boot")
	assert.Contains(t, out, "PCRs:         7")
	assert.Contains(t, out, "aa")
}

func TestTPMPolicyCreate_RequiresValidPCRs(t *testing.T) {
	serverTPMPolicies(t)
	withTPMPolicyFlags(t, "", "sha256", false, false)
	_, err := runTPMPolicyCommand(t, runTPMPolicyCreate, "boot")
	assert.ErrorIs(t, err, ErrTPMPolicyPCRsRequired)

	withTPMPolicyFlags(t, "7-x", "sha256", false, false)
	_, err = runTPMPolicyCommand(t, runTPMPolicyCreate, "boot")
	assert.ErrorIs(t, err, ErrInvalidPCRIndices)
}

func TestTPMPolicyCreate_AutoUnsealOnServerSetsTheMark(t *testing.T) {
	serverTPMPolicies(t)
	withTPMPolicyFlags(t, "7", "sha256", true, false)
	withTPMOutputFormat(t, "json")
	out, err := runTPMPolicyCommand(t, runTPMPolicyCreate, "boot")
	require.NoError(t, err)
	var p services.TPMPolicyInfo
	require.NoError(t, json.Unmarshal([]byte(out), &p))
	assert.True(t, p.AutoUnseal)
}

func TestTPMPolicyList_ShowsPlatformAndObjectCounts(t *testing.T) {
	fake := serverTPMPolicies(t)
	withTPMPolicyFlags(t, "7", "sha256", false, false)
	_, err := runTPMPolicyCommand(t, runTPMPolicyCreate, "boot")
	require.NoError(t, err)
	fake.Assign("", "key", "k1", "boot")

	out, err := runTPMPolicyCommand(t, runTPMPolicyList)
	require.NoError(t, err)
	assert.Contains(t, out, "Source: xkmsd")
	assert.Contains(t, out, "platform PCR or password")
	assert.Regexp(t, `boot\s+sha256\s+7\s+yes\s+no\s+1`, out)

	withTPMOutputFormat(t, "json")
	out, err = runTPMPolicyCommand(t, runTPMPolicyList)
	require.NoError(t, err)
	var policies []services.TPMPolicyInfo
	require.NoError(t, json.Unmarshal([]byte(out), &policies))
	require.Len(t, policies, 2)
	assert.True(t, policies[0].Builtin)
}

func TestTPMPolicyGetUpdateRevoke(t *testing.T) {
	fake := serverTPMPolicies(t)
	withTPMPolicyFlags(t, "7", "sha256", false, false)
	_, err := runTPMPolicyCommand(t, runTPMPolicyCreate, "boot")
	require.NoError(t, err)

	out, err := runTPMPolicyCommand(t, runTPMPolicyGet, "boot")
	require.NoError(t, err)
	assert.Contains(t, out, "Approved:     yes")

	fake.SetPCR(7, []byte{0xbb})
	out, err = runTPMPolicyCommand(t, runTPMPolicyUpdate, "boot")
	require.NoError(t, err)
	assert.Contains(t, out, "bb")

	out, err = runTPMPolicyCommand(t, runTPMPolicyRevoke, "boot")
	require.NoError(t, err)
	assert.Contains(t, out, "Approved:     no")

	_, err = runTPMPolicyCommand(t, runTPMPolicyGet, "missing")
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
}

func TestTPMPolicyVerify_FailsWhenThePlatformChanged(t *testing.T) {
	fake := serverTPMPolicies(t)
	withTPMPolicyFlags(t, "7", "sha256", false, false)
	_, err := runTPMPolicyCommand(t, runTPMPolicyCreate, "boot")
	require.NoError(t, err)

	out, err := runTPMPolicyCommand(t, runTPMPolicyVerify, "boot")
	require.NoError(t, err)
	assert.Contains(t, out, "PCRs match")

	fake.SetPCR(7, []byte{0xcc})
	out, err = runTPMPolicyCommand(t, runTPMPolicyVerify, "boot")
	assert.ErrorIs(t, err, ErrTPMPolicyNotSatisfied)
	assert.Contains(t, out, "PCRs changed: 7")
}

func TestTPMPolicyDelete_RefusedWhileObjectsAreBound(t *testing.T) {
	fake := serverTPMPolicies(t)
	withTPMPolicyFlags(t, "7", "sha256", false, false)
	_, err := runTPMPolicyCommand(t, runTPMPolicyCreate, "boot")
	require.NoError(t, err)
	fake.Assign("", "key", "k1", "boot")
	fake.Assign("", "key", "k2", "boot")

	_, err = runTPMPolicyCommand(t, runTPMPolicyDelete, "boot")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key/k1, key/k2")

	out, err := runTPMPolicyCommand(t, runTPMPolicyObjects, "boot")
	require.NoError(t, err)
	assert.Equal(t, "key/k1\nkey/k2\n", out)

	serverTPMPolicies(t)
	withTPMPolicyFlags(t, "7", "sha256", false, false)
	_, err = runTPMPolicyCommand(t, runTPMPolicyCreate, "unused")
	require.NoError(t, err)
	out, err = runTPMPolicyCommand(t, runTPMPolicyObjects, "unused")
	require.NoError(t, err)
	assert.Contains(t, out, "No objects are bound")
	out, err = runTPMPolicyCommand(t, runTPMPolicyDelete, "unused")
	require.NoError(t, err)
	assert.Contains(t, out, `Deleted TPM policy "unused"`)
}

func TestTPMPolicyKey(t *testing.T) {
	fake := serverTPMPolicies(t)
	fake.Assign("", "key", "k1", "")
	out, err := runTPMPolicyCommand(t, runTPMPolicyKey, "k1")
	require.NoError(t, err)
	assert.Contains(t, out, "Policy:     platform")

	_, err = runTPMPolicyCommand(t, runTPMPolicyKey, "k9")
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotAssigned)
}

func TestTPMPolicyAutoUnseal_ServerMarksAndClears(t *testing.T) {
	serverTPMPolicies(t)
	withTPMPolicyFlags(t, "7", "sha256", false, false)
	_, err := runTPMPolicyCommand(t, runTPMPolicyCreate, "boot")
	require.NoError(t, err)

	out, err := runTPMPolicyCommand(t, runTPMPolicyAutoUnseal, "boot")
	require.NoError(t, err)
	assert.Contains(t, out, `"boot" is the auto-unseal policy`)

	withTPMPolicyFlags(t, "", "", false, true)
	out, err = runTPMPolicyCommand(t, runTPMPolicyAutoUnseal)
	require.NoError(t, err)
	assert.Contains(t, out, `"boot" is no longer the auto-unseal policy`)

	out, err = runTPMPolicyCommand(t, runTPMPolicyAutoUnseal)
	require.NoError(t, err)
	assert.Contains(t, out, "No TPM policy is the auto-unseal policy")
}

func TestTPMPolicyAutoUnseal_NeedsNameOrOff(t *testing.T) {
	serverTPMPolicies(t)
	withTPMPolicyFlags(t, "", "", false, false)
	_, err := runTPMPolicyCommand(t, runTPMPolicyAutoUnseal)
	assert.ErrorIs(t, err, ErrTPMPolicyAutoUnsealName)

	withTPMPolicyFlags(t, "", "", false, true)
	_, err = runTPMPolicyCommand(t, runTPMPolicyAutoUnseal, "boot")
	assert.ErrorIs(t, err, ErrTPMPolicyAutoUnsealName)
}

func TestTPMAuthorityRotate(t *testing.T) {
	serverTPMPolicies(t)
	out, err := runTPMPolicyCommand(t, runTPMAuthorityRotate)
	require.NoError(t, err)
	assert.Contains(t, out, "Generation: 2")
}

func TestTPMPolicyCommands_SessionErrorsPropagate(t *testing.T) {
	errOpen := errors.New("no tpm here")
	previous := tpmPolicySessionFactory
	tpmPolicySessionFactory = func(*cobra.Command) (*tpmPolicySession, error) { return nil, errOpen }
	t.Cleanup(func() { tpmPolicySessionFactory = previous })

	_, err := runTPMPolicyCommand(t, runTPMPolicyList)
	assert.ErrorIs(t, err, errOpen)
	_, err = runTPMPolicyCommand(t, runTPMAuthorityRotate)
	assert.ErrorIs(t, err, errOpen)
}

func TestOpenLocalTPMPolicies_FailsWithoutATPM(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := openLocalTPMPolicies(logger, t.TempDir(), filepath.Join(t.TempDir(), "no-such-tpm"), false)
	assert.ErrorIs(t, err, ErrLocalTPMPoliciesOpenFailed)
}

func TestTryBarrierPolicyAutoUnseal_FailsWithoutATPM(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	barrierSvc := services.NewBarrierService(t.TempDir(), logger)
	unsealed, closer, err := tryBarrierPolicyAutoUnseal(context.Background(), logger, barrierSvc, t.TempDir(),
		xkms.StrategyPassphrase, filepath.Join(t.TempDir(), "no-such-tpm"), false)
	assert.False(t, unsealed)
	assert.Nil(t, closer)
	assert.ErrorIs(t, err, ErrLocalTPMPoliciesOpenFailed)
}

func TestOpenEngineStore(t *testing.T) {
	store, err := openEngineStore(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), "k", []byte("v")))
	require.NoError(t, store.Close())

	_, err = openEngineStore("")
	assert.Error(t, err, "a store needs a directory")
}

func TestTPMPolicySession_CloseWithoutCloser(t *testing.T) {
	assert.NoError(t, (&tpmPolicySession{}).Close())
}

func TestOpenTPMPolicySession_ServerModeCallsTheServer(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, _ := startTestXKMSd(t)
	xkmsdURL = address

	// The harness server has no TPM policy service, so it answers "not
	// configured" -- which proves the command reached it over the transport.
	_, err := runTPMPolicyCommand(t, runTPMPolicyList)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not configured")
}

func TestOpenTPMPolicySession_UnreachableServer(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, cleanup := startTestXKMSd(t)
	xkmsdURL = address
	cleanup()

	_, err := runTPMPolicyCommand(t, runTPMPolicyList)
	assert.ErrorIs(t, err, ErrTPMPolicyServerConnect)
}

func TestOpenTPMPolicySession_LocalModeWithoutATPM(t *testing.T) {
	isolateXKMSdEndpoint(t)
	t.Setenv("XKEY_DATA_DIR", t.TempDir())
	previous := tpmCfg.device
	tpmCfg.device = filepath.Join(t.TempDir(), "no-such-tpm")
	t.Cleanup(func() { tpmCfg.device = previous })

	_, err := runTPMPolicyCommand(t, runTPMPolicyList)
	assert.ErrorIs(t, err, ErrLocalTPMPoliciesOpenFailed)
}
