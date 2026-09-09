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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------
// device share-policy
// ---------------------------------------------------------------

// sharePolicyCmd builds a detached command carrying the share-policy flags.
func sharePolicyCmd(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: "share-policy-test"}
	fs := cmd.Flags()
	fs.Bool("allow", false, "")
	fs.Bool("share-public", false, "")
	fs.Bool("share-symmetric", false, "")
	fs.Bool("share-private", false, "")
	fs.StringSlice("devices", nil, "")

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

func TestGetSharePolicyPath_SitsBesideTheDeviceConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	previous := resolvedHome
	resolvedHome = nil
	t.Cleanup(func() { resolvedHome = previous })

	configPath, err := getDevicesConfigPath()
	require.NoError(t, err)

	policyPath, err := getSharePolicyPath()
	require.NoError(t, err)

	assert.Equal(t, filepath.Dir(configPath), filepath.Dir(policyPath),
		"the sharing policy file must live next to the device config")
	assert.Equal(t, sharingPoliciesFileName, filepath.Base(policyPath))
}

// withSharePolicyHome points $HOME at a temp dir and pre-creates ~/.xkey.
//
// The pre-creation is required: FileSharingPolicyStore.SetPolicy writes
// straight to sharing-policies.json without creating its parent directory,
// so on a genuinely fresh install the first `share-policy set` fails with a
// raw ENOENT. See the reported finding.
func withSharePolicyHome(t *testing.T) string {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".xkey"), 0700))

	previous := resolvedHome
	resolvedHome = nil
	t.Cleanup(func() { resolvedHome = previous })
	return home
}

// TestRunSharePolicySet_CreatesTheXKeyHome: the data-dir chain resolves the
// home through xhome, which creates ~/.xkey (0700) when it is absent, so a
// missing home is not a state the command can observe any more. The policy
// lands under the created directory. (This test used to pin the opposite,
// pre-xhome behaviour and had never run in CI, #332.)
func TestRunSharePolicySet_CreatesTheXKeyHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	previous := resolvedHome
	resolvedHome = nil
	t.Cleanup(func() { resolvedHome = previous })

	set, _ := sharePolicyCmd(t)
	require.NoError(t, set.Flags().Set("allow", "true"))
	require.NoError(t, runSharePolicySet(set, []string{"tpm2", "key-abc"}))

	info, err := os.Stat(filepath.Join(home, ".xkey"))
	require.NoError(t, err, "the resolved home is created on first use")
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm(), "the home is private to the user")
	_, err = os.Stat(filepath.Join(home, ".xkey", sharingPoliciesFileName))
	assert.NoError(t, err, "the policy file is written under the created home")
}

// TestRunSharePolicySet_FailsWhenXKeyHomeUnwritable: the one way the store
// can still fail to persist is a home the user cannot write, and that failure
// surfaces as ErrSharePolicySetFailed carrying the permission error, not as a
// silently unsaved policy.
func TestRunSharePolicySet_FailsWhenXKeyHomeUnwritable(t *testing.T) {
	home := withSharePolicyHome(t)
	xkeyHome := filepath.Join(home, ".xkey")
	require.NoError(t, os.Chmod(xkeyHome, 0500))
	t.Cleanup(func() { _ = os.Chmod(xkeyHome, 0700) })

	set, _ := sharePolicyCmd(t)
	require.NoError(t, set.Flags().Set("allow", "true"))

	err := runSharePolicySet(set, []string{"tpm2", "key-abc"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSharePolicySetFailed)
	assert.ErrorIs(t, err, os.ErrPermission,
		"the failure is the unwritable ~/.xkey, not a policy problem")
}

func TestSharePolicy_SetListRemove(t *testing.T) {
	withSharePolicyHome(t)

	list, listBuf := sharePolicyCmd(t)
	require.NoError(t, runSharePolicyList(list, nil))
	assert.Contains(t, listBuf.String(), "No sharing policies configured.")

	set, setBuf := sharePolicyCmd(t)
	require.NoError(t, set.Flags().Set("allow", "true"))
	require.NoError(t, set.Flags().Set("share-public", "true"))
	require.NoError(t, set.Flags().Set("devices", "phone-1,phone-2"))
	require.NoError(t, runSharePolicySet(set, []string{"tpm2", "key-abc"}))

	setOut := setBuf.String()
	assert.Contains(t, setOut, "Sharing policy set for tpm2/key-abc:")
	assert.Contains(t, setOut, "Allow Sharing:     true")
	assert.Contains(t, setOut, "Share Public Key:  true")
	assert.Contains(t, setOut, "Share Private:     false",
		"private-key sharing must stay off unless explicitly requested")
	assert.Contains(t, setOut, "Allowed Devices:   phone-1, phone-2")

	list2, list2Buf := sharePolicyCmd(t)
	require.NoError(t, runSharePolicyList(list2, nil))
	listOut := list2Buf.String()
	assert.Contains(t, listOut, "Sharing Policies (1):")
	assert.Contains(t, listOut, "tpm2")
	assert.Contains(t, listOut, "key-abc")
	assert.Contains(t, listOut, "2 device(s)")

	remove, removeBuf := sharePolicyCmd(t)
	require.NoError(t, runSharePolicyRemove(remove, []string{"tpm2", "key-abc"}))
	assert.Contains(t, removeBuf.String(), "Sharing policy removed for tpm2/key-abc.")

	after, afterBuf := sharePolicyCmd(t)
	require.NoError(t, runSharePolicyList(after, nil))
	assert.Contains(t, afterBuf.String(), "No sharing policies configured.")
}

func TestSharePolicy_SetWithoutDevicesAllowsAnyPairedDevice(t *testing.T) {
	withSharePolicyHome(t)

	set, setBuf := sharePolicyCmd(t)
	require.NoError(t, set.Flags().Set("allow", "true"))
	require.NoError(t, runSharePolicySet(set, []string{"software", "key-xyz"}))
	assert.Contains(t, setBuf.String(), "Allowed Devices:   (any paired device)")

	list, listBuf := sharePolicyCmd(t)
	require.NoError(t, runSharePolicyList(list, nil))
	assert.Contains(t, listBuf.String(), "(any)")
}

func TestRunSharePolicyRemove_UnknownPolicy(t *testing.T) {
	withSharePolicyHome(t)

	cmd, _ := sharePolicyCmd(t)
	err := runSharePolicyRemove(cmd, []string{"tpm2", "absent"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSharePolicyRemoveFailed)
	assert.Contains(t, err.Error(), "no policy found for tpm2/absent")
}

// ---------------------------------------------------------------
// import-data
// ---------------------------------------------------------------

func TestReadImportPassphrase_Piped(t *testing.T) {
	pipeStdin(t, "luks-passphrase\n")

	var buf bytes.Buffer
	got, err := readImportPassphrase(&buf)
	require.NoError(t, err)
	assert.Equal(t, "luks-passphrase", got)
}

func TestReadImportPassphrase_EmptyPipeYieldsEmptyString(t *testing.T) {
	pipeStdin(t, "")

	var buf bytes.Buffer
	got, err := readImportPassphrase(&buf)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestImportDataError_Message(t *testing.T) {
	assert.Equal(t, "import-data: mount", (&ImportDataError{Operation: "mount"}).Error())
	assert.Equal(t, "import-data: mount: busy",
		(&ImportDataError{Operation: "mount", Message: "busy"}).Error())
	assert.Equal(t, "import-data: mount: permission denied",
		(&ImportDataError{Operation: "mount", Err: os.ErrPermission}).Error())
	assert.Equal(t, "import-data: mount: busy: permission denied",
		(&ImportDataError{Operation: "mount", Message: "busy", Err: os.ErrPermission}).Error())
	assert.ErrorIs(t, &ImportDataError{Operation: "x", Err: os.ErrPermission}, os.ErrPermission)
}

// ---------------------------------------------------------------
// usb
// ---------------------------------------------------------------

func TestReadUSBPassphrase_RejectsMismatchedPipedLines(t *testing.T) {
	pipeStdin(t, "one\ntwo\n")

	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})

	_, err := readUSBPassphrase(cmd)
	require.Error(t, err)

	var usbErr *USBCmdError
	require.ErrorAs(t, err, &usbErr)
	assert.Equal(t, "confirm_passphrase", usbErr.Operation)
	assert.Contains(t, err.Error(), "passphrases do not match")
}

func TestReadUSBPassphrase_AcceptsMatchingPipedLines(t *testing.T) {
	pipeStdin(t, "correct-horse\ncorrect-horse\n")

	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})

	got, err := readUSBPassphrase(cmd)
	require.NoError(t, err)
	assert.Equal(t, "correct-horse", got)
}

func TestUSBCmdError_Message(t *testing.T) {
	assert.Equal(t, "usb: create", (&USBCmdError{Operation: "create"}).Error())
	assert.Equal(t, "usb: create: no space",
		(&USBCmdError{Operation: "create", Message: "no space"}).Error())
	assert.Equal(t, "usb: create: permission denied",
		(&USBCmdError{Operation: "create", Err: os.ErrPermission}).Error())
	assert.Equal(t, "usb: create: no space: permission denied",
		(&USBCmdError{Operation: "create", Message: "no space", Err: os.ErrPermission}).Error())
	assert.ErrorIs(t, &USBCmdError{Operation: "x", Err: os.ErrPermission}, os.ErrPermission)
	assert.Nil(t, (&USBCmdError{Operation: "x"}).Unwrap())
}

// ---------------------------------------------------------------
// policy store
// ---------------------------------------------------------------

func TestOpenPolicyStore_RoundTripsThroughDisk(t *testing.T) {
	dir := t.TempDir()

	store, err := openPolicyStore(dir)
	require.NoError(t, err)
	require.NotNil(t, store)

	// A fresh store holds no policies; the listing must succeed rather than
	// erroring on the missing backing file.
	policies, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestOpenPolicyStore_RejectsUnusablePath(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	_, err := openPolicyStore(filepath.Join(blocker, "store"))
	assert.Error(t, err)
}
