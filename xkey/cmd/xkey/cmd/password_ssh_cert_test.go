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
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// ---------------------------------------------------------------
// password
// ---------------------------------------------------------------

// passwordTestCmd builds a detached command wired to a temp password store.
func passwordTestCmd(t *testing.T) (*cobra.Command, *bytes.Buffer, string) {
	t.Helper()

	store := t.TempDir()

	cmd := &cobra.Command{Use: "password-test"}
	fs := cmd.Flags()
	fs.String("store", store, "")
	fs.Bool("show-passwords", false, "")
	fs.Bool("force", false, "")
	// These cases exercise the on-disk store, so they name it explicitly
	// rather than depending on whether a daemon happens to be running.
	fs.String("socket", "", "")
	fs.String("source", sourceDisk, "")

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf, store
}

// addTestPassword writes a password directly into the store.
func addTestPassword(t *testing.T, storePath string, pw *xkms.StaticPassword) {
	t.Helper()

	store, err := openPasswordStore(storePath)
	require.NoError(t, err)
	require.NoError(t, store.Add(pw))
	require.NoError(t, store.Close())
}

func samplePassword(name string) *xkms.StaticPassword {
	return &xkms.StaticPassword{
		Name:     name,
		Title:    name + " title",
		Username: "alice",
		Password: "s3cr3t-value",
		URL:      "https://example.com",
		Notes:    "rotate quarterly",
	}
}

func TestRunPasswordList_EmptyStore(t *testing.T) {
	cmd, buf, _ := passwordTestCmd(t)

	require.NoError(t, runPasswordList(cmd, nil))
	assert.Contains(t, buf.String(), "No passwords found.")
}

func TestRunPasswordList_MasksSecretsByDefault(t *testing.T) {
	cmd, buf, store := passwordTestCmd(t)
	addTestPassword(t, store, samplePassword("DatabaseProd"))

	require.NoError(t, runPasswordList(cmd, nil))
	out := buf.String()

	assert.Contains(t, out, "Static Passwords (1):")
	assert.Contains(t, out, "Name:       DatabaseProd")
	assert.Contains(t, out, "Username:   alice")
	assert.Contains(t, out, "URL:        https://example.com")
	assert.Contains(t, out, "Notes:      rotate quarterly")
	assert.Contains(t, out, "Password:   ********")
	assert.NotContains(t, out, "s3cr3t-value",
		"a listing must never print stored passwords without --show-passwords")
}

func TestRunPasswordList_ShowPasswordsRevealsSecret(t *testing.T) {
	cmd, buf, store := passwordTestCmd(t)
	addTestPassword(t, store, samplePassword("DatabaseProd"))
	require.NoError(t, cmd.Flags().Set("show-passwords", "true"))

	require.NoError(t, runPasswordList(cmd, nil))
	assert.Contains(t, buf.String(), "Password:   s3cr3t-value")
}

func TestRunPasswordGet_RequiresName(t *testing.T) {
	cmd, _, _ := passwordTestCmd(t)
	assert.ErrorIs(t, runPasswordGet(cmd, nil), ErrPasswordMissingGetArg)
}

func TestRunPasswordGet_PrintsBareSecretForPiping(t *testing.T) {
	cmd, buf, store := passwordTestCmd(t)
	addTestPassword(t, store, samplePassword("DatabaseProd"))

	require.NoError(t, runPasswordGet(cmd, []string{"DatabaseProd"}))
	assert.Equal(t, "s3cr3t-value", buf.String(),
		"get must emit only the secret so it can be piped without post-processing")
}

func TestRunPasswordGet_UnknownName(t *testing.T) {
	cmd, _, _ := passwordTestCmd(t)

	err := runPasswordGet(cmd, []string{"absent"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPasswordGetFailed)
}

func TestRunPasswordRemove_RequiresName(t *testing.T) {
	cmd, _, _ := passwordTestCmd(t)
	assert.ErrorIs(t, runPasswordRemove(cmd, nil), ErrPasswordMissingRemoveArg)
}

func TestRunPasswordRemove_ForceDeletes(t *testing.T) {
	cmd, buf, store := passwordTestCmd(t)
	addTestPassword(t, store, samplePassword("DatabaseProd"))
	require.NoError(t, cmd.Flags().Set("force", "true"))

	require.NoError(t, runPasswordRemove(cmd, []string{"DatabaseProd"}))
	assert.Contains(t, buf.String(), "Removed: DatabaseProd")

	listCmd, listBuf, _ := passwordTestCmd(t)
	require.NoError(t, listCmd.Flags().Set("store", store))
	require.NoError(t, runPasswordList(listCmd, nil))
	assert.Contains(t, listBuf.String(), "No passwords found.")
}

func TestRunPasswordRemove_DeclinedConfirmationKeepsPassword(t *testing.T) {
	cmd, buf, store := passwordTestCmd(t)
	addTestPassword(t, store, samplePassword("DatabaseProd"))
	pipeStdin(t, "n\n")

	require.NoError(t, runPasswordRemove(cmd, []string{"DatabaseProd"}))
	out := buf.String()
	assert.Contains(t, out, "Remove password 'DatabaseProd'? [y/N]: ")
	assert.Contains(t, out, "Skipped DatabaseProd")

	listCmd, listBuf, _ := passwordTestCmd(t)
	require.NoError(t, listCmd.Flags().Set("store", store))
	require.NoError(t, runPasswordList(listCmd, nil))
	assert.Contains(t, listBuf.String(), "DatabaseProd")
}

func TestRunPasswordRemove_ConfirmedDeletion(t *testing.T) {
	cmd, buf, store := passwordTestCmd(t)
	addTestPassword(t, store, samplePassword("DatabaseProd"))
	pipeStdin(t, "yes\n")

	require.NoError(t, runPasswordRemove(cmd, []string{"DatabaseProd"}))
	assert.Contains(t, buf.String(), "Removed: DatabaseProd")

	listCmd, listBuf, _ := passwordTestCmd(t)
	require.NoError(t, listCmd.Flags().Set("store", store))
	require.NoError(t, runPasswordList(listCmd, nil))
	assert.Contains(t, listBuf.String(), "No passwords found.")
}

func TestRunPasswordRemove_UnknownNameIsSkippedNotFatal(t *testing.T) {
	cmd, buf, store := passwordTestCmd(t)
	addTestPassword(t, store, samplePassword("DatabaseProd"))
	require.NoError(t, cmd.Flags().Set("force", "true"))

	require.NoError(t, runPasswordRemove(cmd, []string{"absent", "DatabaseProd"}))
	assert.Contains(t, buf.String(), "Removed: DatabaseProd")
}

func TestRunPasswordType_RequiresName(t *testing.T) {
	cmd, _, _ := passwordTestCmd(t)
	assert.ErrorIs(t, runPasswordType(cmd, nil), ErrPasswordMissingTypeArg)
}

func TestPasswordStoreError_Message(t *testing.T) {
	assert.Equal(t, "password: add", (&PasswordStoreError{Operation: "add"}).Error())
	assert.Equal(t, "password: add: duplicate",
		(&PasswordStoreError{Operation: "add", Message: "duplicate"}).Error())
	assert.Equal(t, "password: add: permission denied",
		(&PasswordStoreError{Operation: "add", Err: os.ErrPermission}).Error())
	assert.Equal(t, "password: add: duplicate: permission denied",
		(&PasswordStoreError{Operation: "add", Message: "duplicate", Err: os.ErrPermission}).Error())
	assert.ErrorIs(t, &PasswordStoreError{Operation: "add", Err: os.ErrPermission}, os.ErrPermission)
}

// ---------------------------------------------------------------
// ssh profiles
// ---------------------------------------------------------------

// sshProfileCmd builds a detached command carrying the profile flags.
func newSSHProfileTestCmd(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: "ssh-profile-test"}
	fs := cmd.Flags()
	for _, name := range []string{
		"name", "host", "folder", "user", "key", "key-scope", "key-owner",
		"notes", "key-source", "ssh-config-alias", "identity",
	} {
		fs.String(name, "", "")
	}
	fs.Int("port", 0, "")
	fs.Bool("persist-session", false, "")

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

func TestRunSSHProfileAdd_RequiresNameAndTarget(t *testing.T) {
	withCLIHome(t)

	cmd, _ := newSSHProfileTestCmd(t)
	err := runSSHProfileAdd(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--name and (--host or --ssh-config-alias) are required")

	require.NoError(t, cmd.Flags().Set("name", "bastion"))
	err = runSSHProfileAdd(cmd, nil)
	require.Error(t, err, "a profile with no host and no ssh-config alias points nowhere")
}

func TestSSHProfiles_AddListGetMoveRemove(t *testing.T) {
	withCLIHome(t)

	add, addBuf := newSSHProfileTestCmd(t)
	require.NoError(t, add.Flags().Set("name", "bastion"))
	require.NoError(t, add.Flags().Set("host", "bastion.example.com"))
	require.NoError(t, add.Flags().Set("user", "alice"))
	require.NoError(t, add.Flags().Set("port", "2222"))
	require.NoError(t, add.Flags().Set("key", "laptop"))
	require.NoError(t, add.Flags().Set("notes", "jump host"))
	require.NoError(t, runSSHProfileAdd(add, nil))
	assert.Contains(t, addBuf.String(), `Added SSH profile "bastion" (bastion.example.com)`)

	list, listBuf := newSSHProfileTestCmd(t)
	require.NoError(t, runSSHProfileList(list, nil))
	listOut := listBuf.String()
	assert.Contains(t, listOut, "bastion")
	assert.Contains(t, listOut, "alice@bastion.example.com:2222")
	assert.Contains(t, listOut, "key=laptop")

	get, getBuf := newSSHProfileTestCmd(t)
	require.NoError(t, runSSHProfileGet(get, []string{"bastion"}))
	getOut := getBuf.String()
	assert.Contains(t, getOut, "Name: bastion")
	assert.Contains(t, getOut, "Host: bastion.example.com")
	assert.Contains(t, getOut, "Port: 2222")
	assert.Contains(t, getOut, "Notes: jump host")

	move, moveBuf := newSSHProfileTestCmd(t)
	require.NoError(t, move.Flags().Set("folder", "prod"))
	require.NoError(t, runSSHProfileMove(move, []string{"bastion"}))
	assert.Contains(t, moveBuf.String(), `Moved "bastion" to "prod"`)

	byFolder, byFolderBuf := newSSHProfileTestCmd(t)
	require.NoError(t, byFolder.Flags().Set("folder", "prod"))
	require.NoError(t, runSSHProfileList(byFolder, nil))
	assert.Contains(t, byFolderBuf.String(), "bastion")

	remove, removeBuf := newSSHProfileTestCmd(t)
	require.NoError(t, runSSHProfileRemove(remove, []string{"bastion"}))
	assert.Contains(t, removeBuf.String(), `Deleted SSH profile "bastion"`)

	after, afterBuf := newSSHProfileTestCmd(t)
	require.NoError(t, runSSHProfileList(after, nil))
	assert.Contains(t, afterBuf.String(), "No SSH profiles found")
}

func TestRunSSHProfileAdd_LocalIdentityImpliesLocalKeySource(t *testing.T) {
	withCLIHome(t)

	add, _ := newSSHProfileTestCmd(t)
	require.NoError(t, add.Flags().Set("name", "legacy"))
	require.NoError(t, add.Flags().Set("host", "legacy.example.com"))
	require.NoError(t, add.Flags().Set("identity", "~/.ssh/id_ed25519"))
	require.NoError(t, runSSHProfileAdd(add, nil))

	store, err := xkeyProfileStore()
	require.NoError(t, err)
	p, err := store.Get("legacy")
	require.NoError(t, err)
	assert.Equal(t, "local", p.KeySource,
		"a local identity file must default the key source to the local agent")
	assert.Equal(t, "local", p.KeyOwner,
		"an unset --key-owner must default to local rather than an empty owner")
	assert.Equal(t, "~/.ssh/id_ed25519", p.LocalIdentity)
}

// TestRunSSHProfileAdd_SSHConfigAliasWithoutHostIsRejectedByTheStore records
// a contract mismatch: the CLI accepts --ssh-config-alias in place of --host,
// but the profile store still requires a host and rejects the profile with
// its own error. See the reported finding.
func TestRunSSHProfileAdd_SSHConfigAliasWithoutHostIsRejectedByTheStore(t *testing.T) {
	withCLIHome(t)

	add, _ := newSSHProfileTestCmd(t)
	require.NoError(t, add.Flags().Set("name", "legacy"))
	require.NoError(t, add.Flags().Set("ssh-config-alias", "legacy-host"))

	err := runSSHProfileAdd(add, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "host is required")

	store, err := xkeyProfileStore()
	require.NoError(t, err)
	_, err = store.Get("legacy")
	assert.Error(t, err, "a rejected add must not leave a partial profile behind")
}

func TestRunSSHProfileGet_UnknownProfile(t *testing.T) {
	withCLIHome(t)

	cmd, _ := newSSHProfileTestCmd(t)
	assert.Error(t, runSSHProfileGet(cmd, []string{"absent"}))
}

func TestRunSSHProfileMove_RequiresFolder(t *testing.T) {
	withCLIHome(t)

	cmd, _ := newSSHProfileTestCmd(t)
	err := runSSHProfileMove(cmd, []string{"bastion"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--folder is required")
}

func TestXKeyHostKeyStore_OpensUnderResolvedHome(t *testing.T) {
	withCLIHome(t)

	store, err := xkeyHostKeyStore()
	require.NoError(t, err)
	require.NotNil(t, store)
}

// ---------------------------------------------------------------
// cert (file-backed PIV storage)
// ---------------------------------------------------------------

// certTestCmd builds a detached command carrying the cert flags.
func certTestCmd(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: "cert-test"}
	fs := cmd.Flags()
	for _, name := range []string{"server", "cn", "slot", "spki-pin", "profile", "file"} {
		fs.String(name, "", "")
	}
	fs.Int("validity-days", 0, "")

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

func TestRunCertShow_MissingCertificate(t *testing.T) {
	withFilePIVStorage(t)

	cmd, _ := certTestCmd(t)
	require.NoError(t, cmd.Flags().Set("slot", string(xkms.PIVSlotAuthentication)))

	err := runCertShow(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertNotFound)
}

func TestRunCertShow_RendersStoredCertificate(t *testing.T) {
	withFilePIVStorage(t)

	storage, err := createPIVStorage(buildPIVConfig(), slog.Default())
	require.NoError(t, err)
	require.NoError(t, storage.Store(xkms.PIVSlotAuthentication, pivTestCert(t, "client-cert")))
	require.NoError(t, storage.Close())

	cmd, buf := certTestCmd(t)
	require.NoError(t, cmd.Flags().Set("slot", string(xkms.PIVSlotAuthentication)))
	require.NoError(t, runCertShow(cmd, nil))

	out := buf.String()
	assert.Contains(t, out, "Client Certificate - Slot")
	assert.Contains(t, out, "client-cert")
	assert.Contains(t, out, "Serial Number: 42")
	assert.Contains(t, out, "Key Algorithm: ECDSA")
	assert.Contains(t, out, "DNS Names:     piv.example.com")
	assert.Contains(t, out, "Key Usage:")
	assert.Contains(t, out, "Is CA:         false")
	assert.Contains(t, out, "Status:        VALID")
}

func TestRunCertShow_RejectsInvalidSlot(t *testing.T) {
	withFilePIVStorage(t)

	cmd, _ := certTestCmd(t)
	require.NoError(t, cmd.Flags().Set("slot", "zz"))
	assert.Error(t, runCertShow(cmd, nil))
}

func TestRunCertExport_RequiresFile(t *testing.T) {
	withFilePIVStorage(t)

	cmd, _ := certTestCmd(t)
	require.NoError(t, cmd.Flags().Set("slot", string(xkms.PIVSlotAuthentication)))
	assert.ErrorIs(t, runCertExport(cmd, nil), ErrCertFileRequired)
}

func TestRunCertExport_WritesPrivatePEM(t *testing.T) {
	withFilePIVStorage(t)

	storage, err := createPIVStorage(buildPIVConfig(), slog.Default())
	require.NoError(t, err)
	require.NoError(t, storage.Store(xkms.PIVSlotAuthentication, pivTestCert(t, "exported-cert")))
	require.NoError(t, storage.Close())

	target := filepath.Join(t.TempDir(), "client.pem")
	cmd, buf := certTestCmd(t)
	require.NoError(t, cmd.Flags().Set("slot", string(xkms.PIVSlotAuthentication)))
	require.NoError(t, cmd.Flags().Set("file", target))

	require.NoError(t, runCertExport(cmd, nil))
	assert.Contains(t, buf.String(), "Certificate exported from slot")
	assert.Contains(t, buf.String(), "exported-cert")

	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)

	parsed, err := parsePEMCertificate(data)
	require.NoError(t, err)
	assert.Equal(t, "exported-cert", parsed.Subject.CommonName)
}

func TestRunCertExport_MissingCertificate(t *testing.T) {
	withFilePIVStorage(t)

	cmd, _ := certTestCmd(t)
	require.NoError(t, cmd.Flags().Set("slot", string(xkms.PIVSlotAuthentication)))
	require.NoError(t, cmd.Flags().Set("file", filepath.Join(t.TempDir(), "out.pem")))

	err := runCertExport(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertNotFound)
}

func TestRunCertExport_ReportsUnwritableTarget(t *testing.T) {
	withFilePIVStorage(t)

	storage, err := createPIVStorage(buildPIVConfig(), slog.Default())
	require.NoError(t, err)
	require.NoError(t, storage.Store(xkms.PIVSlotAuthentication, pivTestCert(t, "cert")))
	require.NoError(t, storage.Close())

	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	cmd, _ := certTestCmd(t)
	require.NoError(t, cmd.Flags().Set("slot", string(xkms.PIVSlotAuthentication)))
	require.NoError(t, cmd.Flags().Set("file", filepath.Join(blocker, "out.pem")))

	err = runCertExport(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertExportFailed)
}

func TestRunCertRequest_RejectsMissingSPKIPin(t *testing.T) {
	withFilePIVStorage(t)

	cmd, _ := certTestCmd(t)
	require.NoError(t, cmd.Flags().Set("server", "https://ca.example.com"))
	require.NoError(t, cmd.Flags().Set("cn", "alice"))
	require.NoError(t, cmd.Flags().Set("slot", string(xkms.PIVSlotAuthentication)))

	err := runCertRequest(cmd, nil)
	require.Error(t, err)
	// Without a pin the client cannot establish trust; whichever step fails
	// first, the command must never reach the network unpinned.
	assert.NotContains(t, strings.ToLower(err.Error()), "certificate issued")
}
