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

// Package xkey provides integration tests for the "xkey backup" command
// group (create, list, contents, restore), exercised against the compiled
// CLI binary with an isolated HOME so the host user's real backups are
// never touched.
//
// The backup file is sealed with XChaCha20-Poly1305 and stored as the JSON
// encoding of the backup envelope, so these tests assert both halves of the
// contract: the right credential reads real data back, and a wrong
// credential fails without writing anything.
package xkey

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// setupIsolatedBackupHome creates a temporary directory and points HOME at
// it. "xkey backup" commands resolve paths via $HOME/.xkey (see
// getBackupDir and backupDataDir in cmd/xkey/cmd/backup.go) rather than
// XKEY_HOME, so isolating HOME is required to keep these tests hermetic.
func setupIsolatedBackupHome(t *testing.T) string {
	t.Helper()

	dir := SetupCleanEnvironment(t)
	t.Setenv("HOME", dir)
	return dir
}

// switchBackupHome points HOME at a second temporary directory so a restore
// can be verified against stores that started out empty.
func switchBackupHome(t *testing.T) string {
	t.Helper()

	dir := SetupCleanEnvironment(t)
	t.Setenv("HOME", dir)
	return dir
}

// backupDataDir returns the xkey data directory beneath an isolated home.
// It mirrors the default store locations "backup create" reads from.
func backupDataDir(home string) string {
	return filepath.Join(home, ".xkey", "data")
}

// backupOATHStorePath returns the default OATH store path for a home.
func backupOATHStorePath(home string) string {
	return filepath.Join(backupDataDir(home), "oath.json")
}

// backupPasswordStorePath returns the default password store path for a home.
func backupPasswordStorePath(home string) string {
	return filepath.Join(backupDataDir(home), "passwords")
}

// seededBackupData names the entries seedBackupData writes, so assertions
// can look for the exact values that must survive a backup/restore cycle.
const (
	seedCertCommonName = "xKey Backup Integration CA"
	seedOATHName       = "BackupSeedOATH"
	seedOATHSecret     = "JBSWY3DPEHPK3PXP"
	seedPasswordName   = "BackupSeedEntry"
	seedPasswordValue  = "seed-password-value"
)

// seedBackupData populates the trust store, the OATH store, and the static
// password store of the current HOME through the CLI itself, using the same
// default locations "backup create" reads from.
func seedBackupData(t *testing.T, binary, home string) {
	t.Helper()

	_, pemBytes := generateSelfSignedTrustCert(t, seedCertCommonName)
	pemPath := writeCertFile(t, home, "backup-seed-ca.pem", pemBytes)
	RunXKeyExpectSuccess(t, binary, "", "trust", "add", pemPath, "--purpose", "general")

	RunXKeyExpectSuccess(t, binary, "",
		"oath", "add",
		"--name", seedOATHName,
		"--issuer", "Example",
		"--secret", seedOATHSecret,
		"--store", backupOATHStorePath(home))

	RunXKeyExpectSuccess(t, binary, "",
		"password", "add",
		"--name", seedPasswordName,
		"--password", seedPasswordValue,
		"--store", backupPasswordStorePath(home))
}

// manifestCountPattern extracts the integer that follows a manifest label
// such as "Trust certs:" in the padded output of the backup commands.
func manifestCount(t *testing.T, output, label string) int {
	t.Helper()

	re := regexp.MustCompile(regexp.QuoteMeta(label) + `\s+(\d+)`)
	match := re.FindStringSubmatch(output)
	if match == nil {
		t.Fatalf("Label %q not found in output:\n%s", label, output)
	}

	count, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("Failed to parse count for %q: %v", label, err)
	}
	return count
}

// restoreResultPattern matches the per-category restore line printed by
// "backup restore", tolerating the column padding.
func restoreResultPattern(item string, restored int) *regexp.Regexp {
	return regexp.MustCompile(regexp.QuoteMeta(item+":") + `\s+restored ` + strconv.Itoa(restored))
}

// generatedKeyPattern matches the hex key "backup create" prints when no
// password was supplied.
var generatedKeyPattern = regexp.MustCompile(`Generated encryption key \(save this\):\s+([0-9a-f]{64})`)

// encryptedBackupEnvelope mirrors the on-disk format written by
// cmd/xkey/cmd/backup.go: a plaintext header plus the sealed archive.
type encryptedBackupEnvelope struct {
	Magic      string `json:"magic"`
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// readBackupEnvelope parses a .xkb file and fails the test if it is not a
// well-formed sealed envelope.
func readBackupEnvelope(t *testing.T, path string) encryptedBackupEnvelope {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read backup file: %v", err)
	}

	var envelope encryptedBackupEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("Backup file is not valid JSON: %v", err)
	}
	if envelope.Magic != "XKBK" {
		t.Errorf("Expected magic XKBK, got %q", envelope.Magic)
	}
	if envelope.Version != 1 {
		t.Errorf("Expected envelope version 1, got %d", envelope.Version)
	}
	if len(envelope.Nonce) == 0 {
		t.Error("Expected a non-empty nonce")
	}
	if len(envelope.Ciphertext) == 0 {
		t.Error("Expected non-empty ciphertext")
	}

	// Nothing that was backed up may be readable in the file.
	raw := string(data)
	for _, secret := range []string{seedPasswordValue, seedOATHSecret, seedPasswordName} {
		if strings.Contains(raw, secret) {
			t.Errorf("Backup file leaks %q in the clear", secret)
		}
	}

	return envelope
}

// ---------------------------------------------------------------------------
// backup create
// ---------------------------------------------------------------------------

// TestBackupCLI_Create_Success verifies that "backup create --password ..."
// writes a sealed backup at the requested --output path and reports the
// counts of the data it actually read.
func TestBackupCLI_Create_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)
	seedBackupData(t, binary, home)

	output := filepath.Join(home, "manual-backup.xkb")
	stdout := RunXKeyExpectSuccess(t, binary, "",
		"backup", "create", "--password", "s3cret-passphrase", "--output", output)

	if !strings.Contains(stdout, "Backup created: "+output) {
		t.Errorf("Expected 'Backup created: %s' in output, got: %s", output, stdout)
	}
	if !strings.Contains(stdout, "Using password-derived encryption key.") {
		t.Errorf("Expected password-derived key notice, got: %s", stdout)
	}

	if got := manifestCount(t, stdout, "Trust certs:"); got != 1 {
		t.Errorf("Expected 1 trust certificate in the backup, got %d\n%s", got, stdout)
	}
	if got := manifestCount(t, stdout, "OATH:"); got != 1 {
		t.Errorf("Expected 1 OATH credential in the backup, got %d\n%s", got, stdout)
	}
	if got := manifestCount(t, stdout, "Passwords:"); got != 1 {
		t.Errorf("Expected 1 static password in the backup, got %d\n%s", got, stdout)
	}

	readBackupEnvelope(t, output)
}

// TestBackupCLI_Create_NoData_Fails verifies that "backup create" refuses to
// write an empty backup when every data store is empty, instead of silently
// producing a file that restores nothing.
func TestBackupCLI_Create_NoData_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)

	output := filepath.Join(home, "empty-backup.xkb")
	errOutput := RunXKeyExpectFailure(t, binary, "",
		"backup", "create", "--password", "pw", "--output", output)

	if !strings.Contains(errOutput, "no data available to back up") {
		t.Errorf("Expected 'no data available to back up' in error output, got: %s", errOutput)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Errorf("Expected no backup file to be written, stat error was: %v", err)
	}
}

// TestBackupCLI_Create_InvalidOutputDir_Fails verifies that "backup create"
// fails when the output path's parent cannot be created (a path component
// is an existing regular file).
func TestBackupCLI_Create_InvalidOutputDir_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)

	blocker := filepath.Join(home, "blocker-file")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("Failed to write blocker file: %v", err)
	}
	output := filepath.Join(blocker, "sub", "backup.xkb")

	errOutput := RunXKeyExpectFailure(t, binary, "", "backup", "create", "--output", output)
	if !strings.Contains(errOutput, "cannot create backup directory") {
		t.Errorf("Expected 'cannot create backup directory' in error output, got: %s", errOutput)
	}
}

// TestBackupCLI_Create_GeneratedKey_RoundTrip verifies that the key printed
// when no password is supplied really is the key that opens the backup.
func TestBackupCLI_Create_GeneratedKey_RoundTrip(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)
	seedBackupData(t, binary, home)

	output := filepath.Join(home, "generated-key.xkb")
	createOut := RunXKeyExpectSuccess(t, binary, "", "backup", "create", "--output", output)

	match := generatedKeyPattern.FindStringSubmatch(createOut)
	if match == nil {
		t.Fatalf("Expected a generated hex key in output, got: %s", createOut)
	}

	contentsOut := RunXKeyExpectSuccess(t, binary, "",
		"backup", "contents", output, "--key", match[1])
	if got := manifestCount(t, contentsOut, "Passwords:"); got != 1 {
		t.Errorf("Expected the generated key to open the backup, got %d passwords\n%s", got, contentsOut)
	}
}

// TestBackupCLI_Create_CustomStorePaths verifies that the --oath-store and
// --password-store overrides are honored, so a backup can be taken of stores
// that live outside the default data directory.
func TestBackupCLI_Create_CustomStorePaths(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)

	oathStore := filepath.Join(home, "custom", "oath.json")
	passwordStore := filepath.Join(home, "custom", "passwords")

	RunXKeyExpectSuccess(t, binary, "",
		"oath", "add", "--name", "CustomStore", "--secret", seedOATHSecret, "--store", oathStore)
	RunXKeyExpectSuccess(t, binary, "",
		"password", "add", "--name", "CustomEntry", "--password", "custom-value", "--store", passwordStore)

	output := filepath.Join(home, "custom-stores.xkb")
	createOut := RunXKeyExpectSuccess(t, binary, "",
		"backup", "create", "--password", "pw", "--output", output,
		"--oath-store", oathStore, "--password-store", passwordStore)

	if got := manifestCount(t, createOut, "OATH:"); got != 1 {
		t.Errorf("Expected 1 OATH credential from the custom store, got %d\n%s", got, createOut)
	}
	if got := manifestCount(t, createOut, "Passwords:"); got != 1 {
		t.Errorf("Expected 1 password from the custom store, got %d\n%s", got, createOut)
	}
	if got := manifestCount(t, createOut, "Trust certs:"); got != 0 {
		t.Errorf("Expected no trust certificates, got %d\n%s", got, createOut)
	}
}

// ---------------------------------------------------------------------------
// backup list
// ---------------------------------------------------------------------------

// TestBackupCLI_List_Success verifies that "backup list" enumerates .xkb
// files in the default backup directory.
func TestBackupCLI_List_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)
	seedBackupData(t, binary, home)

	first := filepath.Join(home, ".xkey", "backups", "backup-one.xkb")
	second := filepath.Join(home, ".xkey", "backups", "backup-two.xkb")

	RunXKeyExpectSuccess(t, binary, "", "backup", "create", "--password", "pw1", "--output", first)
	RunXKeyExpectSuccess(t, binary, "", "backup", "create", "--password", "pw2", "--output", second)

	listOut := RunXKeyExpectSuccess(t, binary, "", "backup", "list")
	if !strings.Contains(listOut, "backup-one.xkb") {
		t.Errorf("Expected list to include backup-one.xkb, got: %s", listOut)
	}
	if !strings.Contains(listOut, "backup-two.xkb") {
		t.Errorf("Expected list to include backup-two.xkb, got: %s", listOut)
	}
	if !strings.Contains(listOut, "Backups (2):") {
		t.Errorf("Expected list header to report 2 backups, got: %s", listOut)
	}
}

// TestBackupCLI_List_BlockedDirectory_Fails verifies that "backup list"
// fails with the list sentinel -- not the creation sentinel -- when the
// default backup directory path is blocked by a non-directory file.
func TestBackupCLI_List_BlockedDirectory_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)

	xkeyDir := filepath.Join(home, ".xkey")
	if err := os.MkdirAll(xkeyDir, 0700); err != nil {
		t.Fatalf("Failed to create .xkey dir: %v", err)
	}
	blocked := filepath.Join(xkeyDir, "backups")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0600); err != nil {
		t.Fatalf("Failed to write blocking file: %v", err)
	}

	errOutput := RunXKeyExpectFailure(t, binary, "", "backup", "list")
	if !strings.Contains(errOutput, "list failed") {
		t.Errorf("Expected 'list failed' in error output, got: %s", errOutput)
	}
	if strings.Contains(errOutput, "creation failed") {
		t.Errorf("A list failure must not be reported as a creation failure, got: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// backup contents
// ---------------------------------------------------------------------------

// TestBackupCLI_Contents_Success verifies that "backup contents" decrypts a
// previously created backup and prints its real item counts.
func TestBackupCLI_Contents_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)
	seedBackupData(t, binary, home)

	output := filepath.Join(home, "contents-test.xkb")
	RunXKeyExpectSuccess(t, binary, "", "backup", "create", "--password", "content-pw", "--output", output)

	contentsOut := RunXKeyExpectSuccess(t, binary, "", "backup", "contents", output, "--password", "content-pw")
	if !strings.Contains(contentsOut, "Backup Contents: contents-test.xkb") {
		t.Errorf("Expected contents header for contents-test.xkb, got: %s", contentsOut)
	}
	if !strings.Contains(contentsOut, "Version:") {
		t.Errorf("Expected 'Version:' field, got: %s", contentsOut)
	}
	if !strings.Contains(contentsOut, "Checksum:") {
		t.Errorf("Expected 'Checksum:' field, got: %s", contentsOut)
	}
	if got := manifestCount(t, contentsOut, "Trust certs:"); got != 1 {
		t.Errorf("Expected 1 trust certificate, got %d\n%s", got, contentsOut)
	}
	if got := manifestCount(t, contentsOut, "OATH:"); got != 1 {
		t.Errorf("Expected 1 OATH credential, got %d\n%s", got, contentsOut)
	}
	if got := manifestCount(t, contentsOut, "Passwords:"); got != 1 {
		t.Errorf("Expected 1 static password, got %d\n%s", got, contentsOut)
	}
}

// TestBackupCLI_Contents_WrongPassword_Fails verifies that a mismatched
// password cannot reveal the manifest.
func TestBackupCLI_Contents_WrongPassword_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)
	seedBackupData(t, binary, home)

	output := filepath.Join(home, "contents-wrong-pw.xkb")
	RunXKeyExpectSuccess(t, binary, "", "backup", "create", "--password", "the-real-one", "--output", output)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"backup", "contents", output, "--password", "not-the-real-one")
	if !strings.Contains(errOutput, "decryption failed") {
		t.Errorf("Expected 'decryption failed' in error output, got: %s", errOutput)
	}
	if !strings.Contains(errOutput, "incorrect password or key") {
		t.Errorf("Expected 'incorrect password or key' in error output, got: %s", errOutput)
	}
}

// TestBackupCLI_Contents_WrongHexKey_Fails verifies that a syntactically
// valid but incorrect --key is rejected.
func TestBackupCLI_Contents_WrongHexKey_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)
	seedBackupData(t, binary, home)

	output := filepath.Join(home, "contents-wrong-key.xkb")
	RunXKeyExpectSuccess(t, binary, "", "backup", "create", "--password", "pw", "--output", output)

	wrongKey := strings.Repeat("ab", 32)
	errOutput := RunXKeyExpectFailure(t, binary, "", "backup", "contents", output, "--key", wrongKey)
	if !strings.Contains(errOutput, "incorrect password or key") {
		t.Errorf("Expected 'incorrect password or key' in error output, got: %s", errOutput)
	}
}

// TestBackupCLI_Contents_FileNotFound_Fails verifies that "backup contents"
// fails when the given file does not exist.
func TestBackupCLI_Contents_FileNotFound_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)

	missing := filepath.Join(home, "no-such-backup.xkb")
	errOutput := RunXKeyExpectFailure(t, binary, "", "backup", "contents", missing, "--password", "whatever")
	if !strings.Contains(errOutput, "file not found") {
		t.Errorf("Expected 'file not found' in error output, got: %s", errOutput)
	}
}

// TestBackupCLI_Contents_MissingCredential_Fails verifies that "backup
// contents" fails when neither --password nor --key is supplied.
func TestBackupCLI_Contents_MissingCredential_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)
	seedBackupData(t, binary, home)

	output := filepath.Join(home, "no-credential.xkb")
	RunXKeyExpectSuccess(t, binary, "", "backup", "create", "--password", "pw", "--output", output)

	errOutput := RunXKeyExpectFailure(t, binary, "", "backup", "contents", output)
	if !strings.Contains(errOutput, "password or key required") {
		t.Errorf("Expected 'password or key required' in error output, got: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// backup restore
// ---------------------------------------------------------------------------

// TestBackupCLI_Restore_Success verifies that "backup restore" decrypts a
// backup and writes its contents into the stores of a clean home.
func TestBackupCLI_Restore_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)
	seedBackupData(t, binary, home)

	output := filepath.Join(home, "restore-test.xkb")
	RunXKeyExpectSuccess(t, binary, "", "backup", "create", "--password", "restore-pw", "--output", output)

	restoreHome := switchBackupHome(t)

	restoreOut := RunXKeyExpectSuccess(t, binary, "", "backup", "restore", output, "--password", "restore-pw")
	if !strings.Contains(restoreOut, "Restoring from: "+output) {
		t.Errorf("Expected restore to report source file, got: %s", restoreOut)
	}
	if !strings.Contains(restoreOut, "Restore completed successfully.") {
		t.Errorf("Expected restore success message, got: %s", restoreOut)
	}
	if !restoreResultPattern("static-passwords", 1).MatchString(restoreOut) {
		t.Errorf("Expected the password restore result, got: %s", restoreOut)
	}

	pwOut := RunXKeyExpectSuccess(t, binary, "",
		"password", "list", "--store", backupPasswordStorePath(restoreHome))
	if !strings.Contains(pwOut, seedPasswordName) {
		t.Errorf("Expected %s in the restored password store, got: %s", seedPasswordName, pwOut)
	}
}

// TestBackupCLI_Restore_WrongPassword_Fails verifies that a mismatched
// password fails the restore and leaves the target stores untouched. This
// replaces an earlier test that documented the opposite (a placeholder
// implementation accepted any password).
func TestBackupCLI_Restore_WrongPassword_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)
	seedBackupData(t, binary, home)

	output := filepath.Join(home, "wrongpw.xkb")
	RunXKeyExpectSuccess(t, binary, "",
		"backup", "create", "--password", "correct-horse-battery-staple", "--output", output)

	restoreHome := switchBackupHome(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"backup", "restore", output, "--password", "totally-different-password")
	if !strings.Contains(errOutput, "decryption failed") {
		t.Errorf("Expected 'decryption failed' in error output, got: %s", errOutput)
	}
	if strings.Contains(errOutput, "Restore completed") {
		t.Errorf("A mismatched password must never report a completed restore, got: %s", errOutput)
	}

	pwOut := RunXKeyExpectSuccess(t, binary, "",
		"password", "list", "--store", backupPasswordStorePath(restoreHome))
	if strings.Contains(pwOut, seedPasswordName) {
		t.Errorf("A failed restore must not write data, got: %s", pwOut)
	}
}

// TestBackupCLI_Restore_FileNotFound_Fails verifies that "backup restore"
// fails when the given file does not exist.
func TestBackupCLI_Restore_FileNotFound_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)

	missing := filepath.Join(home, "ghost.xkb")
	errOutput := RunXKeyExpectFailure(t, binary, "", "backup", "restore", missing, "--password", "irrelevant")
	if !strings.Contains(errOutput, "file not found") {
		t.Errorf("Expected 'file not found' in error output, got: %s", errOutput)
	}
}

// TestBackupCLI_Restore_CorruptFile_Fails verifies that "backup restore"
// rejects a file that is not a backup envelope.
func TestBackupCLI_Restore_CorruptFile_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)

	corrupt := filepath.Join(home, "corrupt.xkb")
	if err := os.WriteFile(corrupt, []byte("not valid json { at all"), 0600); err != nil {
		t.Fatalf("Failed to write corrupt backup file: %v", err)
	}

	errOutput := RunXKeyExpectFailure(t, binary, "", "backup", "restore", corrupt, "--password", "any-password")
	if !strings.Contains(errOutput, "not an xkey backup envelope") {
		t.Errorf("Expected 'not an xkey backup envelope' in error output, got: %s", errOutput)
	}
}

// TestBackupCLI_Restore_TamperedCiphertext_Fails verifies that flipping a
// byte of the sealed payload is detected by the AEAD tag rather than
// silently restoring corrupt data.
func TestBackupCLI_Restore_TamperedCiphertext_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)
	seedBackupData(t, binary, home)

	output := filepath.Join(home, "tampered.xkb")
	RunXKeyExpectSuccess(t, binary, "", "backup", "create", "--password", "tamper-pw", "--output", output)

	envelope := readBackupEnvelope(t, output)
	envelope.Ciphertext[0] ^= 0xFF
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Failed to re-encode tampered envelope: %v", err)
	}
	if err := os.WriteFile(output, tampered, 0600); err != nil {
		t.Fatalf("Failed to write tampered backup: %v", err)
	}

	errOutput := RunXKeyExpectFailure(t, binary, "", "backup", "restore", output, "--password", "tamper-pw")
	if !strings.Contains(errOutput, "decryption failed") {
		t.Errorf("Expected 'decryption failed' for tampered ciphertext, got: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// Full lifecycle
// ---------------------------------------------------------------------------

// TestBackupCLI_FullLifecycle_CreateListContentsRestore seeds a certificate,
// an OATH credential, and a static password, then runs backup create ->
// list -> contents -> restore into a second, clean HOME and verifies every
// seeded item is present afterwards.
func TestBackupCLI_FullLifecycle_CreateListContentsRestore(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedBackupHome(t)
	seedBackupData(t, binary, home)

	backupPassword := "backup-encryption-password!"
	output := filepath.Join(home, ".xkey", "backups", "lifecycle.xkb")

	createOut := RunXKeyExpectSuccess(t, binary, "",
		"backup", "create", "--password", backupPassword, "--output", output)
	if !strings.Contains(createOut, "Backup created: "+output) {
		t.Fatalf("Expected create confirmation for %s, got: %s", output, createOut)
	}

	listOut := RunXKeyExpectSuccess(t, binary, "", "backup", "list")
	if !strings.Contains(listOut, "lifecycle.xkb") {
		t.Errorf("Expected list output to include lifecycle.xkb, got: %s", listOut)
	}

	contentsOut := RunXKeyExpectSuccess(t, binary, "",
		"backup", "contents", output, "--password", backupPassword)
	if !strings.Contains(contentsOut, "Backup Contents:") {
		t.Errorf("Expected contents header, got: %s", contentsOut)
	}
	for label, want := range map[string]int{"Trust certs:": 1, "OATH:": 1, "Passwords:": 1} {
		if got := manifestCount(t, contentsOut, label); got != want {
			t.Errorf("Expected %s %d in the manifest, got %d\n%s", label, want, got, contentsOut)
		}
	}

	// Restore into a second, clean home and confirm every category landed.
	restoreHome := switchBackupHome(t)

	restoreOut := RunXKeyExpectSuccess(t, binary, "",
		"backup", "restore", output, "--password", backupPassword)
	if !strings.Contains(restoreOut, "Restore completed successfully.") {
		t.Errorf("Expected restore success message, got: %s", restoreOut)
	}

	pwOut := RunXKeyExpectSuccess(t, binary, "",
		"password", "list", "--store", backupPasswordStorePath(restoreHome))
	if !strings.Contains(pwOut, seedPasswordName) {
		t.Errorf("Expected %s to be restored, got: %s", seedPasswordName, pwOut)
	}

	oathOut := RunXKeyExpectSuccess(t, binary, "",
		"oath", "list", "--store", backupOATHStorePath(restoreHome), "--secrets")
	if !strings.Contains(oathOut, seedOATHName) {
		t.Errorf("Expected %s to be restored, got: %s", seedOATHName, oathOut)
	}
	if !strings.Contains(oathOut, seedOATHSecret) {
		t.Errorf("Expected the OATH secret to be restored, got: %s", oathOut)
	}

	trustOut := RunXKeyExpectSuccess(t, binary, "", "trust", "list")
	if !strings.Contains(trustOut, seedCertCommonName) {
		t.Errorf("Expected %s to be restored into the trust store, got: %s", seedCertCommonName, trustOut)
	}

	// A second backup taken from the restored home must see the same data,
	// proving the restore wrote through to the stores the CLI reads.
	secondBackup := filepath.Join(restoreHome, "round-two.xkb")
	secondOut := RunXKeyExpectSuccess(t, binary, "",
		"backup", "create", "--password", backupPassword, "--output", secondBackup)
	for label, want := range map[string]int{"Trust certs:": 1, "OATH:": 1, "Passwords:": 1} {
		if got := manifestCount(t, secondOut, label); got != want {
			t.Errorf("Expected %s %d in the second backup, got %d\n%s", label, want, got, secondOut)
		}
	}
}
