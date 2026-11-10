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

//go:build integration && pkcs11 && pkcs11_tool
// +build integration,pkcs11,pkcs11_tool

// Package module drives pkcs11-tool's --wrap and --unwrap verbs against the
// go-xkms PKCS#11 shared library (T3).
//
// pkcs11-tool's wrap/unwrap CLI surface was verified directly against a
// SoftHSM2 token (a real, independent Cryptoki implementation) before this
// file was written, so the flag semantics below are confirmed rather than
// guessed:
//
//   - "--wrap --id <wrapping-key-id> --application-id <target-key-id>
//     --mechanism <mech> --output-file <path>" wraps the object named by
//     --application-id under the key named by --id, and writes the wrapped
//     blob to --output-file.
//   - "--unwrap --id <wrapping-key-id> --mechanism <mech>
//     --input-file <path> --key-type <type> --application-id <new-id>
//     --application-label <new-label>" reverses that, creating a new token
//     object named by --application-id/--application-label.
//   - pkcs11-tool's default --keygen (no --usage-* flag) puts only
//     CKA_ENCRYPT and CKA_DECRYPT in the C_GenerateKey template; CKA_WRAP and
//     CKA_UNWRAP are sent, both CK_TRUE, only with --usage-wrap. PKCS#11 v3.2
//     §4.11 (secret key objects) gives CKA_WRAP no default, so it is
//     token-specific: SoftHSM2 defaults it to CK_TRUE, go-xkms to CK_FALSE.
//     §5.18.3 requires CKA_WRAP CK_TRUE on the wrapping key (and §5.18.4
//     CKA_UNWRAP for C_UnwrapKey), so the wrapping key is generated with
//     --usage-wrap.
//   - The key being wrapped needs CKA_EXTRACTABLE, which pkcs11-tool only
//     sets when --extractable is passed; go-xkms's C_WrapKey refuses a
//     non-extractable target with CKR_KEY_UNEXTRACTABLE (see
//     pkg/pkcs11/module/module.go WrapKey), matching the PKCS#11 v3.2 §5.18.3
//     requirement, so the target key generation below passes --extractable.
//
// Build tags: integration,pkcs11,pkcs11_tool
package module

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestPKCS11Tool_KeyWrapUnwrap wraps a target AES key under a wrapping AES
// key using CKM_AES_KEY_WRAP, then unwraps the resulting blob back into a new
// token object, exercising C_WrapKey and C_UnwrapKey through the external
// pkcs11-tool binary end to end (T3).
func TestPKCS11Tool_KeyWrapUnwrap(t *testing.T) {
	requireFilePersistence(t)
	requireTool(t)
	cfg := NewPKCS11ToolTestConfig(t)
	requireModule(t, cfg.ModulePath)

	// Establish token + user PIN state for the pkcs11-tool subprocesses this
	// test drives; SetupInitializedModule's own module handle is not used
	// because every operation below goes through pkcs11-tool instead, to
	// keep this test's coverage limited to the external-tool code path.
	SetupInitializedModule(t)

	t.Run("aes_key_wrap_roundtrip", func(t *testing.T) {
		wrapLabel := "wrap-key-aeskw"
		wrapID := "90"
		targetLabel := "wrap-target-aeskw"
		targetID := "91"

		// Wrapping key: AES-256 with CKA_WRAP and CKA_UNWRAP set by --usage-wrap.
		keygenOutput, keygenStderr, keygenErr := runPKCS11ToolCommand(t, cfg,
			"--login", "--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keygen",
			"--key-type", "aes:32",
			"--usage-wrap",
			"--label", wrapLabel,
			"--id", wrapID,
		)
		if keygenErr != nil {
			t.Fatalf("wrapping key generation failed: %v\nstdout: %s\nstderr: %s", keygenErr, keygenOutput, keygenStderr)
		}

		// Target key: AES-128, marked extractable so C_WrapKey will export it.
		targetOutput, targetStderr, targetErr := runPKCS11ToolCommand(t, cfg,
			"--login", "--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--keygen",
			"--key-type", "aes:16",
			"--label", targetLabel,
			"--id", targetID,
			"--extractable",
		)
		if targetErr != nil {
			t.Fatalf("target key generation failed: %v\nstdout: %s\nstderr: %s", targetErr, targetOutput, targetStderr)
		}

		wrappedFile := filepath.Join(cfg.TempDir, "wrapped_aeskw.bin")
		wrapOutput, wrapStderr, wrapErr := runPKCS11ToolCommand(t, cfg,
			"--login", "--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--wrap",
			"--id", wrapID,
			"--application-id", targetID,
			"--mechanism", "AES-KEY-WRAP",
			"--output-file", wrappedFile,
		)
		if wrapErr != nil {
			t.Fatalf("pkcs11-tool --wrap failed: %v\nstdout: %s\nstderr: %s", wrapErr, wrapOutput, wrapStderr)
		}

		wrapped := readTestDataFile(t, wrappedFile)
		if len(wrapped) == 0 {
			t.Fatal("expected a non-empty wrapped key blob")
		}
		if len(wrapped)%8 != 0 {
			t.Fatalf("RFC 3394 AES key wrap output must be a multiple of 8 bytes, got %d", len(wrapped))
		}
		// RFC 3394 §2.2: the wrapped output is exactly 8 bytes longer than the
		// plaintext key it wraps.
		const targetKeyLenBytes = 16
		wantLen := targetKeyLenBytes + 8
		if len(wrapped) != wantLen {
			t.Fatalf("expected wrapped AES-128 key to be %d bytes, got %d", wantLen, len(wrapped))
		}
		t.Logf("wrapped key blob: %d bytes", len(wrapped))

		// Unwrap the blob back into a new token object.
		unwrappedLabel := "unwrap-target-aeskw"
		unwrappedID := "92"
		unwrapOutput, unwrapStderr, unwrapErr := runPKCS11ToolCommand(t, cfg,
			"--login", "--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--unwrap",
			"--id", wrapID,
			"--mechanism", "AES-KEY-WRAP",
			"--input-file", wrappedFile,
			"--key-type", "AES:",
			"--application-id", unwrappedID,
			"--application-label", unwrappedLabel,
		)
		if unwrapErr != nil {
			t.Fatalf("pkcs11-tool --unwrap failed: %v\nstdout: %s\nstderr: %s", unwrapErr, unwrapOutput, unwrapStderr)
		}

		// Confirm the unwrapped key landed on the token under the requested
		// label, proving C_UnwrapKey produced a usable object rather than
		// merely returning CKR_OK.
		listOutput := mustRunPKCS11ToolCommand(t, cfg,
			"--login", "--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
			"--type", "secrkey",
		)
		if !strings.Contains(listOutput, unwrappedLabel) {
			t.Fatalf("expected unwrapped key label %q in --list-objects output:\n%s", unwrappedLabel, listOutput)
		}
		if !strings.Contains(listOutput, unwrappedID) {
			t.Fatalf("expected unwrapped key ID %q in --list-objects output:\n%s", unwrappedID, listOutput)
		}
	})
}
