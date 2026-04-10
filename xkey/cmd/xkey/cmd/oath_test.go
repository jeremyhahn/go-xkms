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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOATHCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"oath", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("oath --help failed: %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"OATH",
		"TOTP",
		"HOTP",
		"add",
		"list",
		"generate",
		"remove",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("OATH help output missing %q", expected)
		}
	}
}

func TestOATHCmd_SubcommandRegistration(t *testing.T) {
	subcommands := map[string]bool{
		"add":      false,
		"list":     false,
		"generate": false,
		"remove":   false,
	}

	for _, cmd := range OATHCmd.Commands() {
		if _, ok := subcommands[cmd.Name()]; ok {
			subcommands[cmd.Name()] = true
		}
	}

	for name, found := range subcommands {
		if !found {
			t.Errorf("OATH subcommand %q not registered", name)
		}
	}
}

// NOTE: Tests that execute commands through RootCmd.Execute() have state
// pollution issues due to Cobra flag persistence. Instead, test validation
// at the function level.

func TestOATHGenerateCmd_NoArgs(t *testing.T) {
	storePath := filepath.Join(os.TempDir(), "oath-test-generate-empty.json")
	defer os.Remove(storePath)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"oath", "generate", "--store", storePath})

	err := RootCmd.Execute()
	if err != ErrOATHMissingCredential {
		t.Errorf("oath generate with no args: error = %v, want %v", err, ErrOATHMissingCredential)
	}
}

func TestOATHRemoveCmd_NoArgs(t *testing.T) {
	storePath := filepath.Join(os.TempDir(), "oath-test-remove-empty.json")
	defer os.Remove(storePath)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"oath", "remove", "--store", storePath, "--force"})

	err := RootCmd.Execute()
	if err != ErrOATHMissingRemoveArg {
		t.Errorf("oath remove with no args: error = %v, want %v", err, ErrOATHMissingRemoveArg)
	}
}

func TestOATHErrors(t *testing.T) {
	// Test that all OATH errors have proper messages
	errors := []error{
		ErrOATHMissingName,
		ErrOATHMissingSecret,
		ErrOATHMissingCredential,
		ErrOATHMissingRemoveArg,
		ErrOATHStoreOpenFailed,
		ErrOATHInvalidURI,
		ErrOATHInvalidCredential,
		ErrOATHAddFailed,
		ErrOATHListFailed,
		ErrOATHGenerateFailed,
		ErrOATHDeleteFailed,
		ErrOATHCredentialNotFound,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("OATH error has empty message: %v", err)
		}
		if !strings.HasPrefix(err.Error(), "oath:") {
			t.Errorf("OATH error missing 'oath:' prefix: %v", err)
		}
	}
}
