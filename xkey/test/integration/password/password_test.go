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

//go:build integration

// Package password provides integration tests for the xkey password CLI commands.
// These tests execute the real xkey binary and verify actual CLI behavior.
package password

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPasswordCLI_FullWorkflow tests the complete password management lifecycle:
// add, list, get, remove, and verify removal.
func TestPasswordCLI_FullWorkflow(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	credName := "TestServer"
	credPassword := "s3cret123!"

	// Step 1: Add password.
	t.Run("Add", func(t *testing.T) {
		result := helper.AddPassword(credName, credPassword)
		require.True(t, result.Success(),
			"Add command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.True(t, result.OutputContains("Added") || result.OutputContains("added"),
			"Output should confirm password was added: %s", result.Combined())
	})

	// Step 2: Verify password appears in list.
	t.Run("List", func(t *testing.T) {
		result := helper.RunPassword("list")
		require.True(t, result.Success(),
			"List command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.True(t, result.OutputContains(credName),
			"List output should contain password name: %s", result.Combined())
	})

	// Step 3: Retrieve password by name.
	t.Run("Get", func(t *testing.T) {
		result := helper.RunPassword("get", credName)
		require.True(t, result.Success(),
			"Get command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.True(t, result.OutputContains(credPassword),
			"Get output should contain the password value: %s", result.Combined())
	})

	// Step 4: Remove password with force flag.
	t.Run("Remove", func(t *testing.T) {
		result := helper.RunPassword("remove", credName, "--force")
		require.True(t, result.Success(),
			"Remove command failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.True(t, result.OutputContains("Removed") || result.OutputContains("removed"),
			"Output should confirm removal: %s", result.Combined())
	})

	// Step 5: Verify password is gone from list.
	t.Run("ListAfterRemove", func(t *testing.T) {
		result := helper.RunPassword("list")
		require.True(t, result.Success(),
			"List command failed after remove: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		assert.False(t, result.OutputContains(credName),
			"List output should not contain removed password: %s", result.Combined())
	})
}

// TestPasswordCLI_GeneratePassword tests that --generate produces a random password
// and that the generated password can be retrieved.
func TestPasswordCLI_GeneratePassword(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	credName := "Generated"

	// Add with --generate.
	result := helper.AddGeneratedPassword(credName)
	require.True(t, result.Success(),
		"Add --generate failed: stdout=%s stderr=%s", result.Stdout, result.Stderr)
	assert.True(t, result.OutputContains(credName),
		"Output should contain the credential name: %s", result.Combined())
	assert.True(t, result.OutputContains("Generated:") || result.OutputContains("generated"),
		"Output should show the generated password: %s", result.Combined())

	// Get the generated password and verify it is non-empty.
	getResult := helper.RunPassword("get", credName)
	require.True(t, getResult.Success(),
		"Get generated password failed: %s", getResult.Combined())

	password := strings.TrimSpace(getResult.Stdout)
	assert.NotEmpty(t, password,
		"Generated password should not be empty")
	// Default length is 32.
	assert.Len(t, password, 32,
		"Default generated password should be 32 characters, got %d: %q", len(password), password)
}

// TestPasswordCLI_GenerateCustomLength tests --generate --length 64 produces
// a password of exactly 64 characters.
func TestPasswordCLI_GenerateCustomLength(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	credName := "Long"

	result := helper.RunPassword("add",
		"--name", credName,
		"--generate",
		"--length", "64")
	require.True(t, result.Success(),
		"Add --generate --length 64 failed: %s", result.Combined())

	getResult := helper.RunPassword("get", credName)
	require.True(t, getResult.Success(),
		"Get long password failed: %s", getResult.Combined())

	password := strings.TrimSpace(getResult.Stdout)
	assert.Len(t, password, 64,
		"Generated password should be 64 characters, got %d: %q", len(password), password)
}

// TestPasswordCLI_GenerateAlphanumeric tests --charset alphanumeric produces
// a password containing only letters and digits.
func TestPasswordCLI_GenerateAlphanumeric(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	credName := "AlphaNum"

	result := helper.RunPassword("add",
		"--name", credName,
		"--generate",
		"--charset", "alphanumeric")
	require.True(t, result.Success(),
		"Add --generate --charset alphanumeric failed: %s", result.Combined())

	getResult := helper.RunPassword("get", credName)
	require.True(t, getResult.Success(),
		"Get alphanumeric password failed: %s", getResult.Combined())

	password := strings.TrimSpace(getResult.Stdout)
	assert.NotEmpty(t, password, "Alphanumeric password should not be empty")

	alphanumericPattern := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	assert.True(t, alphanumericPattern.MatchString(password),
		"Password should only contain [a-zA-Z0-9], got: %q", password)
}

// TestPasswordCLI_ListHidesPasswords verifies that default list output masks
// password values with asterisks.
func TestPasswordCLI_ListHidesPasswords(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	secretValue := "visible_secret"
	result := helper.AddPassword("HiddenTest", secretValue)
	require.True(t, result.Success(),
		"Add failed: %s", result.Combined())

	listResult := helper.RunPassword("list")
	require.True(t, listResult.Success(),
		"List failed: %s", listResult.Combined())

	assert.False(t, listResult.OutputContains(secretValue),
		"Default list should NOT reveal the password value: %s", listResult.Combined())
	assert.True(t, listResult.OutputContains("********"),
		"Default list should show masked password: %s", listResult.Combined())
}

// TestPasswordCLI_ListShowPasswords verifies that --show-passwords reveals
// the actual password values in list output.
func TestPasswordCLI_ListShowPasswords(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	secretValue := "visible_secret"
	result := helper.AddPassword("ShowTest", secretValue)
	require.True(t, result.Success(),
		"Add failed: %s", result.Combined())

	listResult := helper.RunPassword("list", "--show-passwords")
	require.True(t, listResult.Success(),
		"List --show-passwords failed: %s", listResult.Combined())

	assert.True(t, listResult.OutputContains(secretValue),
		"List --show-passwords should reveal the password value: %s", listResult.Combined())
}

// TestPasswordCLI_DuplicateAdd verifies that adding a password with the same
// name twice fails with an appropriate error.
func TestPasswordCLI_DuplicateAdd(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	credName := "DupTest"

	// First add should succeed.
	result := helper.AddPassword(credName, "pw1")
	require.True(t, result.Success(),
		"First add should succeed: %s", result.Combined())

	// Second add with same name should fail.
	result = helper.AddPassword(credName, "pw2")
	assert.False(t, result.Success(),
		"Duplicate add should fail")
	assert.True(t, result.OutputContains("exist") || result.OutputContains("Exist") ||
		result.OutputContains("duplicate") || result.OutputContains("Duplicate"),
		"Error should mention existence or duplicate: %s", result.Combined())
}

// TestPasswordCLI_RemoveMultiple verifies removing multiple passwords at once
// while leaving unspecified passwords intact.
func TestPasswordCLI_RemoveMultiple(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	// Add three passwords.
	for _, name := range []string{"Rem1", "Rem2", "Rem3"} {
		result := helper.AddPassword(name, "pw-"+name)
		require.True(t, result.Success(),
			"Add %s failed: %s", name, result.Combined())
	}

	// Remove Rem1 and Rem3, leave Rem2.
	result := helper.RunPassword("remove", "Rem1", "Rem3", "--force")
	require.True(t, result.Success(),
		"Remove multiple failed: %s", result.Combined())

	// Verify only Rem2 remains.
	listResult := helper.RunPassword("list")
	require.True(t, listResult.Success(),
		"List after remove failed: %s", listResult.Combined())
	assert.False(t, listResult.OutputContains("Rem1"),
		"Rem1 should be gone: %s", listResult.Combined())
	assert.True(t, listResult.OutputContains("Rem2"),
		"Rem2 should remain: %s", listResult.Combined())
	assert.False(t, listResult.OutputContains("Rem3"),
		"Rem3 should be gone: %s", listResult.Combined())
}

// TestPasswordCLI_GetNonExistent verifies that getting a password that does
// not exist fails with an appropriate error.
func TestPasswordCLI_GetNonExistent(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	result := helper.RunPassword("get", "DoesNotExist")
	assert.False(t, result.Success(),
		"Get non-existent password should fail")
	assert.True(t, result.OutputContains("not found") || result.OutputContains("Not found") ||
		result.OutputContains("error") || result.OutputContains("Error") ||
		result.OutputContains("failed") || result.OutputContains("Failed"),
		"Error should indicate the password was not found: %s", result.Combined())
}

// TestPasswordCLI_RemoveNonExistent verifies that removing a password that
// does not exist outputs an error indication.
func TestPasswordCLI_RemoveNonExistent(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	result := helper.RunPassword("remove", "DoesNotExist", "--force")
	// The remove command prints errors to stderr per-entry but does not
	// return a non-zero exit code for individual failures. Verify that
	// the output indicates the entry was not found.
	assert.True(t, result.OutputContains("not found") || result.OutputContains("Not found") ||
		result.OutputContains("error") || result.OutputContains("Error") ||
		!result.Success(),
		"Remove non-existent should fail or show error: %s", result.Combined())
}

// TestPasswordCLI_CommandAliases verifies that ls, show, and rm aliases work
// identically to their canonical counterparts.
func TestPasswordCLI_CommandAliases(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	credName := "AliasTest"
	credPassword := "aliasP@ss"

	// Add a password to test against.
	result := helper.AddPassword(credName, credPassword)
	require.True(t, result.Success(),
		"Add failed: %s", result.Combined())

	// Test 'ls' alias for list.
	t.Run("LsAlias", func(t *testing.T) {
		result := helper.RunPassword("ls")
		require.True(t, result.Success(),
			"ls alias should work: %s", result.Combined())
		assert.True(t, result.OutputContains(credName),
			"ls should show password: %s", result.Combined())
	})

	// Test 'show' alias for get.
	t.Run("ShowAlias", func(t *testing.T) {
		result := helper.RunPassword("show", credName)
		require.True(t, result.Success(),
			"show alias should work: %s", result.Combined())
		assert.True(t, result.OutputContains(credPassword),
			"show should return password value: %s", result.Combined())
	})

	// Test 'rm' alias for remove.
	t.Run("RmAlias", func(t *testing.T) {
		result := helper.RunPassword("rm", credName, "--force")
		require.True(t, result.Success(),
			"rm alias should work: %s", result.Combined())
	})

	// Verify removal via alias.
	listResult := helper.RunPassword("list")
	assert.False(t, listResult.OutputContains(credName),
		"Password should be removed via rm alias: %s", listResult.Combined())
}

// TestPasswordCLI_MissingRequiredArgs verifies that the CLI rejects commands
// with missing required arguments.
func TestPasswordCLI_MissingRequiredArgs(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	// add without --name should fail.
	t.Run("AddMissingName", func(t *testing.T) {
		result := helper.RunPassword("add", "--password", "test")
		assert.False(t, result.Success(),
			"Add without --name should fail")
	})

	// add --name without --password or --generate should fail.
	t.Run("AddMissingSource", func(t *testing.T) {
		result := helper.RunPassword("add", "--name", "Test")
		assert.False(t, result.Success(),
			"Add without --password or --generate should fail")
	})

	// get without name argument should fail.
	t.Run("GetMissingName", func(t *testing.T) {
		result := helper.RunPassword("get")
		assert.False(t, result.Success(),
			"Get without name should fail")
	})

	// remove without name argument should fail.
	t.Run("RemoveMissingName", func(t *testing.T) {
		result := helper.RunPassword("remove", "--force")
		assert.False(t, result.Success(),
			"Remove without name should fail")
	})
}

// TestPasswordCLI_StorePersistence verifies that passwords survive across
// separate CLI invocations sharing the same store path.
func TestPasswordCLI_StorePersistence(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	// Add first password in one invocation.
	result := helper.AddPassword("Persist1", "pw1")
	require.True(t, result.Success(),
		"Add Persist1 failed: %s", result.Combined())

	// Add second password in a separate invocation.
	result = helper.AddPassword("Persist2", "pw2")
	require.True(t, result.Success(),
		"Add Persist2 failed: %s", result.Combined())

	// Both should appear in a third invocation's list.
	listResult := helper.RunPassword("list")
	require.True(t, listResult.Success(),
		"List failed: %s", listResult.Combined())
	assert.True(t, listResult.OutputContains("Persist1"),
		"Persist1 should appear in list: %s", listResult.Combined())
	assert.True(t, listResult.OutputContains("Persist2"),
		"Persist2 should appear in list: %s", listResult.Combined())

	// Verify get works for both across invocations.
	get1 := helper.RunPassword("get", "Persist1")
	require.True(t, get1.Success(),
		"Get Persist1 failed: %s", get1.Combined())
	assert.True(t, get1.OutputContains("pw1"),
		"Get Persist1 should return pw1: %s", get1.Combined())

	get2 := helper.RunPassword("get", "Persist2")
	require.True(t, get2.Success(),
		"Get Persist2 failed: %s", get2.Combined())
	assert.True(t, get2.OutputContains("pw2"),
		"Get Persist2 should return pw2: %s", get2.Combined())
}

// TestPasswordCLI_HelpOutput verifies that help text is present and contains
// expected keywords for the password command and its subcommands.
func TestPasswordCLI_HelpOutput(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	// password --help
	t.Run("PasswordHelp", func(t *testing.T) {
		result := helper.RunCommand("password", "--help")
		require.True(t, result.Success(),
			"password --help should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("password") || result.OutputContains("Password"),
			"Help should mention password: %s", result.Combined())
		assert.True(t, result.OutputContains("static") || result.OutputContains("Static"),
			"Help should mention static: %s", result.Combined())
	})

	// password add --help
	t.Run("AddHelp", func(t *testing.T) {
		result := helper.RunCommand("password", "add", "--help")
		require.True(t, result.Success(),
			"password add --help should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("name") || result.OutputContains("Name"),
			"Add help should mention name: %s", result.Combined())
	})

	// password list --help
	t.Run("ListHelp", func(t *testing.T) {
		result := helper.RunCommand("password", "list", "--help")
		require.True(t, result.Success(),
			"password list --help should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("show-passwords") || result.OutputContains("show"),
			"List help should mention show-passwords: %s", result.Combined())
	})

	// password get --help
	t.Run("GetHelp", func(t *testing.T) {
		result := helper.RunCommand("password", "get", "--help")
		require.True(t, result.Success(),
			"password get --help should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("get") || result.OutputContains("Get") ||
			result.OutputContains("retrieve") || result.OutputContains("Retrieve"),
			"Get help should describe the get command: %s", result.Combined())
	})

	// password remove --help
	t.Run("RemoveHelp", func(t *testing.T) {
		result := helper.RunCommand("password", "remove", "--help")
		require.True(t, result.Success(),
			"password remove --help should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("remove") || result.OutputContains("Remove") ||
			result.OutputContains("force"),
			"Remove help should mention remove or force: %s", result.Combined())
	})
}

// TestPasswordCLI_ListEmpty verifies that listing an empty store succeeds
// and produces an appropriate empty-state message.
func TestPasswordCLI_ListEmpty(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	result := helper.RunPassword("list")
	require.True(t, result.Success(),
		"List on empty store should succeed: %s", result.Combined())
	assert.True(t, result.OutputContains("No") || result.OutputContains("no") ||
		result.OutputContains("(0)"),
		"Output should indicate no passwords found: %s", result.Combined())
}

// TestPasswordCLI_MutuallyExclusiveFlags verifies that providing both
// --password and --generate fails with an appropriate error.
func TestPasswordCLI_MutuallyExclusiveFlags(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	result := helper.RunPassword("add",
		"--name", "MutexTest",
		"--password", "manual",
		"--generate")
	assert.False(t, result.Success(),
		"Providing both --password and --generate should fail")
	assert.True(t, result.OutputContains("exclusive") || result.OutputContains("Exclusive") ||
		result.OutputContains("mutually"),
		"Error should mention mutual exclusivity: %s", result.Combined())
}

// TestPasswordCLI_NotesField verifies that optional --notes are stored and
// displayed in list output.
func TestPasswordCLI_NotesField(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	credName := "WithNotes"
	credNotes := "Production database credentials"

	result := helper.RunPassword("add",
		"--name", credName,
		"--password", "dbpass",
		"--notes", credNotes)
	require.True(t, result.Success(),
		"Add with --notes failed: %s", result.Combined())

	listResult := helper.RunPassword("list")
	require.True(t, listResult.Success(),
		"List failed: %s", listResult.Combined())
	assert.True(t, listResult.OutputContains(credName),
		"List should contain the password name: %s", listResult.Combined())
	assert.True(t, listResult.OutputContains(credNotes),
		"List should display the notes: %s", listResult.Combined())
}

// TestPasswordCLI_GetOutputIsPipeable verifies that the get command outputs
// only the raw password value without trailing newlines or decorative text,
// making it suitable for piping to other commands.
func TestPasswordCLI_GetOutputIsPipeable(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	credPassword := "pipeableSecret123"

	result := helper.AddPassword("PipeTest", credPassword)
	require.True(t, result.Success(),
		"Add failed: %s", result.Combined())

	getResult := helper.RunPassword("get", "PipeTest")
	require.True(t, getResult.Success(),
		"Get failed: %s", getResult.Combined())

	// The get command uses fmt.Print (no newline), so stdout should be
	// exactly the password value.
	assert.Equal(t, credPassword, getResult.Stdout,
		"Get output should be exactly the password value for piping")
}

// TestPasswordCLI_SpecialCharactersInPassword verifies that passwords with
// special characters, spaces, and shell metacharacters are stored and
// retrieved correctly.
func TestPasswordCLI_SpecialCharactersInPassword(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	specialPasswords := []struct {
		name     string
		password string
	}{
		{"Symbols", "p@$$w0rd!#%^&*()"},
		{"Spaces", "my secret pass word"},
		{"Unicode", "p\u00e4ssw\u00f6rd"},
	}

	for _, tc := range specialPasswords {
		t.Run(tc.name, func(t *testing.T) {
			result := helper.AddPassword(tc.name, tc.password)
			require.True(t, result.Success(),
				"Add %s failed: %s", tc.name, result.Combined())

			getResult := helper.RunPassword("get", tc.name)
			require.True(t, getResult.Success(),
				"Get %s failed: %s", tc.name, getResult.Combined())

			assert.Equal(t, tc.password, getResult.Stdout,
				"Password with special characters should round-trip correctly")
		})
	}
}

// TestPasswordCLI_DeleteAlias verifies that the 'delete' alias for remove
// works correctly.
func TestPasswordCLI_DeleteAlias(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	credName := "DeleteAliasTest"

	result := helper.AddPassword(credName, "pw")
	require.True(t, result.Success(),
		"Add failed: %s", result.Combined())

	// Use 'delete' alias.
	result = helper.RunPassword("delete", credName, "--force")
	require.True(t, result.Success(),
		"delete alias should work: %s", result.Combined())

	// Verify removal.
	listResult := helper.RunPassword("list")
	assert.False(t, listResult.OutputContains(credName),
		"Password should be removed via delete alias: %s", listResult.Combined())
}

// TestPasswordCLI_ListCountHeader verifies that the list output shows the
// correct count of stored passwords.
func TestPasswordCLI_ListCountHeader(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	// Add three passwords.
	for i, name := range []string{"Count1", "Count2", "Count3"} {
		result := helper.AddPassword(name, "pw"+intToString(i))
		require.True(t, result.Success(),
			"Add %s failed: %s", name, result.Combined())
	}

	listResult := helper.RunPassword("list")
	require.True(t, listResult.Success(),
		"List failed: %s", listResult.Combined())
	assert.True(t, listResult.OutputContains("(3)"),
		"List should show count of 3: %s", listResult.Combined())
}

// TestPasswordCLI_GenerateDefaultLength verifies that --generate without
// --length uses the default length of 32 characters.
func TestPasswordCLI_GenerateDefaultLength(t *testing.T) {
	helper := NewPasswordTestHelper(t)

	result := helper.AddGeneratedPassword("DefaultLen")
	require.True(t, result.Success(),
		"Add --generate failed: %s", result.Combined())

	getResult := helper.RunPassword("get", "DefaultLen")
	require.True(t, getResult.Success(),
		"Get failed: %s", getResult.Combined())

	password := strings.TrimSpace(getResult.Stdout)
	assert.Len(t, password, 32,
		"Default generated password should be 32 characters")
}
