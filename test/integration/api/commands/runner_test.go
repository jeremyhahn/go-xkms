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

package commands

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// argvString joins built arguments so assertions can talk about adjacency,
// which is what distinguishes a bare boolean flag from one given a value.
func argvString(args []string) string {
	return strings.Join(args, " ")
}

// TestBuildCommandArgsEmitsBooleanFlagsBare covers the flag form that had no
// working support.
//
// The runner used to decide a flag was boolean by comparing its name against a
// hardcoded pair, "dealer" and "local" -- neither of which appears in any
// command definition in this package. Every boolean argument therefore fell
// through to the value-carrying branch, where an empty Value meant the flag was
// dropped entirely and a non-empty one meant it was passed a value the CLI flag
// does not accept. A command definition asking for --exportable silently tested
// a key that was not exportable.
//
// This matters more than an ordinary helper because BuildCommandArgs constructs
// every CLI invocation the multi-protocol suite makes: a defect here does not
// fail the suite, it quietly changes what the suite covers.
func TestBuildCommandArgsEmitsBooleanFlagsBare(t *testing.T) {
	runner := &TestRunner{}

	cmd := CommandDefinition{
		Name:    "key-generate-bool",
		Command: []string{"key", "generate"},
		RequiredArgs: []ArgDefinition{
			{Flag: "", Value: "some-key", Description: "Key ID", IsPositional: true},
		},
		OptionalArgs: []ArgDefinition{
			{Flag: "key-type", Value: "symmetric", Description: "Key type"},
			{Flag: "exportable", Value: "", Description: "Allow export", IsBoolean: true},
			{Flag: "sensitive", Value: "", Description: "Never reveal plaintext", IsBoolean: true},
		},
	}

	args := runner.BuildCommandArgs(cmd, nil)
	argv := argvString(args)

	assert.Contains(t, args, "--exportable",
		"a boolean flag with an empty Value must still be emitted; an empty Value is "+
			"the normal case for a flag that carries none")
	assert.Contains(t, args, "--sensitive")

	assert.NotContains(t, argv, "--exportable --sensitive=",
		"neither boolean flag may be given a value")
	for i, arg := range args {
		if arg != "--exportable" && arg != "--sensitive" {
			continue
		}
		if i+1 < len(args) {
			assert.True(t, strings.HasPrefix(args[i+1], "--"),
				"%s must be followed by another flag or nothing, not a value: %q", arg, args[i+1])
		}
	}

	// The value-carrying flags must be unaffected.
	assert.Contains(t, argv, "--key-type symmetric")
	assert.Contains(t, args, "some-key", "the positional key ID must survive")
}

// TestBuildCommandArgsStillPassesValuedFlags is the counterweight: the boolean
// branch must not swallow flags that do take a value.
func TestBuildCommandArgsStillPassesValuedFlags(t *testing.T) {
	runner := &TestRunner{}

	cmd := CommandDefinition{
		Name:    "key-generate-valued",
		Command: []string{"key", "generate"},
		OptionalArgs: []ArgDefinition{
			{Flag: "key-type", Value: "rsa", Description: "Key type"},
			{Flag: "key-size", Value: "2048", Description: "Key size"},
		},
	}

	argv := argvString(runner.BuildCommandArgs(cmd, nil))
	assert.Contains(t, argv, "--key-type rsa")
	assert.Contains(t, argv, "--key-size 2048")
}

// TestBuildCommandArgsOverrideReplacesValue pins the override path, which is how
// the suite gives each run unique key identifiers.
func TestBuildCommandArgsOverrideReplacesValue(t *testing.T) {
	runner := &TestRunner{}

	cmd := CommandDefinition{
		Name:    "key-generate-override",
		Command: []string{"key", "generate"},
		OptionalArgs: []ArgDefinition{
			{Flag: "key-size", Value: "2048", Description: "Key size"},
		},
	}

	argv := argvString(runner.BuildCommandArgs(cmd, map[string]string{"key-size": "4096"}))
	assert.Contains(t, argv, "--key-size 4096")
	assert.NotContains(t, argv, "2048")
}

// TestKeyCommandsCoverTheProtectionFlags checks the command set actually
// exercises both protection attributes.
//
// They are the only key attributes the CLI can set that change what the daemon
// will later release, and they travel a request field that every transport has
// to map for itself -- the failure mode a multi-protocol suite exists to catch.
func TestKeyCommandsCoverTheProtectionFlags(t *testing.T) {
	var sawExportable, sawSensitive bool

	for _, cmd := range KeyCommands() {
		for _, arg := range cmd.OptionalArgs {
			switch arg.Flag {
			case "exportable":
				require.True(t, arg.IsBoolean, "--exportable takes no value")
				sawExportable = true
			case "sensitive":
				require.True(t, arg.IsBoolean, "--sensitive takes no value")
				sawSensitive = true
			}
		}
	}

	assert.True(t, sawExportable, "no command generates an exportable key")
	assert.True(t, sawSensitive, "no command generates a sensitive key, so CKA_SENSITIVE "+
		"never crosses any transport in this suite")
}

// TestEveryKeyIDIsUniquified catches the fixture defect that made two newly
// added commands fail on five of the six protocols.
//
// RunAllCommandsForProtocol replaces each command's literal key identifier with
// a per-run unique one, but only for identifiers listed in uniqueKeyIDs. Every
// protocol runs in the same process against the same daemon, so a command whose
// identifier is missing from that map creates its key on the first protocol and
// then fails on the rest with "key already exists" -- a failure that looks like
// a protocol-specific defect and is not one.
//
// Only creating commands need an entry: key-info, key-sign and key-delete
// deliberately name a key another command created, and their identifiers are
// mapped to that same unique value.
func TestEveryKeyIDIsUniquified(t *testing.T) {
	uniquified := uniqueKeyIDs(1)

	for _, cmd := range AllCommands() {
		for _, arg := range cmd.RequiredArgs {
			if arg.Description != "Key ID" || arg.Value == "" {
				continue
			}
			assert.Contains(t, uniquified, arg.Value,
				"command %q names key ID %q, which uniqueKeyIDs does not map; it will be "+
					"created by the first protocol and rejected by every protocol after it",
				cmd.Name, arg.Value)
		}
	}
}
