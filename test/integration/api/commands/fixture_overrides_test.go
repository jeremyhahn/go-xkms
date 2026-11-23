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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// fixtureStartableSealStrategies are the credentials.seal_strategy values
// pkg/server/platform_store.go (initializePlatformStore) starts with on the
// compose fixture: "manual" (also the empty default) and "barrier" skip the
// platform store. Every other strategy needs a source or device the fixture
// does not have (passphrase and the KMS/PIN strategies are refused with
// ErrPlatformStoreStrategyUnavailable; tpm2 needs an enrolled Platform SRK).
var fixtureStartableSealStrategies = map[string]bool{
	"":        true,
	"manual":  true,
	"barrier": true,
}

func TestAPIFixtureSealStrategyIsSupported(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "config.test.yaml"))
	require.NoError(t, err)

	var cfg struct {
		Credentials struct {
			SealStrategy string `yaml:"seal_strategy"`
		} `yaml:"credentials"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &cfg))

	assert.True(t, fixtureStartableSealStrategies[cfg.Credentials.SealStrategy],
		"config.test.yaml credentials.seal_strategy %q makes xkmsd abort startup",
		cfg.Credentials.SealStrategy)
}

func TestCAIssueCommonNameDiffersPerProtocol(t *testing.T) {
	var caIssue CommandDefinition
	for _, cmd := range AllCommands() {
		if cmd.Name == "ca-issue" {
			caIssue = cmd
		}
	}
	require.Equal(t, "ca-issue", caIssue.Name, "ca-issue command not defined")

	runner := &TestRunner{}
	runID := int64(42)
	keyIDs := uniqueKeyIDs(runID)
	workDir := t.TempDir()

	cn := func(protocol ProtocolType) string {
		argv := runner.BuildCommandArgs(caIssue,
			commandOverrides(caIssue, protocol, runID, keyIDs, workDir))
		for i := 0; i+1 < len(argv); i++ {
			if argv[i] == "--cn" {
				return argv[i+1]
			}
		}
		t.Fatalf("ca-issue argv has no --cn: %v", argv)
		return ""
	}

	rest, grpc := cn(ProtocolREST), cn(ProtocolGRPC)
	assert.NotEqual(t, rest, grpc, "ca-issue sends the same --cn on two protocols")
}
