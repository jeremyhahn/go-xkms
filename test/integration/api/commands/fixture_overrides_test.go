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
	"strings"
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

// TestAPIFixtureProvidesClientIdentity pins the client identity the API stack
// hands the CLI matrix runner (Codex round 5 P1-1 on #2324): the server asks
// for a client certificate, and the integration-tests service presents the
// first-boot admin credential that xkmsd writes into datastore.path, read
// from the xkms-server data volume mounted read-only.
func TestAPIFixtureProvidesClientIdentity(t *testing.T) {
	rawCfg, err := os.ReadFile(filepath.Join("..", "config.test.yaml"))
	require.NoError(t, err)

	var cfg struct {
		TLS struct {
			ClientAuth string `yaml:"client_auth"`
		} `yaml:"tls"`
		Datastore struct {
			Path string `yaml:"path"`
		} `yaml:"datastore"`
	}
	require.NoError(t, yaml.Unmarshal(rawCfg, &cfg))
	require.NotEmpty(t, cfg.Datastore.Path, "config.test.yaml datastore.path")

	assert.Equal(t, "request", cfg.TLS.ClientAuth,
		"config.test.yaml tls.client_auth must ask for the runner's client certificate")

	rawCompose, err := os.ReadFile(filepath.Join("..", "docker-compose.yml"))
	require.NoError(t, err)

	var compose struct {
		Services map[string]struct {
			Volumes     []string `yaml:"volumes"`
			Environment []string `yaml:"environment"`
		} `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(rawCompose, &compose))

	server, ok := compose.Services["xkms-server"]
	require.True(t, ok, "docker-compose.yml has no xkms-server service")
	runner, ok := compose.Services["integration-tests"]
	require.True(t, ok, "docker-compose.yml has no integration-tests service")

	// The named volume xkms-server mounts at the directory holding datastore.path.
	var volume, serverMount string
	for _, v := range server.Volumes {
		parts := strings.Split(v, ":")
		if len(parts) < 2 {
			continue
		}
		mount := strings.TrimSuffix(parts[1], "/")
		if strings.HasPrefix(cfg.Datastore.Path, mount+"/") || cfg.Datastore.Path == mount {
			volume, serverMount = parts[0], mount
			break
		}
	}
	require.NotEmpty(t, volume, "xkms-server mounts no volume holding datastore.path %q", cfg.Datastore.Path)

	// The integration-tests service mounts the same volume read-only.
	var runnerMount string
	for _, v := range runner.Volumes {
		parts := strings.Split(v, ":")
		if len(parts) == 3 && parts[0] == volume && parts[2] == "ro" {
			runnerMount = strings.TrimSuffix(parts[1], "/")
			break
		}
	}
	require.NotEmpty(t, runnerMount, "integration-tests must mount volume %q read-only (:ro)", volume)

	env := map[string]string{}
	for _, e := range runner.Environment {
		if k, v, found := strings.Cut(e, "="); found {
			env[k] = v
		}
	}
	dataDir := runnerMount + strings.TrimPrefix(cfg.Datastore.Path, serverMount)
	assert.Equal(t, dataDir+"/admin-cert.pem", env["KEYSTORE_TLS_CERT"],
		"integration-tests KEYSTORE_TLS_CERT must name the first-boot admin certificate")
	assert.Equal(t, dataDir+"/admin-key.pem", env["KEYSTORE_TLS_KEY"],
		"integration-tests KEYSTORE_TLS_KEY must name the first-boot admin key")
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
