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

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeServerConfig writes a minimal valid daemon configuration whose server
// section carries the given lines and returns its path. An empty serverLines
// omits server.host so the defaults layer is what Load resolves.
func writeServerConfig(t *testing.T, serverLines string) string {
	t.Helper()
	return writeConfigBody(t, serverLines, "")
}

// writeConfigBody is writeServerConfig with extra lines under `backends:`,
// for tests that need a pointer section declared or omitted.
func writeConfigBody(t *testing.T, serverLines, backendsLines string) string {
	t.Helper()

	content := `
server:
  rest_port: 8443
  grpc_port: 9443
` + serverLines + `
protocols:
  rest: true
  grpc: true

logging:
  level: "info"
  format: "json"

tls:
  enabled: true

auth:
  enabled: false

storage:
  backend: "qrdb"
  path: "/data"

default_backend: "pkcs8"

backends:
  pkcs8:
    enabled: true
    path: "/data/pkcs8"
` + backendsLines
	path := filepath.Join(t.TempDir(), "xkmsd.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestLoad_ServerHost_DefaultsLayer proves a file that never mentions
// server.host resolves to the defaults layer, not to whatever the struct's
// zero value happens to be.
func TestLoad_ServerHost_DefaultsLayer(t *testing.T) {
	cfg, err := Load(writeServerConfig(t, ""))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.Host != DefaultServerHost {
		t.Fatalf("Server.Host = %q, want defaults layer %q", cfg.Server.Host, DefaultServerHost)
	}
	if Defaults().Server.Host != DefaultServerHost {
		t.Fatalf("Defaults().Server.Host = %q, want %q", Defaults().Server.Host, DefaultServerHost)
	}
}

// TestLoad_ServerHost_FileOverridesDefaults proves the file layer sits above
// the defaults layer.
func TestLoad_ServerHost_FileOverridesDefaults(t *testing.T) {
	cfg, err := Load(writeServerConfig(t, `  host: "10.0.0.5"`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.Host != "10.0.0.5" {
		t.Fatalf("Server.Host = %q, want file value 10.0.0.5", cfg.Server.Host)
	}
}

// TestLoad_ServerHost_EnvOverridesFile proves the canonical XKMS_SERVER_HOST
// variable sits above the file layer.
func TestLoad_ServerHost_EnvOverridesFile(t *testing.T) {
	t.Setenv("XKMS_SERVER_HOST", "10.0.0.6")

	cfg, err := Load(writeServerConfig(t, `  host: "10.0.0.5"`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.Host != "10.0.0.6" {
		t.Fatalf("Server.Host = %q, want env value 10.0.0.6", cfg.Server.Host)
	}
}

// TestLoad_ServerHost_EnvWithoutFileKey proves the environment resolves a key
// the file omits: the defaults layer registers every key with viper, so env
// resolution never depends on the file mentioning it.
func TestLoad_ServerHost_EnvWithoutFileKey(t *testing.T) {
	t.Setenv("XKMS_SERVER_HOST", "10.0.0.7")

	cfg, err := Load(writeServerConfig(t, ""))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.Host != "10.0.0.7" {
		t.Fatalf("Server.Host = %q, want env value 10.0.0.7", cfg.Server.Host)
	}
}

// TestLoad_ServerHost_LegacyAlias proves the pre-viper XKMS_HOST name still
// resolves server.host, and that the canonical name wins when both are set.
func TestLoad_ServerHost_LegacyAlias(t *testing.T) {
	t.Run("alias alone", func(t *testing.T) {
		t.Setenv("XKMS_HOST", "10.0.0.8")

		cfg, err := Load(writeServerConfig(t, `  host: "10.0.0.5"`))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Server.Host != "10.0.0.8" {
			t.Fatalf("Server.Host = %q, want legacy alias value 10.0.0.8", cfg.Server.Host)
		}
	})

	t.Run("canonical wins over alias", func(t *testing.T) {
		t.Setenv("XKMS_HOST", "10.0.0.8")
		t.Setenv("XKMS_SERVER_HOST", "10.0.0.9")

		cfg, err := Load(writeServerConfig(t, `  host: "10.0.0.5"`))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Server.Host != "10.0.0.9" {
			t.Fatalf("Server.Host = %q, want canonical value 10.0.0.9", cfg.Server.Host)
		}
	})
}

// TestLoad_CanonicalEnvResolvesEveryKey proves the binding is generic: a
// server key that has no alias resolves through XKMS_<SECTION>_<KEY> with a
// typed conversion, so later remediation slices add nothing but aliases.
func TestLoad_CanonicalEnvResolvesEveryKey(t *testing.T) {
	t.Setenv("XKMS_SERVER_GRPC_PORT", "9555")

	cfg, err := Load(writeServerConfig(t, ""))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.GRPCPort != 9555 {
		t.Fatalf("Server.GRPCPort = %d, want env value 9555", cfg.Server.GRPCPort)
	}
}

// TestLoad_EnvValueOfWrongTypeIsRejected proves a value that cannot decode
// into the field's type fails Load instead of being silently dropped.
func TestLoad_EnvValueOfWrongTypeIsRejected(t *testing.T) {
	t.Setenv("XKMS_SERVER_GRPC_PORT", "not-a-port")

	cfg, err := Load(writeServerConfig(t, ""))
	if err == nil {
		t.Fatal("Load() error = nil, want a decode error for a non-numeric port")
	}
	if cfg != nil {
		t.Fatalf("Load() = %+v, want nil on error", cfg)
	}
}

// TestLoad_MalformedFileIsRejected proves the viper-backed reader still
// surfaces a parse error for a file that is not YAML.
func TestLoad_MalformedFileIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xkmsd.yaml")
	if err := os.WriteFile(path, []byte("server: [unclosed"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want a parse error")
	}
	if cfg != nil {
		t.Fatalf("Load() = %+v, want nil on error", cfg)
	}
}

// TestCanonicalEnvName pins the key-to-variable rendering the aliases table
// and the documentation rely on.
func TestCanonicalEnvName(t *testing.T) {
	cases := map[string]string{
		"server.host":      "XKMS_SERVER_HOST",
		"server.rest_port": "XKMS_SERVER_REST_PORT",
		"logging.level":    "XKMS_LOGGING_LEVEL",
	}
	for key, want := range cases {
		if got := canonicalEnvName(key); got != want {
			t.Errorf("canonicalEnvName(%q) = %q, want %q", key, got, want)
		}
	}
}

// TestLoad_LegacyLadderCedesToCanonicalName proves the documented rule for
// every name the legacy ladder owns: where both the canonical XKMS_<SECTION>_<KEY> form and the
// legacy form are set, the canonical form wins. Before this the ladder ran
// after viper and over its result, so the legacy name won silently and an
// operator migrating to the dotted names who left an old variable in a unit
// file got the old value.
func TestLoad_LegacyLadderCedesToCanonicalName(t *testing.T) {
	t.Run("rest port: canonical over legacy", func(t *testing.T) {
		t.Setenv("XKMS_SERVER_REST_PORT", "1")
		t.Setenv("XKMS_REST_PORT", "9999")

		cfg, err := Load(writeServerConfig(t, ""))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Server.RESTPort != 1 {
			t.Fatalf("Server.RESTPort = %d, want the canonical value 1 over the legacy 9999", cfg.Server.RESTPort)
		}
	})

	t.Run("log level: canonical over legacy", func(t *testing.T) {
		t.Setenv("XKMS_LOGGING_LEVEL", "debug")
		t.Setenv("XKMS_LOG_LEVEL", "error")

		cfg, err := Load(writeServerConfig(t, ""))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Logging.Level != "debug" {
			t.Fatalf("Logging.Level = %q, want the canonical value debug over the legacy error", cfg.Logging.Level)
		}
	})

	t.Run("legacy alone still applies", func(t *testing.T) {
		t.Setenv("XKMS_REST_PORT", "9999")

		cfg, err := Load(writeServerConfig(t, ""))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Server.RESTPort != 9999 {
			t.Fatalf("Server.RESTPort = %d, want the legacy value 9999 with no canonical set", cfg.Server.RESTPort)
		}
	})

	t.Run("a legacy name that is the canonical spelling is still read", func(t *testing.T) {
		// rng.tpm2 is a pointer section the file omits, so viper does not
		// resolve XKMS_RNG_TPM2_DEVICE for it; the ladder must not mistake
		// its own name for a competing canonical form and drop the value.
		t.Setenv("XKMS_RNG_TPM2_DEVICE", "/dev/tpmrm0")

		cfg, err := Load(writeServerConfig(t, ""))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.RNG.TPM2 == nil || cfg.RNG.TPM2.Device != "/dev/tpmrm0" {
			t.Fatalf("RNG.TPM2 = %+v, want Device /dev/tpmrm0 from the ladder", cfg.RNG.TPM2)
		}
	})
}

// TestLegacyEnv pins the helper's three cases directly.
func TestLegacyEnv(t *testing.T) {
	t.Run("canonical set: legacy yields nothing", func(t *testing.T) {
		t.Setenv("XKMS_SERVER_REST_PORT", "1")
		t.Setenv("XKMS_REST_PORT", "2")
		if got := legacyEnv("XKMS_REST_PORT", "server.rest_port"); got != "" {
			t.Fatalf("legacyEnv = %q, want empty when the canonical name is set", got)
		}
	})
	t.Run("canonical unset: legacy read", func(t *testing.T) {
		t.Setenv("XKMS_REST_PORT", "2")
		if got := legacyEnv("XKMS_REST_PORT", "server.rest_port"); got != "2" {
			t.Fatalf("legacyEnv = %q, want 2", got)
		}
	})
	t.Run("legacy is the canonical spelling: read as is", func(t *testing.T) {
		t.Setenv("XKMS_STORAGE_BACKEND", "memory")
		if got := legacyEnv("XKMS_STORAGE_BACKEND", "storage.backend"); got != "memory" {
			t.Fatalf("legacyEnv = %q, want memory", got)
		}
	})
}

// TestLoad_EmptyEnvIsAValue proves a present-but-empty variable is honoured:
// XKMS_SERVER_HOST="" is the documented way to clear a pinned host and bind
// every interface, and it must win over the file and over the legacy alias
// exactly as a non-empty value does. Before this viper read an empty
// variable as unset and the daemon stayed on the file's host.
func TestLoad_EmptyEnvIsAValue(t *testing.T) {
	t.Run("empty canonical over the file host", func(t *testing.T) {
		t.Setenv("XKMS_SERVER_HOST", "")

		cfg, err := Load(writeServerConfig(t, `  host: "10.0.0.5"`))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Server.Host != "" {
			t.Fatalf("Server.Host = %q, want the empty env value over the file", cfg.Server.Host)
		}
	})

	t.Run("empty canonical over the legacy alias", func(t *testing.T) {
		t.Setenv("XKMS_HOST", "10.0.0.8")
		t.Setenv("XKMS_SERVER_HOST", "")

		cfg, err := Load(writeServerConfig(t, `  host: "10.0.0.5"`))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Server.Host != "" {
			t.Fatalf("Server.Host = %q, want the empty canonical value over XKMS_HOST", cfg.Server.Host)
		}
	})

	t.Run("empty canonical silences the legacy ladder", func(t *testing.T) {
		t.Setenv("XKMS_BOOTSTRAP_DANE_HOSTNAME", "")
		t.Setenv("XKMS_DANE_HOSTNAME", "kms.example.com")

		cfg, err := Load(writeServerConfig(t, ""))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Bootstrap.DANE.Hostname != "" {
			t.Fatalf("Bootstrap.DANE.Hostname = %q, want the empty canonical value; the ladder must not fill it back in", cfg.Bootstrap.DANE.Hostname)
		}
	})

	t.Run("an empty legacy alias is ignored", func(t *testing.T) {
		// A unit file carrying XKMS_HOST= must not clear a pinned host:
		// empty-as-value is a property of the canonical names only.
		t.Setenv("XKMS_HOST", "")

		cfg, err := Load(writeServerConfig(t, `  host: "10.0.0.5"`))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Server.Host != "10.0.0.5" {
			t.Fatalf("Server.Host = %q, want the file host: an empty legacy variable is an absence", cfg.Server.Host)
		}
	})

	t.Run("an empty value a field cannot hold still fails Load", func(t *testing.T) {
		t.Setenv("XKMS_LOGGING_LEVEL", "")

		if _, err := Load(writeServerConfig(t, "")); err == nil {
			t.Fatal("expected Load to reject an empty log level: an empty variable is a value, and this field validates it")
		}
	})
}

// TestLoad_PointerSectionResolvesFromEnv pins invariant 3 of
// docs/xkmsd-configuration/engineering.md for a section the defaults layer
// does not register: a canonical variable under a pointer section
// (backends.awskms here; webauthn, ca, acme, attestation and trust are bound
// the same way) resolves whether or not the file declares the section,
// because registerEnvKeys binds every key of the tree by name. Before this
// viper knew only the keys the defaults layer or the file had set, so an
// env-only value under an omitted section was silently ignored, and even a
// declared section did not help unless the file set that very key.
func TestLoad_PointerSectionResolvesFromEnv(t *testing.T) {
	t.Run("section omitted: the variable creates it", func(t *testing.T) {
		t.Setenv("XKMS_BACKENDS_AWSKMS_REGION", "us-west-2")

		cfg, err := Load(writeConfigBody(t, "", ""))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Backends.AWSKMS == nil || cfg.Backends.AWSKMS.Region != "us-west-2" {
			t.Fatalf("Backends.AWSKMS = %+v, want Region us-west-2 from the environment with no awskms section in the file", cfg.Backends.AWSKMS)
		}
	})

	t.Run("section declared without the key: the variable resolves", func(t *testing.T) {
		t.Setenv("XKMS_BACKENDS_AWSKMS_REGION", "us-west-2")

		cfg, err := Load(writeConfigBody(t, "", "  awskms:\n    enabled: false\n"))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Backends.AWSKMS == nil || cfg.Backends.AWSKMS.Region != "us-west-2" || cfg.Backends.AWSKMS.Enabled {
			t.Fatalf("Backends.AWSKMS = %+v, want Region us-west-2 and Enabled false", cfg.Backends.AWSKMS)
		}
	})

	t.Run("nothing set: the section stays nil", func(t *testing.T) {
		cfg, err := Load(writeConfigBody(t, "", ""))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Backends.AWSKMS != nil || cfg.ACME != nil || cfg.Trust != nil {
			t.Fatalf("pointer sections must stay nil when neither the file nor the environment sets a key in them: awskms=%v acme=%v trust=%v", cfg.Backends.AWSKMS, cfg.ACME, cfg.Trust)
		}
	})

	t.Run("a hyphenated key maps to an underscored name", func(t *testing.T) {
		// trust.server-url lives under the scopes map, which viper cannot
		// bind by name, so the mapping is pinned on the name itself.
		if got := canonicalEnvName("trust.server-url"); got != "XKMS_TRUST_SERVER_URL" {
			t.Fatalf("canonicalEnvName(trust.server-url) = %q, want XKMS_TRUST_SERVER_URL", got)
		}
	})
}
