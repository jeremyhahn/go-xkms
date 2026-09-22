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
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
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
		if cfg.Backends.AWSKMS != nil || cfg.ACME != nil || cfg.Trust != nil || cfg.Escrow != nil {
			t.Fatalf("pointer sections must stay nil when neither the file nor the environment sets a key in them: awskms=%v acme=%v trust=%v escrow=%v", cfg.Backends.AWSKMS, cfg.ACME, cfg.Trust, cfg.Escrow)
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

// TestLoad_IncludeLocalhostSANs pins the defaults-layer value of
// tls.include_localhost_sans and its environment path: a file that never
// mentions the key keeps the loopback SANs, one that sets it false drops
// them, and XKMS_TLS_INCLUDE_LOCALHOST_SANS=false wins over a file that
// says nothing (#140).
func TestLoad_IncludeLocalhostSANs(t *testing.T) {
	t.Run("defaults layer is true", func(t *testing.T) {
		cfg, err := Load(writeServerConfig(t, ""))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if !cfg.TLS.IncludeLocalhostSANs {
			t.Fatal("TLS.IncludeLocalhostSANs = false with no file key, want the defaults-layer true")
		}
	})

	t.Run("environment disables it", func(t *testing.T) {
		t.Setenv("XKMS_TLS_INCLUDE_LOCALHOST_SANS", "false")
		cfg, err := Load(writeServerConfig(t, ""))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.TLS.IncludeLocalhostSANs {
			t.Fatal("TLS.IncludeLocalhostSANs = true, want the environment's false over the defaults layer")
		}
	})
}

// TestLoad_AzureKVAllowLocalVaultURL pins the defaults-layer value of
// backends.azurekv.allow_local_vault_url: a file that never mentions the key
// resolves to false (refusing a local vault URL), a file that sets it true
// resolves to true, and XKMS_BACKENDS_AZUREKV_ALLOW_LOCAL_VAULT_URL=true
// wins over a file that says nothing (#140).
func TestLoad_AzureKVAllowLocalVaultURL(t *testing.T) {
	t.Run("defaults layer is false", func(t *testing.T) {
		cfg, err := Load(writeConfigBody(t, "", "  azurekv:\n    enabled: true\n    vault_url: \"https://myvault.vault.azure.net/\"\n"))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Backends.AzureKV == nil || cfg.Backends.AzureKV.AllowLocalVaultURL {
			t.Fatalf("Backends.AzureKV = %+v, want AllowLocalVaultURL false with no file key", cfg.Backends.AzureKV)
		}
	})

	t.Run("file enables it", func(t *testing.T) {
		cfg, err := Load(writeConfigBody(t, "", "  azurekv:\n    enabled: true\n    vault_url: \"https://myvault.vault.azure.net/\"\n    allow_local_vault_url: true\n"))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Backends.AzureKV == nil || !cfg.Backends.AzureKV.AllowLocalVaultURL {
			t.Fatalf("Backends.AzureKV = %+v, want AllowLocalVaultURL true from the file", cfg.Backends.AzureKV)
		}
	})

	t.Run("environment enables it over a file that says nothing", func(t *testing.T) {
		t.Setenv("XKMS_BACKENDS_AZUREKV_ALLOW_LOCAL_VAULT_URL", "true")
		cfg, err := Load(writeConfigBody(t, "", "  azurekv:\n    enabled: true\n    vault_url: \"https://myvault.vault.azure.net/\"\n"))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Backends.AzureKV == nil || !cfg.Backends.AzureKV.AllowLocalVaultURL {
			t.Fatalf("Backends.AzureKV = %+v, want AllowLocalVaultURL true from the environment", cfg.Backends.AzureKV)
		}
	})
}

// TestLoad_ACMEEnrollmentAllowLoopbackIdentifier pins the defaults-layer
// value of acme.enrollment.allow_loopback_identifier: a file that never
// mentions the key resolves to false, one that sets it true resolves to
// true, and XKMS_ACME_ENROLLMENT_ALLOW_LOOPBACK_IDENTIFIER=true wins over a
// file that says nothing (#140).
func TestLoad_ACMEEnrollmentAllowLoopbackIdentifier(t *testing.T) {
	t.Run("defaults layer is false", func(t *testing.T) {
		cfg, err := Load(writeConfigBody(t, "", ""))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.ACME != nil && cfg.ACME.Enrollment.AllowLoopbackIdentifier {
			t.Fatalf("ACME.Enrollment.AllowLoopbackIdentifier = true, want false with no file key")
		}
	})

	t.Run("environment enables it with no acme section in the file", func(t *testing.T) {
		t.Setenv("XKMS_ACME_ENROLLMENT_ALLOW_LOOPBACK_IDENTIFIER", "true")
		cfg, err := Load(writeConfigBody(t, "", ""))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.ACME == nil || !cfg.ACME.Enrollment.AllowLoopbackIdentifier {
			t.Fatalf("ACME = %+v, want Enrollment.AllowLoopbackIdentifier true from the environment", cfg.ACME)
		}
	})
}

// writeCAPasswordConfig writes a valid daemon configuration whose ca.identity
// carries the given per-key and keystore-level password lines (go-xkms#41),
// mirroring the shape of the shipped configs/xkmsd-dev.yaml ca: block.
func writeCAPasswordConfig(t *testing.T, keyPasswordLine, keystorePasswordLine string) string {
	t.Helper()

	content := `
server:
  rest_port: 8443
  grpc_port: 9443

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

ca:
  identity:
    - subject:
        cn: "Test Root CA"
      valid: 10
      keys:
        - algorithm: "ECDSA"
          ecc:
            curve: "P-256"
` + keyPasswordLine + `
      keystore-type: "software"
      is-root: true
      keystores:
        software:
` + keystorePasswordLine + `
  selected-ca: 0
  default-validity-days: 365
`
	path := filepath.Join(t.TempDir(), "xkmsd.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestLoad_CAKeyPassword_LoadsIntoSecretValueRaw proves that a plain-string
// ca.identity[*].keys[*].password still loads through Load's mapstructure
// chain into the field's SecretValue.Raw, unresolved — Load itself never
// resolves a secret reference, only stringToSecretValueHookFunc's decode
// (go-xkms#41).
func TestLoad_CAKeyPassword_LoadsIntoSecretValueRaw(t *testing.T) {
	path := writeCAPasswordConfig(t,
		`          password: "per-key-secret"`,
		`          password: "keystore-secret"`,
	)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.CA.Identity) != 1 || len(cfg.CA.Identity[0].Keys) != 1 {
		t.Fatalf("CA.Identity = %+v, want exactly one identity with one key", cfg.CA.Identity)
	}

	key := cfg.CA.Identity[0].Keys[0]
	if key.Password.Raw != "per-key-secret" {
		t.Fatalf("Keys[0].Password.Raw = %q, want %q", key.Password.Raw, "per-key-secret")
	}
	if key.Password.Strategy != "" {
		t.Fatalf("Keys[0].Password.Strategy = %q, want empty (unresolved — Load never resolves)", key.Password.Strategy)
	}

	software := cfg.CA.Identity[0].Keystores.Software
	if software == nil || software.Password.Raw != "keystore-secret" {
		t.Fatalf("Keystores.Software.Password.Raw = %+v, want %q", software, "keystore-secret")
	}
}

// TestLoad_CAKeyPassword_CredentialReferenceLoadsVerbatim proves that a
// "credential://..." reference string loads verbatim into Raw, exactly as a
// literal password does — Load's decode hook only stores the reference, it
// never dereferences it.
func TestLoad_CAKeyPassword_CredentialReferenceLoadsVerbatim(t *testing.T) {
	path := writeCAPasswordConfig(t,
		`          password: "credential://ca-key-pw"`,
		`          password: "credential://ca-keystore-pw"`,
	)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got := cfg.CA.Identity[0].Keys[0].Password.Raw; got != "credential://ca-key-pw" {
		t.Fatalf("Keys[0].Password.Raw = %q, want the URI verbatim", got)
	}
	if got := cfg.CA.Identity[0].Keystores.Software.Password.Raw; got != "credential://ca-keystore-pw" {
		t.Fatalf("Keystores.Software.Password.Raw = %q, want the URI verbatim", got)
	}
}

// writeClusterCAKeyPassphraseConfig writes a valid daemon configuration whose
// cluster.raft_enrollment carries the given ca_key_passphrase line, mirroring
// writeCAPasswordConfig's shape for the same stringToSecretValueHookFunc path
// (go-xkms#587).
func writeClusterCAKeyPassphraseConfig(t *testing.T, passphraseLine string) string {
	t.Helper()

	content := `
server:
  rest_port: 8443
  grpc_port: 9443

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

cluster:
  enabled: true
  node_id: 1
  raft_address: "10.0.0.1:63001"
  peers: "1=10.0.0.1:63001"
  raft_enrollment:
    ca_key_protection: "passphrase"
` + passphraseLine + `
`
	path := filepath.Join(t.TempDir(), "xkmsd.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestLoad_ClusterCAKeyPassphrase_LoadsIntoSecretValueRaw proves that a
// plain-string cluster.raft_enrollment.ca_key_passphrase loads through Load's
// mapstructure chain into the field's SecretValue.Raw, unresolved — the same
// contract TestLoad_CAKeyPassword_LoadsIntoSecretValueRaw proves for the CA
// identity passwords (go-xkms#587, go-xkms#41).
func TestLoad_ClusterCAKeyPassphrase_LoadsIntoSecretValueRaw(t *testing.T) {
	path := writeClusterCAKeyPassphraseConfig(t, `    ca_key_passphrase: "cluster-ca-secret"`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	sv := cfg.Cluster.RaftEnrollment.CAKeyPassphrase
	if sv.Raw != "cluster-ca-secret" {
		t.Fatalf("CAKeyPassphrase.Raw = %q, want %q", sv.Raw, "cluster-ca-secret")
	}
	if sv.Strategy != "" {
		t.Fatalf("CAKeyPassphrase.Strategy = %q, want empty (unresolved — Load never resolves)", sv.Strategy)
	}
}

// TestLoad_ClusterCAKeyPassphrase_CredentialReferenceLoadsVerbatim proves
// that a "credential://..." reference loads verbatim into Raw, exactly as a
// literal passphrase does — Load's decode hook only stores the reference, it
// never dereferences it. Server.resolveClusterCAKeyPassphrase performs the
// actual resolution at cluster CA key-strategy setup.
func TestLoad_ClusterCAKeyPassphrase_CredentialReferenceLoadsVerbatim(t *testing.T) {
	path := writeClusterCAKeyPassphraseConfig(t, `    ca_key_passphrase: "credential://cluster-ca-pw"`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got := cfg.Cluster.RaftEnrollment.CAKeyPassphrase.Raw; got != "credential://cluster-ca-pw" {
		t.Fatalf("CAKeyPassphrase.Raw = %q, want the URI verbatim", got)
	}
}

// TestStringToSecretValueHookFunc exercises the mapstructure decode hook
// directly: a string decoding into a SecretValue field stores the reference
// unresolved in Raw, and every other type combination passes data through
// unchanged so the hook composes safely with mapstructure's other hooks and
// its default struct/scalar decoding (go-xkms#41).
func TestStringToSecretValueHookFunc(t *testing.T) {
	secretValueRT := reflect.TypeOf(types.SecretValue{})
	stringRT := reflect.TypeOf("")
	intRT := reflect.TypeOf(0)

	t.Run("string to SecretValue stores Raw unresolved", func(t *testing.T) {
		out, err := stringToSecretValueHookFunc(stringRT, secretValueRT, "credential://x")
		if err != nil {
			t.Fatalf("stringToSecretValueHookFunc() error = %v", err)
		}
		sv, ok := out.(types.SecretValue)
		if !ok {
			t.Fatalf("stringToSecretValueHookFunc() returned %T, want types.SecretValue", out)
		}
		if sv.Raw != "credential://x" || sv.Strategy != "" {
			t.Fatalf("got SecretValue{Raw: %q, Strategy: %q}, want Raw=credential://x, Strategy empty", sv.Raw, sv.Strategy)
		}
	})

	t.Run("non-SecretValue destination passes data through", func(t *testing.T) {
		out, err := stringToSecretValueHookFunc(stringRT, stringRT, "unchanged")
		if err != nil {
			t.Fatalf("stringToSecretValueHookFunc() error = %v", err)
		}
		if out != "unchanged" {
			t.Fatalf("stringToSecretValueHookFunc() = %v, want data passed through unchanged", out)
		}
	})

	t.Run("non-string source passes data through", func(t *testing.T) {
		out, err := stringToSecretValueHookFunc(intRT, secretValueRT, 42)
		if err != nil {
			t.Fatalf("stringToSecretValueHookFunc() error = %v", err)
		}
		if out != 42 {
			t.Fatalf("stringToSecretValueHookFunc() = %v, want data passed through unchanged", out)
		}
	})
}

// TestWalkYAMLKeys_SecretValueTreatedAsLeaf proves walkYAMLKeys registers a
// types.SecretValue field as one leaf key rather than descending into its
// unexported enclave field and registering zero keys for it — the defect
// that would silently drop a SecretValue field from environment-variable
// resolution (go-xkms#41). Today's two SecretValue fields live inside
// ca.Identity, itself under a slice walkYAMLKeys never descends into, so this
// exercises the guard directly against a struct shaped to need it.
func TestWalkYAMLKeys_SecretValueTreatedAsLeaf(t *testing.T) {
	type withSecret struct {
		Name   string            `yaml:"name"`
		Secret types.SecretValue `yaml:"secret"`
	}

	var got []string
	visit := func(key ...string) error {
		got = append(got, key[0])
		return nil
	}

	if err := walkYAMLKeys(reflect.TypeOf(withSecret{}), "", visit); err != nil {
		t.Fatalf("walkYAMLKeys() error = %v", err)
	}

	want := []string{"name", "secret"}
	if len(got) != len(want) {
		t.Fatalf("walkYAMLKeys() visited %v, want exactly %v (secret must be one leaf, not zero keys from descending into it)", got, want)
	}
	for i, k := range want {
		if got[i] != k {
			t.Fatalf("walkYAMLKeys() visited %v, want %v", got, want)
		}
	}
}
