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
	"reflect"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// secretValueType is the reflect.Type of a types.SecretValue field, used to
// give it leaf-value treatment in the mapstructure decode hook and the
// env-key walk below — both of which otherwise treat any struct-kinded field
// as a section to descend into. SecretValue is a struct on the wire, but on
// the wire it is a single scalar reference string (a literal password or a
// "credential://..." URI), never a nested document section.
var secretValueType = reflect.TypeOf(types.SecretValue{})

// envPrefix is the environment namespace of the daemon: the product name, so
// server.host is XKMS_SERVER_HOST (nesting joined by underscores).
const envPrefix = "XKMS"

// removedConfigFields maps a removed dotted config key to the replacement an
// operator should use instead. It is consulted by Load immediately after the
// file and environment are merged (and before Unmarshal, which mapstructure
// would otherwise silently drop the key for since it names no struct field
// any more): unknown fields are never silently ignored, so a config or
// environment variable still naming a removed field fails closed with
// *RemovedFieldError instead of loading with a value nothing reads.
var removedConfigFields = map[string]string{
	"barrier.passphrase": "there is no config-sourced boot-time unseal secret any more " +
		"(matching go-qrdb's own SealConfig, which carries none either). Supply the passphrase " +
		"or Shamir quorum at Initialize/Unseal time via `xkmsctl barrier unseal` (or `unseal-shares`) " +
		"or the equivalent API call, or configure a hardware seal strategy (barrier.strategy: " +
		"\"tpm2\"/\"pkcs11\") for unattended auto-unseal",
	"acme.reuse_tls": "the ACME listener always uses its own dedicated TLS material; " +
		"tls.cert_file and tls.key_file are required when acme.enabled is true " +
		"(there is no reuse of the primary xkmsd TLS config)",
}

// RemovedFieldError is returned by Load when the configuration file or
// environment names a configuration field that no longer exists.
type RemovedFieldError struct {
	// Field is the removed field's dotted configuration key (e.g.
	// "barrier.passphrase").
	Field string
	// Replacement describes what to use instead.
	Replacement string
}

// Error implements the error interface.
func (e *RemovedFieldError) Error() string {
	return "config: \"" + e.Field + "\" was removed: " + e.Replacement
}

// rejectRemovedFields fails closed when v (already merged with the config
// file and bound to the environment) carries a value for a key this version
// no longer declares a struct field for. It must run before v.Unmarshal:
// mapstructure has no notion of "this key used to mean something" and simply
// leaves an unmapped key unread, which would silently accept an operator's
// stale barrier.passphrase (file or XKMS_BARRIER_PASSPHRASE) as a no-op
// instead of the fail-closed rejection a removed secret-bearing field
// requires.
func rejectRemovedFields(v *viper.Viper) error {
	for field, replacement := range removedConfigFields {
		// A removed field is, by construction, no longer walked by
		// registerEnvKeys (it names no struct field), so AutomaticEnv would
		// not otherwise resolve its XKMS_-prefixed environment variable.
		// Bind it explicitly so a stale env var is rejected exactly like a
		// stale file key, not silently ignored.
		if err := v.BindEnv(field, canonicalEnvName(field)); err != nil {
			return &errs.Wrapped{Msg: "failed to bind removed configuration key " + field, Err: err}
		}
		if v.IsSet(field) {
			return &RemovedFieldError{Field: field, Replacement: replacement}
		}
	}
	return nil
}

// Defaults returns the defaults layer: the configuration every deployment
// starts from before the file, the environment and the flags are applied. It
// is the one place a literal infrastructure value may live.
func Defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Host: DefaultServerHost,
		},
		TLS: TLSConfig{
			IncludeLocalhostSANs: true,
		},
	}
}

// Load builds the configuration from, lowest to highest precedence, the
// defaults layer, the YAML file at path and XKMS_-prefixed environment
// variables, then validates it. Every key known to the defaults layer can be
// overridden from the environment whether or not the file mentions it
// (server.host is XKMS_SERVER_HOST). The daemon applies command-line flags on
// top of the returned configuration, so the full order is
// flags > env > file > defaults.
func Load(path string) (*Config, error) {
	// The file is read up front so a missing or unreadable path fails with
	// the operating system's error rather than viper's wrapped one.
	// #nosec G304 - Config file path is provided by admin/user
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read config file", Err: err}
	}

	v, err := newConfigViper()
	if err != nil {
		return nil, err
	}
	if err := v.MergeConfig(strings.NewReader(string(data))); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse config file", Err: err}
	}

	if err := rejectRemovedFields(v); err != nil {
		return nil, err
	}

	// Start from the defaults so a field absent from every source keeps its
	// default, then overlay viper's merged file and environment values using
	// the struct's yaml tags, the same tag the operator sees on disk.
	cfg := Defaults()
	if err := v.Unmarshal(cfg, func(dc *mapstructure.DecoderConfig) {
		dc.TagName = "yaml"
		// Embedded structs are yaml-inline, so their fields decode at the
		// embedding struct's level.
		dc.Squash = true
		dc.DecodeHook = mapstructure.ComposeDecodeHookFunc(dc.DecodeHook, stringToSecretValueHookFunc)
	}); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse config file", Err: err}
	}

	if err := cfg.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid configuration", Err: err}
	}

	return cfg, nil
}

// newConfigViper constructs a viper bound to the configuration sources below
// the file: the defaults layer, registered as known keys so an environment
// variable resolves every field even when the file omits it, and the
// XKMS_-prefixed environment.
func newConfigViper() (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	defaults, err := configToMap(Defaults())
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to register configuration defaults", Err: err}
	}
	if err := v.MergeConfigMap(defaults); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to register configuration defaults", Err: err}
	}

	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(envKeyReplacer)
	// A variable that is present but empty is a value, not an absence:
	// XKMS_SERVER_HOST="" is how an operator clears a pinned host to bind
	// every interface, and it must win over the file exactly as a non-empty
	// value does. Without this viper reads an empty variable as unset.
	v.AllowEmptyEnv(true)
	v.AutomaticEnv()

	// AutomaticEnv resolves a variable only for a key viper already knows,
	// and the defaults layer registers no key under a nil pointer section
	// (webauthn, ca, acme, attestation, trust, backends.*). Bind every key
	// of the configuration tree by name instead: BindEnv registers the key
	// without a value, so a section nobody sets stays nil, while a variable
	// set under a section the file omits now resolves.
	if err := registerEnvKeys(v); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to bind configuration keys to the environment", Err: err}
	}

	return v, nil
}

// envKeyReplacer maps a configuration key to the shape of its environment
// name: path separators and hyphens (trust.server-url) become underscores.
var envKeyReplacer = strings.NewReplacer(".", "_", "-", "_")

// canonicalEnvName renders a configuration key as its XKMS_<PATH> environment
// variable name, the form AutomaticEnv resolves.
func canonicalEnvName(key string) string {
	return envPrefix + "_" + strings.ToUpper(envKeyReplacer.Replace(key))
}

// registerEnvKeys binds every leaf key of the Config tree to its canonical
// environment name. Pointer-typed sections are walked through their element
// type, so their keys are registered whether or not any value exists.
func registerEnvKeys(v *viper.Viper) error {
	return walkYAMLKeys(reflect.TypeOf(Config{}), "", v.BindEnv)
}

// walkYAMLKeys calls visit with the dotted yaml path of every leaf field
// reachable from t. A struct-typed field (directly or through a pointer) is a
// section and is descended into, EXCEPT types.SecretValue: on the wire it is
// a scalar reference string, not a nested document section, and descending
// into its unexported enclave field would register zero leaf keys for it —
// silently dropping it from environment-variable resolution.
func walkYAMLKeys(t reflect.Type, prefix string, visit func(key ...string) error) error {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if f.Anonymous && name == "" && opts == "inline" {
			// An inline embed contributes its fields at this level.
			if err := walkYAMLKeys(f.Type, prefix, visit); err != nil {
				return err
			}
			continue
		}
		if name == "" || name == "-" {
			continue
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && ft != secretValueType {
			if err := walkYAMLKeys(ft, key, visit); err != nil {
				return err
			}
			continue
		}
		if err := visit(key); err != nil {
			return err
		}
	}
	return nil
}

// secretValuePtrType is the reflect.Type of *types.SecretValue, the shape
// every secret-bearing config field now declares (go-xkms#653/#654): nil
// means "not configured" to go-qrdb's secret.ConfigProcessor, which is the
// ONLY way to spell an optional secret in its contract (a value-typed
// SecretValue field is always "required" — an empty one fails the walk). See
// stringToSecretValueHookFunc's doc for how a pointer target is filled.
var secretValuePtrType = reflect.TypeOf((*types.SecretValue)(nil))

// stringToSecretValueHookFunc is a mapstructure.DecodeHookFuncType that
// converts a scalar string source into a types.SecretValue (or
// *types.SecretValue) destination field.
//
// The main Load path decodes through viper's mapstructure chain, not
// yaml.v3, so SecretValue's yaml.Unmarshaler never runs there — mapstructure
// has no notion of it and would otherwise fail trying to decode a plain
// string into a struct. This hook gives mapstructure the same behaviour
// yaml.v3 already provides: the raw reference string (a "credential://..."
// URI) is stored unresolved in Raw, exactly as SecretValue.UnmarshalYAML
// documents. Resolution into the enclave happens later, wherever the field's
// owner has a ResolverRegistry available.
//
// A *types.SecretValue target always matches here too (not just the bare
// value type): mapstructure's decodePtr allocates the pointer and recurses
// into decode() for the pointee with THIS hook's returned value as its new
// input, so returning the bare types.SecretValue{Raw: raw} value — never a
// pointer — lets decodeStruct's direct-assignment fast path
// (dataVal.Type() == val.Type()) complete the recursion correctly; wrapping
// it in a pointer here would recurse a second time with a non-string,
// non-struct-matching input and fail to decode at all.
func stringToSecretValueHookFunc(from reflect.Type, to reflect.Type, data any) (any, error) {
	if (to != secretValueType && to != secretValuePtrType) || from.Kind() != reflect.String {
		return data, nil
	}
	raw, _ := data.(string)
	return types.SecretValue{Raw: raw}, nil
}

// configToMap renders a Config to a generic map keyed by its yaml tags, used
// to seed viper's defaults so every key is known for environment resolution.
func configToMap(cfg *Config) (map[string]any, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}
