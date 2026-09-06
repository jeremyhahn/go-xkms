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
	"regexp"
	"strings"
	"testing"
)

// complianceGateBypassSource is this file's own name, excluded from the
// source scan below because it necessarily spells out the phrases it forbids.
const complianceGateBypassSource = "compliance_gate_bypass_test.go"

// bypassPhrase matches the wording that used to describe a development-mode
// opt-in to the compliance gate. No such opt-in exists (#389): cmd/xkmsd
// refuses to start and to reload on any gap, with no flag, environment
// variable, or build tag that relaxes it. A comment that promises one sends
// an operator looking for a switch that is not there and then concluding the
// gate is broken, so the wording is pinned out of this package.
var bypassPhrase = regexp.MustCompile(`(?i)development[- ]mode|opts? into development|--insecure|XKMS_INSECURE|in secure mode`)

// bypassEnvVars are the names an operator would plausibly try, having read
// a comment that promised a development-mode opt-in. None of them is read by
// applyEnvOverrides, and the gate must not react to any of them.
var bypassEnvVars = []string{
	"XKMS_INSECURE",
	"XKMS_DEV_MODE",
	"XKMS_DEVELOPMENT",
	"XKMS_DEVELOPMENT_MODE",
	"XKMS_ALLOW_INSECURE",
	"XKMS_SKIP_COMPLIANCE",
	"XKMS_COMPLIANCE_GATE",
}

// bypassFieldName matches a configuration field that would constitute an
// opt-in to the compliance gate if one were ever added to this package.
var bypassFieldName = regexp.MustCompile(`(?i)insecure|devmode|development|bypass|skipcompliance`)

// TestComplianceGate_NoDevelopmentBypass pins the property that the compliance
// gate has no development-mode escape hatch, in the three places one could be
// introduced: the package's own comments, the environment, and the Config
// shape. It fails on the pre-#389 tree, where two comments in config.go and
// one in acme.go described an opt-in the code never implemented.
func TestComplianceGate_NoDevelopmentBypass(t *testing.T) {
	t.Run("no comment promises an opt-in", func(t *testing.T) {
		entries, err := os.ReadDir(".")
		if err != nil {
			t.Fatalf("read package dir: %v", err)
		}
		scanned := 0
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || filepath.Ext(name) != ".go" || name == complianceGateBypassSource {
				continue
			}
			src, err := os.ReadFile(name)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			scanned++
			for i, line := range strings.Split(string(src), "\n") {
				if loc := bypassPhrase.FindStringIndex(line); loc != nil {
					t.Errorf("%s:%d describes a compliance-gate opt-in that does not exist: %q",
						name, i+1, strings.TrimSpace(line))
				}
			}
		}
		if scanned == 0 {
			t.Fatal("scanned no source files; the test is not running in the package directory")
		}
	})

	t.Run("no environment variable relaxes the gate", func(t *testing.T) {
		baseline := (&Config{}).ComplianceGaps()
		if len(baseline) == 0 {
			t.Fatal("a zero-value Config must report compliance gaps for this test to mean anything")
		}
		for _, name := range bypassEnvVars {
			for _, value := range []string{"1", "true", "yes", "on"} {
				t.Setenv(name, value)
			}
		}
		cfg := &Config{}
		applyEnvOverrides(cfg)
		if got := cfg.ComplianceGaps(); !reflect.DeepEqual(got, baseline) {
			t.Fatalf("an environment variable relaxed the compliance gate\nbaseline: %v\nwith env: %v", baseline, got)
		}
	})

	t.Run("no Config field names an opt-in", func(t *testing.T) {
		configPkg := reflect.TypeFor[Config]().PkgPath()
		seen := map[reflect.Type]bool{}
		var walk func(typ reflect.Type, path string)
		walk = func(typ reflect.Type, path string) {
			for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map {
				typ = typ.Elem()
			}
			// Types from other packages carry their own semantics (a TLS client
			// option, say); only this package's own fields can gate the daemon.
			if typ.Kind() != reflect.Struct || typ.PkgPath() != configPkg || seen[typ] {
				return
			}
			seen[typ] = true
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				fieldPath := path + "." + field.Name
				if bypassFieldName.MatchString(field.Name) {
					t.Errorf("%s looks like a compliance-gate opt-in; the gate has none", fieldPath)
				}
				walk(field.Type, fieldPath)
			}
		}
		walk(reflect.TypeFor[Config](), "Config")
		if len(seen) < 2 {
			t.Fatalf("walked only %d config struct type(s); the reflection walk is not descending", len(seen))
		}
	})
}

// TestComplianceGate_BypassPhraseDetectsDrift is the error-path check for the
// source scan: the pattern must actually catch the wording it exists to catch,
// so a green scan means the phrases are absent rather than unmatched.
func TestComplianceGate_BypassPhraseDetectsDrift(t *testing.T) {
	for _, line := range []string{
		"// unless the operator explicitly opts into development mode.",
		"// refused in secure mode unless the operator opts into development",
		"// start without --insecure (XKMS_INSECURE=true).",
		"// enable Development-Mode to skip this",
	} {
		if !bypassPhrase.MatchString(line) {
			t.Errorf("pattern failed to match stale wording: %q", line)
		}
	}
	for _, line := range []string{
		"// refuses to start on — there is no override.",
		"// hardware device — for development and testing. SimulatorHost/Port target",
		"// TLS 1.0 and 1.1 are not supported — unknown or insecure values fall",
	} {
		if bypassPhrase.MatchString(line) {
			t.Errorf("pattern falsely matched acceptable wording: %q", line)
		}
	}
	for _, name := range []string{"Insecure", "DevMode", "DevelopmentMode", "BypassComplianceGate", "SkipCompliance"} {
		if !bypassFieldName.MatchString(name) {
			t.Errorf("field pattern failed to match %q", name)
		}
	}
	for _, name := range []string{"Default", "Enabled", "Strategy", "Devices"} {
		if bypassFieldName.MatchString(name) {
			t.Errorf("field pattern falsely matched %q", name)
		}
	}
}
