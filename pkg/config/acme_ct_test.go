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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// ctLogKey returns a fresh P-256 log key as DER SubjectPublicKeyInfo.
func ctLogKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return key, der
}

// TestACMECTConfig_PolicyConfig verifies that both published key encodings,
// the shard times and every policy field reach the ct.PolicyConfig.
func TestACMECTConfig_PolicyConfig(t *testing.T) {
	pemKey, pemDER := ctLogKey(t)
	b64Key, b64DER := ctLogKey(t)

	cfg := ACMECTConfig{
		Logs: []ACMECTLogConfig{
			{
				Name:      "pem",
				Operator:  "op-a",
				URL:       "https://ct-a.example.com",
				PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pemDER})),
				Enabled:   true,
				StartTime: "2026-01-01T00:00:00Z",
				EndTime:   "2027-01-01T00:00:00Z",
			},
			{
				Name:           "base64",
				Operator:       "op-b",
				URL:            "https://ct-b.example.com",
				PublicKey:      base64.StdEncoding.EncodeToString(b64DER),
				Tiled:          true,
				MaxChainLength: 4,
			},
		},
		MinSCTs:                2,
		MinOperators:           2,
		RequireRFC6962Log:      true,
		SubmissionTimeout:      3 * time.Second,
		StaggerDelay:           time.Second,
		MaxParallelSubmissions: 5,
	}

	policy, err := cfg.PolicyConfig()
	if err != nil {
		t.Fatalf("PolicyConfig: %v", err)
	}
	if policy.MinSCTs != 2 || policy.MinOperators != 2 || !policy.RequireRFC6962Log {
		t.Fatalf("policy minimums = %d/%d/%v", policy.MinSCTs, policy.MinOperators, policy.RequireRFC6962Log)
	}
	if policy.SubmissionTimeout != 3*time.Second || policy.StaggerDelay != time.Second || policy.MaxParallelSubmissions != 5 {
		t.Fatalf("policy timing = %v/%v/%d", policy.SubmissionTimeout, policy.StaggerDelay, policy.MaxParallelSubmissions)
	}
	if !policy.Enabled() {
		t.Fatal("policy with an enabled log is not enabled")
	}
	if len(policy.LogGroups) != 2 {
		t.Fatalf("LogGroups = %d, want 2", len(policy.LogGroups))
	}

	first, second := policy.LogGroups[0], policy.LogGroups[1]
	if !pemKey.PublicKey.Equal(first.PublicKey) {
		t.Fatal("PEM public key was not parsed")
	}
	if !b64Key.PublicKey.Equal(second.PublicKey) {
		t.Fatal("base64 public key was not parsed")
	}
	if first.Name != "pem" || first.Operator != "op-a" || first.URL != "https://ct-a.example.com" || !first.Enabled {
		t.Fatalf("first log = %+v", first)
	}
	if !first.StartTime.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		!first.EndTime.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("shard = %v..%v", first.StartTime, first.EndTime)
	}
	if !second.IsTiled || second.MaxChainLength != 4 || second.Enabled {
		t.Fatalf("second log = %+v", second)
	}
	if !second.StartTime.IsZero() || !second.EndTime.IsZero() {
		t.Fatal("empty shard times are not the zero time")
	}
}

// TestACMECTConfig_ZeroValueIsOff verifies the default: no log means CT is
// off, and the zero minimums select one SCT from one operator.
func TestACMECTConfig_ZeroValueIsOff(t *testing.T) {
	var cfg ACMECTConfig

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	policy, err := cfg.PolicyConfig()
	if err != nil {
		t.Fatalf("PolicyConfig: %v", err)
	}
	if policy.Enabled() {
		t.Fatal("zero-value CT config is enabled")
	}
	if policy.MinSCTs != 1 || policy.MinOperators != 1 {
		t.Fatalf("defaults = %d/%d, want 1/1", policy.MinSCTs, policy.MinOperators)
	}
}

// TestACMECTConfig_Invalid verifies that an unusable key or shard time is a
// typed error naming the log, whether or not the log is enabled.
func TestACMECTConfig_Invalid(t *testing.T) {
	_, der := ctLogKey(t)
	goodKey := base64.StdEncoding.EncodeToString(der)

	tests := []struct {
		name string
		log  ACMECTLogConfig
		want error
	}{
		{
			name: "key is not base64",
			log:  ACMECTLogConfig{Name: "bad", PublicKey: "not base64!"},
			want: ErrACMECTLogPublicKey,
		},
		{
			name: "key is not an SPKI",
			log:  ACMECTLogConfig{Name: "bad", PublicKey: base64.StdEncoding.EncodeToString([]byte("junk"))},
			want: ErrACMECTLogPublicKey,
		},
		{
			name: "PEM block is not an SPKI",
			log: ACMECTLogConfig{
				Name:      "bad",
				PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")})),
			},
			want: ErrACMECTLogPublicKey,
		},
		{
			name: "start time is not RFC 3339",
			log:  ACMECTLogConfig{Name: "bad", PublicKey: goodKey, StartTime: "2026-01-01"},
			want: ErrACMECTLogTime,
		},
		{
			name: "end time is not RFC 3339",
			log:  ACMECTLogConfig{Name: "bad", PublicKey: goodKey, EndTime: "tomorrow"},
			want: ErrACMECTLogTime,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ACMECTConfig{Logs: []ACMECTLogConfig{tt.log}}
			err := cfg.Validate()
			if !errors.Is(err, tt.want) {
				t.Fatalf("Validate() = %v, want %v", err, tt.want)
			}
			if _, err := cfg.PolicyConfig(); !errors.Is(err, tt.want) {
				t.Fatalf("PolicyConfig() = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestACMEConfig_ValidateChecksCT verifies the ACME section rejects an
// invalid ct block.
func TestACMEConfig_ValidateChecksCT(t *testing.T) {
	cfg := enabledACME()
	cfg.CT.Logs = []ACMECTLogConfig{{Name: "bad", PublicKey: "not base64!", Enabled: true}}

	if err := cfg.Validate(); !errors.Is(err, ErrACMECTLogPublicKey) {
		t.Fatalf("Validate() = %v, want %v", err, ErrACMECTLogPublicKey)
	}
}

// TestACMECTConfig_YAML verifies the yaml keys the ct block is read under.
func TestACMECTConfig_YAML(t *testing.T) {
	const doc = `
ct:
  min_scts: 2
  min_operators: 2
  require_rfc6962_log: true
  submission_timeout: 5s
  stagger_delay: 250ms
  max_parallel_submissions: 3
  logs:
    - name: argon
      operator: google
      url: https://ct.example.com/argon
      public_key: AAAA
      enabled: true
      start_time: "2026-01-01T00:00:00Z"
      end_time: "2027-01-01T00:00:00Z"
      tiled: true
      max_chain_length: 5
`
	var cfg ACMEConfig
	if err := yaml.Unmarshal([]byte(doc), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	got := cfg.CT
	if got.MinSCTs != 2 || got.MinOperators != 2 || !got.RequireRFC6962Log ||
		got.SubmissionTimeout != 5*time.Second || got.StaggerDelay != 250*time.Millisecond ||
		got.MaxParallelSubmissions != 3 {
		t.Fatalf("ct = %+v", got)
	}
	want := ACMECTLogConfig{
		Name:           "argon",
		Operator:       "google",
		URL:            "https://ct.example.com/argon",
		PublicKey:      "AAAA",
		Enabled:        true,
		StartTime:      "2026-01-01T00:00:00Z",
		EndTime:        "2027-01-01T00:00:00Z",
		Tiled:          true,
		MaxChainLength: 5,
	}
	if len(got.Logs) != 1 || got.Logs[0] != want {
		t.Fatalf("logs = %+v, want %+v", got.Logs, want)
	}
}
