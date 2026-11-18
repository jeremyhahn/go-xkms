package service

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestSaveAccount_YAMLKeepsTheRestOfTheFile pins that persisting a registered
// account touches only accounts.<name>: keys the service does not model,
// comments, other accounts and the file mode stay as the operator wrote them,
// and runtime overrides (flags, env) held in memory are not written.
func TestSaveAccount_YAMLKeepsTheRestOfTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme-client.yaml")
	orig := "# operator comment\nlog_level: debug\naccounts:\n  old:\n    directory: https://old.example/acme/directory\n    email: old@example.com\n"
	if err := os.WriteFile(path, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		ConfigFile: path,
		Accounts: map[string]*AccountConfig{
			// In memory "old" carries an override that is not in the file.
			"old": {DirectoryURL: "https://override.example/acme/directory", Email: "old@example.com"},
			"new": {DirectoryURL: "https://acme.example/acme/directory", Email: "dev@example.com", AccountURL: "https://acme.example/acme/acct/1"},
		},
		Certificates: map[string]*CertificateSpec{"from-env": {}},
	}
	if err := cfg.SaveAccount("new"); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{"# operator comment", "log_level: debug", "https://old.example/acme/directory", "https://acme.example/acme/acct/1"} {
		if !strings.Contains(got, want) {
			t.Errorf("saved file lacks %q:\n%s", want, got)
		}
	}
	for _, bad := range []string{"override.example", "from-env"} {
		if strings.Contains(got, bad) {
			t.Errorf("saved file carries in-memory override %q:\n%s", bad, got)
		}
	}
	var parsed struct {
		Accounts map[string]*AccountConfig `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("saved file is not YAML: %v", err)
	}
	if a := parsed.Accounts["new"]; a == nil || a.Email != "dev@example.com" {
		t.Errorf("accounts.new = %+v", a)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o640 {
		t.Errorf("file mode = %o, want the original 640", mode)
	}
}

// TestSaveAccount_JSONStaysJSON pins that a JSON configuration file is
// written back as JSON with its other keys kept.
func TestSaveAccount_JSONStaysJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme-client.json")
	if err := os.WriteFile(path, []byte(`{"log_level":"debug"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{ConfigFile: path, Accounts: map[string]*AccountConfig{
		"new": {DirectoryURL: "https://acme.example/acme/directory", AccountURL: "https://acme.example/acme/acct/1"},
	}}
	if err := cfg.SaveAccount("new"); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("saved file is not JSON: %v\n%s", err, raw)
	}
	if parsed["log_level"] != "debug" {
		t.Errorf("log_level lost: %s", raw)
	}
	accts, _ := parsed["accounts"].(map[string]any)
	acct, _ := accts["new"].(map[string]any)
	if acct["account_url"] != "https://acme.example/acme/acct/1" {
		t.Errorf("accounts.new.account_url not saved: %s", raw)
	}
}

// TestSaveAccount_RefusesUnknownFormatAndNoFile pins the error cases: no
// file, an unsupported format and an unknown account leave the file alone.
func TestSaveAccount_RefusesUnknownFormatAndNoFile(t *testing.T) {
	if err := (&Config{}).SaveAccount("x"); !errors.Is(err, ErrConfigNotPersistable) {
		t.Errorf("no file: %v, want ErrConfigNotPersistable", err)
	}
	path := filepath.Join(t.TempDir(), "acme-client.toml")
	if err := os.WriteFile(path, []byte("log_level = \"debug\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{ConfigFile: path, Accounts: map[string]*AccountConfig{"x": {}}}
	if err := cfg.SaveAccount("x"); !errors.Is(err, ErrConfigNotPersistable) {
		t.Errorf("toml: %v, want ErrConfigNotPersistable", err)
	}
	if err := cfg.SaveAccount("missing"); err == nil {
		t.Error("unknown account saved without error")
	}
	if raw, _ := os.ReadFile(path); string(raw) != "log_level = \"debug\"\n" {
		t.Errorf("file changed: %q", raw)
	}
}
