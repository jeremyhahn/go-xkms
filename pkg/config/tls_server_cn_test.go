package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestShippedConfigTLSServerCN guards issue #2253: the shipped
// configs/xkmsd.yaml enabled TLS with no tls.server_cn and no cert_file or
// key_file, so boot-time TLS issuance was skipped and the server asked the
// CA for a certificate with an empty Common Name. Validate must reject that
// configuration, and the shipped file must name a server CN.
func TestShippedConfigTLSServerCN(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "xkmsd.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%s): %v", path, err)
	}
	if !cfg.TLS.Enabled {
		t.Fatal("shipped config has tls.enabled = false, want true")
	}
	if strings.TrimSpace(cfg.TLS.ServerCN) == "" {
		t.Fatal("shipped config has an empty tls.server_cn: the CA would be asked for a certificate with an empty CN")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("shipped config does not validate: %v", err)
	}

	cfg.TLS.ServerCN = ""
	cfg.TLS.CertFile = ""
	cfg.TLS.KeyFile = ""
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate accepted tls.enabled with an empty tls.server_cn and no cert_file/key_file")
	}
	if !strings.Contains(err.Error(), "tls.server_cn") {
		t.Fatalf("Validate error %q does not name tls.server_cn", err)
	}
}
