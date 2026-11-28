package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestWebAuthnConfig_TenantHostsYAML(t *testing.T) {
	var cfg WebAuthnConfig
	src := "rp_id: example.com\ntenant_hosts:\n  b.example.com: tenant-b\n"
	require.NoError(t, yaml.Unmarshal([]byte(src), &cfg))
	assert.Equal(t, "example.com", cfg.RPID)
	assert.Equal(t, map[string]string{"b.example.com": "tenant-b"}, cfg.TenantHosts)
}
