package main

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// shippedConfigPath is the configuration file the repository ships.
const shippedConfigPath = "../../configs/xkmsd.yaml"

// TestShippedConfig_ACMENotEnabledByDefault pins that the shipped
// configuration starts no ACME listener: enabling ACME, and provisioning its
// listener certificate, is an operator decision outside the enrolment probe
// of row enrolment-imx95-e2e (#2258).
func TestShippedConfig_ACMENotEnabledByDefault(t *testing.T) {
	cfg, err := config.Load(shippedConfigPath)
	if err != nil {
		t.Fatalf("config.Load(%s): %v", shippedConfigPath, err)
	}
	if cfg.ACME != nil && cfg.ACME.Enabled {
		t.Fatalf("%s enables ACME by default; the shipped configuration must not start an ACME listener", shippedConfigPath)
	}
}
