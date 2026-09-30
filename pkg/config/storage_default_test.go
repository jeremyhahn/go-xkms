// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package config

import "testing"

// TestValidate_EmptyStorageBackendDefaultsToPebble guards the C2 contract: an
// unspecified storage backend resolves to durable PebbleDB.
func TestValidate_EmptyStorageBackendDefaultsToPebble(t *testing.T) {
	c := Config{
		Protocols: ProtocolsConfig{Unix: true},
		Server:    ServerConfig{RESTPort: 8443},
		Logging:   LoggingConfig{Level: "info", Format: "json"},
		Datastore: DatastoreConfig{Path: "/data"},
		Default:   "pkcs8",
		Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() with empty backend = %v, want nil", err)
	}
	if c.Datastore.Engine != "pebble" {
		t.Fatalf("empty backend defaulted to %q, want pebble", c.Datastore.Engine)
	}
}
