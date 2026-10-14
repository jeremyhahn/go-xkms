package config

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeDatastoreEngine(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"memory", "memory"},
		{"file", "file"},
		{"pebble", "pebble"},
		{" Pebble ", "pebble"},
		{"\tMEMORY\n", "memory"},
		{"", ""},
		{"   ", ""},
	}
	for _, tt := range tests {
		got, err := NormalizeDatastoreEngine(tt.in)
		if err != nil {
			t.Errorf("NormalizeDatastoreEngine(%q) error = %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeDatastoreEngine(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeDatastoreEngine_Unknown(t *testing.T) {
	for _, in := range []string{"carrier-pigeon", "raft", "pebbles"} {
		_, err := NormalizeDatastoreEngine(in)
		var engineErr *ErrUnknownDatastoreEngine
		if !errors.As(err, &engineErr) {
			t.Fatalf("NormalizeDatastoreEngine(%q) error = %v, want *ErrUnknownDatastoreEngine", in, err)
		}
		if engineErr.Engine != in {
			t.Errorf("Engine = %q, want %q", engineErr.Engine, in)
		}
		msg := err.Error()
		if !strings.Contains(msg, in) || !strings.Contains(msg, "memory, file, pebble") {
			t.Errorf("error %q does not name the value and the allowed engines", msg)
		}
	}
}

func TestNormalizeDatastoreMode(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"standalone", "standalone"},
		{" Remote ", "remote"},
		{"", ""},
	}
	for _, tt := range tests {
		got, err := NormalizeDatastoreMode(tt.in)
		if err != nil {
			t.Errorf("NormalizeDatastoreMode(%q) error = %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeDatastoreMode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeDatastoreMode_Unknown(t *testing.T) {
	_, err := NormalizeDatastoreMode("clustered")
	var modeErr *ErrUnknownDatastoreMode
	if !errors.As(err, &modeErr) {
		t.Fatalf("error = %v, want *ErrUnknownDatastoreMode", err)
	}
	if modeErr.Mode != "clustered" {
		t.Errorf("Mode = %q, want clustered", modeErr.Mode)
	}
	if msg := err.Error(); !strings.Contains(msg, "clustered") || !strings.Contains(msg, "standalone, remote") {
		t.Errorf("error %q does not name the value and the allowed modes", msg)
	}
}

// TestValidate_DatastoreEngineAndMode verifies Validate rejects an unknown
// engine or mode with the typed errors, and stores the normalised (and
// defaulted) values so later checks compare them exactly.
func TestValidate_DatastoreEngineAndMode(t *testing.T) {
	t.Run("unknown engine", func(t *testing.T) {
		c := &Config{Datastore: DatastoreConfig{Engine: "carrier-pigeon", Path: t.TempDir()}}
		var engineErr *ErrUnknownDatastoreEngine
		if err := c.Validate(); !errors.As(err, &engineErr) {
			t.Fatalf("Validate() error = %v, want *ErrUnknownDatastoreEngine", err)
		}
	})
	t.Run("unknown mode", func(t *testing.T) {
		c := &Config{Datastore: DatastoreConfig{Mode: "clustered", Path: t.TempDir()}}
		var modeErr *ErrUnknownDatastoreMode
		if err := c.Validate(); !errors.As(err, &modeErr) {
			t.Fatalf("Validate() error = %v, want *ErrUnknownDatastoreMode", err)
		}
	})
	t.Run("normalised and defaulted", func(t *testing.T) {
		c := &Config{Datastore: DatastoreConfig{Engine: " Memory ", Path: t.TempDir()}}
		// Validate checks far more than the datastore; only the datastore
		// fields it rewrote are asserted here.
		if err := c.Validate(); errors.As(err, new(*ErrUnknownDatastoreEngine)) || errors.As(err, new(*ErrUnknownDatastoreMode)) {
			t.Fatalf("Validate() error = %v", err)
		}
		if c.Datastore.Engine != "memory" || c.Datastore.Mode != "standalone" {
			t.Errorf("Engine, Mode = %q, %q, want memory, standalone", c.Datastore.Engine, c.Datastore.Mode)
		}
	})
}
