package main

import (
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/internal/testtmp"
)

// TestMain keeps t.TempDir() short so unix socket paths fit in sun_path
// on runners with a deep TMPDIR (#2248).
func TestMain(m *testing.M) { os.Exit(testtmp.Short(m.Run)) }
