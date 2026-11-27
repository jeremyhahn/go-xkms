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

package xkms

import (
	"strings"
	"testing"
)

// TestVersion_FromLinkerVariable: the Makefile sets buildVersion with
// -ldflags -X (#2309, Codex round 3 on #2322). Under -trimpath the source
// file path is module-relative, so Version must report the linker value and
// never look for a VERSION file beside the source.
func TestVersion_FromLinkerVariable(t *testing.T) {
	saved := buildVersion
	t.Cleanup(func() { buildVersion = saved })

	buildVersion = "9.8.7-linker"
	if got := Version(); got != "9.8.7-linker" {
		t.Fatalf("Version() = %q; want the linker variable %q", got, "9.8.7-linker")
	}

	buildVersion = "  1.2.3\n"
	if got := Version(); got != "1.2.3" {
		t.Fatalf("Version() = %q; want the trimmed linker variable %q", got, "1.2.3")
	}
}

// TestVersion_UnsetLinkerVariable: with no -X flag (go test, go build without
// the Makefile) Version reports "unknown" or the main module version, never a
// value read from the source tree.
func TestVersion_UnsetLinkerVariable(t *testing.T) {
	saved := buildVersion
	t.Cleanup(func() { buildVersion = saved })

	buildVersion = ""
	got := Version()
	if got == "" {
		t.Fatal("Version() is empty with the linker variable unset; want \"unknown\"")
	}
	if got != "unknown" && (!strings.HasPrefix(got, "v") || strings.Contains(got, "(devel)")) {
		t.Fatalf("Version() = %q with the linker variable unset; want \"unknown\" or a go-xkms module version", got)
	}
}
