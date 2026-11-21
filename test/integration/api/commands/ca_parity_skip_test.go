package commands

import "testing"

// TestCAParitySkip_EmbeddedNamesNoCA pins the CA parity callers
// (test/integration/api/ca_parity_test.go) to the CACommands capability
// restriction: the embedded case is skipped with ReasonEmbeddedNoCA before
// any ca verb runs, and every server transport runs.
func TestCAParitySkip_EmbeddedNamesNoCA(t *testing.T) {
	for _, p := range CLIProtocols() {
		r, skip := CAParitySkip(p)
		if p == ProtocolEmbedded {
			if !skip || r != ReasonEmbeddedNoCA {
				t.Errorf("CAParitySkip(embedded) = (%q, %v), want (%q, true)", r, skip, ReasonEmbeddedNoCA)
			}
			continue
		}
		if skip {
			t.Errorf("CAParitySkip(%s) skipped: %s", p, r)
		}
	}
}
