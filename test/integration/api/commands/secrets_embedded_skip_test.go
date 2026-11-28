package commands

import "testing"

// TestSecretsWorkflowSkip_EmbeddedNamesMissingServices pins the embedded
// password and PIN cells: NewEmbeddedService (sdk/go/embedded.go) installs
// no password-store or PIN manager, so every such cell on embedded is
// skipped with a named reason before it runs, never failed with
// ErrNotConfigured. The server transports run them.
func TestSecretsWorkflowSkip_EmbeddedNamesMissingServices(t *testing.T) {
	families := map[CommandCategory][]CommandDefinition{
		CategoryPassword: PasswordCommands(),
		CategoryPIN:      PINCommands(),
	}
	for category, cmds := range families {
		r, skip := SecretsWorkflowSkip(category, ProtocolEmbedded)
		if !skip || r != ReasonEmbeddedNoSecrets {
			t.Errorf("SecretsWorkflowSkip(%s, embedded) = (%q, %v), want (%q, true)", category, r, skip, ReasonEmbeddedNoSecrets)
		}
		for _, def := range cmds {
			if r, skip := MatrixSkipReason(def, ProtocolEmbedded, nil); !skip || r != ReasonEmbeddedNoSecrets {
				t.Errorf("(%s, embedded) %s: skip=%v reason=%q, want %q", category, def.Name, skip, r, ReasonEmbeddedNoSecrets)
			}
		}
		for _, p := range CLIProtocols() {
			if p == ProtocolEmbedded {
				continue
			}
			if r, skip := SecretsWorkflowSkip(category, p); skip {
				t.Errorf("SecretsWorkflowSkip(%s, %s) skipped: %s", category, p, r)
			}
		}
	}
	if r, skip := SecretsWorkflowSkip(CategoryPIV, ProtocolEmbedded); skip {
		t.Errorf("piv on embedded skipped: %s", r)
	}
}
