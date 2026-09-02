// Copyright (c) 2026 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Every documented WebAuthn ceremony invocation must name --email.
//
// This exists because grepping for command strings is not an enumeration. A
// previous sweep fixed the subcommands' help, both `status` remediations and
// the docs — and missed the PARENT `auth` command's own examples, one level up
// from everything it had looked at (Codex, go-xkms #190). Walking the command
// tree is the enumeration; a grep was a sample of it.
//
// Help text is invisible to the compiler, the linter and every other test, so
// this is the only thing that can notice it going stale.
func TestHelpText_WebAuthnExamplesNameTheEmailFlag(t *testing.T) {
	// The ceremonies that resolve an account by its canonical email login key.
	ceremonies := []string{"auth register", "auth login"}

	// Lines that legitimately need no login key: PIV authenticates with a
	// certificate and is resolved by its SPKI thumbprint.
	exempt := func(inv string) bool {
		return strings.Contains(inv, "--piv") || strings.Contains(inv, "--slot")
	}

	// invocations joins backslash-continued lines into one logical command, so
	// a flag on the continuation counts toward the invocation it belongs to.
	invocations := func(text string) []string {
		var out []string
		var cur strings.Builder
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if cur.Len() > 0 {
				cur.WriteString(" ")
				cur.WriteString(strings.TrimSuffix(trimmed, "\\"))
				if !strings.HasSuffix(trimmed, "\\") {
					out = append(out, cur.String())
					cur.Reset()
				}
				continue
			}
			if !strings.HasPrefix(trimmed, "xkey ") {
				continue
			}
			if strings.HasSuffix(trimmed, "\\") {
				cur.WriteString(strings.TrimSuffix(trimmed, "\\"))
				continue
			}
			out = append(out, trimmed)
		}
		if cur.Len() > 0 {
			out = append(out, cur.String())
		}
		return out
	}

	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, text := range []string{c.Long, c.Example} {
			for _, inv := range invocations(text) {
				for _, ceremony := range ceremonies {
					if !strings.Contains(inv, ceremony) || exempt(inv) {
						continue
					}
					// PER INVOCATION, not per help text. The first version of
					// this guard asked whether "--email" appeared ANYWHERE in
					// the command's help, which the flags section alone
					// satisfies — so it passed while two copyable register
					// examples omitted the flag they require. A guard that
					// asserts something weaker than the property it names is
					// the defect it was written to prevent (Codex, #190).
					if !strings.Contains(inv, "--email") {
						t.Errorf("%s: this invocation cannot work as written — it runs %q with no --email:\n  %s",
							c.CommandPath(), ceremony, inv)
					}
				}
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(RootCmd)
}
