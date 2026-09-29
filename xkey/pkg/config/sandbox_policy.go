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

package config

import (
	"fmt"
	"strings"
)

// SafeDefaultAPIExplorerSandboxPolicy is the iframe sandbox directive list
// a caller should fall back to when a candidate API Explorer preview policy
// is refused by ValidateAPIExplorerSandboxPolicy. It grants allow-forms and
// allow-popups only: enough for a previewed HTML response to render and
// behave like a normal page for its own links/forms/popups, without
// allow-scripts or allow-same-origin -- whose combination is exactly what
// lets a previewed response escape the sandbox (go-xkms#1274).
const SafeDefaultAPIExplorerSandboxPolicy = "allow-forms allow-popups"

// forbiddenSandboxDirectives are refused in the API Explorer preview policy
// outright, independent of any other directive present: each lets the
// preview escape its role without needing allow-same-origin at all.
var forbiddenSandboxDirectives = map[string]struct{}{
	"allow-popups-to-escape-sandbox": {},
	"allow-modals":                   {},
}

// forbiddenSandboxDirectivePrefixes covers the allow-top-navigation family
// (allow-top-navigation, allow-top-navigation-by-user-activation,
// allow-top-navigation-to-custom-protocols): any of them lets the preview
// navigate the application's own top-level window.
var forbiddenSandboxDirectivePrefixes = []string{"allow-top-navigation"}

// ValidateAPIExplorerSandboxPolicy checks that policy is a safe iframe
// sandbox directive list for the API Explorer response preview, which
// renders arbitrary HTML fetched from wherever the user points it via
// srcdoc.
//
// An empty policy is valid: it means "no override", and the caller applies
// its own default. A non-empty policy is refused -- regardless of whether
// it came from the user's own config or from an enterprise policy override
// -- when it combines allow-scripts with allow-same-origin: a srcdoc frame
// with allow-same-origin shares the parent document's origin, so script in
// the previewed response could reach window.parent, including xKey's own
// Wails service bindings. A policy is also refused outright if it contains
// allow-top-navigation(-by-user-activation|-to-custom-protocols),
// allow-popups-to-escape-sandbox, or allow-modals: each lets the preview
// escape its role without needing allow-same-origin at all.
//
// Mirrored in xkey/frontend/src/lib/utils/sandboxPolicy.ts; keep the two
// implementations in sync.
func ValidateAPIExplorerSandboxPolicy(policy string) error {
	if policy == "" {
		return nil
	}

	tokens := strings.Fields(policy)
	set := make(map[string]struct{}, len(tokens))
	for _, t := range tokens {
		set[t] = struct{}{}
	}

	if _, scripts := set["allow-scripts"]; scripts {
		if _, sameOrigin := set["allow-same-origin"]; sameOrigin {
			return &DetailError{
				Err:    ErrSandboxPolicyCombo,
				Detail: ": allow-scripts + allow-same-origin lets a previewed response escape the sandbox",
			}
		}
	}

	for _, t := range tokens {
		if _, forbidden := forbiddenSandboxDirectives[t]; forbidden {
			return &DetailError{Err: ErrSandboxPolicyForbiddenDirective, Detail: fmt.Sprintf(": %q is not permitted", t)}
		}
		for _, prefix := range forbiddenSandboxDirectivePrefixes {
			if strings.HasPrefix(t, prefix) {
				return &DetailError{Err: ErrSandboxPolicyForbiddenDirective, Detail: fmt.Sprintf(": %q is not permitted", t)}
			}
		}
	}

	return nil
}
