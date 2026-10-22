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

//go:build gui

package admin

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	adminfe "github.com/jeremyhahn/go-xkms/pkg/acme/web/packages/admin"
)

// listEnvelopeRule matches, in the minified bundle, the shared API client
// returning a list response with its {data, pagination} envelope intact
// (`return Array.isArray(a.data)?a:...`). The desktop list handlers answer
// {data: [...], pagination}; the admin stores read res.data and
// res.pagination, so a client that unwrapped data would show every list
// empty.
var listEnvelopeRule = regexp.MustCompile(`Array\.isArray\((\w+)\.data\)\?(\w+):`)

// errorThrow is the shared API client's throw for an error envelope.
const errorThrow = "Request failed with status"

// shippedBundle returns the JavaScript of the admin SPA the desktop GUI embeds.
func shippedBundle(t *testing.T) string {
	t.Helper()
	paths, err := fs.Glob(adminfe.Assets, "dist/assets/*.js")
	if err != nil {
		t.Fatalf("listing the embedded admin bundle: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("the embedded admin bundle has no JavaScript asset")
	}
	var bundle strings.Builder
	for _, path := range paths {
		source, err := fs.ReadFile(adminfe.Assets, path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		bundle.Write(source)
	}
	return bundle.String()
}

// listRuleIndex returns where the bundle keeps a list envelope, or -1.
func listRuleIndex(bundle string) int {
	for _, match := range listEnvelopeRule.FindAllStringSubmatchIndex(bundle, -1) {
		response := bundle[match[2]:match[3]]
		returned := bundle[match[4]:match[5]]
		if response == returned {
			return match[0]
		}
	}
	return -1
}

func TestShippedBundle_ListResponseKeepsItsEnvelope(t *testing.T) {
	if listRuleIndex(shippedBundle(t)) < 0 {
		t.Fatal("the embedded admin bundle unwraps list responses to a bare array; " +
			"the stores then read res.data and res.pagination from it and show every list empty. " +
			"Rebuild it with `npm run build:admin` in pkg/acme/web")
	}
}

func TestShippedBundle_ErrorEnvelopeThrowsBeforeTheListRule(t *testing.T) {
	bundle := shippedBundle(t)
	throwAt := strings.Index(bundle, errorThrow)
	if throwAt < 0 {
		t.Fatalf("the embedded admin bundle no longer throws %q for an error envelope", errorThrow)
	}
	listAt := listRuleIndex(bundle)
	if listAt < 0 {
		t.Fatal("the embedded admin bundle has no list-envelope rule")
	}
	// An error envelope that also carries data must reach the ApiClientError
	// throw, never be returned as a list.
	if listAt < throwAt {
		t.Fatal("the embedded admin bundle returns a list envelope before checking it for an error")
	}
}
