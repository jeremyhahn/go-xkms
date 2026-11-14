// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package mcp

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// trustRootVerbs is every TrustRoot* verb with the MCP method it calls.
// TrustRootRemove answers with no result, so it has no answer to decode.
func trustRootVerbs() map[string]verbCase {
	removeReq := filled[transport.TrustRootRequest]()
	return map[string]verbCase{
		"TrustRootList":       verb("trust.root.list", (*Transport).TrustRootList),
		"TrustRootGet":        verb("trust.root.get", (*Transport).TrustRootGet),
		"TrustRootImport":     verb("trust.root.import", (*Transport).TrustRootImport),
		"TrustRootQuarantine": verb("trust.root.quarantine", (*Transport).TrustRootQuarantine),
		"TrustRootRemove": {
			method: "trust.root.remove",
			req:    removeReq,
			call: func(ctx context.Context, tr *Transport) (any, error) {
				return nil, tr.TrustRootRemove(ctx, removeReq)
			},
		},
	}
}

func TestTrustRootVerbs_CallTheTool(t *testing.T) {
	assertVerbsCallTheTool(t, trustRootVerbs())
}

func TestTrustRootVerbs_ServerRefusal(t *testing.T) {
	assertVerbsServerRefusal(t, trustRootVerbs())
}

func TestTrustRootVerbs_MalformedAnswer(t *testing.T) {
	verbs := trustRootVerbs()
	delete(verbs, "TrustRootRemove")
	assertVerbsRejectMalformedAnswer(t, verbs)
}

func TestTrustRootVerbs_NotConnected(t *testing.T) {
	assertVerbsNotConnected(t, trustRootVerbs())
}
