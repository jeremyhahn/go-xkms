//go:build integration

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

package integration

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// mcpGenerateFixtures returns the string fields of every map literal in
// mcp_test.go that carries a "key_id" and a "key_type": the generateKey
// requests of the MCP suite.
func mcpGenerateFixtures(t *testing.T) []map[string]string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "mcp_test.go", nil, 0)
	if err != nil {
		t.Fatalf("parse mcp_test.go: %v", err)
	}
	var fixtures []map[string]string
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if _, isMap := lit.Type.(*ast.MapType); !isMap {
			return true
		}
		fields := map[string]string{}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.BasicLit)
			if !ok || key.Kind != token.STRING {
				continue
			}
			name, _ := strconv.Unquote(key.Value)
			value := "<non-literal>"
			if v, ok := kv.Value.(*ast.BasicLit); ok && v.Kind == token.STRING {
				value, _ = strconv.Unquote(v.Value)
			}
			fields[name] = value
		}
		_, hasID := fields["key_id"]
		_, hasType := fields["key_type"]
		if hasID && hasType {
			fixtures = append(fixtures, fields)
		}
		return true
	})
	return fixtures
}

// TestMCPGenerateFixturesNameAlgorithmAndPurpose checks every MCP generate
// request names its algorithm (handleGenerateKey refuses an empty one) and
// sends a key purpose types.ParseKeyType accepts as key_type.
func TestMCPGenerateFixturesNameAlgorithmAndPurpose(t *testing.T) {
	fixtures := mcpGenerateFixtures(t)
	if len(fixtures) < 4 {
		t.Fatalf("found %d MCP generate fixtures in mcp_test.go, want at least 4", len(fixtures))
	}
	for i, f := range fixtures {
		if f["algorithm"] != "rsa" {
			t.Errorf("fixture %d (key_id %q): algorithm = %q, want \"rsa\"", i, f["key_id"], f["algorithm"])
		}
		if types.ParseKeyType(f["key_type"]) == 0 {
			t.Errorf("fixture %d (key_id %q): key_type %q is not a key purpose", i, f["key_id"], f["key_type"])
		}
	}
}
