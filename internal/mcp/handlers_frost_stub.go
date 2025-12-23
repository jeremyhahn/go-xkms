// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build !frost

package mcp

import (
	"fmt"
	"strings"
)

// routeFrostMethods returns an error for FROST methods when not compiled with frost tag
func (s *Server) routeFrostMethods(req *JSONRPCRequest) (interface{}, error, bool) {
	if strings.HasPrefix(req.Method, "frost.") {
		return nil, fmt.Errorf("FROST support not compiled - rebuild with '-tags frost'"), true
	}
	return nil, nil, false
}
