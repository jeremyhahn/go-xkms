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

package commands

import (
	"fmt"
	"slices"
	"strings"
)

// CommandFamilies returns every xkmsctl command family of the CLI matrix
// (docs/SPEC.md row cli-protocol-matrix), in a stable order.
func CommandFamilies() []CommandCategory {
	return []CommandCategory{
		CategoryVersion, CategoryBackends, CategoryBackend, CategoryKey,
		CategoryCert, CategoryTLS, CategoryFrost, CategoryFIDO2,
		CategoryUser, CategoryAdmin, CategorySealing, CategoryCA,
		CategoryPolicy,
	}
}

// MatrixCell is one (family, transport) cell of the CLI matrix: the number
// of commands that run in it, and why none run when Runs is zero.
type MatrixCell struct {
	Family   CommandCategory
	Protocol ProtocolType
	Runs     int
	Reason   string
}

// SkipReason reports whether the matrix skips cmd on protocol, and why.
// enabledTags are the build tags the test binary was built with.
func SkipReason(cmd CommandDefinition, protocol ProtocolType, enabledTags []string) (string, bool) {
	for _, tag := range cmd.BuildTags {
		if !slices.Contains(enabledTags, tag) {
			return fmt.Sprintf("requires build tags %v", cmd.BuildTags), true
		}
	}
	if cmd.RequiresSetup {
		return "requires prior setup (workflow tests; later #2321 slices)", true
	}
	return "", false
}

// MatrixCellFor computes the cell of family on protocol.
func MatrixCellFor(family CommandCategory, protocol ProtocolType, enabledTags []string) MatrixCell {
	cell := MatrixCell{Family: family, Protocol: protocol}
	var reasons []string
	for _, cmd := range AllCommands() {
		if cmd.Category != family {
			continue
		}
		reason, skip := SkipReason(cmd, protocol, enabledTags)
		if !skip {
			cell.Runs++
			continue
		}
		reasons = append(reasons, cmd.Name+": "+reason)
	}
	switch {
	case cell.Runs > 0:
	case len(reasons) == 0:
		cell.Reason = "no command definitions in AllCommands yet (#2321 slice f)"
	default:
		cell.Reason = strings.Join(reasons, "; ")
	}
	return cell
}
