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
		CategoryPolicy, CategoryPlatform, CategoryServer, CategoryAlgorithms,
		CategoryCluster, CategoryRebalance, CategoryBootstrap,
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

// Skip reasons shared by command definitions and their tests.
const (
	// ReasonQRDBControlPlane: cluster and rebalance drive go-qrdb's own
	// control-plane SDK, which xkmsd serves on its unix socket and gRPC
	// server only (cmd/xkmsctl/cluster.go newQRDBControlTransport).
	ReasonQRDBControlPlane = "qrdb control-plane SDK: unix and grpc/grpcs only"

	// ReasonNoSDKTransport: the command uses no SDK client (local key and
	// certificate tooling, or its own bootstrap channel), so it runs once, on
	// the embedded cell.
	ReasonNoSDKTransport = "no SDK transport (local or own bootstrap channel)"
)

// SkipReason reports whether the standalone run (RunAllCommandsForProtocol)
// skips cmd on protocol, and why. enabledTags are the build tags the test
// binary was built with. A Workflow command is left to its workflow test.
func SkipReason(cmd CommandDefinition, protocol ProtocolType, enabledTags []string) (string, bool) {
	if reason, skip := MatrixSkipReason(cmd, protocol, enabledTags); skip {
		return reason, true
	}
	if cmd.Workflow != "" {
		return "runs in order in " + cmd.Workflow, true
	}
	return "", false
}

// MatrixSkipReason reports whether cmd's (family, protocol) cell runs it at
// all, in the standalone run or in its Workflow test, and why not.
func MatrixSkipReason(cmd CommandDefinition, protocol ProtocolType, enabledTags []string) (string, bool) {
	for _, tag := range cmd.BuildTags {
		if !slices.Contains(enabledTags, tag) {
			return fmt.Sprintf("requires build tags %v", cmd.BuildTags), true
		}
	}
	if cmd.Unsupported != "" {
		return cmd.Unsupported, true
	}
	if len(cmd.Transports) > 0 && !slices.Contains(cmd.Transports, protocol) {
		return cmd.TransportSkip, true
	}
	if cmd.RequiresSetup && cmd.Workflow == "" {
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
		reason, skip := MatrixSkipReason(cmd, protocol, enabledTags)
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
