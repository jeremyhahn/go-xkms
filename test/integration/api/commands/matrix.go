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
		CategoryPolicy, CategoryTenant, CategoryAuth, CategoryCredential,
		CategoryOIDC, CategoryPassword, CategoryPIN, CategoryPIV,
		CategoryPlatform, CategoryServer, CategoryAlgorithms,
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

	// ReasonEmbeddedNoCA: the embedded service (sdk/go/embedded.go) sets up
	// software key and certificate storage only and installs no CA, so the
	// ca verbs reach servicer_ca.go's getCA guard there.
	ReasonEmbeddedNoCA = "embedded service installs no CA (sdk/go/embedded.go)"
)

// SkipReason reports whether the standalone run (RunAllCommandsForProtocol)
// skips cmd on protocol, and why. enabledTags are the build tags the test
// binary was built with. A Workflow command is left to its workflow test.
// CAParitySkip reports whether the CA parity tests (ca_parity_test.go) skip
// protocol, and why. It applies the CACommands transport restriction, so a
// transport that serves no CA (embedded: ReasonEmbeddedNoCA) is skipped
// before any ca verb runs.
func CAParitySkip(protocol ProtocolType) (string, bool) {
	for _, cmd := range CACommands() {
		if len(cmd.Transports) > 0 && !slices.Contains(cmd.Transports, protocol) {
			return cmd.TransportSkip, true
		}
	}
	return "", false
}

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
// optionalFamilyTags maps each optional build tag a command definition can
// require to the xkmsctl subcommand that exists only when the binary was
// built with it.
var optionalFamilyTags = []struct{ tag, command string }{
	{tag: "frost", command: "frost"},
	{tag: "fido2", command: "fido2"},
}

// CompiledTags returns the matrix tag set: "integration" plus every optional
// tag whose subcommand probe reports compiled into the CLI binary. probe
// receives the subcommand name (e.g. "fido2").
func CompiledTags(probe func(command string) bool) []string {
	tags := []string{"integration"}
	for _, opt := range optionalFamilyTags {
		if probe(opt.command) {
			tags = append(tags, opt.tag)
		}
	}
	return tags
}

func MatrixSkipReason(cmd CommandDefinition, protocol ProtocolType, enabledTags []string) (string, bool) {
	for _, tag := range cmd.BuildTags {
		if !slices.Contains(enabledTags, tag) {
			return fmt.Sprintf("requires build tags %v", cmd.BuildTags), true
		}
	}
	if cmd.Skip != "" {
		return cmd.Skip, true
	}
	if cmd.Unsupported != "" {
		return cmd.Unsupported, true
	}
	if len(cmd.Transports) > 0 && !slices.Contains(cmd.Transports, protocol) {
		return cmd.TransportSkip, true
	}
	if cmd.RequiresSetup && cmd.Workflow == "" && len(cmd.SetupSteps) == 0 {
		return skipChain, true
	}
	return "", false
}

// failedSetupStep returns the first SetupSteps entry of cmd that has not
// passed in this run.
func failedSetupStep(cmd CommandDefinition, passed map[string]bool) (string, bool) {
	for _, step := range cmd.SetupSteps {
		if !passed[step] {
			return step, true
		}
	}
	return "", false
}

// unsupportedOnBackend reports a failed result whose output carries one of
// cmd.SkipWhenOutputContains: the backend lacks the capability, so the cell
// is skipped with cmd.SkipWhenReason.
func unsupportedOnBackend(cmd CommandDefinition, result *TestResult) (string, bool) {
	if result.Passed {
		return "", false
	}
	output := result.Stdout + result.Stderr
	for _, marker := range cmd.SkipWhenOutputContains {
		if strings.Contains(output, marker) {
			return cmd.SkipWhenReason, true
		}
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
		cell.Reason = "no command definitions in AllCommands yet (#2321 slice g)"
	default:
		cell.Reason = strings.Join(reasons, "; ")
	}
	return cell
}
