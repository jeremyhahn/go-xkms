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

// Workflow tests (test/integration/api/cli_platform_matrix_test.go) that run
// the ordered commands of #2321 slice (e) on every transport.
const (
	WorkflowPlatform  = "TestCLIPlatformMatrix"
	WorkflowCluster   = "TestCLIClusterMatrix"
	WorkflowBootstrap = "TestCLIBootstrapMatrix"
)

// ReasonNoTLSAZone: verify-tlsa and show-tlsa resolve TLSA records over
// DNS; the integration environment serves no zone with them.
const ReasonNoTLSAZone = "needs a DNS server serving TLSA records; the integration env has none"

// Argument descriptions the workflow tests override by.
const (
	ArgPlatformSecret = "Platform secret name"
	ArgFile           = "File path"
)

// qrdbControlTransports are the transports go-qrdb's control-plane SDK
// speaks (cmd/xkmsctl/cluster.go newQRDBControlTransport).
var qrdbControlTransports = []ProtocolType{ProtocolUnix, ProtocolGRPC}

// ServerCommands returns the top-level server status command.
func ServerCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name:           "server-status",
			Category:       CategoryServer,
			Command:        []string{"status"},
			Description:    "Show server status",
			RequiresServer: true,
		},
	}
}

// AlgorithmsCommands returns the algorithms listing command.
func AlgorithmsCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name:           "algorithms",
			Category:       CategoryAlgorithms,
			Command:        []string{"algorithms"},
			Description:    "List the algorithms the server supports",
			RequiresServer: true,
		},
	}
}

// PlatformCommands returns the platform secret commands, in workflow order:
// put creates the secret every later verb reads, reseals or deletes.
func PlatformCommands() []CommandDefinition {
	secret := func() []ArgDefinition {
		return []ArgDefinition{
			{Value: "it-platform-secret", Description: ArgPlatformSecret, IsPositional: true},
		}
	}
	def := func(name, verb, desc string, args []ArgDefinition) CommandDefinition {
		return CommandDefinition{
			Name:           name,
			Category:       CategoryPlatform,
			Command:        []string{"platform", verb},
			Description:    desc,
			RequiresServer: true,
			Workflow:       WorkflowPlatform,
			RequiredArgs:   args,
		}
	}
	put := def("platform-put", "put", "Seal and store a platform secret", secret())
	put.RequiredArgs = append(put.RequiredArgs, ArgDefinition{Flag: "value", Value: "it-platform-value", Description: "Secret value"})
	cmds := serverOnly(ReasonEmbeddedNoPlatformStore, []CommandDefinition{
		put,
		def("platform-get", "get", "Unseal and return a platform secret", secret()),
		def("platform-list", "list", "List platform secrets", nil),
		def("platform-reseal", "reseal", "Reseal a platform secret", secret()),
		def("platform-status", "status", "Show platform sealing status", nil),
		def("platform-delete", "delete", "Delete a platform secret", secret()),
	})
	for i := range cmds {
		cmds[i].Unsupported = ReasonNoPlatformStore
	}
	return cmds
}

// ClusterCommands returns the qrdb cluster membership commands. add and
// remove take the replica the workflow names; on a one-node cluster there is
// none, and the workflow skips them with that reason.
func ClusterCommands() []CommandDefinition {
	def := func(name, verb, desc string) CommandDefinition {
		return CommandDefinition{
			Name:           name,
			Category:       CategoryCluster,
			Command:        []string{"cluster", verb},
			Description:    desc,
			RequiresServer: true,
			Workflow:       WorkflowCluster,
			Transports:     qrdbControlTransports,
			TransportSkip:  ReasonQRDBControlPlane,
		}
	}
	add := def("cluster-add", "add", "Add a replica to a shard")
	add.RequiredArgs = []ArgDefinition{
		{Flag: "replica-id", Value: "2", Description: "Replica ID"},
		{Flag: "raft-address", Value: "", Description: "Replica Raft address"},
	}
	remove := def("cluster-remove", "remove", "Remove a replica from a shard")
	remove.RequiredArgs = []ArgDefinition{
		{Flag: "replica-id", Value: "2", Description: "Replica ID"},
	}
	return []CommandDefinition{
		def("cluster-status", "status", "Show shard leadership and membership"),
		def("cluster-members", "members", "List shard replicas"),
		add,
		remove,
	}
}

// RebalanceCommands returns the qrdb rebalance commands, in workflow order:
// plan saves the plan execute runs.
func RebalanceCommands() []CommandDefinition {
	def := func(name, verb, desc string, args []ArgDefinition) CommandDefinition {
		return CommandDefinition{
			Name:           name,
			Category:       CategoryRebalance,
			Command:        []string{"rebalance", verb},
			Description:    desc,
			RequiresServer: true,
			Workflow:       WorkflowCluster,
			Transports:     qrdbControlTransports,
			TransportSkip:  ReasonQRDBControlPlane,
			RequiredArgs:   args,
		}
	}
	return []CommandDefinition{
		def("rebalance-stats", "stats", "Show shard distribution", nil),
		def("rebalance-plan", "plan", "Plan shard moves", []ArgDefinition{
			{Flag: "out", Value: "rebalance-plan.json", Description: ArgFile},
		}),
		def("rebalance-execute", "execute", "Execute a saved rebalance plan", []ArgDefinition{
			{Flag: "plan", Value: "rebalance-plan.json", Description: ArgFile},
		}),
		def("rebalance-report", "report", "Show the last rebalance report", nil),
	}
}

// BootstrapCommands returns the trust-bootstrap commands. show-keys asks the
// running server over the SDK and runs on every transport; the rest are
// local key and certificate tooling or bootstrap's own channel, and run once
// on the embedded cell.
func BootstrapCommands() []CommandDefinition {
	local := func(name string, verb []string, desc string, args ...ArgDefinition) CommandDefinition {
		return CommandDefinition{
			Name:          name,
			Category:      CategoryBootstrap,
			Command:       append([]string{"bootstrap"}, verb...),
			Description:   desc,
			Workflow:      WorkflowBootstrap,
			Transports:    []ProtocolType{ProtocolEmbedded},
			TransportSkip: ReasonNoSDKTransport,
			RequiredArgs:  args,
		}
	}
	file := func(flag string) ArgDefinition {
		return ArgDefinition{Flag: flag, Value: "", Description: ArgFile}
	}
	verifyTLSA := local("bootstrap-dane-verify-tlsa", []string{"dane", "verify-tlsa"}, "Verify a certificate against DNS TLSA records")
	verifyTLSA.Unsupported = ReasonNoTLSAZone
	showTLSA := local("bootstrap-dane-show-tlsa", []string{"dane", "show-tlsa"}, "Show DNS TLSA records")
	showTLSA.Unsupported = ReasonNoTLSAZone

	return []CommandDefinition{
		limitToServer(CommandDefinition{
			Name:           "bootstrap-show-keys",
			Category:       CategoryBootstrap,
			Command:        []string{"bootstrap", "show-keys"},
			Description:    "Show the server's bootstrap listener public keys",
			RequiresServer: true,
			Workflow:       WorkflowBootstrap,
		}, ReasonEmbeddedNoBootstrap),
		local("bootstrap-noise-generate-key", []string{"noise", "generate-key"}, "Generate a Noise_NK static key", file("output")),
		local("bootstrap-noise-show-key", []string{"noise", "show-key"}, "Show a Noise_NK public key", file("key-file")),
		local("bootstrap-noise-generate-p256-key", []string{"noise", "generate-p256-key"}, "Generate a P-256 static key", file("output")),
		local("bootstrap-noise-show-p256-key", []string{"noise", "show-p256-key"}, "Show a P-256 public key", file("key-file")),
		local("bootstrap-noise-show-spki-pin", []string{"noise", "show-spki-pin"}, "Show a certificate's SPKI pin", file("cert-file")),
		local("bootstrap-spki-show-pin", []string{"spki", "show-pin"}, "Show a certificate's SPKI pin", file("cert-file")),
		local("bootstrap-dane-generate-tlsa", []string{"dane", "generate-tlsa"}, "Generate TLSA records for a certificate",
			file("cert-file"), ArgDefinition{Flag: "hostname", Value: "kms.example.com", Description: "TLSA hostname"}),
		verifyTLSA,
		showTLSA,
		local("bootstrap-auto", []string{"auto"}, "Fetch the CA bundle over a pinned bootstrap channel",
			ArgDefinition{Flag: "server-url", Value: "", Description: "Server URL"},
			ArgDefinition{Flag: "spki-pin", Value: "", Description: "Server SPKI pin"},
			file("bundle-output")),
	}
}
