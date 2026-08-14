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

// Package initgate defines the canonical, transport-neutral table of init
// ceremony operations and derives, from that ONE table, the pre-operational
// authentication-exemption allowlist for every xkms transport.
//
// The M-of-N enrollment ceremony is a chicken-and-egg problem: an officer's
// FIRST credential is the certificate handed out by claim-cert, so requiring
// a credential to reach the claim surface would make the ceremony impossible
// to complete under any real authenticator (mTLS in particular). The exempt
// routes are protected by ceremony-layer controls instead of by the
// authentication middleware:
//
//   - claim-cert/begin issues a single-use random nonce bound to the officer
//     username, valid for five minutes.
//   - claim-cert/complete verifies a signature over that nonce against the
//     public key in the officer's pre-submitted CSR, then burns the nonce and
//     marks the pending certificate claimed. A second claim is refused.
//   - claim-share/begin and claim-share/complete are NOT username-trusting.
//     They require a client certificate even though the officer has no
//     account yet: the handler derives the caller's thumbprint from the
//     verified mTLS peer chain (never from the request body), matches it
//     against the thumbprint recorded for that officer at enrollment, and
//     only then issues a single-use nonce / releases the share. What these
//     routes skip is *account* authentication, not identity assertion.
//   - status reports only the ceremony state name.
//
// The transport is additionally SPKI-pinned: the officer verifies the
// server's public key against the pin published by the initialization
// ceremony, so the exemption does not widen the set of parties that can
// reach the daemon, only the set of requests that skip identity assertion.
//
// # One table, every transport
//
// Before this package existed the REST, QUIC and MCP transports each carried
// a hand-mirrored copy of the exempt-operation set and the pre-operational
// state set. Hand mirroring is exactly the drift class go-quicbaas
// eliminated with its canonical sealed-window table
// (go-quicbaas/pkg/api/sealedwindow): a set narrowed on one transport and
// left wide open on another serving the same operation. Every transport now
// derives its allowlist from Table:
//
//   - REST and QUIC share the /api/v1/init HTTP surface: HTTPPublicPaths.
//   - MCP dispatches JSON-RPC methods: MCPPublicMethods.
//   - gRPC (and the unix transport, which serves the same generated
//     xkms.v1.KeystoreService on a unix domain socket) exposes NO init
//     ceremony RPC today, so GRPCPublicMethods derives empty. The guard
//     tests in pkg/api/grpc and pkg/api/unix fail if a ceremony-shaped RPC
//     is ever added to the KeystoreService without wiring this gate.
//   - The embedded transport (pkg/api/transport/embedded) is deliberately
//     ungated: it is an in-process transport whose constructor is handed the
//     live *xkms.XKMSService by the composition root. Possession of the
//     service object IS the authorization — the same trust model as `xkmsd
//     init` running in-process before any listener exists — and no
//     authentication layer exists on that path for ANY operation, so a
//     ceremony-only gate would be theater. See the decision comment in
//     pkg/api/transport/embedded/transport.go.
//
// # Exact match only
//
// Every derived allowlist is keyed on the FULL wire name and matched
// exactly. Prefix matching is deliberately avoided: "/api/v1/init" as a
// prefix would also exempt hypothetical routes such as "/api/v1/initialize",
// and it silently re-admits any route a later change mounts beneath it —
// which is exactly how trust-minting ceremony routes became reachable
// pre-authentication in the systems this design replaces. The guard tests
// in initgate_test.go fail if a prefix entry is ever introduced.
//
// # Fail closed
//
// The exemption applies only while the ceremony is pre-operational. Serving
// the claim endpoints unauthenticated on an already-initialized daemon would
// be a live vulnerability, so the exemption stops applying the moment the
// ceremony reaches the operational state, and ANY state not named in
// preOperationalStates — including a state string a future go-qrdb release
// might add — fails closed.
package initgate

import (
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
)

// Op is a transport-neutral identifier for one init ceremony operation.
type Op string

// Canonical init ceremony operations. The set is the complete ceremony
// surface every transport mounts; whether an operation is exempt from
// pre-operational authentication is decided by Exclusions, not by presence
// here.
const (
	OpStatus             Op = "status"
	OpClaimCertBegin     Op = "claim-cert-begin"
	OpClaimCertComplete  Op = "claim-cert-complete"
	OpClaimShareBegin    Op = "claim-share-begin"
	OpClaimShareComplete Op = "claim-share-complete"
	OpSignCSR            Op = "sign-csr"
)

// Ops is the canonical operation list in stable derivation order.
var Ops = []Op{
	OpStatus,
	OpClaimCertBegin,
	OpClaimCertComplete,
	OpClaimShareBegin,
	OpClaimShareComplete,
	OpSignCSR,
}

// Names holds the per-transport wire names for one canonical operation. An
// empty field means the operation has no surface on that transport.
type Names struct {
	// HTTP is the exact request path on the shared /api/v1/init HTTP
	// surface. The REST and QUIC transports mount identical paths, so one
	// field serves both; listing it once keeps the two mounts of one
	// handler in lock-step.
	HTTP string
	// MCP is the JSON-RPC method name dispatched by the MCP transport.
	MCP string
	// GRPC is the fully-qualified gRPC method path in FullMethod form
	// ("/xkms.v1.KeystoreService/..."). It is empty for every operation
	// today: the KeystoreService deliberately declares no init ceremony
	// RPC. If a ceremony RPC is ever added, its path is declared here and
	// the gRPC/unix guard tests force the gate to be wired.
	GRPC string
}

// Table maps every canonical operation to its per-transport wire names.
// This is the single source of truth for the init ceremony
// authentication-exemption allowlists.
var Table = map[Op]Names{
	OpStatus: {
		HTTP: "/api/v1/init/status",
		MCP:  "init.getStatus",
	},
	OpClaimCertBegin: {
		HTTP: "/api/v1/init/claim-cert/begin",
		MCP:  "init.claimCertBegin",
	},
	OpClaimCertComplete: {
		HTTP: "/api/v1/init/claim-cert/complete",
		MCP:  "init.claimCertComplete",
	},
	OpClaimShareBegin: {
		HTTP: "/api/v1/init/claim-share/begin",
		MCP:  "init.claimShareBegin",
	},
	OpClaimShareComplete: {
		HTTP: "/api/v1/init/claim-share/complete",
		MCP:  "init.claimShareComplete",
	},
	// EXCLUDED from every derivation (see Exclusions). The names stay
	// listed so the table describes the complete mounted ceremony surface
	// and the per-transport parity tests can account for every route.
	OpSignCSR: {
		HTTP: "/api/v1/init/sign-csr",
		MCP:  "init.signCSR",
	},
}

// Exclusions names the ceremony operations that are NEVER exempt from
// authentication on any transport, mapped to the reason. Every derivation
// consults it, so an exclusion cannot apply to some transports and not
// others.
//
// The ceremony initialize verb has no entry because it has no wire surface
// at all: initialization runs in-process (`xkmsd init`) before any listener
// exists, so there is nothing to exempt or exclude.
var Exclusions = map[Op]string{
	OpSignCSR: "requires the SO PIN and is invoked by an already-enrolled " +
		"operator, so it stays authenticated and authorized",
}

// Excluded reports whether op is withheld from every exemption derivation.
func Excluded(op Op) bool {
	_, ok := Exclusions[op]
	return ok
}

// preOperationalStates is the explicit allowlist of ceremony states in which
// the exempt operations may be served without authentication. Any state not
// named here — operational included, and any state string a future go-qrdb
// release might add — fails closed.
var preOperationalStates = map[initialize.CeremonyState]bool{
	initialize.StateAwaitingInit: true,
	initialize.StateEnrolling:    true,
}

// PreOperational reports whether state is one in which the exempt ceremony
// operations may be served without authentication. It fails closed: only
// the explicitly named pre-operational states qualify.
func PreOperational(state initialize.CeremonyState) bool {
	return preOperationalStates[state]
}

// PreOperationalName is PreOperational for transports that carry the
// ceremony state as a wire string (QUIC and MCP read it from
// InitStatusResponse.State).
func PreOperationalName(state string) bool {
	return preOperationalStates[initialize.CeremonyState(state)]
}

// HTTPPublicPaths derives the exact-match allowlist of init ceremony HTTP
// paths an officer may reach without an established credential while the
// ceremony is pre-operational. Both the REST and QUIC transports consume
// it; the map is keyed on the FULL request path and matched exactly.
func HTTPPublicPaths() map[string]bool {
	out := make(map[string]bool, len(Ops))
	for _, op := range Ops {
		if Excluded(op) {
			continue
		}
		if p := Table[op].HTTP; p != "" {
			out[p] = true
		}
	}
	return out
}

// MCPPublicMethods derives the exact-match allowlist of init ceremony
// JSON-RPC methods a credential-less officer may invoke while the ceremony
// is pre-operational.
func MCPPublicMethods() map[string]struct{} {
	out := make(map[string]struct{}, len(Ops))
	for _, op := range Ops {
		if Excluded(op) {
			continue
		}
		if m := Table[op].MCP; m != "" {
			out[m] = struct{}{}
		}
	}
	return out
}

// GRPCPublicMethods derives the exact-match allowlist of fully-qualified
// gRPC methods exempt while the ceremony is pre-operational. It is empty
// today because the KeystoreService declares no init ceremony RPC; the
// guard tests in pkg/api/grpc and pkg/api/unix pin that fact so a future
// ceremony RPC cannot ship without wiring this gate.
func GRPCPublicMethods() map[string]struct{} {
	out := make(map[string]struct{})
	for _, op := range Ops {
		if Excluded(op) {
			continue
		}
		if m := Table[op].GRPC; m != "" {
			out[m] = struct{}{}
		}
	}
	return out
}
