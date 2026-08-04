// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package cluster

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// followerURL returns a node URL that is NOT the current leader, so a test can
// prove an operation works on a non-leader replica.
func followerURL(t *testing.T, ctx context.Context, nodes [3]string, leader string) string {
	t.Helper()
	for _, u := range nodes {
		if u != leader {
			return u
		}
	}
	t.Fatalf("no follower distinct from leader %q found", leader)
	return ""
}

// TestCluster_KeyGenSignVerify_AcrossNodes proves the core cluster guarantee:
// a key generated on the leader is replicated through Raft to every node, and
// its PRIVATE material is usable on a FOLLOWER (sign) while its PUBLIC half
// verifies on yet another node. Exercised across ECDSA/Ed25519/RSA.
func TestCluster_KeyGenSignVerify_AcrossNodes(t *testing.T) {
	nodes := nodeURLs(t)
	ctx := context.Background()
	waitAllReady(t, ctx, nodes)
	leader := waitLeader(t, ctx, nodes)
	follower := followerURL(t, ctx, nodes, leader)

	for _, spec := range cryptoKeySpecs {
		spec := spec
		t.Run(spec.name, func(t *testing.T) {
			keyID := fmt.Sprintf("cluster-crypto-%s-%d", spec.name, time.Now().UnixNano())

			code, body, err := genKey(ctx, leader, spec, keyID)
			if err != nil || (code != http.StatusOK && code != http.StatusCreated) {
				t.Fatalf("gen %s on leader %s: status=%d err=%v body=%s", spec.name, leader, code, err, body)
			}

			// Committed on the leader → must converge on every node.
			waitKeyReplicated(t, ctx, nodes, keyID)

			// Sign on a FOLLOWER (private key replicated), verify on the LEADER.
			signAndVerifyRoundTrip(t, ctx, follower, leader, keyID)
			// And the symmetric direction: sign on the leader, verify on a follower.
			signAndVerifyRoundTrip(t, ctx, leader, follower, keyID)

			t.Logf("%s: generated on leader, signed on follower %s, verified cluster-wide", spec.name, follower)
		})
	}
}

// TestCluster_PublicKeyConsistency proves that the replicated public key is
// byte-identical on all three nodes (no divergence in the replicated state).
func TestCluster_PublicKeyConsistency(t *testing.T) {
	nodes := nodeURLs(t)
	ctx := context.Background()
	waitAllReady(t, ctx, nodes)
	leader := waitLeader(t, ctx, nodes)

	keyID := fmt.Sprintf("cluster-pubkey-consistency-%d", time.Now().UnixNano())
	code, body, err := genKey(ctx, leader, cryptoKeySpecs[0], keyID)
	if err != nil || (code != http.StatusOK && code != http.StatusCreated) {
		t.Fatalf("gen key on leader: status=%d err=%v body=%s", code, err, body)
	}
	waitKeyReplicated(t, ctx, nodes, keyID)

	var reference string
	for i, u := range nodes {
		nodeIdx := i + 1
		var pem string
		poll(t, 15*time.Second, 400*time.Millisecond, func() (bool, string) {
			p, code, perr := publicKeyPEM(ctx, u, keyID)
			if perr != nil || code != http.StatusOK || p == "" {
				return false, fmt.Sprintf("node%d public key not yet available (code=%d err=%v)", nodeIdx, code, perr)
			}
			pem = p
			return true, ""
		})
		if reference == "" {
			reference = pem
			continue
		}
		if pem != reference {
			t.Fatalf("public key on node%d diverges from node1:\nnode1=%q\nnode%d=%q", nodeIdx, reference, nodeIdx, pem)
		}
	}
	t.Logf("public key for %q is byte-identical across all three nodes", keyID)
}

// TestCluster_DeleteReplication proves that a delete committed on one node
// removes the key everywhere (negative replication).
func TestCluster_DeleteReplication(t *testing.T) {
	nodes := nodeURLs(t)
	ctx := context.Background()
	waitAllReady(t, ctx, nodes)
	leader := waitLeader(t, ctx, nodes)

	keyID := fmt.Sprintf("cluster-delete-repl-%d", time.Now().UnixNano())
	code, body, err := genKey(ctx, leader, cryptoKeySpecs[0], keyID)
	if err != nil || (code != http.StatusOK && code != http.StatusCreated) {
		t.Fatalf("gen key on leader: status=%d err=%v body=%s", code, err, body)
	}
	waitKeyReplicated(t, ctx, nodes, keyID)

	// Delete must be routed to / committed by the leader; issue it against the
	// current leader to avoid NotLeader rejections.
	leader = waitLeader(t, ctx, nodes)
	code, body, err = deleteKey(ctx, leader, keyID)
	if err != nil || (code != http.StatusOK && code != http.StatusNoContent) {
		t.Fatalf("delete key on leader %s: status=%d err=%v body=%s", leader, code, err, body)
	}

	for i, u := range nodes {
		nodeIdx := i + 1
		poll(t, 20*time.Second, 400*time.Millisecond, func() (bool, string) {
			return !keyExists(ctx, u, keyID),
				fmt.Sprintf("key %q still present on node%d after delete", keyID, nodeIdx)
		})
	}
	t.Logf("delete of %q replicated to all three nodes", keyID)
}
