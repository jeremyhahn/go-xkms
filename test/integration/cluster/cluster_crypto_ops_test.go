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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// rsaSpec is the RSA key spec (asymmetric encrypt/decrypt requires RSA).
var rsaSpec = keySpec{name: "rsa-2048", keyType: "rsa", bits: 2048}

// TestCluster_AsymEncryptDecrypt_AcrossNodes proves asymmetric encryption round
// trips across the cluster: an RSA key is generated on the leader and
// replicated; plaintext is encrypted to its PUBLIC key on a FOLLOWER and
// decrypted with its PRIVATE key on the LEADER (and vice-versa) — confirming
// both halves of the key are consistent cluster-wide.
func TestCluster_AsymEncryptDecrypt_AcrossNodes(t *testing.T) {
	nodes := nodeURLs(t)
	ctx := context.Background()
	waitAllReady(t, ctx, nodes)
	leader := waitLeader(t, ctx, nodes)
	follower := followerURL(t, ctx, nodes, leader)

	keyID := fmt.Sprintf("cluster-asym-%d", time.Now().UnixNano())
	code, body, err := genKey(ctx, leader, rsaSpec, keyID)
	if err != nil || (code != http.StatusOK && code != http.StatusCreated) {
		t.Fatalf("gen rsa key on leader: status=%d err=%v body=%s", code, err, body)
	}
	waitKeyReplicated(t, ctx, nodes, keyID)

	plaintext := []byte("cluster asymmetric secret")

	// Encrypt on the follower (public key), decrypt on the leader (private key).
	ct, code, err := encryptAsym(ctx, follower, keyID, plaintext)
	if err != nil || code != http.StatusOK || len(ct) == 0 {
		t.Fatalf("encrypt-asym on follower %s: status=%d err=%v", follower, code, err)
	}
	pt, code, err := decryptData(ctx, leader, keyID, ct)
	if err != nil || code != http.StatusOK {
		t.Fatalf("decrypt on leader %s: status=%d err=%v", leader, code, err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("decrypt on leader returned %q, want %q", pt, plaintext)
	}

	// Symmetric direction: encrypt on the leader, decrypt on the follower.
	ct2, code, err := encryptAsym(ctx, leader, keyID, plaintext)
	if err != nil || code != http.StatusOK || len(ct2) == 0 {
		t.Fatalf("encrypt-asym on leader: status=%d err=%v", code, err)
	}
	pt2, code, err := decryptData(ctx, follower, keyID, ct2)
	if err != nil || code != http.StatusOK {
		t.Fatalf("decrypt on follower %s: status=%d err=%v", follower, code, err)
	}
	if !bytes.Equal(pt2, plaintext) {
		t.Fatalf("decrypt on follower returned %q, want %q", pt2, plaintext)
	}
	t.Logf("asymmetric encrypt/decrypt round-trips both directions across the cluster")
}

// TestCluster_RotateReplication proves a key MUTATION (rotation) replicates: the
// key is rotated on the leader, the NEW public key differs from the original and
// converges on every node, and the rotated key is usable cluster-wide.
func TestCluster_RotateReplication(t *testing.T) {
	nodes := nodeURLs(t)
	ctx := context.Background()
	waitAllReady(t, ctx, nodes)
	leader := waitLeader(t, ctx, nodes)

	keyID := fmt.Sprintf("cluster-rotate-%d", time.Now().UnixNano())
	code, body, err := genKey(ctx, leader, cryptoKeySpecs[0], keyID)
	if err != nil || (code != http.StatusOK && code != http.StatusCreated) {
		t.Fatalf("gen key on leader: status=%d err=%v body=%s", code, err, body)
	}
	waitKeyReplicated(t, ctx, nodes, keyID)

	original, code, err := publicKeyPEM(ctx, leader, keyID)
	if err != nil || code != http.StatusOK || original == "" {
		t.Fatalf("read original public key: status=%d err=%v", code, err)
	}

	// Rotate on the current leader.
	leader = waitLeader(t, ctx, nodes)
	rotated, code, err := rotateKey(ctx, leader, keyID)
	if err != nil || code != http.StatusOK {
		t.Fatalf("rotate on leader %s: status=%d err=%v", leader, code, err)
	}
	if rotated == original {
		t.Fatalf("rotation did not change the public key")
	}

	// The rotated public key must converge on every node.
	for i, u := range nodes {
		nodeIdx := i + 1
		poll(t, 20*time.Second, 400*time.Millisecond, func() (bool, string) {
			p, code, perr := publicKeyPEM(ctx, u, keyID)
			if perr != nil || code != http.StatusOK {
				return false, fmt.Sprintf("node%d public key unavailable", nodeIdx)
			}
			if p == original {
				return false, fmt.Sprintf("node%d still has the pre-rotation key", nodeIdx)
			}
			return p == rotated, fmt.Sprintf("node%d has not converged on the rotated key", nodeIdx)
		})
	}

	// The rotated key still signs+verifies cluster-wide.
	follower := followerURL(t, ctx, nodes, leader)
	signAndVerifyRoundTrip(t, ctx, follower, leader, keyID)
	t.Logf("rotation of %q replicated the new key to all nodes and it remains usable", keyID)
}
