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
	"os/exec"
	"strings"
	"testing"
	"time"
)

// nodeContainer maps a 1-based node index to its docker container name.
func nodeContainer(nodeIdx int) string {
	return fmt.Sprintf("cluster-node%d", nodeIdx)
}

// requireDocker asserts that the docker CLI and the daemon socket are reachable
// from inside the test container.
//
// The cluster harness (test/integration/cluster/Dockerfile.test and the `test`
// service in docker-compose.yml) installs the docker client and bind-mounts
// /var/run/docker.sock precisely so the chaos tests can kill and restart nodes.
// If docker is unreachable the harness is broken, not the environment, so this
// is a hard failure rather than a reason to declare the chaos coverage passed.
func requireDocker(t *testing.T) {
	t.Helper()
	out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput()
	if err != nil {
		t.Fatalf("docker control unavailable: %v (%s); the cluster harness must mount /var/run/docker.sock "+
			"and provide the docker CLI - see test/integration/cluster/Dockerfile.test",
			err, strings.TrimSpace(string(out)))
	}
}

// dockerAction runs `docker <action> <container>` and fails the test on error.
func dockerAction(t *testing.T, action, container string) {
	t.Helper()
	out, err := exec.Command("docker", action, container).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s %s failed: %v (%s)", action, container, err, string(out))
	}
	t.Logf("docker %s %s", action, container)
}

// leaderNodeIndex returns the 1-based index of the current leader, polling the
// reachable nodes until one reports a leader.
func leaderNodeIndex(t *testing.T, ctx context.Context, nodes [3]string) int {
	t.Helper()
	var idx int
	poll(t, 45*time.Second, 500*time.Millisecond, func() (bool, string) {
		for _, u := range nodes {
			st, err := fetchStatus(ctx, u)
			if err == nil && st.Status.HasLeader && st.Status.LeaderID != 0 {
				idx = int(st.Status.LeaderID)
				return true, ""
			}
		}
		return false, "no leader visible on any reachable node yet"
	})
	return idx
}

// waitContainerHealthy waits until the given node's REST /health answers 200,
// i.e. the (restarted) process is serving again.
func waitContainerHealthy(t *testing.T, ctx context.Context, url string) {
	t.Helper()
	poll(t, 90*time.Second, 1*time.Second, func() (bool, string) {
		return isReady(ctx, url), fmt.Sprintf("%s not healthy yet", url)
	})
}

// restoreCluster restarts a container (idempotent — `docker start` on a running
// container is a no-op) and waits for the whole cluster to be healthy with a
// single agreed leader, so a chaos test never leaves the cluster degraded for
// the tests that follow.
func restoreCluster(t *testing.T, ctx context.Context, nodes [3]string, container string) {
	_, _ = exec.Command("docker", "start", container).CombinedOutput()
	waitAllReady(t, ctx, nodes)
	_ = waitLeader(t, ctx, nodes)
}

// TestCluster_LeaderFailover kills the current leader and asserts the cluster
// re-elects a new leader and continues to serve crypto operations on the
// surviving nodes using key material that was replicated before the failure.
func TestCluster_LeaderFailover(t *testing.T) {
	requireDocker(t)
	nodes := nodeURLs(t)
	ctx := context.Background()
	waitAllReady(t, ctx, nodes)

	// Seed a key that must survive the leader's death and remain usable.
	keyID := fmt.Sprintf("failover-key-%d", time.Now().UnixNano())
	code, body, err := genKey(ctx, waitLeader(t, ctx, nodes), cryptoKeySpecs[0], keyID)
	if err != nil || (code != http.StatusOK && code != http.StatusCreated) {
		t.Fatalf("seed key: status=%d err=%v body=%s", code, err, body)
	}
	waitKeyReplicated(t, ctx, nodes, keyID)

	oldLeaderIdx := leaderNodeIndex(t, ctx, nodes)
	leaderContainer := nodeContainer(oldLeaderIdx)
	t.Cleanup(func() { restoreCluster(t, ctx, nodes, leaderContainer) })

	// Kill the leader.
	dockerAction(t, "kill", leaderContainer)

	// The survivors must elect a NEW leader (different node id).
	var newLeaderIdx int
	poll(t, 60*time.Second, 1*time.Second, func() (bool, string) {
		for i, u := range nodes {
			if i+1 == oldLeaderIdx {
				continue // the killed node is unreachable
			}
			st, serr := fetchStatus(ctx, u)
			if serr == nil && st.Status.HasLeader && st.Status.LeaderID != 0 && int(st.Status.LeaderID) != oldLeaderIdx {
				newLeaderIdx = int(st.Status.LeaderID)
				return true, ""
			}
		}
		return false, fmt.Sprintf("no new leader elected yet (old leader was node%d)", oldLeaderIdx)
	})
	t.Logf("leader failover: node%d killed, node%d elected new leader", oldLeaderIdx, newLeaderIdx)

	// Crypto must still work on a surviving node using the pre-replicated key.
	survivor := nodes[newLeaderIdx-1]
	signAndVerifyRoundTrip(t, ctx, survivor, survivor, keyID)
	t.Logf("crypto operations continue on survivor node%d after leader failover", newLeaderIdx)
}

// TestCluster_NodeRestartRejoin kills a follower, commits new state on the
// surviving majority, then restarts the follower and asserts it rejoins and
// catches up — the state written while it was down becomes visible on it.
func TestCluster_NodeRestartRejoin(t *testing.T) {
	requireDocker(t)
	nodes := nodeURLs(t)
	ctx := context.Background()
	waitAllReady(t, ctx, nodes)

	leaderIdx := leaderNodeIndex(t, ctx, nodes)
	// Pick a follower to restart (killing a follower keeps a stable leader).
	followerIdx := 1
	for followerIdx == leaderIdx {
		followerIdx++
	}
	followerContainer := nodeContainer(followerIdx)
	followerURLStr := nodes[followerIdx-1]
	t.Cleanup(func() { restoreCluster(t, ctx, nodes, followerContainer) })

	// Kill the follower.
	dockerAction(t, "kill", followerContainer)

	// Commit new state on the surviving 2-node majority.
	keyID := fmt.Sprintf("rejoin-key-%d", time.Now().UnixNano())
	leader := waitLeader(t, ctx, nodes)
	code, body, err := genKey(ctx, leader, cryptoKeySpecs[0], keyID)
	if err != nil || (code != http.StatusOK && code != http.StatusCreated) {
		t.Fatalf("gen key on majority: status=%d err=%v body=%s", code, err, body)
	}
	// Confirm it committed on the two survivors.
	for i, u := range nodes {
		if i+1 == followerIdx {
			continue
		}
		nodeIdx := i + 1
		poll(t, 20*time.Second, 400*time.Millisecond, func() (bool, string) {
			return keyExists(ctx, u, keyID),
				fmt.Sprintf("key %q not committed on surviving node%d", keyID, nodeIdx)
		})
	}
	t.Logf("committed %q on the surviving majority while node%d was down", keyID, followerIdx)

	// Restart the follower and wait for it to serve again.
	dockerAction(t, "start", followerContainer)
	waitContainerHealthy(t, ctx, followerURLStr)

	// It must catch up: the key written while it was down becomes present.
	poll(t, 60*time.Second, 1*time.Second, func() (bool, string) {
		return keyExists(ctx, followerURLStr, keyID),
			fmt.Sprintf("restarted node%d has not yet caught up on %q", followerIdx, keyID)
	})
	t.Logf("node%d rejoined and caught up: %q is present after restart", followerIdx, keyID)

	// And the recovered node can serve crypto with the caught-up key.
	signAndVerifyRoundTrip(t, ctx, followerURLStr, followerURLStr, keyID)
}
