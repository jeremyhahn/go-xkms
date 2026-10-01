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
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// nodeContainer returns the docker container of the 1-based node index: the
// container of compose service node<idx> in the test container's own compose
// project, so concurrent runs of the suite never touch each other's nodes.
func nodeContainer(t *testing.T, nodeIdx int) string {
	t.Helper()
	self, err := os.Hostname()
	if err != nil {
		t.Fatalf("test container hostname: %v", err)
	}
	project := dockerOutput(t, "inspect", "--format", `{{index .Config.Labels "com.docker.compose.project"}}`, self)
	container := dockerOutput(t, "ps", "--all", "--quiet",
		"--filter", "label=com.docker.compose.project="+project,
		"--filter", fmt.Sprintf("label=com.docker.compose.service=node%d", nodeIdx))
	if container == "" {
		t.Fatalf("no container for service node%d in compose project %q", nodeIdx, project)
	}
	return container
}

// dockerOutput runs a docker command and returns its trimmed output, failing
// the test on error.
func dockerOutput(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v (%s)", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
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
			lid, err := shardLeader(ctx, u)
			if err == nil && lid != 0 {
				idx = int(lid)
				return true, ""
			}
		}
		return false, "no leader visible on any reachable node yet"
	})
	return idx
}

// startNode starts the stopped node nodeIdx, unseals the barrier it boots
// sealed with, and waits until it is ready again.
func startNode(t *testing.T, ctx context.Context, nodes [3]string, nodeIdx int) {
	t.Helper()
	dockerAction(t, "start", nodeContainer(t, nodeIdx))
	if err := openBarrier(nodes[nodeIdx-1], fmt.Sprintf("/node%d-data", nodeIdx)); err != nil {
		t.Fatalf("unseal restarted node%d: %v", nodeIdx, err)
	}
	poll(t, 90*time.Second, 1*time.Second, func() (bool, string) {
		return isReady(ctx, nodes[nodeIdx-1]), fmt.Sprintf("node%d not ready yet", nodeIdx)
	})
}

// restoreCluster restarts node nodeIdx if a test left it stopped, and waits
// for the whole cluster to be ready with a single agreed leader, so a chaos
// test never leaves the cluster degraded for the tests that follow.
func restoreCluster(t *testing.T, ctx context.Context, nodes [3]string, nodeIdx int) {
	t.Helper()
	running := dockerOutput(t, "inspect", "--format", "{{.State.Running}}", nodeContainer(t, nodeIdx))
	if running != "true" {
		startNode(t, ctx, nodes, nodeIdx)
	}
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
	t.Cleanup(func() { restoreCluster(t, ctx, nodes, oldLeaderIdx) })

	// Kill the leader.
	dockerAction(t, "kill", nodeContainer(t, oldLeaderIdx))

	// The survivors must elect a NEW leader (different node id).
	var newLeaderIdx int
	poll(t, 60*time.Second, 1*time.Second, func() (bool, string) {
		for i, u := range nodes {
			if i+1 == oldLeaderIdx {
				continue // the killed node is unreachable
			}
			lid, serr := shardLeader(ctx, u)
			if serr == nil && lid != 0 && int(lid) != oldLeaderIdx {
				newLeaderIdx = int(lid)
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
	followerURLStr := nodes[followerIdx-1]
	t.Cleanup(func() { restoreCluster(t, ctx, nodes, followerIdx) })

	// Kill the follower.
	dockerAction(t, "kill", nodeContainer(t, followerIdx))

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

	// Restart the follower, unseal it, and wait for it to serve again.
	startNode(t, ctx, nodes, followerIdx)

	// It must catch up: the key written while it was down becomes present.
	poll(t, 60*time.Second, 1*time.Second, func() (bool, string) {
		return keyExists(ctx, followerURLStr, keyID),
			fmt.Sprintf("restarted node%d has not yet caught up on %q", followerIdx, keyID)
	})
	t.Logf("node%d rejoined and caught up: %q is present after restart", followerIdx, keyID)

	// And the recovered node can serve crypto with the caught-up key.
	signAndVerifyRoundTrip(t, ctx, followerURLStr, followerURLStr, keyID)
}
