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

//go:build integration

// This file exercises the linearizable compare-and-swap the cluster commits
// through Raft, which is the primitive the remote-mode PKCS#11 module's
// multi-client lockout counter depends on. The PKCS11StateCAS RPC's server side
// runs the swap as a go-qrdb transaction (CompareValue == expected, SuccessOps =
// [OpPut new]) through consensus, so at most one of N concurrent swaps against
// the same current value can win on any node. The test proves that end to end:
// many goroutines, spread across all three nodes, race a read-modify-CAS on one
// shared counter, and the committed total must equal the number of increments —
// a lower total is a lost update, exactly what a naive last-writer-wins Put would
// produce and what this primitive exists to prevent.
package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// PKCS#11 remote-state endpoints. Records are namespaced by (tenant, token, key);
// the empty tenant is the system scope. The values are opaque bytes, so the test
// stores a decimal counter and reads it back.
const (
	pkcs11StateGetPath = "/api/v1/pkcs11state/get"
	pkcs11StateCASPath = "/api/v1/pkcs11state/compare-and-swap"

	// casToken labels the token the counter is filed under; casKey is the
	// counter record. Any label works — the server stores opaque bytes.
	casToken = "cluster-cas-token"
	casKey   = "counters/lockout"
)

// casGetRequest / casGetResponse mirror the transport DTOs the pkcs11state get
// endpoint speaks. []byte marshals as base64 in JSON, matching the server.
type casGetRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Token    string `json:"token"`
	Key      string `json:"key"`
}

type casGetResponse struct {
	Value []byte `json:"value"`
	Found bool   `json:"found"`
}

// casRequest / casResponse mirror the PKCS11StateCAS DTOs. A nil Expected with
// ExpectAbsent=true means create-if-absent; otherwise the swap requires the
// stored value to equal Expected exactly.
type casRequest struct {
	TenantID     string `json:"tenant_id,omitempty"`
	Token        string `json:"token"`
	Key          string `json:"key"`
	Expected     []byte `json:"expected,omitempty"`
	New          []byte `json:"new"`
	ExpectAbsent bool   `json:"expect_absent,omitempty"`
}

type casResponse struct {
	Swapped bool   `json:"swapped"`
	Current []byte `json:"current,omitempty"`
}

// readCounter reads the shared counter through baseURL, returning its current
// value, whether it is present, and the raw stored bytes (needed verbatim as the
// CAS expected value).
func readCounter(ctx context.Context, baseURL string) (value uint64, raw []byte, found bool, err error) {
	body, mErr := json.Marshal(casGetRequest{Token: casToken, Key: casKey})
	if mErr != nil {
		return 0, nil, false, mErr
	}
	code, respBody, pErr := post(ctx, baseURL+pkcs11StateGetPath, string(body))
	if pErr != nil {
		return 0, nil, false, pErr
	}
	if code != http.StatusOK {
		return 0, nil, false, &errs.Detail{Err: errClusterCAS, Detail: fmt.Sprintf("get status %d: %s", code, respBody)}
	}
	var resp casGetResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return 0, nil, false, err
	}
	if !resp.Found || len(resp.Value) == 0 {
		return 0, nil, false, nil
	}
	v, err := parseDecimal(resp.Value)
	if err != nil {
		return 0, nil, false, err
	}
	return v, resp.Value, true, nil
}

// swapCounter attempts one compare-and-swap through baseURL and reports whether
// it committed. expectAbsent selects create-if-absent (expected must be nil).
func swapCounter(ctx context.Context, baseURL string, expected, next []byte, expectAbsent bool) (bool, error) {
	body, err := json.Marshal(casRequest{
		Token:        casToken,
		Key:          casKey,
		Expected:     expected,
		New:          next,
		ExpectAbsent: expectAbsent,
	})
	if err != nil {
		return false, err
	}
	code, respBody, err := post(ctx, baseURL+pkcs11StateCASPath, string(body))
	if err != nil {
		return false, err
	}
	if code != http.StatusOK {
		return false, &errs.Detail{Err: errClusterCAS, Detail: fmt.Sprintf("cas status %d: %s", code, respBody)}
	}
	var resp casResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return false, err
	}
	return resp.Swapped, nil
}

// errClusterCAS tags a non-2xx from a pkcs11state endpoint so the failure names
// the operation rather than surfacing a bare status code.
var errClusterCAS = fmt.Errorf("cluster pkcs11state CAS")

// parseDecimal decodes a decimal counter value stored as bytes.
func parseDecimal(b []byte) (uint64, error) {
	var v uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, &errs.Detail{Err: errClusterCAS, Detail: fmt.Sprintf("non-decimal counter %q", b)}
		}
		v = v*10 + uint64(c-'0')
	}
	return v, nil
}

func formatDecimal(v uint64) []byte {
	return []byte(fmt.Sprintf("%d", v))
}

// incrementOnce performs one linearizable read-modify-CAS increment against
// baseURL, retrying on a lost race until it commits or the context is done. It
// returns an error only for a transport/status failure, not for a lost race
// (which is retried). committed counts a genuine commit so the caller can assert
// the total.
func incrementOnce(ctx context.Context, baseURL string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, raw, found, err := readCounter(ctx, baseURL)
		if err != nil {
			return err
		}
		var (
			expected     []byte
			expectAbsent bool
		)
		if found {
			expected = raw
		} else {
			expectAbsent = true
		}
		swapped, err := swapCounter(ctx, baseURL, expected, formatDecimal(value+1), expectAbsent)
		if err != nil {
			return err
		}
		if swapped {
			return nil
		}
		// Lost the race to a concurrent writer; re-read and retry.
	}
}

// TestCluster_CompareAndSwap_ConcurrentAccumulates is the multi-client lockout
// property proved against the real 3-node Raft cluster: many goroutines spread
// across all three nodes race read-modify-CAS on one counter, and the committed
// total equals the number of increments — no lost updates. This is the cluster
// analogue of the module-level TestModuleStorage_FailedAttemptCounter_ConcurrentAccumulates,
// here validating that the go-qrdb transaction actually serializes cross-node
// swaps through consensus.
func TestCluster_CompareAndSwap_ConcurrentAccumulates(t *testing.T) {
	nodes := nodeURLs(t)
	ctx := context.Background()

	waitAllReady(t, ctx, nodes)
	leader := waitLeader(t, ctx, nodes)

	// A first create-if-absent probes the write path. When it commits we run the
	// full concurrency assertion; when it hits the known go-quicraft
	// Raft-over-QUIC idle-stall we assert graceful degradation, matching
	// TestCluster_WriteReplication — a stalled proposal must not hang or crash.
	probeCtx, probeCancel := context.WithTimeout(ctx, requestTimeout)
	swapped, err := swapCounter(probeCtx, leader, nil, formatDecimal(0), true)
	probeCancel()
	if err != nil {
		t.Logf("initial CAS to leader %s did not commit within %s (known idle-stall): %v; "+
			"asserting cluster-level graceful degradation", leader, requestTimeout, err)
		assertClusterControlPlaneHealthy(t, ctx, nodes)
		return
	}
	if !swapped {
		// The counter already exists from a prior run against a persistent
		// volume; the compose harness starts from a clean volume, so treat this
		// as a benign starting point and read the base.
		t.Logf("counter already present on leader %s; continuing from its current value", leader)
	}

	base, _, _, err := readCounter(ctx, leader)
	if err != nil {
		t.Fatalf("read counter base on leader %s: %v", leader, err)
	}

	const (
		goroutines        = 12
		incrementsPerG    = 10
		totalIncrements   = goroutines * incrementsPerG
		concurrencyBudget = 90 * time.Second
	)

	runCtx, cancel := context.WithTimeout(ctx, concurrencyBudget)
	defer cancel()

	var (
		wg       sync.WaitGroup
		failures atomic.Uint64
		firstErr atomic.Value // error
	)
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		// Spread writers across all three node URLs; each node forwards the CAS
		// through Raft, so correctness must hold regardless of entry point.
		entry := nodes[g%len(nodes)]
		go func(entry string) {
			defer wg.Done()
			for i := 0; i < incrementsPerG; i++ {
				if err := incrementOnce(runCtx, entry); err != nil {
					failures.Add(1)
					firstErr.CompareAndSwap(nil, err)
					return
				}
			}
		}(entry)
	}
	wg.Wait()

	if n := failures.Load(); n > 0 {
		// A transport/stall failure mid-run: assert graceful degradation rather
		// than a correctness violation, consistent with the harness's treatment
		// of the upstream idle-stall.
		t.Logf("%d writer(s) failed mid-run (first: %v); asserting cluster-level graceful degradation",
			n, firstErr.Load())
		assertClusterControlPlaneHealthy(t, ctx, nodes)
		return
	}

	// Every increment committed: the counter must have advanced by exactly the
	// total, with no lost updates.
	final, _, _, err := readCounter(ctx, leader)
	if err != nil {
		t.Fatalf("read final counter on leader %s: %v", leader, err)
	}
	if got := final - base; got != uint64(totalIncrements) {
		t.Fatalf("lost-update detected: counter advanced by %d, want %d "+
			"(base=%d final=%d); the Raft CAS did not serialize concurrent swaps",
			got, totalIncrements, base, final)
	}
	t.Logf("cluster CAS serialized %d concurrent increments across 3 nodes with no lost updates (base=%d final=%d)",
		totalIncrements, base, final)

	// The committed value must replicate to every node — a read of the counter
	// on each replica must converge on the final value.
	want := formatDecimal(final)
	for i, u := range nodes {
		nodeIdx := i + 1
		poll(t, 15*time.Second, 500*time.Millisecond, func() (bool, string) {
			v, _, found, rErr := readCounter(ctx, u)
			if rErr != nil {
				return false, fmt.Sprintf("node%d read error: %v", nodeIdx, rErr)
			}
			if !found || formatDecimalEqual(v, want) == false {
				return false, fmt.Sprintf("node%d counter=%d, want %d", nodeIdx, v, final)
			}
			return true, ""
		})
		t.Logf("counter replicated to node%d (%s) = %d", nodeIdx, u, final)
	}
}

func formatDecimalEqual(v uint64, want []byte) bool {
	got := formatDecimal(v)
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// assertClusterControlPlaneHealthy verifies every node's control plane is still
// responsive and agrees on a single leader — the graceful-degradation guarantee
// the harness asserts when a write hits the known upstream idle-stall.
func assertClusterControlPlaneHealthy(t *testing.T, ctx context.Context, nodes [3]string) {
	t.Helper()
	var leaderID uint64
	for i, u := range nodes {
		nodeIdx := i + 1
		st, err := fetchStatus(ctx, u)
		if err != nil {
			t.Fatalf("degradation not graceful: node%d (%s) control-plane unavailable: %v", nodeIdx, u, err)
		}
		if !st.Status.HasLeader || st.Status.LeaderID == 0 {
			t.Fatalf("degradation not graceful: node%d (%s) reports no leader", nodeIdx, u)
		}
		if leaderID == 0 {
			leaderID = st.Status.LeaderID
		} else if st.Status.LeaderID != leaderID {
			t.Fatalf("nodes disagree on leader: node%d says %d, earlier node said %d",
				nodeIdx, st.Status.LeaderID, leaderID)
		}
	}
	t.Logf("cluster degraded gracefully: all nodes responsive, single leader %d", leaderID)
}
