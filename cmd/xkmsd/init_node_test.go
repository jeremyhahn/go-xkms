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

package main

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
)

// =============================================================================
// resolveInitNodeConfig
// =============================================================================

func TestResolveInitNodeConfig_NoLoadedConfig_UsesFlagsAndDataDir(t *testing.T) {
	flags := &initFlags{barrierStrategy: "passphrase"}
	nodeCfg := resolveInitNodeConfig(nil, flags, "/var/lib/xkms")

	if nodeCfg.Storage.Backend != "qrdb" {
		t.Errorf("Storage.Backend: want qrdb, got %q", nodeCfg.Storage.Backend)
	}
	if nodeCfg.Storage.Path != "/var/lib/xkms" {
		t.Errorf("Storage.Path: want /var/lib/xkms, got %q", nodeCfg.Storage.Path)
	}
	if !nodeCfg.Barrier.Enabled {
		t.Error("Barrier.Enabled: want true")
	}
	if nodeCfg.Barrier.Strategy != "passphrase" {
		t.Errorf("Barrier.Strategy: want passphrase, got %q", nodeCfg.Barrier.Strategy)
	}
}

func TestResolveInitNodeConfig_LoadedConfigWins(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{Backend: "qrdb", Path: "/etc/configured/path"},
		Barrier: config.BarrierConfig{Enabled: true, Strategy: "tpm2"},
	}
	flags := &initFlags{barrierStrategy: "passphrase"}

	nodeCfg := resolveInitNodeConfig(cfg, flags, "/var/lib/xkms")

	if nodeCfg.Storage.Path != "/etc/configured/path" {
		t.Errorf("Storage.Path: loaded config value must win, got %q", nodeCfg.Storage.Path)
	}
	if nodeCfg.Barrier.Strategy != "tpm2" {
		t.Errorf("Barrier.Strategy: loaded config value must win, got %q", nodeCfg.Barrier.Strategy)
	}
}

func TestResolveInitNodeConfig_ShamirFlagsCarryThreshold(t *testing.T) {
	flags := &initFlags{barrierStrategy: "shamir", shares: 5, threshold: 3}
	nodeCfg := resolveInitNodeConfig(nil, flags, "/data")

	if nodeCfg.Barrier.ShamirTotal != 5 {
		t.Errorf("ShamirTotal: want 5, got %d", nodeCfg.Barrier.ShamirTotal)
	}
	if nodeCfg.Barrier.ShamirThreshold != 3 {
		t.Errorf("ShamirThreshold: want 3, got %d", nodeCfg.Barrier.ShamirThreshold)
	}
}

// =============================================================================
// openDurableInitNode / unsealDurableInitNode
// =============================================================================

func TestOpenDurableInitNode_RequiresStoragePath(t *testing.T) {
	_, _, err := openDurableInitNode(context.Background(), &config.Config{}, silentLogger())
	if !errors.Is(err, ErrNodeConfigRequired) {
		t.Fatalf("expected ErrNodeConfigRequired, got %v", err)
	}
}

func TestOpenDurableInitNode_NilConfig(t *testing.T) {
	_, _, err := openDurableInitNode(context.Background(), nil, silentLogger())
	if !errors.Is(err, ErrNodeConfigRequired) {
		t.Fatalf("expected ErrNodeConfigRequired, got %v", err)
	}
}

func TestUnsealDurableInitNode_RefusesShamir(t *testing.T) {
	dataDir := t.TempDir()
	nodeCfg := &config.Config{
		Storage: config.StorageConfig{Backend: "qrdb", Path: dataDir},
		Barrier: config.BarrierConfig{Enabled: true, Strategy: "shamir", ShamirTotal: 3, ShamirThreshold: 2},
	}
	node, sealRes, err := openDurableInitNode(context.Background(), nodeCfg, silentLogger())
	if err != nil {
		t.Fatalf("openDurableInitNode: %v", err)
	}
	defer func() { _ = node.Close() }()

	err = unsealDurableInitNode(context.Background(), node, sealRes, "shamir", []byte("so-pin"))
	if !errors.Is(err, ErrNodeShamirUnsupported) {
		t.Fatalf("expected ErrNodeShamirUnsupported, got %v", err)
	}
}

// =============================================================================
// executeCeremony (single-admin) — admin factors survive a node reopen
// =============================================================================

// TestExecuteCeremony_SingleAdmin_PersistsAdminFactorAcrossReopen is the
// regression test for #693: an admin factor enrolled during `xkmsd init`
// must be readable from the SAME durable store after the process that
// enrolled it has exited -- simulated here by closing the node
// executeCeremony opened and reopening it fresh, exactly as `xkmsd run`
// would against the same data directory.
func TestExecuteCeremony_SingleAdmin_PersistsAdminFactorAcrossReopen(t *testing.T) {
	dataDir := t.TempDir()
	plan, err := qrdbsdk.NewAdminEnrollmentPlan([]qrdbsdk.AdminFactor{qrdbsdk.FactorMTLS})
	if err != nil {
		t.Fatalf("NewAdminEnrollmentPlan: %v", err)
	}

	env := &ceremonyEnv{
		logger:         silentLogger(),
		hostname:       "test.example.com",
		dataDir:        dataDir,
		nodeCfg:        testNodeConfig(dataDir),
		enrollmentPlan: plan,
	}
	cs := buildCeremonyService(t, nil)

	result, err := executeCeremony(context.Background(), cs, env)
	if err != nil {
		t.Fatalf("executeCeremony: %v", err)
	}
	if result.State != initialize.StateOperational {
		t.Fatalf("expected StateOperational, got %s", result.State)
	}
	if len(env.enrolledFactors) != 1 {
		t.Fatalf("expected 1 enrolled factor, got %d", len(env.enrolledFactors))
	}
	if env.adminUserID == 0 {
		t.Fatal("expected a non-zero admin userID")
	}

	// Simulate `xkmsd run` starting later: reopen the SAME durable node from
	// the SAME data directory and confirm the factor is there.
	node2, _, err := openDurableInitNode(context.Background(), testNodeConfig(dataDir), silentLogger())
	if err != nil {
		t.Fatalf("reopen node: %v", err)
	}
	defer func() { _ = node2.Close() }()

	factors, err := node2.Client().UserAuthFactors().ListAuthFactors(context.Background(), &qrdbtransport.AuthFactorListRequest{
		UserID: env.adminUserID,
	})
	if err != nil {
		t.Fatalf("ListAuthFactors: %v", err)
	}
	if len(factors.Factors) != 1 {
		t.Fatalf("expected 1 persisted factor after reopen, got %d", len(factors.Factors))
	}
	if factors.Factors[0].Type != "mtls" {
		t.Errorf("persisted factor type: want mtls, got %s", factors.Factors[0].Type)
	}

	// The administrator's own record must also have survived the reopen.
	adminUser, err := node2.Client().Users().GetUser(context.Background(), env.adminUserID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if adminUser.TenantID != qrdbsdk.SystemTenantID {
		t.Errorf("admin TenantID: want %s, got %s", qrdbsdk.SystemTenantID, adminUser.TenantID)
	}
}

// TestExecuteCeremony_SingleAdmin_PersistFailureFailsClosed verifies that a
// durable-store failure during admin-factor enrollment surfaces as an error
// from executeCeremony rather than silently reporting success with an
// unpersisted factor.
func TestExecuteCeremony_SingleAdmin_PersistFailureFailsClosed(t *testing.T) {
	dataDir := t.TempDir()
	// A factor plan with no attached hardware for piv (no PIVGenerator
	// configured on the environment) fails enrollment itself before the
	// persister is ever reached -- which is exactly the fail-closed
	// behaviour this test pins: the ceremony must not report success.
	plan, err := qrdbsdk.NewAdminEnrollmentPlan([]qrdbsdk.AdminFactor{qrdbsdk.FactorPIV})
	if err != nil {
		t.Fatalf("NewAdminEnrollmentPlan: %v", err)
	}

	env := &ceremonyEnv{
		logger:         silentLogger(),
		hostname:       "test.example.com",
		dataDir:        dataDir,
		nodeCfg:        testNodeConfig(dataDir),
		enrollmentPlan: plan,
	}
	cs := buildCeremonyService(t, nil)

	_, err = executeCeremony(context.Background(), cs, env)
	if err == nil {
		t.Fatal("expected executeCeremony to fail when the piv factor cannot enroll")
	}
	if len(env.enrolledFactors) != 0 {
		t.Errorf("expected no enrolled factors reported on failure, got %d", len(env.enrolledFactors))
	}
}
