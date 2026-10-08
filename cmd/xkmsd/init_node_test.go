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

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// =============================================================================
// resolveInitNodeConfig
// =============================================================================

func TestResolveInitNodeConfig_NoLoadedConfig_UsesFlagsAndDataDir(t *testing.T) {
	flags := &initFlags{barrierStrategy: "passphrase"}
	nodeCfg := resolveInitNodeConfig(nil, flags, "/var/lib/xkms")

	if nodeCfg.Datastore.Mode != "standalone" {
		t.Errorf("Datastore.Mode: want standalone, got %q", nodeCfg.Datastore.Mode)
	}
	if nodeCfg.Datastore.Path != "/var/lib/xkms" {
		t.Errorf("Datastore.Path: want /var/lib/xkms, got %q", nodeCfg.Datastore.Path)
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
		Datastore: config.DatastoreConfig{Path: "/etc/configured/path"},
		Barrier:   config.BarrierConfig{Enabled: true, Strategy: "tpm2"},
	}
	flags := &initFlags{barrierStrategy: "passphrase"}

	nodeCfg := resolveInitNodeConfig(cfg, flags, "/var/lib/xkms")

	if nodeCfg.Datastore.Path != "/etc/configured/path" {
		t.Errorf("Storage.Path: loaded config value must win, got %q", nodeCfg.Datastore.Path)
	}
	if nodeCfg.Barrier.Strategy != "tpm2" {
		t.Errorf("Barrier.Strategy: loaded config value must win, got %q", nodeCfg.Barrier.Strategy)
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

// TestUnsealDurableInitNode_PassphraseStrategyCompletesTheUnseal is the
// success path unsealDurableInitNode exists for: `xkmsd init` IS the
// operator-present ceremony, so a "passphrase" node barrier that comes up
// sealed after construction is completed directly with the operator's
// --so-pin rather than waiting on a remote sealed-window listener (that is
// what `xkmsd run` does instead; see the function's doc comment).
func TestUnsealDurableInitNode_PassphraseStrategyCompletesTheUnseal(t *testing.T) {
	dataDir := t.TempDir()
	nodeCfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: dataDir},
		Barrier:   config.BarrierConfig{Enabled: true, Strategy: "passphrase"},
	}
	node, sealRes, err := openDurableInitNode(context.Background(), nodeCfg, silentLogger())
	if err != nil {
		t.Fatalf("openDurableInitNode: %v", err)
	}
	defer func() { _ = node.Close() }()

	if !node.IsSealed() {
		t.Fatal("fixture setup: a fresh passphrase-strategy node must come up sealed")
	}

	if err := unsealDurableInitNode(context.Background(), node, sealRes, "passphrase", []byte("test-so-pin")); err != nil {
		t.Fatalf("unsealDurableInitNode: %v", err)
	}
	if node.IsSealed() {
		t.Fatal("unsealDurableInitNode returned nil but the node is still sealed")
	}
}

func TestUnsealDurableInitNode_RefusesShamir(t *testing.T) {
	dataDir := t.TempDir()
	nodeCfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: dataDir},
		Barrier:   config.BarrierConfig{Enabled: true, Strategy: "shamir", ShamirTotal: 3, ShamirThreshold: 2},
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
