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

package xkms

import (
	"errors"
	"fmt"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

func TestAsNotLeader_DirectMatch(t *testing.T) {
	src := &qrdbtransport.NotLeaderError{ShardID: 3, LeaderID: 2, LeaderAddress: "10.0.0.2:63001"}

	nl, ok := AsNotLeader(src)
	if !ok {
		t.Fatal("AsNotLeader(NotLeaderError) = false, want true")
	}
	if nl.ShardID != 3 || nl.LeaderID != 2 || nl.LeaderAddress != "10.0.0.2:63001" {
		t.Fatalf("translated = %+v, want shard 3 / leader 2 / 10.0.0.2:63001", nl)
	}
}

func TestAsNotLeader_Wrapped(t *testing.T) {
	src := &qrdbtransport.NotLeaderError{ShardID: 1, LeaderID: 5, LeaderAddress: "node5:63001"}
	wrapped := fmt.Errorf("write key blob: %w", src)

	nl, ok := AsNotLeader(wrapped)
	if !ok {
		t.Fatal("AsNotLeader(wrapped NotLeaderError) = false, want true")
	}
	if nl.LeaderID != 5 || nl.LeaderAddress != "node5:63001" {
		t.Fatalf("translated = %+v, want leader 5 at node5:63001", nl)
	}
}

func TestAsNotLeader_LeaderUnknown(t *testing.T) {
	src := &qrdbtransport.NotLeaderError{ShardID: 9}

	nl, ok := AsNotLeader(src)
	if !ok {
		t.Fatal("AsNotLeader(leader unknown) = false, want true")
	}
	if nl.LeaderID != 0 {
		t.Fatalf("LeaderID = %d, want 0", nl.LeaderID)
	}
	want := "keystore: not leader for shard 9, leader unknown"
	if nl.Error() != want {
		t.Fatalf("Error() = %q, want %q", nl.Error(), want)
	}
}

func TestAsNotLeader_NoMatch(t *testing.T) {
	if nl, ok := AsNotLeader(nil); ok || nl != nil {
		t.Fatalf("AsNotLeader(nil) = (%v, %v), want (nil, false)", nl, ok)
	}
	if nl, ok := AsNotLeader(errors.New("some other error")); ok || nl != nil {
		t.Fatalf("AsNotLeader(other) = (%v, %v), want (nil, false)", nl, ok)
	}
	if nl, ok := AsNotLeader(ErrKeyNotFound); ok || nl != nil {
		t.Fatalf("AsNotLeader(ErrKeyNotFound) = (%v, %v), want (nil, false)", nl, ok)
	}
}

func TestErrNotLeader_ErrorMessage(t *testing.T) {
	e := &ErrNotLeader{ShardID: 2, LeaderID: 4, LeaderAddress: "10.0.0.4:63001"}
	want := "keystore: not leader for shard 2, leader is replica 4 at 10.0.0.4:63001"
	if e.Error() != want {
		t.Fatalf("Error() = %q, want %q", e.Error(), want)
	}
}
