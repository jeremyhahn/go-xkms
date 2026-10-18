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

//go:build raft

package server

import (
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
)

// TestNodeClusterOptions checks that the cluster topology maps onto the
// embedded node options unchanged; enrollment settings stay with the
// TrustedCA resolver and never reach node construction (go-xkms#1381).
func TestNodeClusterOptions(t *testing.T) {
	s := &Server{config: &config.Config{
		Cluster: config.ClusterConfig{
			Enabled:     true,
			NodeID:      2,
			RaftAddress: "10.0.0.2:63001",
			Peers:       "1=10.0.0.1:63001,2=10.0.0.2:63001",
			Join:        true,
		},
	}}

	got := s.nodeClusterOptions()

	want := embeddednode.ClusterOptions{
		Enabled:     true,
		NodeID:      2,
		RaftAddress: "10.0.0.2:63001",
		Peers:       "1=10.0.0.1:63001,2=10.0.0.2:63001",
		Join:        true,
	}
	if got != want {
		t.Errorf("nodeClusterOptions() = %+v, want %+v", got, want)
	}
}

// TestSplitClusterPeers checks the comma-separated "id=addr" peer parser,
// including empty, whitespace, and empty-element handling.
func TestSplitClusterPeers(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"single", "1=a:1", []string{"1=a:1"}},
		{"two", "1=a:1,2=b:2", []string{"1=a:1", "2=b:2"}},
		{"trimmed", " 1=a:1 , 2=b:2 ", []string{"1=a:1", "2=b:2"}},
		{"empty element skipped", "1=a:1,,2=b:2", []string{"1=a:1", "2=b:2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := splitClusterPeers(c.in); !reflect.DeepEqual(got, c.want) {
				t.Errorf("splitClusterPeers(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
