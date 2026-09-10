// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)
// for non-commercial use. Commercial licenses are available.
// See LICENSE and LICENSE-COMMERCIAL for details.

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestListenAddr pins how server.host reaches the metrics, MCP and Noise
// bootstrap listeners: joined with net.JoinHostPort, so an IPv6 host is
// bracketed and the empty default binds every interface. Before this the
// three were built with "%s:%d", which turned "::1" into "::1:9090" -- an
// address net.Listen rejects -- while REST and gRPC bracketed correctly, so
// the configured host was not consumable by every listener (#140).
func TestListenAddr(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "IPv4 host", host: "10.0.0.5", port: 9090, want: "10.0.0.5:9090"},
		{name: "IPv6 host is bracketed", host: "::1", port: 9090, want: "[::1]:9090"},
		{name: "empty host binds every interface", host: "", port: 8445, want: ":8445"},
		{name: "hostname", host: "kms.example.com", port: 9443, want: "kms.example.com:9443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{config: &config.Config{Server: config.ServerConfig{Host: tc.host}}}
			assert.Equal(t, tc.want, s.listenAddr(tc.port))
		})
	}
}
