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

package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// recordedRPC is one control-plane call the bearer recorder served.
type recordedRPC struct {
	method        string
	authorization string
}

// bearerRecorder answers every RPC on a test server like a node that refuses
// anonymous callers: no bearer is Unauthenticated, a bearer is reachable but
// unauthorized (PermissionDenied), which the SDK's connect counts as healthy.
type bearerRecorder struct {
	mu    sync.Mutex
	calls []recordedRPC
}

func (r *bearerRecorder) handle(_ any, stream grpc.ServerStream) error {
	method, ok := grpc.MethodFromServerStream(stream)
	if !ok {
		return status.Error(codes.Internal, "no method on stream")
	}
	md, _ := metadata.FromIncomingContext(stream.Context())
	authorization := strings.Join(md.Get(controlPlaneAuthorizationKey), ",")

	r.mu.Lock()
	r.calls = append(r.calls, recordedRPC{method: method, authorization: authorization})
	r.mu.Unlock()

	if authorization == "" {
		return status.Error(codes.Unauthenticated, "anonymous caller")
	}
	return status.Error(codes.PermissionDenied, "recorded")
}

func (r *bearerRecorder) recorded() []recordedRPC {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedRPC(nil), r.calls...)
}

// startBearerRecordingServer serves the bearer recorder over TLS on a Unix
// socket and returns the recorder, the socket path and the server's CA file.
func startBearerRecordingServer(t *testing.T) (*bearerRecorder, string, string) {
	t.Helper()
	rec := &bearerRecorder{}
	socketPath, caFile := startTLSUnixServer(t, grpc.UnknownServiceHandler(rec.handle))
	return rec, socketPath, caFile
}

// TestDefaultQRDBControlClientFactory_ForwardsToken connects with --token and
// --tls-ca but no client certificate, and shows the connect and every cluster
// and rebalance RPC present the token as a bearer.
func TestDefaultQRDBControlClientFactory_ForwardsToken(t *testing.T) {
	rec, socketPath, caFile := startBearerRecordingServer(t)
	withGlobalConfig(t, &Config{Server: "unix://" + socketPath, TLSCACert: caFile, JWTToken: "secret-token"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ctrl, closer, err := defaultQRDBControlClientFactory(ctx)
	if err != nil {
		t.Fatalf("defaultQRDBControlClientFactory() error = %v, want a connect with the bearer", err)
	}
	defer closeFuncQuietly(closer)
	if ctrl.Cluster == nil || ctrl.Rebalance == nil {
		t.Fatalf("control client = %+v, want cluster and rebalance surfaces", ctrl)
	}

	calls := map[string]func() error{
		"cluster members": func() error {
			_, err := ctrl.Cluster.Members(ctx, defaultShardID)
			return err
		},
		"cluster leader": func() error {
			_, _, err := ctrl.Cluster.Leader(ctx, defaultShardID)
			return err
		},
		"cluster add": func() error {
			return ctrl.Cluster.AddReplica(ctx, defaultShardID, 2, "127.0.0.1:7000", "")
		},
		"cluster remove": func() error {
			return ctrl.Cluster.RemoveReplica(ctx, defaultShardID, 2)
		},
		"rebalance stats": func() error {
			_, err := ctrl.Rebalance.GetShardStats(ctx, defaultShardID)
			return err
		},
		"rebalance plan": func() error {
			_, err := ctrl.Rebalance.CreateRebalancePlan(ctx, &qrdbtransport.RebalancePlanRequest{})
			return err
		},
		"rebalance execute": func() error {
			_, err := ctrl.Rebalance.ExecuteRebalance(ctx, &qrdbtransport.RebalancePlan{})
			return err
		},
		"rebalance report": func() error {
			_, err := ctrl.Rebalance.GetImbalanceReport(ctx)
			return err
		},
	}
	for name, call := range calls {
		before := len(rec.recorded())
		if err := call(); err == nil {
			t.Fatalf("%s: error = nil, want the recorder's PermissionDenied", name)
		}
		served := rec.recorded()[before:]
		if len(served) == 0 {
			t.Fatalf("%s: no RPC reached the server", name)
		}
		for _, rpc := range served {
			if rpc.authorization != "Bearer secret-token" {
				t.Errorf("%s: %s authorization = %q, want the bearer token", name, rpc.method, rpc.authorization)
			}
		}
	}
}

// TestDefaultQRDBControlClientFactory_NoTokenIsAnonymous connects with
// --tls-ca but neither a client certificate nor a token: the connect carries
// no bearer and the node's anonymous rejection fails it.
func TestDefaultQRDBControlClientFactory_NoTokenIsAnonymous(t *testing.T) {
	rec, socketPath, caFile := startBearerRecordingServer(t)
	withGlobalConfig(t, &Config{Server: "unix://" + socketPath, TLSCACert: caFile})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, _, err := defaultQRDBControlClientFactory(ctx)
	var connectErr *QRDBControlConnectError
	if !errors.As(err, &connectErr) {
		t.Fatalf("defaultQRDBControlClientFactory() error = %v, want *QRDBControlConnectError", err)
	}
	served := rec.recorded()
	if len(served) == 0 {
		t.Fatal("the connect never reached the server")
	}
	for _, rpc := range served {
		if rpc.authorization != "" {
			t.Errorf("%s authorization = %q, want none without --token", rpc.method, rpc.authorization)
		}
	}
}

// TestNewQRDBControlTransport_PlaintextBearer shows a token is refused for a
// plaintext grpc:// control plane and accepted once TLS is in force.
func TestNewQRDBControlTransport_PlaintextBearer(t *testing.T) {
	t.Run("plaintext is refused", func(t *testing.T) {
		_, err := newQRDBControlTransport(&Config{Server: "grpc://127.0.0.1:7443", JWTToken: "secret-token"})
		var plaintext *QRDBControlPlaintextBearerError
		if !errors.As(err, &plaintext) {
			t.Fatalf("newQRDBControlTransport() error = %v, want *QRDBControlPlaintextBearerError", err)
		}
		if plaintext.Address != "127.0.0.1:7443" {
			t.Errorf("Address = %q, want the dialled address", plaintext.Address)
		}
	})

	t.Run("TLS carries the token", func(t *testing.T) {
		_, caFile := startTLSUnixServer(t)
		tr, err := newQRDBControlTransport(&Config{Server: "grpcs://127.0.0.1:7443", TLSCACert: caFile, JWTToken: "secret-token"})
		if err != nil {
			t.Fatalf("newQRDBControlTransport() error = %v", err)
		}
		if err := tr.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
}

// TestQRDBControlClient_WithBearer shows an empty token leaves the client as
// it is and a token keeps a missing rebalance surface missing.
func TestQRDBControlClient_WithBearer(t *testing.T) {
	ctrl := &QRDBControlClient{Cluster: &fakeClusterControl{}}

	if got := ctrl.withBearer(""); got != ctrl {
		t.Errorf("withBearer(\"\") = %p, want the client unchanged (%p)", got, ctrl)
	}

	got := ctrl.withBearer("secret-token")
	if _, ok := got.Cluster.(*bearerClusterControl); !ok {
		t.Errorf("Cluster = %T, want *bearerClusterControl", got.Cluster)
	}
	if got.Rebalance != nil {
		t.Errorf("Rebalance = %T, want nil so rebalance commands report unsupported", got.Rebalance)
	}
}
