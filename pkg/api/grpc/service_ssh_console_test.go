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

package grpc

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// echoSSHServer is an in-process SSH server granting a PTY and echoing input.
func startEchoSSH(t *testing.T) (host string, port int, hostPub gossh.PublicKey) {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := gossh.NewSignerFromKey(hostPriv)
	cfg := &gossh.ServerConfig{
		PublicKeyCallback: func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
			return &gossh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(p)
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go serveEcho(c, cfg)
		}
	}()
	return h, port, hostSigner.PublicKey()
}

func serveEcho(conn net.Conn, cfg *gossh.ServerConfig) {
	defer conn.Close()
	sc, chans, reqs, err := gossh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go gossh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(gossh.UnknownChannelType, "no")
			continue
		}
		ch, requests, _ := nc.Accept()
		go func(ch gossh.Channel, in <-chan *gossh.Request) {
			for req := range in {
				switch req.Type {
				case "pty-req", "window-change", "env":
					_ = req.Reply(true, nil)
				case "shell":
					_ = req.Reply(true, nil)
					go func() { _, _ = io.Copy(ch, ch); _ = ch.Close() }()
				default:
					_ = req.Reply(false, nil)
				}
			}
		}(ch, requests)
	}
}

func TestService_SSHConsoleStream(t *testing.T) {
	ctx := context.Background()
	host, port, hostPub := startEchoSSH(t)

	// Embedded SSH client + a software key, plus a pinned host key.
	backend := storage.New()
	embedded, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Backend: backend})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	if _, err := embedded.Keys().Generate(ctx, sdkssh.GenerateRequest{Scope: "user", Owner: "default", Name: "k", Algorithm: "ed25519"}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	hostKeys, err := sdkssh.NewHostKeyStore(backend)
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}
	if err := hostKeys.Add(ctx, known_hosts.PinFromPublicKey(host, scope.User, "default", hostPub, known_hosts.SourceManual)); err != nil {
		t.Fatalf("pin: %v", err)
	}

	// In-process gRPC server with the SSHConsole service.
	svc := NewService(nil, nil, nil)
	svc.SetSSHClient(embedded)
	svc.SetSSHHostKeyStore(hostKeys)

	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(grpcSrv, svc)
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.Stop()

	// SDK gRPC client over the bufconn dialer.
	client, err := sdkssh.NewGRPC(sdkssh.GRPCOptions{
		Endpoint: "passthrough:///bufnet",
		DialOptions: []grpc.DialOption{
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		},
	})
	if err != nil {
		t.Fatalf("NewGRPC: %v", err)
	}
	defer client.Close()

	cons, err := client.Console(ctx, sdkssh.ConsoleConnectRequest{
		KeyScope: "user", KeyOwner: "default", KeyName: "k",
		Host: host, Port: port, User: "tester",
	}, sdkssh.ConsoleConfig{Term: "xterm-256color", Rows: 24, Cols: 80})
	if err != nil {
		t.Fatalf("Console: %v", err)
	}
	defer cons.Close()

	if err := cons.Resize(40, 120); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if _, err := cons.Write([]byte("grpc-console-hi\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	doneCh := make(chan string, 1)
	go func() {
		reader := bufio.NewReader(cons)
		line, _ := reader.ReadString('\n')
		doneCh <- line
	}()
	select {
	case line := <-doneCh:
		if !strings.Contains(line, "grpc-console-hi") {
			t.Fatalf("echo mismatch over gRPC stream: %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for echo over gRPC console stream")
	}
}
