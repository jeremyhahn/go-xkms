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

// sshechod is a loopback SSH echo server for xkey's live end-to-end tests
// (Playwright's embedded-console spec spawns it with `go run`). It accepts
// any public key, grants a PTY + shell, and echoes the session byte stream
// back until it sees "exit". On startup it prints one line to stdout:
//
//	SSHECHO LISTEN <host> <port>
//
// and then serves until the process is killed.
//
// An optional argument selects the loopback bind IP (default 127.0.0.1).
// Tests pass a unique 127.0.0.0/8 address per run so each run's fresh host
// key gets its own known-hosts pin entry — reusing one IP across runs would
// trip the (correct) pin-mismatch hard failure.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	fatalIf(err, "generate host key")
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	fatalIf(err, "host signer")

	cfg := &ssh.ServerConfig{
		// Accept any client key — the tests exercise the console byte
		// stream and host-key trust, not server-side authorization.
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostSigner)

	bindIP := "127.0.0.1"
	if len(os.Args) > 1 && os.Args[1] != "" {
		bindIP = os.Args[1]
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(bindIP, "0"))
	fatalIf(err, "listen")
	addr := ln.Addr().(*net.TCPAddr)
	fmt.Printf("SSHECHO LISTEN %s %d\n", addr.IP.String(), addr.Port)

	for {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		go handle(conn, cfg)
	}
}

func handle(conn net.Conn, cfg *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		ch, requests, aerr := nc.Accept()
		if aerr != nil {
			continue
		}
		go func(ch ssh.Channel, in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "pty-req", "window-change", "env":
					_ = req.Reply(true, nil)
				case "shell":
					_ = req.Reply(true, nil)
					go echoUntilExit(ch)
				default:
					_ = req.Reply(false, nil)
				}
			}
		}(ch, requests)
	}
}

// echoUntilExit copies the channel back to itself, closing it once "exit"
// appears so the client session ends deterministically. Interactive typing
// arrives one byte per read, so detection runs over a rolling tail window —
// matching only within a single read buffer would never fire for a human
// (or Playwright) typing key by key.
func echoUntilExit(ch ssh.Channel) {
	buf := make([]byte, 256)
	var tail []byte
	for {
		n, rerr := ch.Read(buf)
		if n > 0 {
			_, _ = ch.Write(buf[:n])
			tail = append(tail, buf[:n]...)
			if len(tail) > 16 {
				tail = tail[len(tail)-16:]
			}
			if bytes.Contains(tail, []byte("exit")) {
				_ = ch.Close()
				return
			}
		}
		if rerr != nil {
			_ = ch.Close()
			return
		}
	}
}

func fatalIf(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshechod: %s: %v\n", what, err)
		os.Exit(1)
	}
}
