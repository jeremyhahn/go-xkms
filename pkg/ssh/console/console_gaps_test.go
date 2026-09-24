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

package console

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestConfigDefaults covers the term/rows/cols default and override branches.
func TestConfigDefaults(t *testing.T) {
	def := Config{}
	if def.term() != defaultTerm {
		t.Fatalf("term default: got %q", def.term())
	}
	if def.rows() != defaultRows {
		t.Fatalf("rows default: got %d", def.rows())
	}
	if def.cols() != defaultCols {
		t.Fatalf("cols default: got %d", def.cols())
	}

	custom := Config{Term: "vt100", Rows: 40, Cols: 132}
	if custom.term() != "vt100" || custom.rows() != 40 || custom.cols() != 132 {
		t.Fatalf("overrides not honored: %+v", custom)
	}
}

// TestErrorTypes covers the console error String/Unwrap methods.
func TestErrorTypes(t *testing.T) {
	ie := &InputError{Field: "Signer"}
	if ie.Error() == "" {
		t.Fatal("InputError.Error empty")
	}

	inner := errors.New("pty boom")
	se := &SessionError{Err: inner}
	if se.Error() == "" {
		t.Fatal("SessionError.Error empty")
	}
	if !errors.Is(se, inner) {
		t.Fatal("SessionError.Unwrap did not expose inner")
	}

	ce := &ClosedError{}
	if ce.Error() == "" {
		t.Fatal("ClosedError.Error empty")
	}
}

// TestDial_InputGuards covers the nil Signer / nil KnownHosts guards without a
// live server.
func TestDial_InputGuards(t *testing.T) {
	_, err := Dial(context.Background(), DialRequest{}, Config{})
	var ie *InputError
	if !errors.As(err, &ie) || ie.Field != "Signer" {
		t.Fatalf("expected Signer InputError, got %v", err)
	}
}

// TestOpen_NilClient covers the nil-client guard in Open.
func TestOpen_NilClient(t *testing.T) {
	_, err := Open(nil, Config{})
	var ie *InputError
	if !errors.As(err, &ie) || ie.Field != "client" {
		t.Fatalf("expected client InputError, got %v", err)
	}
}

// TestConsole_OpenOnClient covers Open() and the open(ownClient=false) path:
// Console.Close terminates only the SSH session, leaving the caller-owned
// *ssh.Client usable.
func TestConsole_OpenOnClient(t *testing.T) {
	srv := startEchoSSHServer(t)

	cfg := &ssh.ClientConfig{
		User:            "tester",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner(t))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(srv.host, strconv.Itoa(srv.port)), cfg)
	if !requireHandshake(t, err) {
		return
	}
	defer client.Close()

	c, err := Open(client, Config{Rows: 20, Cols: 80})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, err := c.Write([]byte("ping\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !strings.Contains(line, "ping") {
		t.Fatalf("echo mismatch: %q", line)
	}

	// Close terminates the session only; the caller-owned client stays open.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("client should remain usable after console Close: %v", err)
	}
	_ = sess.Close()
}

// TestHandlerOptions covers the WithDialTimeout and WithCheckOrigin options.
func TestHandlerOptions(t *testing.T) {
	h := &wsHandler{}

	WithDialTimeout(7 * time.Second)(h)
	if h.dialTimeout != 7*time.Second {
		t.Fatalf("WithDialTimeout not applied: %v", h.dialTimeout)
	}

	called := false
	WithCheckOrigin(func(*http.Request) bool { called = true; return true })(h)
	if h.upgrader.CheckOrigin == nil {
		t.Fatal("WithCheckOrigin did not set the upgrader callback")
	}
	if !h.upgrader.CheckOrigin(nil) || !called {
		t.Fatal("CheckOrigin callback not wired through")
	}
}
