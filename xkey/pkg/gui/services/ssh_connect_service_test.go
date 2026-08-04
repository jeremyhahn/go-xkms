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

package services

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// setupConnect builds a connect service backed by a real embedded SSH client
// with a software key, plus injected lookPath/execCommand so no real terminal
// is spawned. It returns the service and a pointer to the captured exec call.
func setupConnect(t *testing.T) (*SSHConnectService, *capturedExec) {
	t.Helper()
	ctx := context.Background()
	backend := storage.New()

	client, err := sshclient.NewEmbedded(sshclient.EmbeddedOptions{Backend: backend})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	if _, err := client.Keys().Generate(ctx, sshclient.GenerateRequest{
		Scope: "user", Owner: "local", Name: "laptop", Algorithm: "ed25519",
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	hostKeys, err := sshclient.NewHostKeyStore(backend)
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}

	svc := NewSSHConnectService()
	svc.SetContext(ctx)
	svc.SetSSHClient(client)
	svc.SetHostKeyStore(hostKeys)

	cap := &capturedExec{}
	svc.lookPath = func(name string) (string, error) {
		if name == "x-terminal-emulator" {
			return "/usr/bin/x-terminal-emulator", nil
		}
		return "", exec.ErrNotFound
	}
	svc.execCommand = func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		cap.name = name
		cap.args = arg
		// Return a harmless command so Start() succeeds without a terminal.
		return exec.CommandContext(ctx, "true")
	}
	return svc, cap
}

type capturedExec struct {
	name string
	args []string
}

func (c *capturedExec) argsContain(want string) bool {
	for _, a := range c.args {
		if a == want {
			return true
		}
	}
	return false
}

func TestSSHConnect_OneTimeLaunch(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectOneTime(SSHConnectParams{
		Host: "server.example.com", Port: 2222, User: "deploy",
		KeyScope: "user", KeyOwner: "local", KeyName: "laptop",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}

	if !strings.HasSuffix(cap.name, "x-terminal-emulator") {
		t.Fatalf("unexpected terminal: %s", cap.name)
	}
	if !cap.argsContain("-e") || !cap.argsContain("ssh") {
		t.Fatalf("missing terminal/ssh args: %v", cap.args)
	}
	if !cap.argsContain("deploy@server.example.com") {
		t.Fatalf("missing target: %v", cap.args)
	}
	if !cap.argsContain("-p") || !cap.argsContain("2222") {
		t.Fatalf("missing port: %v", cap.args)
	}
	var hasKH bool
	for _, a := range cap.args {
		if strings.HasPrefix(a, "UserKnownHostsFile=") {
			hasKH = true
		}
	}
	if !hasKH {
		t.Fatalf("missing UserKnownHostsFile option: %v", cap.args)
	}
}

func TestSSHConnect_TerminalOverride(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()
	svc.SetTerminalCommand("kitty -e")

	if err := svc.ConnectOneTime(SSHConnectParams{
		Host: "h", User: "u", KeyScope: "user", KeyOwner: "local", KeyName: "laptop",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}
	if cap.name != "kitty" || cap.args[0] != "-e" || cap.args[1] != "ssh" {
		t.Fatalf("override not applied: name=%s args=%v", cap.name, cap.args)
	}
}

func TestSSHConnect_LocalPassthrough_HostPort(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectOneTime(SSHConnectParams{
		Host: "server.example.com", Port: 2222, User: "deploy",
		KeySource: "local",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}

	if !cap.argsContain("-p") || !cap.argsContain("2222") {
		t.Fatalf("missing port: %v", cap.args)
	}
	if !cap.argsContain("deploy@server.example.com") {
		t.Fatalf("missing target: %v", cap.args)
	}
	// No agent/known_hosts option injection for a passthrough connection.
	for _, a := range cap.args {
		if strings.HasPrefix(a, "UserKnownHostsFile=") || strings.HasPrefix(a, "IdentitiesOnly") {
			t.Fatalf("unexpected managed-connection option in passthrough args: %v", cap.args)
		}
	}
}

func TestSSHConnect_LocalPassthrough_ConfigAlias(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectOneTime(SSHConnectParams{
		KeySource: "local", SSHConfigAlias: "bastion",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}
	if len(cap.args) < 2 || cap.args[len(cap.args)-1] != "bastion" {
		t.Fatalf("expected plain alias invocation, got %v", cap.args)
	}
}

func TestSSHConnect_ConnectConfigHost(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectConfigHost("prod-bastion"); err != nil {
		t.Fatalf("ConnectConfigHost: %v", err)
	}
	if cap.args[len(cap.args)-1] != "prod-bastion" {
		t.Fatalf("expected alias in argv, got %v", cap.args)
	}
}

func TestSSHConnect_ConnectConfigHost_MissingAlias(t *testing.T) {
	svc := NewSSHConnectService()
	if err := svc.ConnectConfigHost("  "); !errors.Is(err, ErrSSHConnectMissingTarget) {
		t.Fatalf("expected ErrSSHConnectMissingTarget, got %v", err)
	}
}

func TestSSHConnect_LocalPassthrough_MissingTarget(t *testing.T) {
	svc := NewSSHConnectService()
	// KeySource == "local" bypasses the "not configured" check entirely
	// (no sshClient/hostKeys are required for a passthrough connection), so
	// an empty target must fail with ErrSSHConnectMissingTarget specifically.
	if err := svc.ConnectOneTime(SSHConnectParams{KeySource: "local"}); !errors.Is(err, ErrSSHConnectMissingTarget) {
		t.Fatalf("expected ErrSSHConnectMissingTarget, got %v", err)
	}
}

func TestSSHConnect_NotConfigured(t *testing.T) {
	svc := NewSSHConnectService()
	if err := svc.ConnectOneTime(SSHConnectParams{Host: "h", KeyName: "k"}); err == nil {
		t.Fatal("expected error when not configured")
	}
}

// TestSSHConnect_NoKeyPassthrough verifies that a connection with no key
// selected launches a plain passthrough `ssh` (agent/password auth handled by
// the system client) instead of failing to resolve a nameless managed key.
func TestSSHConnect_NoKeyPassthrough(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectOneTime(SSHConnectParams{
		Host: "server.example.com", Port: 2222, User: "deploy",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}

	if !cap.argsContain("deploy@server.example.com") || !cap.argsContain("2222") {
		t.Fatalf("missing target/port: %v", cap.args)
	}
	for _, a := range cap.args {
		if strings.HasPrefix(a, "UserKnownHostsFile=") || a == "-i" {
			t.Fatalf("unexpected managed/identity option in no-key passthrough: %v", cap.args)
		}
	}
}

// TestSSHConnect_LocalPassthrough_IdentityFile verifies that a file-backed
// LocalIdentity is forwarded to ssh as -i <path>.
func TestSSHConnect_LocalPassthrough_IdentityFile(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectOneTime(SSHConnectParams{
		Host: "server.example.com", User: "deploy",
		KeySource: "local", LocalIdentity: "/home/op/.ssh/id_ed25519",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}

	var iAt int = -1
	for i, a := range cap.args {
		if a == "-i" {
			iAt = i
		}
	}
	if iAt == -1 || iAt+1 >= len(cap.args) || cap.args[iAt+1] != "/home/op/.ssh/id_ed25519" {
		t.Fatalf("missing -i <path>: %v", cap.args)
	}
	if cap.args[len(cap.args)-1] != "deploy@server.example.com" {
		t.Fatalf("target must come last: %v", cap.args)
	}
}

// TestSSHConnect_LocalPassthrough_AgentIdentityNoFlag verifies that an
// agent-held LocalIdentity ("agent:<fp>") adds no -i flag — the system agent
// offers the key itself.
func TestSSHConnect_LocalPassthrough_AgentIdentityNoFlag(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectOneTime(SSHConnectParams{
		Host: "server.example.com", User: "deploy",
		KeySource: "local", LocalIdentity: "agent:SHA256:abcdef",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}
	if cap.argsContain("-i") {
		t.Fatalf("agent identity must not add -i: %v", cap.args)
	}
	if cap.args[len(cap.args)-1] != "deploy@server.example.com" {
		t.Fatalf("missing target: %v", cap.args)
	}
}
