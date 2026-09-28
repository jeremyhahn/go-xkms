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

package cmd

import (
	"errors"
	"reflect"
	"testing"

	"github.com/spf13/cobra"

	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// newSSHConnectCmd builds a cobra.Command with sshConnectCmd's flags
// registered, so resolveSSHConnect can be exercised directly without going
// through the full command tree / init().
func newSSHConnectCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{RunE: runSSHConnect}
	cmd.Flags().String("key", "", "")
	cmd.Flags().String("key-scope", "user", "")
	cmd.Flags().String("key-owner", "", "")
	cmd.Flags().Int("port", 0, "")
	cmd.Flags().String("user", "", "")
	cmd.Flags().String("known-hosts-policy", "barrier", "")
	cmd.Flags().Bool("local", false, "")
	cmd.Flags().String("ssh-config-alias", "", "")
	cmd.Flags().String("identity", "", "")
	return cmd
}

func TestBuildLocalSSHArgs(t *testing.T) {
	cases := []struct {
		name          string
		host          string
		port          int
		user          string
		alias         string
		identity      string
		want          []string
		wantErrTarget bool
	}{
		{
			name: "alias only", alias: "bastion",
			want: []string{"bastion"},
		},
		{
			name: "host only", host: "example.com",
			want: []string{"example.com"},
		},
		{
			name: "host and port and user", host: "example.com", port: 2222, user: "deploy",
			want: []string{"-p", "2222", "deploy@example.com"},
		},
		{
			name: "inline user@host with no explicit user", host: "carol@example.com",
			want: []string{"carol@example.com"},
		},
		{
			name: "alias takes precedence over host", host: "example.com", alias: "bastion",
			want: []string{"bastion"},
		},
		{
			name: "neither alias nor host", wantErrTarget: true,
		},
		{
			name: "file identity adds -i", host: "example.com", user: "deploy",
			identity: "/home/op/.ssh/id_ed25519",
			want:     []string{"-i", "/home/op/.ssh/id_ed25519", "deploy@example.com"},
		},
		{
			name: "agent identity adds no flag", host: "example.com",
			identity: "agent:SHA256:abcdef",
			want:     []string{"example.com"},
		},
		{
			name: "alias suppresses identity flag", alias: "bastion",
			identity: "/home/op/.ssh/id_ed25519",
			want:     []string{"bastion"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, err := buildLocalSSHArgs(tc.host, tc.port, tc.user, tc.alias, tc.identity)
			if tc.wantErrTarget {
				if !errors.Is(err, ErrSSHConnectTarget) {
					t.Fatalf("expected ErrSSHConnectTarget, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildLocalSSHArgs: %v", err)
			}
			if !reflect.DeepEqual(args, tc.want) {
				t.Fatalf("args = %v, want %v", args, tc.want)
			}
			// A passthrough argv must never carry the managed flow's
			// agent/known_hosts option injection.
			for _, a := range args {
				if a == "IdentitiesOnly=yes" || a == "-o" {
					t.Fatalf("unexpected managed-flow option leaked into passthrough args: %v", args)
				}
			}
		})
	}
}

func TestResolveSSHConnect_FlagsOnly(t *testing.T) {
	withCLIHome(t)
	cmd := newSSHConnectCmd(t)
	_ = setFlagForTest(t, cmd.Flags(), "port", "2222")
	_ = setFlagForTest(t, cmd.Flags(), "user", "deploy")

	r, err := resolveSSHConnect(cmd, []string{"server.example.com"})
	if err != nil {
		t.Fatalf("resolveSSHConnect: %v", err)
	}
	if r.Host != "server.example.com" || r.Port != 2222 || r.User != "deploy" || r.Local {
		t.Fatalf("unexpected resolved target: %+v", r)
	}
}

func TestResolveSSHConnect_LocalFlagAndAlias(t *testing.T) {
	withCLIHome(t)
	cmd := newSSHConnectCmd(t)
	_ = setFlagForTest(t, cmd.Flags(), "ssh-config-alias", "bastion")

	r, err := resolveSSHConnect(cmd, nil)
	if err != nil {
		t.Fatalf("resolveSSHConnect: %v", err)
	}
	if !r.Local || r.Alias != "bastion" {
		t.Fatalf("expected Local=true, Alias=bastion; got %+v", r)
	}
}

func TestResolveSSHConnect_ProfileOverridesKeySource(t *testing.T) {
	withCLIHome(t)
	store, err := xkeyProfileStore()
	if err != nil {
		t.Fatalf("xkeyProfileStore: %v", err)
	}
	if err := store.Add(&sshsdk.Profile{
		Name: "bastion-profile", Host: "bastion.example.com",
		KeySource: "local", SSHConfigAlias: "bastion-alias",
	}); err != nil {
		t.Fatalf("Add profile: %v", err)
	}

	cmd := newSSHConnectCmd(t)
	r, err := resolveSSHConnect(cmd, []string{"bastion-profile"})
	if err != nil {
		t.Fatalf("resolveSSHConnect: %v", err)
	}
	if !r.Local || r.Alias != "bastion-alias" {
		t.Fatalf("expected profile's local key source to apply, got %+v", r)
	}
}

func TestResolveSSHConnect_ManagedFlowUnaffected(t *testing.T) {
	withCLIHome(t)
	store, err := xkeyProfileStore()
	if err != nil {
		t.Fatalf("xkeyProfileStore: %v", err)
	}
	if err := store.Add(&sshsdk.Profile{
		Name: "managed-profile", Host: "managed.example.com",
		KeyScope: "user", KeyOwner: "local", KeyName: "laptop",
	}); err != nil {
		t.Fatalf("Add profile: %v", err)
	}

	cmd := newSSHConnectCmd(t)
	r, err := resolveSSHConnect(cmd, []string{"managed-profile"})
	if err != nil {
		t.Fatalf("resolveSSHConnect: %v", err)
	}
	if r.Local || r.Alias != "" || r.Host != "managed.example.com" || r.Name != "laptop" {
		t.Fatalf("unexpected resolved target: %+v", r)
	}
}

// TestSSHConnectResult pins the exit status after ssh exits. The case that
// matters is the last one: a successful ssh with a failed host-key sync used to
// exit zero, telling the user their trust decision was recorded when the store
// had in fact rejected it — so the next connection would be first contact
// again, silently.
func TestSSHConnectResult(t *testing.T) {
	runErr := errors.New("ssh exited 255")
	syncErr := errors.New("pin store unavailable")

	tests := []struct {
		name string
		run  error
		sync error
		want error
	}{
		{"both succeeded", nil, nil, nil},
		{"ssh failed, sync fine", runErr, nil, runErr},
		{"ssh failed and sync failed — ssh wins", runErr, syncErr, runErr},
		{"ssh succeeded, sync failed", nil, syncErr, syncErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sshConnectResult(tt.run, tt.sync); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
