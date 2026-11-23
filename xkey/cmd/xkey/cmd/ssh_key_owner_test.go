package cmd

import (
	"io"
	"testing"

	"github.com/spf13/cobra"

	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// Issue #2284 (rulings 937, 938): against a server, ssh connect and ssh
// console send no key owner unless --key-owner is given, so the server
// resolves an empty user-scope owner to the logged-in caller. Only the local
// store path, which has no logged-in caller, defaults the owner to "local".

// withSSHServer configures an xkmsd server URL, so ssh commands without
// --local target the server rather than the embedded local store.
func withSSHServer(t *testing.T) {
	t.Helper()
	isolateXKMSdEndpoint(t)
	t.Setenv(envXKMSdURL, "https://xkmsd.example.test:8443")
}

// With no xkmsd server configured the embedded local store answers, and it
// has no logged-in caller: the owner still defaults to "local".
func TestSSHKeyOwner_NoServerDefaultsLocal(t *testing.T) {
	withCLIHome(t)
	isolateXKMSdEndpoint(t)

	connect := newSSHConnectCmd(t)
	if err := connect.Flags().Set("key", "laptop"); err != nil {
		t.Fatal(err)
	}
	r, err := resolveSSHConnect(connect, []string{"host.example.com"})
	if err != nil {
		t.Fatalf("resolveSSHConnect: %v", err)
	}
	if r.KeyOwner != "local" {
		t.Fatalf("connect KeyOwner = %q, want local", r.KeyOwner)
	}

	console := sshConsoleTestCmd()
	if err := console.Flags().Set("key", "laptop"); err != nil {
		t.Fatal(err)
	}
	if c := resolveSSHConsole(console, "host.example.com"); c.keyOwner != "local" {
		t.Fatalf("console keyOwner = %q, want local", c.keyOwner)
	}
}

func addTestSSHProfile(t *testing.T, p *sshsdk.Profile) {
	t.Helper()
	store, closeStore, err := xkeyProfileStore()
	if err != nil {
		t.Fatalf("xkeyProfileStore: %v", err)
	}
	defer closeStore()
	if err := store.Add(p); err != nil {
		t.Fatalf("Add profile: %v", err)
	}
}

func TestResolveSSHConnect_KeyOwnerDefault(t *testing.T) {
	cases := []struct {
		name  string
		flags map[string]string
		want  string
	}{
		{"server, no owner", map[string]string{"key": "laptop"}, ""},
		{"server, explicit owner", map[string]string{"key": "laptop", "key-owner": "alice"}, "alice"},
		{"local flag", map[string]string{"local": "true"}, "local"},
		{"identity", map[string]string{"identity": "~/.ssh/id_ed25519"}, "local"},
		{"ssh config alias", map[string]string{"ssh-config-alias": "bastion"}, "local"},
		{"local flag, explicit owner", map[string]string{"local": "true", "key-owner": "alice"}, "alice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withCLIHome(t)
			withSSHServer(t)
			cmd := newSSHConnectCmd(t)
			for k, v := range tc.flags {
				if err := cmd.Flags().Set(k, v); err != nil {
					t.Fatalf("set %s: %v", k, err)
				}
			}
			r, err := resolveSSHConnect(cmd, []string{"host.example.com"})
			if err != nil {
				t.Fatalf("resolveSSHConnect: %v", err)
			}
			if r.KeyOwner != tc.want {
				t.Fatalf("KeyOwner = %q, want %q", r.KeyOwner, tc.want)
			}
		})
	}
}

func TestResolveSSHConnect_ProfileKeyOwner(t *testing.T) {
	withCLIHome(t)
	withSSHServer(t)
	addTestSSHProfile(t, &sshsdk.Profile{
		Name: "owned", Host: "owned.example.com",
		KeyScope: "user", KeyOwner: "bob", KeyName: "laptop",
	})
	addTestSSHProfile(t, &sshsdk.Profile{
		Name: "unowned", Host: "unowned.example.com",
		KeyScope: "user", KeyName: "laptop",
	})
	addTestSSHProfile(t, &sshsdk.Profile{
		Name: "local-src", Host: "local.example.com", KeySource: "local",
	})

	for target, want := range map[string]string{"owned": "bob", "unowned": "", "local-src": "local"} {
		r, err := resolveSSHConnect(newSSHConnectCmd(t), []string{target})
		if err != nil {
			t.Fatalf("resolveSSHConnect(%s): %v", target, err)
		}
		if r.KeyOwner != want {
			t.Fatalf("%s: KeyOwner = %q, want %q", target, r.KeyOwner, want)
		}
	}
}

func TestResolveSSHConsole_KeyOwnerDefault(t *testing.T) {
	cases := []struct {
		name  string
		flags map[string]string
		want  string
	}{
		{"server, no owner", map[string]string{"key": "laptop"}, ""},
		{"server, explicit owner", map[string]string{"key": "laptop", "key-owner": "alice"}, "alice"},
		{"local flag", map[string]string{"key": "laptop", "local": "true"}, "local"},
		{"identity", map[string]string{"identity": "~/.ssh/id_ed25519"}, "local"},
		{"no key selected", map[string]string{}, "local"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withCLIHome(t)
			withSSHServer(t)
			cmd := sshConsoleTestCmd()
			for k, v := range tc.flags {
				if err := cmd.Flags().Set(k, v); err != nil {
					t.Fatalf("set %s: %v", k, err)
				}
			}
			r := resolveSSHConsole(cmd, "host.example.com")
			if r.keyOwner != tc.want {
				t.Fatalf("keyOwner = %q, want %q", r.keyOwner, tc.want)
			}
		})
	}
}

func TestResolveSSHConsole_ProfileKeyOwner(t *testing.T) {
	withCLIHome(t)
	withSSHServer(t)
	addTestSSHProfile(t, &sshsdk.Profile{
		Name: "owned", Host: "owned.example.com",
		KeyScope: "user", KeyOwner: "bob", KeyName: "laptop",
	})
	addTestSSHProfile(t, &sshsdk.Profile{
		Name: "unowned", Host: "unowned.example.com",
		KeyScope: "user", KeyName: "laptop",
	})

	for target, want := range map[string]string{"owned": "bob", "unowned": ""} {
		r := resolveSSHConsole(sshConsoleTestCmd(), target)
		if r.keyOwner != want {
			t.Fatalf("%s: keyOwner = %q, want %q", target, r.keyOwner, want)
		}
	}
}

func sshProfileAddTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "add"}
	cmd.SetOut(io.Discard)
	for _, f := range []string{"name", "folder", "host", "user", "key", "key-owner", "key-source", "ssh-config-alias", "identity", "notes"} {
		cmd.Flags().String(f, "", "")
	}
	cmd.Flags().String("key-scope", "user", "")
	cmd.Flags().Int("port", 22, "")
	cmd.Flags().Bool("persist-session", false, "")
	return cmd
}

// A server profile saved without --key-owner must not carry "local" to the
// server on a later connect or console.
func TestRunSSHProfileAdd_KeyOwnerDefault(t *testing.T) {
	cases := []struct {
		name  string
		flags map[string]string
		want  string
	}{
		{"server, no owner", map[string]string{"key": "laptop"}, ""},
		{"server, explicit owner", map[string]string{"key": "laptop", "key-owner": "alice"}, "alice"},
		{"local key source", map[string]string{"key-source": "local"}, "local"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withCLIHome(t)
			withSSHServer(t)
			cmd := sshProfileAddTestCmd()
			flags := map[string]string{"name": "p", "host": "h.example.com"}
			for k, v := range tc.flags {
				flags[k] = v
			}
			for k, v := range flags {
				if err := cmd.Flags().Set(k, v); err != nil {
					t.Fatalf("set %s: %v", k, err)
				}
			}
			if err := runSSHProfileAdd(cmd, nil); err != nil {
				t.Fatalf("runSSHProfileAdd: %v", err)
			}
			p, ok := lookupSSHProfile("p")
			if !ok {
				t.Fatal("profile not saved")
			}
			if p.KeyOwner != tc.want {
				t.Fatalf("KeyOwner = %q, want %q", p.KeyOwner, tc.want)
			}
		})
	}
}
