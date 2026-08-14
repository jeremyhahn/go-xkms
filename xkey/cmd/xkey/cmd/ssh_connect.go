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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ErrSSHConnectTarget is returned when `ssh connect` gets no usable target.
var ErrSSHConnectTarget = errors.New("ssh connect: a profile name or user@host target is required")

var sshConnectCmd = &cobra.Command{
	Use:   "connect [profile|user@host]",
	Short: "Open an SSH session in the current terminal using an xkey key",
	Long: `Open an SSH session using an xkey-managed key served over an in-process
SSH agent (the private key never leaves a hardware backend). The argument is
either a saved profile name or a user@host target for a one-time connection.

Host-key first contact is handled by the native ssh client; accepted keys are
pinned back into xkey. The session runs in the current terminal.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSSHConnect,
}

var sshProfileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage saved SSH connection profiles",
}

var sshProfileAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add an SSH connection profile",
	RunE:  runSSHProfileAdd,
}

var sshProfileListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List SSH connection profiles",
	RunE:    runSSHProfileList,
}

var sshProfileGetCmd = &cobra.Command{
	Use:   "get [name]",
	Short: "Show an SSH connection profile",
	Args:  cobra.ExactArgs(1),
	RunE:  runSSHProfileGet,
}

var sshProfileRemoveCmd = &cobra.Command{
	Use:     "remove [name]",
	Aliases: []string{"rm", "delete"},
	Short:   "Delete an SSH connection profile",
	Args:    cobra.ExactArgs(1),
	RunE:    runSSHProfileRemove,
}

var sshProfileMoveCmd = &cobra.Command{
	Use:   "mv [name]",
	Short: "Move a profile to a different folder",
	Args:  cobra.ExactArgs(1),
	RunE:  runSSHProfileMove,
}

func init() {
	SSHCmd.AddCommand(sshConnectCmd)
	sshConnectCmd.Flags().String("key", "", "SSH key name to authenticate with")
	sshConnectCmd.Flags().String("key-scope", "user", "Key scope")
	sshConnectCmd.Flags().String("key-owner", "", "Key owner (defaults to local for GUI keys, $USER for CLI keys)")
	sshConnectCmd.Flags().Int("port", 0, "Target port (default 22)")
	sshConnectCmd.Flags().String("user", "", "Remote user (for user@host targets without an inline user)")
	sshConnectCmd.Flags().String("known-hosts-policy", "barrier", "Where to record host-key pins: barrier|system|both")
	sshConnectCmd.Flags().Bool("local", false, "Authenticate using the local ssh-agent/~/.ssh identities instead of an xkey-managed key (plain passthrough `ssh`, no in-process agent)")
	sshConnectCmd.Flags().String("ssh-config-alias", "", "ssh_config(5) Host alias to connect through (implies --local)")
	sshConnectCmd.Flags().String("identity", "", "Local identity to authenticate with: an identity file path (passed to ssh as -i) or agent:<SHA256-fingerprint> for an agent-held key (implies --local)")

	SSHCmd.AddCommand(sshProfileCmd)
	sshProfileCmd.AddCommand(sshProfileAddCmd, sshProfileListCmd, sshProfileGetCmd, sshProfileRemoveCmd, sshProfileMoveCmd)
	sshProfileAddCmd.Flags().String("name", "", "Profile name (required)")
	sshProfileAddCmd.Flags().String("folder", "", "Folder path (e.g. work/prod)")
	sshProfileAddCmd.Flags().String("host", "", "Target host (required)")
	sshProfileAddCmd.Flags().Int("port", 22, "Target port")
	sshProfileAddCmd.Flags().String("user", "", "Remote user")
	sshProfileAddCmd.Flags().String("key", "", "SSH key name")
	sshProfileAddCmd.Flags().String("key-scope", "user", "Key scope")
	sshProfileAddCmd.Flags().String("key-owner", "", "Key owner (defaults to local)")
	sshProfileAddCmd.Flags().String("key-source", "", "Authentication key source: \"\" (xkey-managed, default) or \"local\" (ssh-agent/~/.ssh)")
	sshProfileAddCmd.Flags().String("ssh-config-alias", "", "ssh_config(5) Host alias to connect through when --key-source=local (implies --key-source=local)")
	sshProfileAddCmd.Flags().String("identity", "", "Local identity pin: an identity file path or agent:<SHA256-fingerprint> (implies --key-source=local)")
	sshProfileAddCmd.Flags().Bool("persist-session", false, "Record embedded-console sessions from this profile in the persistent session store (GUI tabs restored after reload/restart; default memory-only)")
	sshProfileAddCmd.Flags().String("notes", "", "Free-form notes")
	sshProfileListCmd.Flags().String("folder", "", "Limit to a folder (and its subfolders)")
	sshProfileMoveCmd.Flags().String("folder", "", "Destination folder (required)")
}

// xkeyProfileStore builds the shared SSH profile store (see xkey/pkg/sshstore).
func xkeyProfileStore() (sshsdk.ProfileStore, error) {
	backend, err := xkeySSHBackend()
	if err != nil {
		return nil, err
	}
	return sshsdk.NewProfileStore(backend)
}

// xkeyHostKeyStore builds the shared SSH host-key pin store (see xkey/pkg/sshstore).
func xkeyHostKeyStore() (sshsdk.HostKeyStore, error) {
	backend, err := xkeySSHBackend()
	if err != nil {
		return nil, err
	}
	return sshsdk.NewHostKeyStore(backend)
}

// sshConnectResolved is the fully-resolved connection target for `ssh
// connect`, after applying CLI flags and — when the positional target names
// one — a saved profile's settings. Resolving is a pure, side-effect-free
// step (besides the profile store lookup) so it can be tested without
// spawning any process.
type sshConnectResolved struct {
	Host, User               string
	Port                     int
	KeyScope, KeyOwner, Name string
	KnownHostsPolicy         string

	// Local, when true, means "authenticate via the operator's own
	// ssh-agent/~/.ssh identities" (see buildLocalSSHArgs /
	// runSSHConnectLocal) rather than an xkey-managed key.
	Local bool
	Alias string

	// Identity pins one specific local key: an identity file path (passed
	// to ssh as -i) or "agent:<SHA256-fingerprint>" for an agent-held key
	// (no flag added — the agent offers it).
	Identity string
}

// resolveSSHConnect reads `ssh connect`'s flags and, when the positional
// target names a saved profile, merges in that profile's settings (a
// profile with KeySource == "local" forces Local, and its SSHConfigAlias
// fills Alias when the --ssh-config-alias flag left it empty).
func resolveSSHConnect(cmd *cobra.Command, args []string) (*sshConnectResolved, error) {
	var target string
	if len(args) > 0 {
		target = strings.TrimSpace(args[0])
	}

	r := &sshConnectResolved{}
	r.Name, _ = cmd.Flags().GetString("key")
	r.KeyScope, _ = cmd.Flags().GetString("key-scope")
	r.KeyOwner, _ = cmd.Flags().GetString("key-owner")
	r.Port, _ = cmd.Flags().GetInt("port")
	r.User, _ = cmd.Flags().GetString("user")
	r.KnownHostsPolicy, _ = cmd.Flags().GetString("known-hosts-policy")
	r.Local, _ = cmd.Flags().GetBool("local")
	r.Alias, _ = cmd.Flags().GetString("ssh-config-alias")
	r.Alias = strings.TrimSpace(r.Alias)
	r.Identity, _ = cmd.Flags().GetString("identity")
	r.Identity = strings.TrimSpace(r.Identity)
	if r.Alias != "" || r.Identity != "" {
		r.Local = true
	}
	if r.KeyOwner == "" {
		r.KeyOwner = "local"
	}

	r.Host = target
	// If the target matches a saved profile, use its settings.
	if store, err := xkeyProfileStore(); err == nil && target != "" {
		if p, gerr := store.Get(target); gerr == nil {
			r.Host = p.Host
			if r.Port == 0 {
				r.Port = p.EffectivePort()
			}
			if r.User == "" {
				r.User = p.User
			}
			if r.Name == "" {
				r.Name = p.KeyName
				if p.KeyScope != "" {
					r.KeyScope = p.KeyScope
				}
				if p.KeyOwner != "" {
					r.KeyOwner = p.KeyOwner
				}
			}
			if p.KeySource == "local" {
				r.Local = true
			}
			if r.Alias == "" {
				r.Alias = p.SSHConfigAlias
			}
			if r.Identity == "" {
				r.Identity = p.LocalIdentity
			}
		}
	}
	return r, nil
}

func runSSHConnect(cmd *cobra.Command, args []string) error {
	r, err := resolveSSHConnect(cmd, args)
	if err != nil {
		return err
	}

	// No key selected (and not explicitly local) also falls through to the
	// plain passthrough — the system agent/identities or a password prompt
	// authenticate, exactly like typing `ssh user@host`.
	if r.Local || r.Name == "" {
		return runSSHConnectLocal(r.Host, r.Port, r.User, r.Alias, r.Identity)
	}

	host, user := r.Host, r.User
	// Parse an inline user@host target.
	if at := strings.Index(host, "@"); at >= 0 {
		if user == "" {
			user = host[:at]
		}
		host = host[at+1:]
	}
	if host == "" {
		return ErrSSHConnectTarget
	}

	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()

	signer, err := client.Keys().Signer(context.Background(), sshsdk.GetKeyRequest{Scope: r.KeyScope, Owner: r.KeyOwner, Name: r.Name})
	if err != nil {
		return err
	}
	hostKeys, err := xkeyHostKeyStore()
	if err != nil {
		return err
	}

	var extraKnownHosts []string
	skipStore := false
	if r.KnownHostsPolicy == "system" || r.KnownHostsPolicy == "both" {
		if home, herr := os.UserHomeDir(); herr == nil {
			extraKnownHosts = []string{home + "/.ssh/known_hosts"}
		}
		skipStore = r.KnownHostsPolicy == "system"
	}

	session, err := sshsdk.StartConnect(context.Background(), sshsdk.ConnectOptions{
		Host:            host,
		Port:            r.Port,
		User:            user,
		Signer:          signer,
		HostKeys:        hostKeys,
		Scope:           r.KeyScope,
		Owner:           r.KeyOwner,
		ExtraKnownHosts: extraKnownHosts,
		SkipStore:       skipStore,
	})
	if err != nil {
		return err
	}

	// Run ssh inheriting the current terminal so the native first-contact prompt
	// works inline; sync pins back when it exits.
	sshCmd := exec.Command("ssh", session.Args...)
	sshCmd.Env = append(os.Environ(), session.Env...)
	sshCmd.Stdin = os.Stdin
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr
	runErr := sshCmd.Run()
	if added, serr := session.SyncAndStop(); serr == nil && added > 0 {
		fmt.Fprintf(os.Stderr, "xkey: pinned %d new host key(s)\n", added)
	}
	return runErr
}

// buildLocalSSHArgs computes the argv for a plain passthrough `ssh`
// invocation: no in-process agent, no temporary known_hosts, no option
// injection — just what a human would type. When alias is set the result is
// `[alias]` verbatim (letting ssh_config resolve host/port/user); otherwise
// it is `[-p port] [-i identity] [user@]host`. A file-backed identity is
// passed as -i; an agent-held one ("agent:<fp>") adds no flag — the system
// agent offers it. Returns ErrSSHConnectTarget when neither alias nor host
// is set.
func buildLocalSSHArgs(host string, port int, user, alias, identity string) ([]string, error) {
	if alias != "" {
		return []string{alias}, nil
	}
	if host == "" {
		return nil, ErrSSHConnectTarget
	}
	// Parse an inline user@host target.
	if at := strings.Index(host, "@"); at >= 0 {
		if user == "" {
			user = host[:at]
		}
		host = host[at+1:]
	}
	var args []string
	if port != 0 {
		args = append(args, "-p", strconv.Itoa(port))
	}
	if identity != "" && !strings.HasPrefix(identity, "agent:") {
		args = append(args, "-i", identity)
	}
	if user != "" {
		host = user + "@" + host
	}
	args = append(args, host)
	return args, nil
}

// runSSHConnectLocal spawns a plain passthrough `ssh` in the current
// terminal, authenticating however the operator's own ssh_config/ssh-agent
// resolves it: no in-process agent, no temporary known_hosts, no env
// injection beyond the inherited process environment (see buildLocalSSHArgs
// for the argv construction).
func runSSHConnectLocal(host string, port int, user, alias, identity string) error {
	sshArgs, err := buildLocalSSHArgs(host, port, user, alias, identity)
	if err != nil {
		return err
	}

	sshCmd := exec.Command("ssh", sshArgs...)
	sshCmd.Env = os.Environ()
	sshCmd.Stdin = os.Stdin
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr
	return sshCmd.Run()
}

func runSSHProfileAdd(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	name, _ := cmd.Flags().GetString("name")
	host, _ := cmd.Flags().GetString("host")
	keySource, _ := cmd.Flags().GetString("key-source")
	sshConfigAlias, _ := cmd.Flags().GetString("ssh-config-alias")
	localIdentity, _ := cmd.Flags().GetString("identity")
	persistSession, _ := cmd.Flags().GetBool("persist-session")
	if name == "" || (host == "" && sshConfigAlias == "") {
		return errors.New("ssh profile add: --name and (--host or --ssh-config-alias) are required")
	}
	folder, _ := cmd.Flags().GetString("folder")
	port, _ := cmd.Flags().GetInt("port")
	user, _ := cmd.Flags().GetString("user")
	keyName, _ := cmd.Flags().GetString("key")
	keyScope, _ := cmd.Flags().GetString("key-scope")
	keyOwner, _ := cmd.Flags().GetString("key-owner")
	notes, _ := cmd.Flags().GetString("notes")
	if keyOwner == "" {
		keyOwner = "local"
	}
	if (sshConfigAlias != "" || localIdentity != "") && keySource == "" {
		keySource = "local"
	}

	store, err := xkeyProfileStore()
	if err != nil {
		return err
	}
	if aerr := store.Add(&sshsdk.Profile{
		Name: name, FolderPath: folder, Host: host, Port: port, User: user,
		KeyScope: keyScope, KeyOwner: keyOwner, KeyName: keyName, Notes: notes,
		KeySource: keySource, SSHConfigAlias: sshConfigAlias, LocalIdentity: localIdentity,
		PersistSession: persistSession,
	}); aerr != nil {
		return aerr
	}
	fmt.Fprintf(out, "Added SSH profile %q (%s)\n", name, host)
	return nil
}

func runSSHProfileList(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	folder, _ := cmd.Flags().GetString("folder")
	store, err := xkeyProfileStore()
	if err != nil {
		return err
	}
	var profiles []*sshsdk.Profile
	if folder != "" {
		profiles, err = store.ListByFolder(folder)
	} else {
		profiles, err = store.List()
	}
	if err != nil {
		return err
	}
	if len(profiles) == 0 {
		fmt.Fprintln(out, "No SSH profiles found")
		return nil
	}
	for _, p := range profiles {
		loc := p.Host
		if p.User != "" {
			loc = p.User + "@" + p.Host
		}
		fmt.Fprintf(out, "%s\t%s:%d\t%s\tkey=%s\n", p.Name, loc, p.EffectivePort(), p.FolderPath, p.KeyName)
	}
	return nil
}

func runSSHProfileGet(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	store, err := xkeyProfileStore()
	if err != nil {
		return err
	}
	p, err := store.Get(args[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Name: %s\nFolder: %s\nHost: %s\nPort: %d\nUser: %s\nKey: %s/%s/%s\nNotes: %s\n",
		p.Name, p.FolderPath, p.Host, p.EffectivePort(), p.User, p.KeyScope, p.KeyOwner, p.KeyName, p.Notes)
	return nil
}

func runSSHProfileRemove(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	store, err := xkeyProfileStore()
	if err != nil {
		return err
	}
	if derr := store.Delete(args[0]); derr != nil {
		return derr
	}
	fmt.Fprintf(out, "Deleted SSH profile %q\n", args[0])
	return nil
}

func runSSHProfileMove(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	folder, _ := cmd.Flags().GetString("folder")
	if folder == "" {
		return errors.New("ssh profile mv: --folder is required")
	}
	store, err := xkeyProfileStore()
	if err != nil {
		return err
	}
	if merr := store.MoveToFolder(args[0], folder); merr != nil {
		return merr
	}
	fmt.Fprintf(out, "Moved %q to %q\n", args[0], folder)
	return nil
}
