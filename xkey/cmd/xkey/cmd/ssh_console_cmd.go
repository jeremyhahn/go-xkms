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
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

var sshConsoleCmd = &cobra.Command{
	Use:   "console [profile|user@host]",
	Short: "Open an interactive SSH console in the current terminal",
	Long: `Open an interactive SSH PTY console using an xkey-managed key — or, with
--local/--identity, the operator's own ssh-agent/~/.ssh identities. Unlike
'ssh connect' (which execs the system ssh client), 'ssh console' runs the
session in-process through the xkms SDK console capability — the same capability
the embedded GUI terminal and other apps use. The argument is a saved profile
name or a user@host target.`,
	Args: cobra.ExactArgs(1),
	RunE: runSSHConsole,
}

func init() {
	SSHCmd.AddCommand(sshConsoleCmd)
	sshConsoleCmd.Flags().String("key", "", "SSH key name to authenticate with")
	sshConsoleCmd.Flags().String("key-scope", "user", "Key scope")
	sshConsoleCmd.Flags().String("key-owner", "", "Key owner (defaults to local)")
	sshConsoleCmd.Flags().Int("port", 0, "Target port (default 22)")
	sshConsoleCmd.Flags().String("user", "", "Remote user")
	sshConsoleCmd.Flags().Bool("local", false, "Authenticate using the local ssh-agent/~/.ssh identities instead of an xkey-managed key")
	sshConsoleCmd.Flags().String("identity", "", "Local identity to authenticate with: an identity file path or agent:<SHA256-fingerprint> (implies --local)")
}

func runSSHConsole(cmd *cobra.Command, args []string) error {
	target := strings.TrimSpace(args[0])
	if target == "" {
		return ErrSSHConnectTarget
	}
	keyName, _ := cmd.Flags().GetString("key")
	keyScope, _ := cmd.Flags().GetString("key-scope")
	keyOwner, _ := cmd.Flags().GetString("key-owner")
	port, _ := cmd.Flags().GetInt("port")
	user, _ := cmd.Flags().GetString("user")
	local, _ := cmd.Flags().GetBool("local")
	identity, _ := cmd.Flags().GetString("identity")
	identity = strings.TrimSpace(identity)
	if identity != "" {
		local = true
	}
	if keyOwner == "" {
		keyOwner = "local"
	}

	host := target
	if store, err := xkeyProfileStore(); err == nil {
		if p, gerr := store.Get(target); gerr == nil {
			host = p.Host
			if port == 0 {
				port = p.EffectivePort()
			}
			if user == "" {
				user = p.User
			}
			if keyName == "" {
				keyName = p.KeyName
				if p.KeyScope != "" {
					keyScope = p.KeyScope
				}
				if p.KeyOwner != "" {
					keyOwner = p.KeyOwner
				}
			}
			if p.KeySource == "local" {
				local = true
			}
			if identity == "" {
				identity = p.LocalIdentity
			}
		}
	}
	if at := strings.Index(host, "@"); at >= 0 {
		if user == "" {
			user = host[:at]
		}
		host = host[at+1:]
	}
	// No key selected (and not explicitly local) also authenticates with
	// the operator's local identities, matching the GUI embedded console.
	if keyName == "" {
		local = true
	}

	// Initial terminal size + type.
	rows, cols := 24, 80
	fd := int(os.Stdin.Fd())
	if w, h, gerr := term.GetSize(fd); gerr == nil {
		cols, rows = w, h
	}
	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}
	consoleCfg := sshsdk.ConsoleConfig{Term: termType, Rows: rows, Cols: cols}

	var cons sshsdk.ConsoleSession
	if local {
		signers, rerr := sshsdk.ResolveLocalSigners(context.Background(), sshsdk.LocalKeySelector{
			Identity: identity, Host: host,
		}, os.Getenv("SSH_AUTH_SOCK"))
		if rerr != nil {
			return rerr
		}
		hostKeys, herr := xkeyHostKeyStore()
		if herr != nil {
			return herr
		}
		cons, err := sshsdk.OpenConsoleWithSigners(context.Background(), signers, sshsdk.ConsoleRequest{
			Host: host, Port: port, User: user,
			HostKeys: hostKeys, Scope: keyScope, Owner: keyOwner,
		}, consoleCfg)
		if err != nil {
			return err
		}
		return runConsoleSession(cons, fd)
	}

	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()

	cons, err = client.Console(context.Background(), sshsdk.ConsoleConnectRequest{
		KeyScope: keyScope, KeyOwner: keyOwner, KeyName: keyName,
		Host: host, Port: port, User: user,
	}, consoleCfg)
	if err != nil {
		return err
	}
	return runConsoleSession(cons, fd)
}

// runConsoleSession bridges a live console session to the current terminal:
// raw mode, SIGWINCH forwarding, and the stdin/stdout pumps. It owns Close.
func runConsoleSession(cons sshsdk.ConsoleSession, fd int) error {
	defer func() { _ = cons.Close() }()

	// Put the local terminal in raw mode so keystrokes pass through.
	if term.IsTerminal(fd) {
		oldState, merr := term.MakeRaw(fd)
		if merr == nil {
			defer func() { _ = term.Restore(fd, oldState) }()
		}
	}

	// Forward SIGWINCH to the remote PTY.
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	go func() {
		for range winch {
			if w, h, gerr := term.GetSize(fd); gerr == nil {
				_ = cons.Resize(h, w)
			}
		}
	}()

	// Pump stdin → console; console → stdout blocks until the session ends.
	// When local stdin ends (a piped script, or Ctrl-D on a non-raw stdin)
	// the write half is half-closed so the remote command sees EOF and can
	// exit — Close only tears the session down, it no longer signals EOF.
	go func() {
		_, _ = io.Copy(cons, os.Stdin)
		_ = cons.CloseWrite()
	}()
	_, copyErr := io.Copy(os.Stdout, cons)
	if copyErr != nil && !errors.Is(copyErr, io.EOF) {
		return copyErr
	}
	return nil
}
