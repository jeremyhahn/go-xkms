package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// consoleTestServer is an in-process SSH server on 127.0.0.1:0 that accepts
// only clientKey, presents hostSigner, and replies true to pty-req and shell.
type consoleTestServer struct {
	port    int
	hostKey gossh.PublicKey
}

func startConsoleTestServer(t *testing.T, clientKey gossh.PublicKey) consoleTestServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := gossh.NewSignerFromKey(priv)
	require.NoError(t, err)

	cfg := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if bytes.Equal(key.Marshal(), clientKey.Marshal()) {
				return &gossh.Permissions{}, nil
			}
			return nil, errors.New("unknown client key")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go serveConsoleTestConn(nc, cfg)
		}
	}()
	return consoleTestServer{
		port:    ln.Addr().(*net.TCPAddr).Port,
		hostKey: hostSigner.PublicKey(),
	}
}

func serveConsoleTestConn(nc net.Conn, cfg *gossh.ServerConfig) {
	defer nc.Close()
	sc, chans, reqs, err := gossh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go gossh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(gossh.UnknownChannelType, "session only")
			continue
		}
		ch, creqs, aerr := nch.Accept()
		if aerr != nil {
			return
		}
		go func() {
			defer ch.Close()
			for req := range creqs {
				ok := req.Type == "pty-req" || req.Type == "shell" || req.Type == "window-change"
				if req.WantReply {
					_ = req.Reply(ok, nil)
				}
			}
		}()
	}
}

// pinConsoleHost pins key for 127.0.0.1 (the console's pin host carries no
// port) in the local pin store under user/owner, the store listPins reads.
func pinConsoleHost(t *testing.T, owner string, key gossh.PublicKey) {
	t.Helper()
	hostKeys, closeHostKeys, err := xkeyHostKeyStore()
	require.NoError(t, err)
	defer closeHostKeys()
	require.NoError(t, hostKeys.Add(context.Background(), &pkgknownhosts.Pin{
		Host:        "127.0.0.1",
		Fingerprint: gossh.FingerprintSHA256(key),
		Algorithm:   key.Type(),
		Scope:       "user",
		Owner:       owner,
		Source:      "test",
		PublicKey:   key.Marshal(),
	}))
}

// standInSignerKey returns the public key of the stand-in xkmsd signer that
// withServerBackedConnect installs, and clears the owners it recorded.
func standInSignerKey(t *testing.T, owners *[]string) gossh.PublicKey {
	t.Helper()
	client, _, closer, err := sshConnectClient(sshConsoleTestCmd())
	require.NoError(t, err)
	defer closer()
	signer, err := client.Keys().Signer(context.Background(), sshsdk.GetKeyRequest{Name: "bob-key"})
	require.NoError(t, err)
	*owners = (*owners)[:0]
	return signer.PublicKey()
}

func openServerBackedConsole(t *testing.T, port int, keyOwner string) error {
	t.Helper()
	cmd := sshConsoleTestCmd()
	require.NoError(t, cmd.Flags().Set("key", "bob-key"))
	require.NoError(t, cmd.Flags().Set("port", strconv.Itoa(port)))
	if keyOwner != "" {
		require.NoError(t, cmd.Flags().Set("key-owner", keyOwner))
	}
	r := resolveSSHConsole(cmd, "u@127.0.0.1")
	cons, err := openSSHConsole(cmd, r, sshsdk.ConsoleConfig{Term: "xterm", Rows: 24, Cols: 80})
	var unsupported *sshsdk.ConsoleUnsupportedError
	assert.False(t, errors.As(err, &unsupported), "server-backed console must not be refused: %v", err)
	if err != nil {
		return err
	}
	return cons.Close()
}

// TestSSHConsole_ServerBackedSignsThroughServerAndVerifiesLocalPins drives the
// CLI console path against an xkmsd server stand-in: the key signs through
// the server's Keys().Signer with the owner the caller gave (none when
// --key-owner is omitted) and the host is verified against this machine's pin
// store under "local" (or the given owner), like `xkey ssh connect`.
func TestSSHConsole_ServerBackedSignsThroughServerAndVerifiesLocalPins(t *testing.T) {
	owners := withServerBackedConnect(t)
	clientKey := standInSignerKey(t, owners)
	h1 := startConsoleTestServer(t, clientKey)
	h2 := startConsoleTestServer(t, clientKey)
	// 127.0.0.1 is pinned to H1 for "local" and to H2 for "alice" only, so
	// the server on h2.port fails the local pin check.
	pinConsoleHost(t, "local", h1.hostKey)
	pinConsoleHost(t, "alice", h2.hostKey)

	t.Run("omitted owner opens against the local pin", func(t *testing.T) {
		*owners = (*owners)[:0]
		require.NoError(t, openServerBackedConsole(t, h1.port, ""))
		assert.Equal(t, []string{""}, *owners, "no owner is sent to the server")
	})

	t.Run("omitted owner refuses a host pinned only for alice", func(t *testing.T) {
		*owners = (*owners)[:0]
		err := openServerBackedConsole(t, h2.port, "")
		require.Error(t, err)
		var notFound *pkgknownhosts.NotFoundError
		var mismatch *pkgknownhosts.MismatchError
		assert.True(t, errors.As(err, &notFound) || errors.As(err, &mismatch),
			"want a host-key error, got %T: %v", err, err)
	})

	t.Run("explicit owner reaches the server", func(t *testing.T) {
		*owners = (*owners)[:0]
		_ = openServerBackedConsole(t, h1.port, "bob")
		assert.Equal(t, []string{"bob"}, *owners)
	})
}
