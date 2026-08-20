# SSH Agent Sessions — Usage

> **Status: NORMATIVE** · Feature: `ssh-agent-sessions` · Repo: `go-xkms` · Last verified: 2026-08-20

Use an agent-only session when you have a key in xkms and a tool that speaks
the ssh-agent protocol but does not connect anywhere: `git commit -S` under
`gpg.format=ssh`, `ssh-keygen -Y sign`, `age`.

If your tool *does* connect to a host, you want `StartConnect` instead — it
starts one of these sessions and adds host-key verification.

## Sign git commits with an xkms-held key

The private half never touches disk; only the public half does, as
`user.signingkey`.

```go
package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	gossh "golang.org/x/crypto/ssh"
	xkmsssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

func commitSigned(ctx context.Context, client xkmsssh.Client, repo, msg string) error {
	key, err := client.Keys().Get(ctx, xkmsssh.GetKeyRequest{
		Scope: "user", Owner: "alice", Name: "commit-signing",
	})
	if err != nil {
		return err
	}
	signer, err := client.Keys().Signer(ctx, xkmsssh.GetKeyRequest{
		Scope: "user", Owner: "alice", Name: "commit-signing",
	})
	if err != nil {
		return err
	}

	// Public half only -- this is what user.signingkey points at.
	pub := filepath.Join(os.TempDir(), "commit-signing.pub")
	if err := os.WriteFile(pub, []byte(key.PublicKey+"\n"), 0o600); err != nil {
		return err
	}

	sess, err := xkmsssh.StartAgent(ctx, xkmsssh.AgentOptions{
		Signers: []gossh.Signer{signer},
	})
	if err != nil {
		return err
	}
	defer sess.Stop()

	cmd := exec.CommandContext(ctx, "git",
		"-c", "gpg.format=ssh",
		"-c", "user.signingkey="+pub,
		"commit", "-S", "-m", msg,
	)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), sess.Env...) // SSH_AUTH_SOCK
	return cmd.Run()
}
```

## Check that it worked

The commit object carries an SSH signature:

```console
$ git cat-file commit HEAD | head -5
tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
author Alice <alice@example.com> ...
committer Alice <alice@example.com> ...
gpgsig -----BEGIN SSH SIGNATURE-----
 U1NIU0lHAAAAAQ...
```

**A `gpgsig` header is not proof the signature is good** — it is present even
when the signature is garbage. Verify against an allowed-signers file naming
the key:

```console
$ printf 'alice@example.com %s\n' "$(cat commit-signing.pub)" > allowed_signers
$ git -c gpg.format=ssh \
      -c gpg.ssh.allowedSignersFile=allowed_signers \
      verify-commit -v HEAD
Good "git" signature for alice@example.com with ED25519 key SHA256:...
```

## Signing a file instead of a commit

Anything that reads `SSH_AUTH_SOCK` works the same way:

```console
$ SSH_AUTH_SOCK=<sess.SockPath> \
  ssh-keygen -Y sign -f commit-signing.pub -n file document.txt
```

## Serving more than one key

The ssh-agent protocol is multi-identity; pass several signers and the socket
advertises all of them. A tool picks by public key.

```go
sess, err := xkmsssh.StartAgent(ctx, xkmsssh.AgentOptions{
	Signers: []gossh.Signer{signing, deploy},
})
```

## Lifetime — the part to get right

The session ends at the first of `Stop()` or cancellation of the context you
passed in. Either way the socket file is removed.

- `defer sess.Stop()` is the normal shape. It blocks until the socket is gone.
- If you cancel the context instead, wait on `sess.Done()` before assuming the
  socket has been cleaned up.
- Never hand `SockPath` to something that outlives the session — the path stops
  answering, and while it answers it will sign anything asked of it.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `*AgentInputError` on `Signers` | no signers, or a nil entry in the slice |
| `context.Canceled` on `StartAgent` | the context was already cancelled or expired when you called; a session under a dead context is refused rather than returned half-dead |
| `*AgentInputError` on `WorkDir` | the `WorkDir` you supplied is not an existing directory. It is not created for you: the session does not own what it did not create, so a typo would leave a directory behind on every run |
| `*AgentListenError` wrapping `ErrAgentSocketInUse` | a session is already running in that `WorkDir`. Give each session its own directory, or leave `WorkDir` empty and let it pick one |
| `*AgentListenError` wrapping `ErrAgentPathOccupied` | `<WorkDir>/agent.sock` holds something this session will not use — a file that is not a socket, or a socket left by a crashed run. It is never removed for you, because clearing one cannot be done without a window where another process could lose its live socket. Delete it yourself, or use a different `WorkDir` |
| `*AgentListenError` otherwise | the socket could not be bound — usually a `WorkDir` that is not writable, or one that makes the socket path longer than the ~108-byte unix-socket limit |
| git: `error: Load key ... invalid format` | `user.signingkey` points at a **private** key file; it must be the public key |
| git: `sign_and_send_pubkey: no mutual signature supported` | the tool asked for an algorithm the key cannot produce; check the key's algorithm |
| `git verify-commit` fails but the commit has `gpgsig` | the signature does not match the key in `allowedSignersFile` — a real failure, not a configuration nit |
| The socket path does not exist | the session already ended; a live `StartAgent` return always has a connectable socket |
