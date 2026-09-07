- **`AgentOptions.SocketDir` lets the caller of the SDK's ephemeral SSH signing
  agent choose where its socket goes.** `StartAgent` bound its socket under a
  directory of its own choosing in the OS temporary directory, which is exactly
  the location a sandbox mount policy will not admit — so a consumer that runs
  the signing client in a container (go-quicbaas's `sdlc` job runner mounts the
  socket read-only and names it `SSH_AUTH_SOCK`, with no credential in argv or
  environment) could not use the agent at all. Setting `SocketDir` puts the
  socket inside a tree the caller's own policy already allows, and
  `SockPath` is `<SocketDir>/agent.sock`, computable before the call, because a
  mount specification has to name the socket before there is a session to ask.

  It gives the caller the **location**, never the directory. The session
  creates `SocketDir` itself with `os.Mkdir` (mode 0700 — never more
  permissive, since the process umask can only clear bits), binds the socket
  inside it with mode 0600, and removes the directory with the socket on `Stop` or
  context cancellation. That is what keeps the reason a 0600 socket is safe — no
  other user can traverse into its directory — a construction rather than a
  claim inherited from whoever made the directory first. An existing path is
  refused with `*SocketDirExistsError` (`*AgentSocketDirExistsError` through the
  SDK, unwrapping to `fs.ErrExist`), whether it holds a directory, a file or a
  socket from a crashed run: adopting one puts a signing oracle somewhere this
  package cannot vouch for, and clearing one would delete whatever the caller
  keeps there, up to and including another live agent. `os.Mkdir` makes the test
  and the claim the same syscall, so nothing can slip between them.

  The parent is checked and never created, by the same rule a supplied
  `WorkDir` passes — an existing, non-symlink, self-owned directory that is not
  group- or world-writable, else `*InsecureWorkDirError`. Creating the socket's
  own directory closes the substitution window inside it; nothing closes one in
  a parent another user can write to, where the whole directory can be renamed
  away and the container would then sign through somebody else's agent.
  `SocketDir` and `WorkDir` are mutually exclusive, since they say opposite
  things about who owns the directory and therefore about whether it survives
  shutdown. A relative `SocketDir` resolves against this process's directory
  on entry, once, so `SockPath` stays absolute and means the same thing to a
  process with its own working directory and PID namespace.

  Default behaviour is unchanged: an empty `SocketDir` still lands in the OS
  temporary directory. Sixteen tests across `pkg/ssh/agent` and the SDK cover
  the honoured path and its modes, every refusal, removal on both exit paths,
  and a client signing from a different working directory;
  `pkg/ssh/agent` coverage is 94.4%. Documented in
  `docs/ssh-agent-sessions/`. (#444)
