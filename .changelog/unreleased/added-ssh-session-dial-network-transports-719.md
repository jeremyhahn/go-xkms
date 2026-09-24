- **`sdk/go/client/ssh`'s `Session.Dial` now works over every network
  transport (REST/QUIC, gRPC/unix, MCP), not just embedded.** The owner
  ruling closing #719's provenance investigation found no server-side SSH
  proxy is needed: the caller's own process dials the target host directly
  (`golang.org/x/crypto/ssh`), authenticating through the remote key's
  `Keys().Signer` forward-signing proxy — the private key never leaves
  xkmsd — and verifying the presented host key against the remote
  `KnownHosts().Callback` before the handshake completes; the network
  transport carries only those two RPCs, never the SSH byte stream, which is
  why MCP's request/response JSON-RPC framing (which cannot carry the
  interactive `Console`) has no trouble with `Dial`. One shared helper,
  `dialNetworkSession` (`sdk/go/client/ssh/session_dial.go`), backs
  `restSessionClient`, `grpcSessionClient`, and `mcpSessionClient`; it calls
  a new `pkg/ssh/session.NewSession` constructor that wraps an
  already-dialed `*ssh.Client` in the existing `Session` implementation so
  `Run`/`Shell`/`Upload`/`Close` are not duplicated per transport. QUIC and
  unix needed no new code: `NewQUIC` already wraps `restClient` verbatim and
  `NewClientForServer`'s `unix://` scheme already wraps `NewGRPC`, so both
  reuse the REST/gRPC `Dial` implementation exactly. Host-key verification
  fails closed on every transport — an unrecognized or mismatched host is a
  typed error (`*NotFoundError` / `*MismatchError` on REST and gRPC;
  MCP's existing wire mapping collapses every server verify failure to
  `*ProtocolError`, still typed, never a silent accept) — and there is no
  `InsecureIgnoreHostKey` anywhere in the SDK. The three transport stubs'
  stale `*NotImplementedError` returns and the REST package doc's "wait for
  streaming-session phase" note are gone; `doc.go` and `mcp.go`'s package
  comments now describe all six implemented transports and the Dial/Console
  split. New integration-style tests dial a real in-process
  `golang.org/x/crypto/ssh` server through each transport's existing test
  harness (REST: `pkg/api/rest.NewSSHHandlers`; gRPC/unix: the real
  `pkg/api/grpc.Service` with `SetSSHClient`, lighter than the full daemon
  since the SSH RPCs need no `XKMSService`/authenticator; MCP: the existing
  `fakeMCPServer` wired to a real embedded client, since `pkg/api/mcp.Server`
  requires the full daemon to construct), covering a successful `Run`, an
  unknown-host refusal, a host-key-mismatch refusal, and a deleted-key
  signer-resolution failure propagating intact. go-xkms#719.
