- **BREAKING: the MCP `ssh.knownHosts.verify` and REST `POST
  /xkms/v1/ssh/known-hosts/{host}/verify` endpoints now take the presented
  host public key instead of a caller-claimed fingerprint, and delegate to
  the canonical `pkg/ssh/known_hosts.Verify` full-key comparison.** Both
  handlers previously did their own `KnownHosts().List` + string compare of
  a client-supplied `fingerprint`/`algorithm` pair against the stored pin's
  `Fingerprint` field — a caller only had to ship a string that matched, not
  the key it claimed to be presenting, so the check trusted the caller's
  claim about the key rather than examining it. `handleSSHKnownHostsVerify`
  (`pkg/api/mcp/handlers_ssh.go`) and `handleVerifyKnownHost`
  (`pkg/api/rest/handlers_ssh.go`) now parse the wire `public_key`
  (`authorized_keys` format) and call the SDK client's
  `KnownHosts().Verify(ctx, scope, owner, host, pub)`, which for the
  embedded client (used by both transports) delegates straight to
  `known_hosts.Verify` — the same full `received.Marshal()` vs.
  `Pin.PublicKey` byte comparison the gRPC transport already relies on. The
  parallel List+compare is deleted from both handlers. Wire shapes changed
  to match: `SSHKnownHostsVerifyParams` (MCP) and the REST verify DTO
  dropped `fingerprint`/`algorithm` for a required `public_key` field; the
  SDK REST and MCP clients (`sdk/go/client/ssh/rest.go`,
  `sdk/go/client/ssh/mcp.go`) now send the presented key's
  `authorized_keys` line instead of computing and shipping a fingerprint.
  A malformed `public_key` is rejected with the existing
  `sdkssh.InvalidPublicKeyError` (now also mapped to HTTP 400 in
  `HTTPStatusForError`, alongside `MissingPublicKeyError`, closing a gap
  where both fell through to 500). `xkmsctl`/`xkey` callers are unaffected:
  they already called `KnownHosts().Verify` with the actual
  `gossh.PublicKey` they held, so only the internal wire encoding changed.
