- **`TestGRPCServer_SocketPermissions` no longer reads the socket mode inside
  the listen→chmod window, where it flaked at 755** (#357). `Start()` creates
  the Unix socket via `net.Listen` and sets the configured mode with a
  separate `os.Chmod`, so the test's poll-for-existence loop could observe the
  socket at the umask default before the chmod ran. The test now polls for the
  condition it asserts — the mode reaching 0640 — and still fails at the
  deadline if the server never sets it (verified by mutation: with the
  `os.Chmod` removed the test goes red at the umask default).
  `pkg/api/unix/grpc_server_test.go`. Verified with 200 consecutive green
  runs. The production-side window (socket briefly world-accessible before
  the chmod) is a separate question recorded in the issue and deliberately
  not changed here.

