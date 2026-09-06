- **The DNS-01 provider unit tests no longer query the internet, so their
  result depends on the code rather than on the runner's network** (#418).
  `pkg/acme/challenges/dns-01/providers/{util_coverage_test,propagation_test}.go`.
  `TestDNSQueryNoNameserversResponded` asserted that a query to `192.0.2.1`
  (RFC 5737 documentation space) fails — an assertion about the network, not
  about `DNSQuery`: anything that answers or synthesizes a reply, as the
  runner's network did on PR #414, turns "no nameserver responded" into a
  successful query and fails the test while the code is correct. Five tests in
  the package queried `8.8.8.8`/`8.8.4.4` from the unit suite, four of them
  discarding their own error (`_ = err`) and so asserting nothing while still
  blocking on a live lookup, and a sixth asserted on the host's
  `/etc/resolv.conf`. Every one now runs against a local `miekg/dns` server on
  `127.0.0.1:0` — the `testDNSServer` the package already had, extended with a
  silent mode, A/CNAME records, empty-NOERROR answers, a helper for a loopback
  address with nothing bound to it, and a UDP-truncating server paired with a
  TCP server on one port — and asserts the response instead of discarding it,
  so the UDP-to-TCP fallback, the nameserver-fallthrough loop, CNAME chasing,
  CNAME loop detection and the default-port rule are covered for the first
  time. The whole package now passes in a loopback-only network namespace, and
  with a resolver answering `192.0.2.1:53` inside that namespace — which
  reproduces the CI failure exactly against the old tests
  (`util_coverage_test.go:219`, "An error is expected but got nil"). Mutating
  `DNSQuery` to return a nil error on nameserver exhaustion, to drop the TCP
  fallback, or to stop appending the default port each turns the matching test
  red. New `make test-dns01` target.
