- **CI runs the whole `sdk/go` test suite (#333).** The nested-module job
  ran three package trees of the public SDK module, 130 of its ~1,000 test
  functions, leaving 23 test directories, including the whole
  `acme/client` family, the module root and `errors`, outside the gate. It
  now runs `go test -race -v ./...` from `sdk/go`. Measured before widening:
  26 packages, all green with no build tags, about one minute of wall time
  under the race detector on a development host, so the addition is
  cheaper than the xkey steps in the same job. A deliberately failing test
  in a formerly dark package turns the step red.
