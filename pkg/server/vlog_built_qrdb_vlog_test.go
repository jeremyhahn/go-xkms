//go:build qrdb_vlog

package server

// vlogBuiltIn reports that go-qrdb's verifiable-log service is compiled in,
// so a test that finds the embedded node without one must fail, not skip.
const vlogBuiltIn = true
