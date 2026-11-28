//go:build !qrdb_vlog

package server

// vlogBuiltIn reports that go-qrdb's verifiable-log service is not compiled
// in (no qrdb_vlog tag), so the node log tests skip.
const vlogBuiltIn = false
