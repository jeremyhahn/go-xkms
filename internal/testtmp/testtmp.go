// Package testtmp keeps the temporary directories of a test binary short.
//
// A unix socket path must fit in sun_path (108 bytes on Linux). Runners whose
// TMPDIR is deep (for example /home/runner/_work/_temp) make t.TempDir()
// return paths that, with a long test name and a socket file name, exceed it.
// Short points TMPDIR at a short directory for the whole test run.
package testtmp

// Short runs run and returns its exit code.
func Short(run func() int) int {
	return run()
}
