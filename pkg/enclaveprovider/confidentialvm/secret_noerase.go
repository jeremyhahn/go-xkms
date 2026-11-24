//go:build !(goexperiment.runtimesecret && linux && !android && (amd64 || arm64))

package confidentialvm

// secretDo runs f; this platform or build has no runtime/secret erasure.
func secretDo(f func()) { f() }
