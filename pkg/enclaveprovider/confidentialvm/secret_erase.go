//go:build goexperiment.runtimesecret && linux && !android && (amd64 || arm64)

package confidentialvm

import "runtime/secret"

// secretDo runs f in runtime/secret.Do, which erases what f leaves behind.
func secretDo(f func()) { secret.Do(f) }
