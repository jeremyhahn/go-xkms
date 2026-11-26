package authenticator

import (
	"os"
	"testing"

	"golang.org/x/crypto/argon2"
)

// testArgon2Memory is the Argon2id memory cost, in KiB, the tests derive
// with. Production derives with 64 MiB per call; under -race the package's
// test binary reached 7.4 GB peak RSS at that cost (CA m2540).
const testArgon2Memory = 256

// TestMain caps the Argon2id memory cost for every derivation in the
// package's tests. Time and threads are unchanged, and the parameters the
// managers store and the tests assert stay at production values.
func TestMain(m *testing.M) {
	argon2IDKey = func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
		return argon2.IDKey(password, salt, time, min(memory, testArgon2Memory), threads, keyLen)
	}
	os.Exit(m.Run())
}
