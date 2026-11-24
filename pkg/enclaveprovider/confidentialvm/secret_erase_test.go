//go:build goexperiment.runtimesecret && linux && !android && amd64

package confidentialvm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-enclave"
)

// residueRounds is how many derivations each half of the test runs.
const residueRounds = 64

// secretKey is a random derived key in locked memory with its two schedule
// probes: the key bytes as they are and with each 32-bit word byte-swapped.
type secretKey struct {
	key, exact, swapped *enclave.MemoryEnclave
}

func newSecretKey(t *testing.T) *secretKey {
	t.Helper()
	s := &secretKey{}
	var err error
	for _, e := range []**enclave.MemoryEnclave{&s.key, &s.exact, &s.swapped} {
		if *e, err = enclave.NewMemoryEnclaveSized(derivedKeySize); err != nil {
			t.Fatalf("NewMemoryEnclaveSized: %v", err)
		}
	}
	t.Cleanup(func() {
		for _, e := range []*enclave.MemoryEnclave{s.key, s.exact, s.swapped} {
			_ = e.Destroy()
		}
	})
	err = s.key.WithBytes(func(k []byte) error {
		if _, err := rand.Read(k); err != nil {
			return err
		}
		if err := s.exact.WithBytes(func(p []byte) error { copy(p, k); return nil }); err != nil {
			return err
		}
		return s.swapped.WithBytes(func(p []byte) error {
			for i := 0; i+4 <= len(k); i += 4 {
				p[i], p[i+1], p[i+2], p[i+3] = k[i+3], k[i+2], k[i+1], k[i]
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("fill the secret key: %v", err)
	}
	return s
}

// found reports whether either probe lies in process memory outside its own
// mapping.
func (s *secretKey) found(t *testing.T) bool {
	t.Helper()
	var hit bool
	err := s.exact.WithBytes(func(pe []byte) error {
		return s.swapped.WithBytes(func(ps []byte) error {
			hit = memoryHolds(t, pe) || memoryHolds(t, ps)
			return nil
		})
	})
	if err != nil {
		t.Fatalf("borrow the probes: %v", err)
	}
	return hit
}

// memoryHolds sweeps every readable mapping of the process, except the one
// holding probe, for probe's bytes.
func memoryHolds(t *testing.T, probe []byte) bool {
	t.Helper()
	own := uint64(uintptr(unsafe.Pointer(&probe[0])))
	maps, err := os.Open("/proc/self/maps")
	if err != nil {
		t.Fatalf("open maps: %v", err)
	}
	defer func() { _ = maps.Close() }()
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Fatalf("open mem: %v", err)
	}
	defer func() { _ = mem.Close() }()
	const chunk = 1 << 20
	buf := make([]byte, chunk+len(probe))
	defer clear(buf)
	sc := bufio.NewScanner(maps)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[1][0] != 'r' {
			continue
		}
		if len(f) >= 6 && strings.HasPrefix(f[5], "[v") {
			continue
		}
		bounds := strings.SplitN(f[0], "-", 2)
		start, err1 := strconv.ParseUint(bounds[0], 16, 64)
		end, err2 := strconv.ParseUint(bounds[1], 16, 64)
		if err1 != nil || err2 != nil || (own >= start && own < end) {
			continue
		}
		for off := start; off < end; off += chunk {
			n := min(end-off, uint64(len(buf)))
			got, _ := mem.ReadAt(buf[:n], int64(off)) //nolint:gosec // G115: user-space addresses fit int64
			hit := bytes.Contains(buf[:got], probe)
			clear(buf[:got])
			if hit {
				return true
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read maps: %v", err)
	}
	return false
}

func TestKeyProtector_ErasesTheKeyScheduleUnderRuntimeSecret(t *testing.T) {
	control := newSecretKey(t)
	err := control.key.WithBytes(func(k []byte) error {
		for range residueRounds {
			block, err := aes.NewCipher(k)
			if err != nil {
				return err
			}
			aead, err := cipher.NewGCMWithRandomNonce(block)
			if err != nil {
				return err
			}
			_ = aead.Seal(nil, nil, []byte("control"), nil)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("control seals: %v", err)
	}
	if err := control.key.Destroy(); err != nil {
		t.Fatalf("destroy the control key: %v", err)
	}
	runtime.GC()
	runtime.GC()
	if !control.found(t) {
		t.Fatal("the sweep did not find an AES schedule built outside any erasing scope")
	}

	s := newSecretKey(t)
	saved := deriveFn
	t.Cleanup(func() { deriveFn = saved })
	deriveFn = func(_ context.Context, _ string, _ keyRequest, dst []byte) error {
		return s.key.WithBytes(func(k []byte) error { copy(dst, k); return nil })
	}
	kp := &KeyProtector{req: testRequest}
	plain := bytes.Repeat([]byte{0x5a}, 32)
	got := make([]byte, len(plain))
	for range residueRounds {
		blob, err := kp.Protect(context.Background(), plain)
		if err != nil {
			t.Fatalf("Protect: %v", err)
		}
		if err := kp.Unprotect(context.Background(), blob, got); err != nil {
			t.Fatalf("Unprotect: %v", err)
		}
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("Unprotect did not recover the key")
	}
	if err := s.key.Destroy(); err != nil {
		t.Fatalf("destroy the key: %v", err)
	}
	runtime.GC()
	runtime.GC()
	if s.found(t) {
		t.Fatal("an AES schedule of the derived key survives Protect/Unprotect")
	}
}
