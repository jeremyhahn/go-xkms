package confidentialvm

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

func TestKeyProtector_RoundTripsUnderFIPSOnly(t *testing.T) {
	if os.Getenv("XKMS_CONFIDENTIALVM_FIPS_SUBPROCESS") != "" {
		keyProtectorRoundTrip(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestKeyProtector_RoundTripsUnderFIPSOnly$", "-test.v")
	cmd.Env = append(os.Environ(), "XKMS_CONFIDENTIALVM_FIPS_SUBPROCESS=only", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=only subprocess failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("PASS")) {
		t.Fatalf("fips140=only subprocess did not pass:\n%s", out)
	}
	if bytes.Contains(out, []byte("panic:")) {
		t.Fatalf("fips140=only subprocess panicked:\n%s", out)
	}
}

// keyProtectorRoundTrip seals and opens a key under a fixed derived key and
// checks the blob framing and the refusal of an altered blob.
func keyProtectorRoundTrip(t *testing.T) {
	saved := deriveFn
	t.Cleanup(func() { deriveFn = saved })
	deriveFn = func(_ context.Context, _ string, _ keyRequest, dst []byte) error {
		for i := range dst {
			dst[i] = byte(i + 1)
		}
		return nil
	}
	kp := &KeyProtector{req: testRequest}
	key := bytes.Repeat([]byte{0xa5}, 32)
	blob, err := kp.Protect(context.Background(), key)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	if len(blob) != blobHeaderSize+len(key)+gcmTagSize {
		t.Fatalf("blob length = %d, want %d", len(blob), blobHeaderSize+len(key)+gcmTagSize)
	}
	if blob[0] != blobVersion {
		t.Fatalf("blob version = %d, want %d", blob[0], blobVersion)
	}
	got := make([]byte, len(key))
	if err := kp.Unprotect(context.Background(), blob, got); err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("Unprotect did not recover the key")
	}
	blob[len(blob)-1] ^= 1
	dst := make([]byte, len(key))
	if err := kp.Unprotect(context.Background(), blob, dst); !errors.Is(err, enclave.ErrSealedAuthentication) {
		t.Fatalf("Unprotect of an altered blob: err = %v, want ErrSealedAuthentication", err)
	}
	if !bytes.Equal(dst, make([]byte, len(key))) {
		t.Fatal("Unprotect of an altered blob wrote dst")
	}
}
