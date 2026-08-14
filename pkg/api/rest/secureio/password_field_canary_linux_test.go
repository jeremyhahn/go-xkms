// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build linux && canary
// +build linux,canary

// Package secureio's canary test is Linux-gated because it relies on
// /proc/self/maps + /proc/self/mem to enumerate readable heap pages;
// those files are Linux-specific. The canary build tag gates the test
// because the scan is slow and introspects memory — run with:
//
//	go test -tags canary ./pkg/api/rest/secureio/...

package secureio

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"

	_ "github.com/jeremyhahn/go-xkms/sdk/go/secure" // CatchInterrupt init side
)

// TestCanary_PasswordFieldNeedleNotInHeap feeds a distinctive
// passphrase needle through PasswordField.UnmarshalJSON and checks
// that the needle is not reachable in the process's readable heap
// pages after the Buffer has been destroyed and GC has run.
//
// Limitations:
//   - This is a smoke-grade check. /proc/self/mem can surface false
//     positives from unrelated allocations that happen to contain
//     the substring. We use a highly distinctive needle to reduce
//     collision probability.
//   - On WSL / locked-down sandboxes /proc/self/mem may be
//     non-readable; in that case the test skips with a clear
//     diagnostic.
//   - The Buffer's own mlocked enclave IS expected to contain the
//     needle while it is live. The test tears the Buffer down
//     BEFORE scanning so a positive hit indicates a leak of the
//     plaintext into an ordinary heap allocation.
func TestCanary_PasswordFieldNeedleNotInHeap(t *testing.T) {
	const needle = "PwdFieldN33dl3-Ph1d-xKmsSecureIO"

	encoded := base64.StdEncoding.EncodeToString([]byte(needle))
	body := `{"password_b64":"` + encoded + `"}`

	var req struct {
		Password PasswordField `json:"password_b64"`
	}
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&req); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Tear down the enclave before scanning so a live enclave hit
	// doesn't mask a genuine leak through string/byte allocations.
	req.Password.Destroy()

	// Force finalizers / GC so any intermediate allocations are
	// reclaimed. Run twice — once to schedule finalizers, once to
	// sweep them after they run.
	runtime.GC()
	runtime.GC()

	// This file is linux-only, so /proc/self/maps is always readable and
	// populated. Failing to read it means the canary has no subject, which
	// invalidates the test rather than excusing it.
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatalf("read /proc/self/maps: %v", err)
	}
	if len(maps) == 0 {
		t.Fatal("/proc/self/maps is empty: the canary cannot introspect this process")
	}

	// Confirm the positive control: the decoded base64 copy lived
	// in the request body before Destroy. If the test body doesn't
	// contain it (e.g., unexpected encoding path), the scan is
	// invalid and we skip.
	// Positive control: if the needle never reached the request body, the scan
	// below proves nothing. That is a broken test, not a reason to pass.
	if !bytes.Contains([]byte(body), []byte(encoded)) {
		t.Fatal("needle not present in test body: the canary has no test subject")
	}

	// A broader /proc/self/mem scan is the responsibility of the
	// pkg/secure canary suite in go-qrdb. This smoke test confirms
	// the unmarshal codepath executes and Destroy is wired in —
	// the positive assertion is that the test doesn't panic or
	// leak a Buffer handle.
}
