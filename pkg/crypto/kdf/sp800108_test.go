// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package kdf

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding %q: %v", s, err)
	}
	return b
}

// runCAVP drives one CAVP record through the adapter and compares against the
// published KO.
func runCAVP(t *testing.T, adapter *SP800108Adapter, v cavpVector) {
	t.Helper()

	params := &KDFParams{
		Algorithm:       adapter.Algorithm(),
		Hash:            v.hash,
		KeyLength:       v.keyLen,
		CounterLength:   v.counterLen,
		CounterLocation: v.location,
		FixedInput:      mustHex(t, v.fixedInput),
	}
	if v.iv != "" {
		params.IV = mustHex(t, v.iv)
	}

	got, err := adapter.DeriveKey(mustHex(t, v.ki), params)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	want := mustHex(t, v.ko)
	if !bytes.Equal(got, want) {
		t.Errorf("KO mismatch\n got: %x\nwant: %x", got, want)
	}
}

// TestSP800108_CAVP_CounterMode validates Counter Mode against the NIST CAVP
// KDFCTR_gen.rsp response file. This is the check that distinguishes a real
// SP 800-108 implementation from something merely labeled as one.
func TestSP800108_CAVP_CounterMode(t *testing.T) {
	adapter := NewSP800108CounterAdapter()
	if len(cavpCounterVectors) == 0 {
		t.Fatal("no counter mode vectors loaded")
	}
	for _, v := range cavpCounterVectors {
		t.Run(v.name, func(t *testing.T) { runCAVP(t, adapter, v) })
	}
}

// TestSP800108_CAVP_FeedbackMode validates Feedback Mode against the NIST
// CAVP KDFFeedback_gen.rsp response file, including the K(0) = IV chaining.
func TestSP800108_CAVP_FeedbackMode(t *testing.T) {
	adapter := NewSP800108FeedbackAdapter()
	if len(cavpFeedbackVectors) == 0 {
		t.Fatal("no feedback mode vectors loaded")
	}
	for _, v := range cavpFeedbackVectors {
		t.Run(v.name, func(t *testing.T) { runCAVP(t, adapter, v) })
	}
}

// TestSP800108_CAVP_DoublePipelineMode validates Double-Pipeline Iteration
// Mode against the NIST CAVP KDFDblPipeline_gen.rsp response file.
func TestSP800108_CAVP_DoublePipelineMode(t *testing.T) {
	adapter := NewSP800108DoublePipelineAdapter()
	if len(cavpDoublePipelineVectors) == 0 {
		t.Fatal("no double-pipeline mode vectors loaded")
	}
	for _, v := range cavpDoublePipelineVectors {
		t.Run(v.name, func(t *testing.T) { runCAVP(t, adapter, v) })
	}
}

// TestSP800108CounterMode_FixedInputAssembly proves the production path
// assembles the fixed input data as SP 800-108r1 specifies,
// Label || 0x00 || Context || [L]_2, for every counter placement. The
// expected value is built independently here with crypto/hmac rather than by
// calling back into the adapter.
func TestSP800108CounterMode_FixedInputAssembly(t *testing.T) {
	kdk := []byte("key-derivation-key-for-assembly!")
	label := []byte("purpose")
	context := []byte("application-context")
	keyLen := 32

	lengthEncoding := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthEncoding, uint32(keyLen)*8)

	// [i]_32 for i = 1, the single iteration a 32-byte SHA-256 output needs.
	counter := []byte{0x00, 0x00, 0x00, 0x01}

	tests := []struct {
		location string
		prfInput []byte
	}{
		{
			location: CounterLocationBefore,
			prfInput: concat(counter, label, []byte{0x00}, context, lengthEncoding),
		},
		{
			location: CounterLocationMiddle,
			prfInput: concat(label, []byte{0x00}, counter, context, lengthEncoding),
		},
		{
			location: CounterLocationAfter,
			prfInput: concat(label, []byte{0x00}, context, lengthEncoding, counter),
		},
	}

	adapter := NewSP800108CounterAdapter()
	for _, tt := range tests {
		t.Run(tt.location, func(t *testing.T) {
			mac := hmac.New(crypto.SHA256.New, kdk)
			mac.Write(tt.prfInput)
			want := mac.Sum(nil)

			got, err := adapter.DeriveKey(kdk, &KDFParams{
				Algorithm:       AlgorithmSP800108Counter,
				Hash:            crypto.SHA256,
				KeyLength:       keyLen,
				Label:           label,
				Context:         context,
				CounterLocation: tt.location,
			})
			if err != nil {
				t.Fatalf("DeriveKey: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("fixed input assembly mismatch\n got: %x\nwant: %x", got, want)
			}
		})
	}
}

// TestSP800108_FixedInputMatchesLabelContext proves FixedInput and the
// Label/Context form describe the same construction: assembling the blob by
// hand and passing it as FixedInput yields the same key.
func TestSP800108_FixedInputMatchesLabelContext(t *testing.T) {
	kdk := []byte("key-derivation-key-for-equality!")
	label := []byte("equality-label")
	context := []byte("equality-context")
	keyLen := 48

	lengthEncoding := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthEncoding, uint32(keyLen)*8)
	assembled := concat(label, []byte{0x00}, context, lengthEncoding)

	for _, adapter := range []*SP800108Adapter{
		NewSP800108CounterAdapter(),
		NewSP800108FeedbackAdapter(),
		NewSP800108DoublePipelineAdapter(),
	} {
		t.Run(string(adapter.Algorithm()), func(t *testing.T) {
			structured, err := adapter.DeriveKey(kdk, &KDFParams{
				Algorithm: adapter.Algorithm(),
				Hash:      crypto.SHA256,
				KeyLength: keyLen,
				Label:     label,
				Context:   context,
			})
			if err != nil {
				t.Fatalf("DeriveKey(label/context): %v", err)
			}

			opaque, err := adapter.DeriveKey(kdk, &KDFParams{
				Algorithm:  adapter.Algorithm(),
				Hash:       crypto.SHA256,
				KeyLength:  keyLen,
				FixedInput: assembled,
			})
			if err != nil {
				t.Fatalf("DeriveKey(fixed input): %v", err)
			}

			if !bytes.Equal(structured, opaque) {
				t.Errorf("Label/Context and FixedInput disagree\n structured: %x\n     opaque: %x", structured, opaque)
			}
		})
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TestSP800108_LabelAndContextChangeOutput proves the caller's Label and
// Context genuinely reach the PRF rather than being dropped, which is the
// defect class that made the old HKDF-backed implementation dangerous.
func TestSP800108_LabelAndContextChangeOutput(t *testing.T) {
	kdk := []byte("key-derivation-key-for-sensitivity")

	base := func(mode KDFAlgorithm) *KDFParams {
		return &KDFParams{
			Algorithm: mode,
			Hash:      crypto.SHA256,
			KeyLength: 32,
			Label:     []byte("label-1"),
			Context:   []byte("context-1"),
		}
	}

	for _, adapter := range []*SP800108Adapter{
		NewSP800108CounterAdapter(),
		NewSP800108FeedbackAdapter(),
		NewSP800108DoublePipelineAdapter(),
	} {
		t.Run(string(adapter.Algorithm()), func(t *testing.T) {
			reference, err := adapter.DeriveKey(kdk, base(adapter.Algorithm()))
			if err != nil {
				t.Fatalf("DeriveKey: %v", err)
			}

			changedLabel := base(adapter.Algorithm())
			changedLabel.Label = []byte("label-2")
			key, err := adapter.DeriveKey(kdk, changedLabel)
			if err != nil {
				t.Fatalf("DeriveKey(changed label): %v", err)
			}
			if bytes.Equal(key, reference) {
				t.Error("changing Label did not change the derived key")
			}

			changedContext := base(adapter.Algorithm())
			changedContext.Context = []byte("context-2")
			key, err = adapter.DeriveKey(kdk, changedContext)
			if err != nil {
				t.Fatalf("DeriveKey(changed context): %v", err)
			}
			if bytes.Equal(key, reference) {
				t.Error("changing Context did not change the derived key")
			}

			// Label and Context are separated by 0x00 precisely so that
			// moving the boundary between them changes the key.
			shifted := base(adapter.Algorithm())
			shifted.Label = []byte("label-1cont")
			shifted.Context = []byte("ext-1")
			key, err = adapter.DeriveKey(kdk, shifted)
			if err != nil {
				t.Fatalf("DeriveKey(shifted boundary): %v", err)
			}
			if bytes.Equal(key, reference) {
				t.Error("moving the Label/Context boundary did not change the derived key")
			}
		})
	}
}

// TestSP800108_OutputLengthsAcrossBlockBoundary exercises requested lengths
// that fall short of, land exactly on, and span the PRF block size, and
// confirms the shorter outputs are prefixes of the longer ones only where the
// construction says they should be.
func TestSP800108_OutputLengthsAcrossBlockBoundary(t *testing.T) {
	kdk := []byte("key-derivation-key-for-lengths!!")

	// SHA-256 emits 32-byte blocks: 1, 31, 32 are one block; 33, 64 are two;
	// 65 is three.
	lengths := []int{1, 31, 32, 33, 64, 65, 100}

	for _, adapter := range []*SP800108Adapter{
		NewSP800108CounterAdapter(),
		NewSP800108FeedbackAdapter(),
		NewSP800108DoublePipelineAdapter(),
	} {
		t.Run(string(adapter.Algorithm()), func(t *testing.T) {
			for _, length := range lengths {
				key, err := adapter.DeriveKey(kdk, &KDFParams{
					Algorithm: adapter.Algorithm(),
					Hash:      crypto.SHA256,
					KeyLength: length,
					Label:     []byte("length"),
					Context:   []byte("test"),
				})
				if err != nil {
					t.Fatalf("DeriveKey(%d): %v", length, err)
				}
				if len(key) != length {
					t.Errorf("requested %d bytes, got %d", length, len(key))
				}
			}

			// [L]_2 is part of the PRF input, so two different requested
			// lengths never share a prefix.
			short, err := adapter.DeriveKey(kdk, &KDFParams{
				Algorithm: adapter.Algorithm(),
				Hash:      crypto.SHA256,
				KeyLength: 32,
				Label:     []byte("length"),
				Context:   []byte("test"),
			})
			if err != nil {
				t.Fatalf("DeriveKey(32): %v", err)
			}
			long, err := adapter.DeriveKey(kdk, &KDFParams{
				Algorithm: adapter.Algorithm(),
				Hash:      crypto.SHA256,
				KeyLength: 64,
				Label:     []byte("length"),
				Context:   []byte("test"),
			})
			if err != nil {
				t.Fatalf("DeriveKey(64): %v", err)
			}
			if bytes.Equal(short, long[:32]) {
				t.Error("outputs of different lengths share a prefix; [L]_2 is not bound into the PRF input")
			}
		})
	}
}

// TestSP800108_RejectedParameters covers the parameter combinations
// SP 800-108 does not permit. Each must return its typed error rather than be
// coerced into something that derives a different key than the caller asked
// for.
func TestSP800108_RejectedParameters(t *testing.T) {
	tests := []struct {
		name    string
		adapter *SP800108Adapter
		params  *KDFParams
		wantErr error
	}{
		{
			name:    "nil params",
			adapter: NewSP800108CounterAdapter(),
			params:  nil,
			wantErr: ErrInvalidIKM,
		},
		{
			name:    "zero key length",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256},
			wantErr: ErrInvalidKeyLength,
		},
		{
			name:    "negative key length",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: -1},
			wantErr: ErrInvalidKeyLength,
		},
		{
			name:    "key length overflows the [L]_2 encoding",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: maxOutputBytes + 1},
			wantErr: ErrOutputTooLong,
		},
		{
			name:    "unavailable hash",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.Hash(0), KeyLength: 32},
			wantErr: ErrInvalidHash,
		},
		{
			name:    "counter width 12 bits",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: 32, CounterLength: 12},
			wantErr: ErrInvalidCounterLength,
		},
		{
			name:    "counter width 64 bits",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: 32, CounterLength: 64},
			wantErr: ErrInvalidCounterLength,
		},
		{
			name:    "negative counter width",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: 32, CounterLength: -8},
			wantErr: ErrInvalidCounterLength,
		},
		{
			name:    "unknown counter location",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: 32, CounterLocation: "sideways"},
			wantErr: ErrInvalidCounterLocation,
		},
		{
			name:    "counter location is case sensitive",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: 32, CounterLocation: "BEFORE"},
			wantErr: ErrInvalidCounterLocation,
		},
		{
			name:    "output exceeds an 8-bit counter",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: 256 * 32, CounterLength: 8},
			wantErr: ErrOutputTooLong,
		},
		{
			name:    "output exceeds a 16-bit counter",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: 65536 * 32, CounterLength: 16},
			wantErr: ErrOutputTooLong,
		},
		{
			name:    "IV in counter mode",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: 32, IV: []byte("iv")},
			wantErr: ErrIVNotPermitted,
		},
		{
			name:    "IV in double-pipeline mode",
			adapter: NewSP800108DoublePipelineAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: 32, IV: []byte("iv")},
			wantErr: ErrIVNotPermitted,
		},
		{
			name:    "FixedInput with Label",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: 32, FixedInput: []byte("fixed"), Label: []byte("label")},
			wantErr: ErrFixedInputConflict,
		},
		{
			name:    "FixedInput with Context",
			adapter: NewSP800108FeedbackAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: 32, FixedInput: []byte("fixed"), Context: []byte("context")},
			wantErr: ErrFixedInputConflict,
		},
		{
			name:    "FixedInput with middle counter location",
			adapter: NewSP800108CounterAdapter(),
			params:  &KDFParams{Hash: crypto.SHA256, KeyLength: 32, FixedInput: []byte("fixed"), CounterLocation: CounterLocationMiddle},
			wantErr: ErrInvalidCounterLocation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.adapter.ValidateParams(tt.params); !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateParams = %v, want %v", err, tt.wantErr)
			}
			if _, err := tt.adapter.DeriveKey([]byte("key-derivation-key"), tt.params); !errors.Is(err, tt.wantErr) {
				t.Errorf("DeriveKey = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestSP800108_AcceptedParameters covers the boundary of the permitted
// parameter space that must not be rejected.
func TestSP800108_AcceptedParameters(t *testing.T) {
	tests := []struct {
		name   string
		params *KDFParams
	}{
		{"default counter width", &KDFParams{Hash: crypto.SHA256, KeyLength: 32}},
		{"8-bit counter", &KDFParams{Hash: crypto.SHA256, KeyLength: 32, CounterLength: 8}},
		{"16-bit counter", &KDFParams{Hash: crypto.SHA256, KeyLength: 32, CounterLength: 16}},
		{"24-bit counter", &KDFParams{Hash: crypto.SHA256, KeyLength: 32, CounterLength: 24}},
		{"32-bit counter", &KDFParams{Hash: crypto.SHA256, KeyLength: 32, CounterLength: 32}},
		{"8-bit counter at its maximum output", &KDFParams{Hash: crypto.SHA256, KeyLength: 255 * 32, CounterLength: 8}},
		{"counter before fixed data", &KDFParams{Hash: crypto.SHA256, KeyLength: 32, CounterLocation: CounterLocationBefore}},
		{"counter in the middle", &KDFParams{Hash: crypto.SHA256, KeyLength: 32, CounterLocation: CounterLocationMiddle}},
		{"counter after fixed data", &KDFParams{Hash: crypto.SHA256, KeyLength: 32, CounterLocation: CounterLocationAfter}},
		{"empty label and context", &KDFParams{Hash: crypto.SHA256, KeyLength: 32, Label: nil, Context: nil}},
		{"single byte output", &KDFParams{Hash: crypto.SHA256, KeyLength: 1}},
	}

	adapter := NewSP800108CounterAdapter()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := adapter.ValidateParams(tt.params); err != nil {
				t.Fatalf("ValidateParams: %v", err)
			}
			key, err := adapter.DeriveKey([]byte("key-derivation-key"), tt.params)
			if err != nil {
				t.Fatalf("DeriveKey: %v", err)
			}
			if len(key) != tt.params.KeyLength {
				t.Errorf("got %d bytes, want %d", len(key), tt.params.KeyLength)
			}
		})
	}
}

// TestSP800108_EmptyIKM rejects a missing key derivation key.
func TestSP800108_EmptyIKM(t *testing.T) {
	adapter := NewSP800108CounterAdapter()
	params := &KDFParams{Hash: crypto.SHA256, KeyLength: 32, Label: []byte("test")}

	if _, err := adapter.DeriveKey(nil, params); !errors.Is(err, ErrInvalidIKM) {
		t.Errorf("nil IKM: got %v, want ErrInvalidIKM", err)
	}
	if _, err := adapter.DeriveKey([]byte{}, params); !errors.Is(err, ErrInvalidIKM) {
		t.Errorf("empty IKM: got %v, want ErrInvalidIKM", err)
	}
}

// inFIPSChild reports whether the caller is the re-executed child running
// under godebug, in which case the caller performs its assertions. Otherwise
// it re-execs testName under GODEBUG=godebug, asserts the child passed, and
// returns false. crypto/fips140.Enforced is fixed when the process starts,
// so only a child can observe a mode other than the parent's.
func inFIPSChild(t *testing.T, godebug, testName string) bool {
	t.Helper()
	if os.Getenv("XKMS_FIPS_SUBPROCESS") == godebug {
		return true
	}
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GODEBUG=") {
			continue
		}
		env = append(env, kv)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$", "-test.v")
	cmd.Env = append(env, "XKMS_FIPS_SUBPROCESS="+godebug, "GODEBUG="+godebug)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s subprocess failed: %v\n%s", godebug, err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Errorf("%s subprocess did not pass:\n%s", godebug, out)
	}
	return false
}

// sp800108Adapters returns one adapter per SP 800-108 mode.
func sp800108Adapters() []*SP800108Adapter {
	return []*SP800108Adapter{
		NewSP800108CounterAdapter(),
		NewSP800108FeedbackAdapter(),
		NewSP800108DoublePipelineAdapter(),
	}
}

// TestSP800108_KDKRefusedUnderFIPS140Only proves a KDK the enforcing module
// refuses as an HMAC key (under 112 bits) returns ErrKDKRefused in every
// mode instead of panicking, and that a 112-bit KDK still derives.
func TestSP800108_KDKRefusedUnderFIPS140Only(t *testing.T) {
	if !inFIPSChild(t, "fips140=only", "TestSP800108_KDKRefusedUnderFIPS140Only") {
		return
	}
	params := &KDFParams{Hash: crypto.SHA256, KeyLength: 32, Label: []byte("test")}
	for _, adapter := range sp800108Adapters() {
		t.Run(string(adapter.Algorithm()), func(t *testing.T) {
			if _, err := adapter.DeriveKey(make([]byte, 13), params); !errors.Is(err, ErrKDKRefused) {
				t.Errorf("13-byte KDK: got %v, want ErrKDKRefused", err)
			}
			key, err := adapter.DeriveKey(make([]byte, 14), params)
			if err != nil {
				t.Fatalf("14-byte KDK: %v", err)
			}
			if len(key) != 32 {
				t.Errorf("14-byte KDK: got %d bytes, want 32", len(key))
			}
		})
	}
}

// TestSP800108_ShortKDKDerivesOutsideFIPS140Only proves the refusal is the
// module's, not ours: with enforcement off the same short KDK derives, and a
// panic that is not a module refusal propagates from newPRF unchanged.
func TestSP800108_ShortKDKDerivesOutsideFIPS140Only(t *testing.T) {
	if !inFIPSChild(t, "fips140=off", "TestSP800108_ShortKDKDerivesOutsideFIPS140Only") {
		return
	}
	params := &KDFParams{Hash: crypto.SHA256, KeyLength: 32, Label: []byte("test")}
	for _, adapter := range sp800108Adapters() {
		if _, err := adapter.DeriveKey(make([]byte, 13), params); err != nil {
			t.Errorf("%s: 13-byte KDK: %v", adapter.Algorithm(), err)
		}
	}

	defer func() {
		if recover() == nil {
			t.Error("newPRF swallowed a panic that was not a module refusal")
		}
	}()
	_, err := newPRF(func() hash.Hash { panic("hash constructor failed") }, make([]byte, 32))
	t.Errorf("newPRF returned %v, want a propagated panic", err)
}

// TestSP800108_UnsupportedMode rejects an adapter constructed with an
// algorithm outside the SP 800-108 family.
func TestSP800108_UnsupportedMode(t *testing.T) {
	adapter := &SP800108Adapter{mode: AlgorithmHKDF}
	_, err := adapter.DeriveKey([]byte("key-derivation-key"), &KDFParams{
		Hash:      crypto.SHA256,
		KeyLength: 32,
	})
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("got %v, want ErrUnsupportedAlgorithm", err)
	}
}
