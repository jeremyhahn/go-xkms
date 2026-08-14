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

package main

// Tests for C_GenerateRandom's length contract (PKCS#11 v3.2 section 5.19.2).

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// randomBufferSentinel is the byte a test buffer is filled with before the
// call, so "the module wrote here" and "the module left this alone" are
// distinguishable afterwards. Zero would not be: a buffer the module never
// touched and a buffer it filled with a zero byte would look the same.
const randomBufferSentinel = 0xAA

// setBufferArg returns a callExport setter that points a CK_BYTE_PTR argument
// at buf. reflect.NewAt builds the pointer without the test naming the cgo
// type, which a _test.go file cannot do because Go rejects `import "C"` there.
func setBufferArg(buf []byte) func(reflect.Value) {
	return func(v reflect.Value) {
		v.Set(reflect.NewAt(v.Type().Elem(), unsafe.Pointer(&buf[0])))
	}
}

// TestGenerateRandom_FillsTheWholeBuffer is the success case: a request the
// entry point can carry fills every byte the caller asked for and reports
// CKR_OK.
//
// The assertion is that no untouched TAIL survives. Checking only that the
// buffer changed would pass for a call that filled one byte of thirty-two,
// which is exactly the partial fill the length guard exists to prevent.
//
// The sentinel is positional rather than a repeated constant, and the check is
// for a contiguous unwritten suffix rather than a count. Counting occurrences of
// one byte value is not a sound test of randomness: random output contains any
// given byte about once per 256, so a fixed sentinel repeated 32 times made this
// test fail roughly one run in 140 for no reason but chance. A partial fill
// always leaves a contiguous tail, which coincidence does not produce.
func TestGenerateRandom_FillsTheWholeBuffer(t *testing.T) {
	f := newTestFixture(t)

	const want = 32
	buf := make([]byte, want)
	for i := range buf {
		buf[i] = randomBufferSentinel ^ byte(i)
	}
	original := append([]byte(nil), buf...)

	rv := callExport(t, C_GenerateRandom, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: setBufferArg(buf),
		2: func(v reflect.Value) { v.SetUint(want) },
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GenerateRandom(%d bytes) returned %s, want CKR_OK", want, rv)
	}

	// Longest suffix still carrying its positional sentinel. Four consecutive
	// coincidences is about one run in four billion; a partial fill leaves a
	// tail far longer than that.
	untouched := 0
	for i := want - 1; i >= 0 && buf[i] == original[i]; i-- {
		untouched++
	}
	if untouched >= 4 {
		t.Fatalf("C_GenerateRandom left a %d byte unwritten tail in a %d byte buffer; "+
			"the whole buffer must be written before CKR_OK is reported", untouched, want)
	}

	if bytes.Equal(buf, original) {
		t.Fatal("C_GenerateRandom wrote nothing at all")
	}
}

// TestGenerateRandom_RefusesLengthItCannotCarry is the bad-input case: a
// request larger than the entry point can carry is refused with
// CKR_ARGUMENTS_BAD and writes nothing.
//
// Both lengths here exceed 2^32, which is what makes them regressions rather
// than hypotheticals. Before the guard, ulRandomLen was converted to uint32:
// the conversion can only shrink, so there was never an overrun, but a request
// of 2^32+16 filled sixteen bytes of the caller's buffer and returned CKR_OK,
// and a request of exactly 2^32 filled none and still returned CKR_OK. Either
// way the caller was told its buffer held the random data it asked for while
// the tail held whatever the heap held.
//
// PKCS#11 v3.2 section 5.19.2 gives C_GenerateRandom no "length too large"
// return code, so CKR_ARGUMENTS_BAD -- which section 5.19.2 does list, and
// which section 5.1 defines as arguments that "were in some way not
// appropriate" -- is what a length this entry point cannot honour reports.
func TestGenerateRandom_RefusesLengthItCannotCarry(t *testing.T) {
	f := newTestFixture(t)

	// Lengths are kept just above the 32-bit boundary rather than at
	// math.MaxInt32 so the case stays cheap: the guard rejects them before any
	// allocation, and a build without the guard reveals itself by writing a
	// short prefix instead of by allocating gigabytes.
	cases := []struct {
		name   string
		length uint64
	}{
		{name: "truncates to a short prefix", length: 1<<32 + 16},
		{name: "truncates to nothing", length: 1 << 32},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const size = 64
			buf := bytes.Repeat([]byte{randomBufferSentinel}, size)

			rv := callExport(t, C_GenerateRandom, map[int]func(reflect.Value){
				0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
				1: setBufferArg(buf),
				2: func(v reflect.Value) { v.SetUint(tc.length) },
			})
			if rv != module.CKR_ARGUMENTS_BAD {
				t.Fatalf("C_GenerateRandom(ulRandomLen=%d) returned %s, want CKR_ARGUMENTS_BAD; "+
					"a request this entry point cannot carry must never be reported as success", tc.length, rv)
			}

			if want := bytes.Repeat([]byte{randomBufferSentinel}, size); !bytes.Equal(buf, want) {
				t.Fatalf("C_GenerateRandom(ulRandomLen=%d) wrote %d of %d bytes and refused the call; "+
					"a refused request must leave the caller's buffer untouched",
					tc.length, size-bytes.Count(buf, []byte{randomBufferSentinel}), size)
			}
		})
	}
}

// TestGenerateRandom_RefusesNullBufferWithLength keeps the pre-existing NULL
// guard alongside the length guard: a NULL pRandomData with a non-zero
// ulRandomLen is CKR_ARGUMENTS_BAD, and a NULL pointer with zero length is a
// no-op that succeeds, since there is nothing to write.
func TestGenerateRandom_RefusesNullBufferWithLength(t *testing.T) {
	f := newTestFixture(t)

	rv := callExport(t, C_GenerateRandom, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		2: func(v reflect.Value) { v.SetUint(16) },
	})
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GenerateRandom(pRandomData=NULL, ulRandomLen=16) returned %s, want CKR_ARGUMENTS_BAD", rv)
	}

	rv = callExport(t, C_GenerateRandom, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GenerateRandom(pRandomData=NULL, ulRandomLen=0) returned %s, want CKR_OK", rv)
	}
}

// TestGenerateRandom_RejectsInvalidSession proves the length guard did not
// displace the session check: a well-formed request on a handle that names no
// session is still CKR_SESSION_HANDLE_INVALID, not CKR_OK with a filled
// buffer.
func TestGenerateRandom_RejectsInvalidSession(t *testing.T) {
	newTestFixture(t)

	const size = 16
	buf := bytes.Repeat([]byte{randomBufferSentinel}, size)

	rv := callExport(t, C_GenerateRandom, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(0xDEADBEEF) },
		1: setBufferArg(buf),
		2: func(v reflect.Value) { v.SetUint(size) },
	})
	if rv != module.CKR_SESSION_HANDLE_INVALID {
		t.Fatalf("C_GenerateRandom on an unknown session returned %s, want CKR_SESSION_HANDLE_INVALID", rv)
	}
	if want := bytes.Repeat([]byte{randomBufferSentinel}, size); !bytes.Equal(buf, want) {
		t.Fatal("C_GenerateRandom wrote to the caller's buffer on a failed call")
	}
}
