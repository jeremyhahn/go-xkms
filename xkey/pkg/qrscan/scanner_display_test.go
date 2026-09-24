// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package qrscan

import (
	"errors"
	"image"
	"image/color"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file exercises ScanScreen, ScanAllScreens, scanDisplay and the
// package-level convenience functions through the numActiveDisplays,
// getDisplayBounds and captureRect seams (see scanner.go), so the display
// path can be pinned without a real display and without modifying the host.

// withFakeDisplays temporarily replaces the display seam with the given
// images, one per virtual display, and restores the real functions when the
// test ends.
func withFakeDisplays(t *testing.T, images ...image.Image) {
	t.Helper()

	origNum, origBounds, origCapture := numActiveDisplays, getDisplayBounds, captureRect
	t.Cleanup(func() {
		numActiveDisplays, getDisplayBounds, captureRect = origNum, origBounds, origCapture
	})

	numActiveDisplays = func() int { return len(images) }
	getDisplayBounds = func(i int) image.Rectangle {
		if i < 0 || i >= len(images) {
			return image.Rectangle{}
		}
		return images[i].Bounds()
	}
	captureRect = func(rect image.Rectangle) (*image.RGBA, error) {
		for _, img := range images {
			if img.Bounds() == rect {
				dst := image.NewRGBA(rect)
				for y := rect.Min.Y; y < rect.Max.Y; y++ {
					for x := rect.Min.X; x < rect.Max.X; x++ {
						dst.Set(x, y, img.At(x, y))
					}
				}
				return dst, nil
			}
		}
		return nil, errors.New("withFakeDisplays: no fixture image for rect")
	}
}

// withCaptureFailure replaces the display seam so every capture fails,
// modeling a display that disconnects mid-scan.
func withCaptureFailure(t *testing.T, numDisplays int) {
	t.Helper()

	origNum, origBounds, origCapture := numActiveDisplays, getDisplayBounds, captureRect
	t.Cleanup(func() {
		numActiveDisplays, getDisplayBounds, captureRect = origNum, origBounds, origCapture
	})

	numActiveDisplays = func() int { return numDisplays }
	getDisplayBounds = func(int) image.Rectangle { return image.Rect(0, 0, 200, 200) }
	captureRect = func(image.Rectangle) (*image.RGBA, error) {
		return nil, errors.New("withCaptureFailure: capture failed")
	}
}

func blankImage(size int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	white := color.RGBA{255, 255, 255, 255}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.Set(x, y, white)
		}
	}
	return img
}

// TestScanScreen_NoDisplaysFound pins the refusal when the host reports no
// active displays at all -- the case a headless CI runner hits.
func TestScanScreen_NoDisplaysFound(t *testing.T) {
	withFakeDisplays(t)

	scanner := NewScanner()
	results, err := scanner.ScanScreen(-1)

	assert.ErrorIs(t, err, ErrNoDisplaysFound)
	assert.Nil(t, results)
}

// TestScanScreen_DisplayIndexOutOfRange pins the bounds check on an explicit
// display index.
func TestScanScreen_DisplayIndexOutOfRange(t *testing.T) {
	withFakeDisplays(t, blankImage(100))

	scanner := NewScanner()
	results, err := scanner.ScanScreen(5)

	assert.ErrorIs(t, err, ErrDisplayIndexOutOfRange)
	assert.Nil(t, results)
}

// TestScanScreen_SpecificDisplayFindsQRCode drives the explicit-index path
// (displayIndex >= 0) to a successful scan.
func TestScanScreen_SpecificDisplayFindsQRCode(t *testing.T) {
	uri := "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP"
	qr := generateQRImage(t, uri, 200)
	withFakeDisplays(t, blankImage(100), qr)

	scanner := NewScanner()
	results, err := scanner.ScanScreen(1)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uri, results[0].URI)
	assert.Equal(t, 1, results[0].DisplayIndex)
}

// TestScanScreen_CaptureFailureOnOneDisplayIsSkipped pins that ScanScreen(-1)
// keeps scanning the remaining displays when one display's capture fails,
// rather than aborting the whole sweep.
func TestScanScreen_CaptureFailureOnOneDisplayIsSkipped(t *testing.T) {
	origNum, origBounds, origCapture := numActiveDisplays, getDisplayBounds, captureRect
	t.Cleanup(func() {
		numActiveDisplays, getDisplayBounds, captureRect = origNum, origBounds, origCapture
	})

	uri := "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP"
	qr := generateQRImage(t, uri, 200)
	blank := blankImage(100)

	numActiveDisplays = func() int { return 2 }
	getDisplayBounds = func(i int) image.Rectangle {
		if i == 0 {
			return blank.Bounds()
		}
		return qr.Bounds()
	}
	captureRect = func(rect image.Rectangle) (*image.RGBA, error) {
		if rect == blank.Bounds() {
			return nil, errors.New("display 0 capture failed")
		}
		dst := image.NewRGBA(rect)
		for y := rect.Min.Y; y < rect.Max.Y; y++ {
			for x := rect.Min.X; x < rect.Max.X; x++ {
				dst.Set(x, y, qr.At(x, y))
			}
		}
		return dst, nil
	}

	scanner := NewScanner()
	results, err := scanner.ScanScreen(-1)

	require.NoError(t, err, "a failed display must not abort the sweep of the others")
	require.Len(t, results, 1)
	assert.Equal(t, uri, results[0].URI)
	assert.Equal(t, 1, results[0].DisplayIndex)
}

// TestScanScreen_AllDisplaysCaptureFailureYieldsNoQRCode pins the outer
// refusal when every display's capture fails: the sweep completes with zero
// results rather than surfacing the underlying capture error directly.
func TestScanScreen_AllDisplaysCaptureFailureYieldsNoQRCode(t *testing.T) {
	withCaptureFailure(t, 2)

	scanner := NewScanner()
	results, err := scanner.ScanScreen(-1)

	assert.ErrorIs(t, err, ErrNoQRCodeFound)
	assert.Nil(t, results)
}

// TestScanScreen_SpecificDisplayCaptureFailurePropagates pins that, unlike
// the sweep-all case, a capture failure on an EXPLICITLY requested display
// index is returned directly rather than swallowed.
func TestScanScreen_SpecificDisplayCaptureFailurePropagates(t *testing.T) {
	withCaptureFailure(t, 1)

	scanner := NewScanner()
	results, err := scanner.ScanScreen(0)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScreenCaptureFailed,
		"an explicit display's capture failure must surface as its own error, not the generic not-found")
	assert.Nil(t, results)
}

// TestScanScreen_MultipleQRCodesRefusedByDefault pins that finding QR codes
// on more than one display refuses unless AllowMultiple is set.
func TestScanScreen_MultipleQRCodesRefusedByDefault(t *testing.T) {
	uri1 := "otpauth://totp/One:user@example.com?secret=JBSWY3DPEHPK3PXP"
	uri2 := "otpauth://totp/Two:user@example.com?secret=JBSWY3DPEHPK3PXP"
	withFakeDisplays(t, generateQRImage(t, uri1, 200), generateQRImage(t, uri2, 200))

	scanner := NewScanner()
	results, err := scanner.ScanScreen(-1)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMultipleQRCodesFound)
	assert.Len(t, results, 2, "the caller still gets both results back alongside the refusal")
}

// TestScanScreen_MultipleQRCodesAllowedWhenConfigured is the accept path
// beside the refusal above.
func TestScanScreen_MultipleQRCodesAllowedWhenConfigured(t *testing.T) {
	uri1 := "otpauth://totp/One:user@example.com?secret=JBSWY3DPEHPK3PXP"
	uri2 := "otpauth://totp/Two:user@example.com?secret=JBSWY3DPEHPK3PXP"
	withFakeDisplays(t, generateQRImage(t, uri1, 200), generateQRImage(t, uri2, 200))

	scanner := NewScanner()
	scanner.AllowMultiple = true
	results, err := scanner.ScanScreen(-1)

	require.NoError(t, err)
	assert.Len(t, results, 2)
}

// TestScanAllScreens_DelegatesToScanScreen pins that ScanAllScreens is
// exactly ScanScreen(-1).
func TestScanAllScreens_DelegatesToScanScreen(t *testing.T) {
	uri := "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP"
	withFakeDisplays(t, generateQRImage(t, uri, 200))

	scanner := NewScanner()
	results, err := scanner.ScanAllScreens()

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uri, results[0].URI)
}

// TestNumDisplays_ReflectsTheSeam pins that the exported NumDisplays reads
// through the same seam ScanScreen uses.
func TestNumDisplays_ReflectsTheSeam(t *testing.T) {
	withFakeDisplays(t, blankImage(10), blankImage(10), blankImage(10))

	assert.Equal(t, 3, NumDisplays())
}

// --- package-level convenience functions ---

// TestScanScreenForOTP_Success pins the convenience wrapper's happy path.
func TestScanScreenForOTP_Success(t *testing.T) {
	uri := "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP"
	withFakeDisplays(t, generateQRImage(t, uri, 200))

	got, err := ScanScreenForOTP()

	require.NoError(t, err)
	assert.Equal(t, uri, got)
}

// TestScanScreenForOTP_NoDisplays pins that the convenience wrapper
// surfaces the underlying refusal rather than panicking on results[0].
func TestScanScreenForOTP_NoDisplays(t *testing.T) {
	withFakeDisplays(t)

	got, err := ScanScreenForOTP()

	assert.ErrorIs(t, err, ErrNoDisplaysFound)
	assert.Empty(t, got)
}

// TestScanScreenForPairing_Success pins the pairing convenience wrapper and
// that it sets ScanModePairing on the scanner it builds.
func TestScanScreenForPairing_Success(t *testing.T) {
	uri := "xkey-pair://server.example.com?spki=abc123"
	withFakeDisplays(t, generateQRImage(t, uri, 200))

	got, err := ScanScreenForPairing()

	require.NoError(t, err)
	assert.Equal(t, uri, got)
}

// TestScanScreenForPairing_NoDisplays mirrors the OTP case for the pairing
// wrapper.
func TestScanScreenForPairing_NoDisplays(t *testing.T) {
	withFakeDisplays(t)

	got, err := ScanScreenForPairing()

	assert.ErrorIs(t, err, ErrNoDisplaysFound)
	assert.Empty(t, got)
}

// --- large-image subregion fallback (scanImage) ---

// TestScanImage_LargeImageWithNoQRCodeSearchesEveryQuadrant drives the
// multi-pass fallback scanImage runs for images over 400x400: the full-image
// decode fails, so it falls through to the center crop and all four
// quadrants before giving up. A large BLANK image guarantees every one of
// those five decode attempts genuinely runs (a real decoder cannot find what
// is not there), pinning that the sweep completes and reports "not found"
// rather than looping forever or panicking on any one region.
func TestScanImage_LargeImageWithNoQRCodeSearchesEveryQuadrant(t *testing.T) {
	img := blankImage(800)

	scanner := NewScanner()
	results, err := scanner.ScanImage(img)

	assert.ErrorIs(t, err, ErrNoQRCodeFound)
	assert.Nil(t, results)
}

// TestScanImage_SmallImageSkipsTheSubregionFallback pins the size guard
// directly: at or under 400px on either axis, a failed full-image decode
// returns immediately rather than entering the subregion loop.
func TestScanImage_SmallImageSkipsTheSubregionFallback(t *testing.T) {
	scanner := NewScanner()
	img := blankImage(400)

	results, err := scanner.scanImage(img, -1)

	require.NoError(t, err)
	assert.Nil(t, results, "a <=400px image must skip subregion scanning and report nothing found")
}
