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

package qrscan

import (
	"image"
	"image/draw"
	"strings"

	"github.com/kbinani/screenshot"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// ScanMode controls which QR code URI schemes the scanner accepts.
type ScanMode int

const (
	// ScanModeOTP accepts only otpauth:// URIs (default, backward compatible).
	ScanModeOTP ScanMode = iota

	// ScanModePairing accepts only xkey-pair:// URIs.
	ScanModePairing

	// ScanModeAny accepts any QR code content without filtering.
	ScanModeAny
)

// URI scheme prefixes for each scan mode.
const (
	schemeOTPAuth = "otpauth://"
	schemePairing = "xkey-pair://"
)

// ScanResult contains the result of a QR code scan.
type ScanResult struct {
	// URI is the matched URI extracted from the QR code.
	URI string

	// DisplayIndex is the display where the QR code was found.
	DisplayIndex int

	// RawContent is the raw content of the QR code (before validation).
	RawContent string
}

// Scanner scans screens for QR codes.
type Scanner struct {
	// AllowMultiple permits scanning when multiple QR codes are found.
	// If false, ErrMultipleQRCodesFound is returned when multiple are found.
	AllowMultiple bool

	// Mode controls which URI schemes are accepted. Defaults to ScanModeOTP.
	Mode ScanMode
}

// NewScanner creates a new QR code scanner with default OTP mode.
func NewScanner() *Scanner {
	return &Scanner{}
}

// NumDisplays returns the number of active displays.
func NumDisplays() int {
	return screenshot.NumActiveDisplays()
}

// ScanScreen captures the specified display and scans for QR codes.
// displayIndex is 0-based. Use -1 to scan all displays.
func (s *Scanner) ScanScreen(displayIndex int) ([]*ScanResult, error) {
	n := screenshot.NumActiveDisplays()
	if n == 0 {
		return nil, ErrNoDisplaysFound
	}

	var results []*ScanResult

	if displayIndex >= 0 {
		// Scan specific display
		if displayIndex >= n {
			return nil, ErrDisplayIndexOutOfRange
		}
		found, err := s.scanDisplay(displayIndex)
		if err != nil {
			return nil, err
		}
		results = append(results, found...)
	} else {
		// Scan all displays
		for i := 0; i < n; i++ {
			found, err := s.scanDisplay(i)
			if err != nil {
				// Continue scanning other displays on error
				continue
			}
			results = append(results, found...)
		}
	}

	if len(results) == 0 {
		return nil, ErrNoQRCodeFound
	}

	filtered := s.filterResults(results)

	if len(filtered) == 0 {
		return nil, ErrInvalidQRContent
	}

	if len(filtered) > 1 && !s.AllowMultiple {
		return filtered, ErrMultipleQRCodesFound
	}

	return filtered, nil
}

// ScanAllScreens scans all displays and returns all found QR codes.
func (s *Scanner) ScanAllScreens() ([]*ScanResult, error) {
	return s.ScanScreen(-1)
}

// scanDisplay captures and scans a single display.
func (s *Scanner) scanDisplay(displayIndex int) ([]*ScanResult, error) {
	bounds := screenshot.GetDisplayBounds(displayIndex)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return nil, ErrScreenCaptureFailed
	}

	return s.scanImage(img, displayIndex)
}

// scanImage scans an image for QR codes using a multi-pass strategy.
// It first tries the full image, then falls back to scanning overlapping
// subregions for better detection of small QR codes on large/HiDPI displays.
func (s *Scanner) scanImage(img image.Image, displayIndex int) ([]*ScanResult, error) {
	// Try full image first
	if result := s.decodeQR(img); result != nil {
		return []*ScanResult{{
			RawContent:   result.GetText(),
			DisplayIndex: displayIndex,
		}}, nil
	}

	// Fall back to scanning subregions for small QR codes on large displays.
	// Each region is 60% of total dimensions, giving 20% overlap between
	// adjacent quadrants so QR codes near boundaries aren't split.
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()

	if w <= 400 || h <= 400 {
		return nil, nil
	}

	subW, subH := w*6/10, h*6/10
	regions := []image.Rectangle{
		// Center crop (most likely location for browser-displayed QR codes)
		{
			Min: image.Point{X: bounds.Min.X + (w-subW)/2, Y: bounds.Min.Y + (h-subH)/2},
			Max: image.Point{X: bounds.Min.X + (w+subW)/2, Y: bounds.Min.Y + (h+subH)/2},
		},
		// Top-left quadrant
		{
			Min: bounds.Min,
			Max: image.Point{X: bounds.Min.X + subW, Y: bounds.Min.Y + subH},
		},
		// Top-right quadrant
		{
			Min: image.Point{X: bounds.Max.X - subW, Y: bounds.Min.Y},
			Max: image.Point{X: bounds.Max.X, Y: bounds.Min.Y + subH},
		},
		// Bottom-left quadrant
		{
			Min: image.Point{X: bounds.Min.X, Y: bounds.Max.Y - subH},
			Max: image.Point{X: bounds.Min.X + subW, Y: bounds.Max.Y},
		},
		// Bottom-right quadrant
		{
			Min: image.Point{X: bounds.Max.X - subW, Y: bounds.Max.Y - subH},
			Max: bounds.Max,
		},
	}

	for _, r := range regions {
		subImg := cropImage(img, r)
		if result := s.decodeQR(subImg); result != nil {
			return []*ScanResult{{
				RawContent:   result.GetText(),
				DisplayIndex: displayIndex,
			}}, nil
		}
	}

	return nil, nil
}

// decodeQR attempts to decode a QR code from the given image using
// the TRY_HARDER hint for improved detection of challenging QR codes.
func (s *Scanner) decodeQR(img image.Image) *gozxing.Result {
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return nil
	}

	reader := qrcode.NewQRCodeReader()
	hints := map[gozxing.DecodeHintType]interface{}{
		gozxing.DecodeHintType_TRY_HARDER: true,
	}

	result, err := reader.Decode(bmp, hints)
	if err != nil {
		return nil
	}
	return result
}

// cropImage extracts a subregion from an image.
func cropImage(src image.Image, rect image.Rectangle) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, rect.Dx(), rect.Dy()))
	draw.Draw(dst, dst.Bounds(), src, rect.Min, draw.Src)
	return dst
}

// ScanImage scans an arbitrary image for QR codes.
func (s *Scanner) ScanImage(img image.Image) ([]*ScanResult, error) {
	results, err := s.scanImage(img, -1)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, ErrNoQRCodeFound
	}

	filtered := s.filterResults(results)

	if len(filtered) == 0 {
		return nil, ErrInvalidQRContent
	}

	return filtered, nil
}

// filterResults applies mode-based filtering to scan results.
// Scheme matching is case-insensitive per RFC 3986.
func (s *Scanner) filterResults(results []*ScanResult) []*ScanResult {
	if s.Mode == ScanModeAny {
		for _, r := range results {
			r.URI = r.RawContent
		}
		return results
	}

	prefix := schemeOTPAuth
	if s.Mode == ScanModePairing {
		prefix = schemePairing
	}
	prefixLen := len(prefix)

	var filtered []*ScanResult
	for _, r := range results {
		if len(r.RawContent) >= prefixLen &&
			strings.EqualFold(r.RawContent[:prefixLen], prefix) {
			r.URI = r.RawContent
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// Quick scan functions for convenience.

// ScanScreenForOTP scans all displays and returns the first otpauth:// URI found.
func ScanScreenForOTP() (string, error) {
	scanner := NewScanner()
	results, err := scanner.ScanAllScreens()
	if err != nil {
		return "", err
	}
	return results[0].URI, nil
}

// ScanScreenForPairing scans all displays and returns the first xkey-pair:// URI found.
func ScanScreenForPairing() (string, error) {
	scanner := NewScanner()
	scanner.Mode = ScanModePairing
	results, err := scanner.ScanAllScreens()
	if err != nil {
		return "", err
	}
	return results[0].URI, nil
}
