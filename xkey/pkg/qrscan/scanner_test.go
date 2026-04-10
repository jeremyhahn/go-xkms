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
	"image/color"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateQRImage creates a QR code image from the given content.
func generateQRImage(t *testing.T, content string, size int) image.Image {
	t.Helper()

	writer := qrcode.NewQRCodeWriter()
	hints := make(map[gozxing.EncodeHintType]interface{})
	hints[gozxing.EncodeHintType_MARGIN] = 1

	matrix, err := writer.Encode(content, gozxing.BarcodeFormat_QR_CODE, size, size, hints)
	require.NoError(t, err)

	// Convert BitMatrix to image
	width := matrix.GetWidth()
	height := matrix.GetHeight()
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	white := color.RGBA{255, 255, 255, 255}
	black := color.RGBA{0, 0, 0, 255}

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			if matrix.Get(x, y) {
				img.Set(x, y, black)
			} else {
				img.Set(x, y, white)
			}
		}
	}

	return img
}

func TestScanner_ScanImage_ValidOTPAuthURI(t *testing.T) {
	uri := "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
	img := generateQRImage(t, uri, 200)

	scanner := NewScanner()
	results, err := scanner.ScanImage(img)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uri, results[0].URI)
}

func TestScanner_ScanImage_InvalidContent(t *testing.T) {
	// QR code with non-otpauth content
	img := generateQRImage(t, "https://example.com", 200)

	scanner := NewScanner()
	results, err := scanner.ScanImage(img)

	assert.ErrorIs(t, err, ErrInvalidQRContent)
	assert.Nil(t, results)
}

func TestScanner_ScanImage_NoQRCode(t *testing.T) {
	// Create a blank white image
	img := image.NewRGBA(image.Rect(0, 0, 200, 200))
	white := color.RGBA{255, 255, 255, 255}
	for y := 0; y < 200; y++ {
		for x := 0; x < 200; x++ {
			img.Set(x, y, white)
		}
	}

	scanner := NewScanner()
	results, err := scanner.ScanImage(img)

	assert.ErrorIs(t, err, ErrNoQRCodeFound)
	assert.Nil(t, results)
}

func TestScanner_ScanImage_HOTPUri(t *testing.T) {
	uri := "otpauth://hotp/TestService:testuser?secret=GEZDGNBVGY3TQOJQ&counter=0&issuer=TestService"
	img := generateQRImage(t, uri, 200)

	scanner := NewScanner()
	results, err := scanner.ScanImage(img)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uri, results[0].URI)
	assert.Contains(t, results[0].URI, "hotp")
}

func TestScanner_ScanImage_SHA256Algorithm(t *testing.T) {
	uri := "otpauth://totp/AWS:admin?secret=JBSWY3DPEHPK3PXP&issuer=AWS&algorithm=SHA256&digits=8"
	img := generateQRImage(t, uri, 200)

	scanner := NewScanner()
	results, err := scanner.ScanImage(img)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uri, results[0].URI)
	assert.Contains(t, results[0].URI, "SHA256")
}

func TestScanner_ScanImage_UppercaseSchemeAccepted(t *testing.T) {
	// RFC 3986: scheme matching is case-insensitive.
	uri := "OTPAUTH://totp/Test:user?secret=JBSWY3DPEHPK3PXP"
	img := generateQRImage(t, uri, 200)

	scanner := NewScanner()
	results, err := scanner.ScanImage(img)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uri, results[0].URI)
}

func TestNewScanner(t *testing.T) {
	scanner := NewScanner()
	assert.NotNil(t, scanner)
	assert.False(t, scanner.AllowMultiple)
	assert.Equal(t, ScanModeOTP, scanner.Mode)
}

func TestNumDisplays(t *testing.T) {
	// Just ensure it doesn't panic and returns a non-negative value
	n := NumDisplays()
	assert.GreaterOrEqual(t, n, 0)
}

func TestScanner_AllowMultiple(t *testing.T) {
	scanner := NewScanner()
	scanner.AllowMultiple = true
	assert.True(t, scanner.AllowMultiple)
}

// Test error types.
func TestErrors(t *testing.T) {
	assert.NotNil(t, ErrNoQRCodeFound)
	assert.NotNil(t, ErrInvalidQRContent)
	assert.NotNil(t, ErrScreenCaptureUnavailable)
	assert.NotNil(t, ErrNoDisplaysFound)
	assert.NotNil(t, ErrMultipleQRCodesFound)
	assert.NotNil(t, ErrScanCancelled)
	assert.NotNil(t, ErrDisplayIndexOutOfRange)
	assert.NotNil(t, ErrScreenCaptureFailed)
	assert.NotNil(t, ErrBitmapCreationFailed)

	// Verify error messages
	assert.Contains(t, ErrNoQRCodeFound.Error(), "no QR code")
	assert.Contains(t, ErrInvalidQRContent.Error(), "scan mode")
	assert.Contains(t, ErrDisplayIndexOutOfRange.Error(), "display index")
	assert.Contains(t, ErrScreenCaptureFailed.Error(), "screen capture")
	assert.Contains(t, ErrBitmapCreationFailed.Error(), "bitmap")
}

// Pairing mode tests.

func TestScanner_ScanImage_PairingMode_ValidURI(t *testing.T) {
	uri := "xkey-pair://server.example.com?spki=abc123&nonce=xyz789"
	img := generateQRImage(t, uri, 200)

	scanner := NewScanner()
	scanner.Mode = ScanModePairing
	results, err := scanner.ScanImage(img)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uri, results[0].URI)
	assert.Equal(t, uri, results[0].RawContent)
}

func TestScanner_ScanImage_PairingMode_RejectsOTPAuth(t *testing.T) {
	uri := "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP"
	img := generateQRImage(t, uri, 200)

	scanner := NewScanner()
	scanner.Mode = ScanModePairing
	results, err := scanner.ScanImage(img)

	assert.ErrorIs(t, err, ErrInvalidQRContent)
	assert.Nil(t, results)
}

func TestScanner_ScanImage_PairingMode_UppercaseSchemeAccepted(t *testing.T) {
	// RFC 3986: scheme matching is case-insensitive.
	uri := "XKEY-PAIR://server.example.com?spki=abc123"
	img := generateQRImage(t, uri, 200)

	scanner := NewScanner()
	scanner.Mode = ScanModePairing
	results, err := scanner.ScanImage(img)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uri, results[0].URI)
}

func TestScanner_ScanImage_PairingMode_InvalidContent(t *testing.T) {
	img := generateQRImage(t, "https://example.com", 200)

	scanner := NewScanner()
	scanner.Mode = ScanModePairing
	results, err := scanner.ScanImage(img)

	assert.ErrorIs(t, err, ErrInvalidQRContent)
	assert.Nil(t, results)
}

// Any mode tests.

func TestScanner_ScanImage_AnyMode_AcceptsOTPAuth(t *testing.T) {
	uri := "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP"
	img := generateQRImage(t, uri, 200)

	scanner := NewScanner()
	scanner.Mode = ScanModeAny
	results, err := scanner.ScanImage(img)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uri, results[0].URI)
}

func TestScanner_ScanImage_AnyMode_AcceptsPairing(t *testing.T) {
	uri := "xkey-pair://server.example.com?spki=abc123"
	img := generateQRImage(t, uri, 200)

	scanner := NewScanner()
	scanner.Mode = ScanModeAny
	results, err := scanner.ScanImage(img)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uri, results[0].URI)
}

func TestScanner_ScanImage_AnyMode_AcceptsArbitraryContent(t *testing.T) {
	content := "https://example.com/some-page"
	img := generateQRImage(t, content, 200)

	scanner := NewScanner()
	scanner.Mode = ScanModeAny
	results, err := scanner.ScanImage(img)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, content, results[0].URI)
	assert.Equal(t, content, results[0].RawContent)
}

// Default mode backward compatibility test.

func TestScanner_ScanImage_DefaultMode_RejectsPairing(t *testing.T) {
	uri := "xkey-pair://server.example.com?spki=abc123"
	img := generateQRImage(t, uri, 200)

	scanner := NewScanner()
	// Default mode is ScanModeOTP, should reject xkey-pair://
	results, err := scanner.ScanImage(img)

	assert.ErrorIs(t, err, ErrInvalidQRContent)
	assert.Nil(t, results)
}

// ScanMode zero value test.

func TestScanMode_ZeroValue(t *testing.T) {
	var mode ScanMode
	assert.Equal(t, ScanModeOTP, mode)
}

// Mixed case scheme tests (RFC 3986 compliance).

func TestScanner_ScanImage_MixedCaseScheme(t *testing.T) {
	uri := "OtpAuth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&issuer=Test"
	img := generateQRImage(t, uri, 200)

	scanner := NewScanner()
	results, err := scanner.ScanImage(img)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uri, results[0].URI)
}

func TestScanner_ScanImage_MixedCasePairingScheme(t *testing.T) {
	uri := "Xkey-Pair://server.example.com?spki=abc123&nonce=xyz789"
	img := generateQRImage(t, uri, 200)

	scanner := NewScanner()
	scanner.Mode = ScanModePairing
	results, err := scanner.ScanImage(img)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uri, results[0].URI)
}

// cropImage tests.

func TestCropImage(t *testing.T) {
	// Create a 100x100 image with known pixel values.
	src := image.NewRGBA(image.Rect(0, 0, 100, 100))
	red := color.RGBA{255, 0, 0, 255}
	blue := color.RGBA{0, 0, 255, 255}

	// Fill the entire image red, then paint a blue block at (25,25)-(75,75).
	for y := 0; y < 100; y++ {
		for x := 0; x < 100; x++ {
			src.Set(x, y, red)
		}
	}
	for y := 25; y < 75; y++ {
		for x := 25; x < 75; x++ {
			src.Set(x, y, blue)
		}
	}

	// Crop the blue region.
	cropped := cropImage(src, image.Rect(25, 25, 75, 75))

	assert.Equal(t, 50, cropped.Bounds().Dx())
	assert.Equal(t, 50, cropped.Bounds().Dy())

	// Every pixel in the cropped image should be blue.
	for y := 0; y < 50; y++ {
		for x := 0; x < 50; x++ {
			r, g, b, a := cropped.At(x, y).RGBA()
			assert.Equal(t, uint32(0), r>>8, "red channel at (%d,%d)", x, y)
			assert.Equal(t, uint32(0), g>>8, "green channel at (%d,%d)", x, y)
			assert.Equal(t, uint32(255), b>>8, "blue channel at (%d,%d)", x, y)
			assert.Equal(t, uint32(255), a>>8, "alpha channel at (%d,%d)", x, y)
		}
	}
}

// decodeQR tests.

func TestScanner_DecodeQR(t *testing.T) {
	content := "otpauth://totp/DecodeTest:user?secret=JBSWY3DPEHPK3PXP"
	img := generateQRImage(t, content, 200)

	scanner := NewScanner()
	result := scanner.decodeQR(img)

	require.NotNil(t, result)
	assert.Equal(t, content, result.GetText())
}

func TestScanner_DecodeQR_BlankImage(t *testing.T) {
	// A blank white image has no QR code to decode.
	img := image.NewRGBA(image.Rect(0, 0, 200, 200))
	white := color.RGBA{255, 255, 255, 255}
	for y := 0; y < 200; y++ {
		for x := 0; x < 200; x++ {
			img.Set(x, y, white)
		}
	}

	scanner := NewScanner()
	result := scanner.decodeQR(img)

	assert.Nil(t, result)
}
