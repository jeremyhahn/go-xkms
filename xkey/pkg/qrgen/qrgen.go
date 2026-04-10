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

package qrgen

import (
	"bytes"
	"errors"
	"image"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/makiuchi-d/gozxing/qrcode/decoder"
	qrterminal "github.com/mdp/qrterminal/v3"
)

const (
	// defaultQRSize is the default QR code image dimension in pixels.
	defaultQRSize = 256
)

// QR generation errors.
var (
	// ErrQRGenerationFailed indicates QR code generation failed.
	ErrQRGenerationFailed = errors.New("qrgen: QR code generation failed")
)

// qrEncodeHints returns the default encoding hints for QR generation.
func qrEncodeHints() map[gozxing.EncodeHintType]interface{} {
	return map[gozxing.EncodeHintType]interface{}{
		gozxing.EncodeHintType_CHARACTER_SET:    "UTF-8",
		gozxing.EncodeHintType_ERROR_CORRECTION: decoder.ErrorCorrectionLevel_M,
		gozxing.EncodeHintType_MARGIN:           1,
	}
}

// GenerateQR generates a QR code image from a PairingPayload.
// The payload is first converted to an xkey-pair:// URI, then encoded
// as a QR code image with default dimensions (256x256).
func GenerateQR(payload *PairingPayload) (image.Image, error) {
	if payload == nil {
		return nil, ErrInvalidPayload
	}

	uri, err := ToURI(payload)
	if err != nil {
		return nil, err
	}

	return GenerateQRFromString(uri, defaultQRSize)
}

// GenerateTerminalQR generates an ASCII art QR code string from a PairingPayload.
// The payload is first converted to an xkey-pair:// URI, then rendered as
// half-block Unicode characters suitable for terminal display.
func GenerateTerminalQR(payload *PairingPayload) (string, error) {
	if payload == nil {
		return "", ErrInvalidPayload
	}

	uri, err := ToURI(payload)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	config := qrterminal.Config{
		Level:          qrterminal.M,
		Writer:         &buf,
		HalfBlocks:     true,
		BlackChar:      qrterminal.BLACK_BLACK,
		WhiteBlackChar: qrterminal.WHITE_BLACK,
		WhiteChar:      qrterminal.WHITE_WHITE,
		BlackWhiteChar: qrterminal.BLACK_WHITE,
		QuietZone:      1,
	}
	qrterminal.GenerateWithConfig(uri, config)

	result := buf.String()
	if result == "" {
		return "", ErrQRGenerationFailed
	}

	return result, nil
}

// GenerateQRFromString generates a QR code image from an arbitrary string.
// The size parameter controls both width and height in pixels.
func GenerateQRFromString(content string, size int) (image.Image, error) {
	if content == "" {
		return nil, ErrQRGenerationFailed
	}
	if size <= 0 {
		return nil, ErrQRGenerationFailed
	}

	writer := qrcode.NewQRCodeWriter()
	matrix, err := writer.Encode(content, gozxing.BarcodeFormat_QR_CODE, size, size, qrEncodeHints())
	if err != nil {
		return nil, ErrQRGenerationFailed
	}

	// gozxing's BitMatrix implements image.Image directly.
	return matrix, nil
}
