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

package embedded

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// otaImageService validates the board id the way XKMSService does, so the
// embedded transport is seen to hand the service's typed error back as is.
type otaImageService struct {
	mockService
}

func (s *otaImageService) CreateOTAImageKey(ctx context.Context, req *transport.OTAImageKeyRequest) (*transport.GenerateKeyResponse, error) {
	if _, err := xkms.OTAImageKeyID(req.BoardID); err != nil {
		return nil, err
	}
	return s.mockService.CreateOTAImageKey(ctx, req)
}

func (s *otaImageService) RotateOTAImageKey(ctx context.Context, req *transport.OTAImageKeyRequest) (*transport.RotateKeyResponse, error) {
	if _, err := xkms.OTAImageKeyID(req.BoardID); err != nil {
		return nil, err
	}
	return s.mockService.RotateOTAImageKey(ctx, req)
}

func (s *otaImageService) SignOTAImage(ctx context.Context, req *transport.OTAImageSignRequest) (*transport.SignResponse, error) {
	if _, err := xkms.OTAImageKeyID(req.BoardID); err != nil {
		return nil, err
	}
	return s.mockService.SignOTAImage(ctx, req)
}

func newOTAImageTransport(t *testing.T) *Transport {
	t.Helper()
	tr, err := New(&otaImageService{})
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	t.Cleanup(func() { assert.NoError(t, tr.Close()) })
	return tr
}

func TestOTAImageKey_Embedded(t *testing.T) {
	tr := newOTAImageTransport(t)
	ctx := context.Background()

	created, err := tr.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4"})
	require.NoError(t, err)
	assert.Equal(t, "ota-image-cm4", created.KeyID)

	rotated, err := tr.RotateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4"})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), rotated.KeyVersion)

	signed, err := tr.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: []byte("image")})
	require.NoError(t, err)
	assert.Equal(t, []byte("sig"), signed.Signature)
	assert.Equal(t, uint32(2), signed.KeyVersion)
}

func TestOTAImageKey_Embedded_InvalidBoard(t *testing.T) {
	tr := newOTAImageTransport(t)
	ctx := context.Background()
	const badBoard = "Bad--Board"

	_, err := tr.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: badBoard})
	assert.ErrorIs(t, err, xkms.ErrInvalidBoardID)
	_, err = tr.RotateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: badBoard})
	assert.ErrorIs(t, err, xkms.ErrInvalidBoardID)
	_, err = tr.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: badBoard, Data: []byte("image")})
	assert.ErrorIs(t, err, xkms.ErrInvalidBoardID)
}

func TestOTAImageKey_Embedded_NotConnected(t *testing.T) {
	tr, err := New(&otaImageService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	ctx := context.Background()

	_, err = tr.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{BoardID: "cm4"})
	assert.ErrorIs(t, err, ErrNotConnected)
	_, err = tr.RotateOTAImageKey(ctx, &transport.OTAImageKeyRequest{BoardID: "cm4"})
	assert.ErrorIs(t, err, ErrNotConnected)
	_, err = tr.SignOTAImage(ctx, &transport.OTAImageSignRequest{BoardID: "cm4"})
	assert.ErrorIs(t, err, ErrNotConnected)
}
