package xkms

import (
	"context"
	"testing"

	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/require"
)

// The signing-key service is the default signer of a repository's images.
var _ ImageRepositorySigners = (*pkgxkms.XKMSService)(nil)

func TestNewRepositoryImageSigner_RefusesWithoutSigner(t *testing.T) {
	_, err := NewRepositoryImageSigner(context.Background(), nil, "acme/app", &ImageSignerConfig{})
	require.ErrorIs(t, err, ErrImageSignerRequired)
	_, err = NewRepositoryImageSigner(context.Background(), &pkgxkms.XKMSService{}, "", &ImageSignerConfig{})
	require.ErrorIs(t, err, ErrImageRepositoryRequired)
}
