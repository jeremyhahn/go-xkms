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

package rest

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestCopyKeyHandler_RefusedPairIs4xx: a source backend that cannot wrap its
// keys for a foreign destination (tpm2 -> software: TPM keys are
// hardware-bound) refuses the copy. That is the key's policy, not a server
// fault, so REST answers 403 with the refusal's message instead of a bare 500.
func TestCopyKeyHandler_RefusedPairIs4xx(t *testing.T) {
	srcKs := newMockKeyStoreWithImportExport()
	dstKs := newMockKeyStoreWithImportExport()

	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"src-backend": srcKs,
			"dst-backend": dstKs,
		},
		DefaultBackend: "src-backend",
	}))
	t.Cleanup(xkms.Reset)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	srcKs.backend.SetKey("source-key", key)
	srcKs.backend.ExportKeyToFunc = func(attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
		return nil, &errs.Detail{Err: backend.ErrExportToUnsupported, Detail: "TPM2 keys are hardware-bound"}
	}

	body := `{"source_backend":"src-backend","source_key_id":"source-key","dest_backend":"dst-backend","dest_key_id":"dest-key","algorithm":"RSAES_OAEP_SHA_256"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
	w := httptest.NewRecorder()
	newTestHandlerContext().CopyKeyHandler(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "hardware-bound")
}

// TestMapKeyOpError_UnsupportedCopyPair: an algorithm the source cannot wrap
// under is a fault in the request (400), and a refused re-wrap is 403.
func TestMapKeyOpError_UnsupportedCopyPair(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"export-to refused": {&xkms.ErrKeyOperation{Operation: "export key", Err: backend.ErrExportToUnsupported}, http.StatusForbidden},
		"invalid algorithm": {&xkms.ErrKeyOperation{Operation: "export key", Err: backend.ErrInvalidAlgorithm}, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mapKeyOpError(w, tc.err)
			assert.Equal(t, tc.want, w.Code)
		})
	}
}

// TestMapCAError_DuplicateCertificateIs409: issuing a certificate whose
// serial or subject already exists is a conflict with existing state.
func TestMapCAError_DuplicateCertificateIs409(t *testing.T) {
	err := &errs.Wrapped{Msg: "issue certificate", Err: ca.ErrCertificateAlreadyExists}
	assert.Equal(t, http.StatusConflict, mapCAError(err))
}
