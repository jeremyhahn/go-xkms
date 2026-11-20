package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestWriteInviteError_TenantNotServedIsForbidden: invitation enrolment
// outside the relying party's tenant (ruling 1029 B) is a 403, not a 500.
func TestWriteInviteError_TenantNotServedIsForbidden(t *testing.T) {
	w := httptest.NewRecorder()
	writeInviteError(w, xkms.ErrInviteTenantNotServed)
	require.Equal(t, http.StatusForbidden, w.Code)
}
