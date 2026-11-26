package webauthn

import (
	"context"
	"errors"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

type bindTestKey struct{}

// usernameCtxRecorder records whether GetUserByUsername saw the bound context.
type usernameCtxRecorder struct {
	*fakeUserClient
	sawBound bool
}

func (r *usernameCtxRecorder) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	r.sawBound = ctx.Value(bindTestKey{}) == "bound"
	return r.fakeUserClient.GetUserByUsername(ctx, tenantID, username)
}

func newBoundTestAdapter(t *testing.T, bind CallContext) (UserStore, *usernameCtxRecorder) {
	t.Helper()
	rec := &usernameCtxRecorder{fakeUserClient: newFakeUserClient()}
	us, _, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users: rec, DAOFactory: newTestDAOFactory(), TenantID: "system", CallContext: bind,
	})
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	return us, rec
}

func TestQRDBAdapter_GetByUsernameUsesBoundContext(t *testing.T) {
	us, rec := newBoundTestAdapter(t, func(ctx context.Context) (context.Context, error) {
		return context.WithValue(ctx, bindTestKey{}, "bound"), nil
	})
	ctx := context.Background()
	if _, err := us.Create(ctx, "alice@example.com", "Alice"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := us.GetByUsername(ctx, "alice@example.com"); err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if !rec.sawBound {
		t.Fatal("GetByUsername called the user client without the bound context")
	}
}

func TestQRDBAdapter_GetByUsernameBindError(t *testing.T) {
	errBind := errors.New("no service context")
	us, rec := newBoundTestAdapter(t, func(ctx context.Context) (context.Context, error) {
		return nil, errBind
	})
	_, err := us.GetByUsername(context.Background(), "alice@example.com")
	if !errors.Is(err, errBind) {
		t.Fatalf("GetByUsername err = %v, want bind error", err)
	}
	if rec.sawBound {
		t.Fatal("user client called after a bind failure")
	}
}
