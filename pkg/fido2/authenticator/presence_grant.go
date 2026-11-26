package authenticator

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// PresenceOperationSelect is the UserPresenceRequest.Operation of
// authenticatorSelection (CTAP 2.1 §6.9).
const PresenceOperationSelect = "select"

// DefaultAuthenticatorDisplayName names the authenticator in a presence
// prompt when Config.DisplayName is empty.
const DefaultAuthenticatorDisplayName = "xkey"

// SelectionPresenceWindow is how long an approved authenticatorSelection
// satisfies the presence check of the next MakeCredential or GetAssertion
// on the same CTAPHID channel.
//
// CTAP 2.1 has no window for Selection itself; it is taken from the
// pinUvAuthToken state of §6.5.2.1, whose userPresentTimeLimit (default
// 30 seconds) is how long a collected user presence may stand in for the
// presence check of a following command. A browser that picked this
// authenticator by a touch then runs the PIN exchange and the operation
// well inside it, so the user touches once, not touch, PIN, touch.
const SelectionPresenceWindow = 30 * time.Second

// selectionGrant is the presence an approved Selection (or the CTAP 2.0
// selection idiom) leaves behind: bound to one CTAPHID channel, valid until
// expires, consumed once.
type selectionGrant struct {
	channel uint32
	expires time.Time
}

type ctaphidChannelKey struct{}

// WithCTAPHIDChannel returns a context that carries the CTAPHID channel ID a
// command arrived on. The CTAPHID transport sets it; a presence grant from
// authenticatorSelection is bound to it.
func WithCTAPHIDChannel(ctx context.Context, cid uint32) context.Context {
	return context.WithValue(ctx, ctaphidChannelKey{}, cid)
}

// ctaphidChannelFrom returns the CTAPHID channel ID carried by ctx.
func ctaphidChannelFrom(ctx context.Context) (uint32, bool) {
	cid, ok := ctx.Value(ctaphidChannelKey{}).(uint32)
	return cid, ok
}

func (a *Authenticator) grantNow() time.Time {
	if a.grantClock != nil {
		return a.grantClock()
	}
	return time.Now()
}

// grantPresence records an approved selection for the channel of ctx. A
// command without a CTAPHID channel leaves no grant.
func (a *Authenticator) grantPresence(ctx context.Context) bool {
	cid, ok := ctaphidChannelFrom(ctx)
	a.grantMu.Lock()
	defer a.grantMu.Unlock()
	// Checked under grantMu so a CANCEL's revoke cannot run before this grant.
	if ctx.Err() != nil {
		a.presenceGrant = nil
		return false
	}
	if !ok {
		a.presenceGrant = nil
		return true
	}
	a.presenceGrant = &selectionGrant{channel: cid, expires: a.grantNow().Add(SelectionPresenceWindow)}
	return true
}

func (a *Authenticator) clearPresenceGrant() {
	a.grantMu.Lock()
	a.presenceGrant = nil
	a.grantMu.Unlock()
}

// revokePresenceGrantForChannel drops the grant when it is bound to cid.
// The CTAPHID transport calls it when a command on cid ends without
// reaching the authenticator (CTAPHID_CANCEL, or a deferred GetAssertion
// that ends by cancel or safety timeout), so the grant cannot outlive the
// ceremony it was given for and skip presence on a later operation.
func (a *Authenticator) revokePresenceGrantForChannel(cid uint32) {
	a.grantMu.Lock()
	defer a.grantMu.Unlock()
	if a.presenceGrant != nil && a.presenceGrant.channel == cid {
		a.presenceGrant = nil
	}
}

// consumePresenceGrant reports whether a live grant exists for the channel of
// ctx, and removes any grant it finds: a grant is used at most once.
func (a *Authenticator) consumePresenceGrant(ctx context.Context) bool {
	a.grantMu.Lock()
	defer a.grantMu.Unlock()
	g := a.presenceGrant
	if g == nil {
		return false
	}
	a.presenceGrant = nil
	cid, ok := ctaphidChannelFrom(ctx)
	return ok && cid == g.channel && a.grantNow().Before(g.expires)
}

// dropForeignPresenceGrant clears the grant when a command arrives from any
// channel but the one it is bound to, or arrives without a channel.
func (a *Authenticator) dropForeignPresenceGrant(ctx context.Context) {
	a.grantMu.Lock()
	defer a.grantMu.Unlock()
	if a.presenceGrant == nil {
		return
	}
	if cid, ok := ctaphidChannelFrom(ctx); !ok || cid != a.presenceGrant.channel {
		a.presenceGrant = nil
	}
}

// presenceEndsGrant reports whether a command error ended a presence wait
// (host cancel or timeout), which clears any grant.
func presenceEndsGrant(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrUserPresenceTimeout)
}

// grantableOperation reports whether a presence check of this operation may
// be satisfied by a Selection grant: only the credential operations a
// browser runs after choosing an authenticator, never reset or token init.
func grantableOperation(operation string) bool {
	return operation == "register" || operation == "authenticate"
}

func (a *Authenticator) displayName() string {
	if a.config != nil && a.config.DisplayName != "" {
		return a.config.DisplayName
	}
	return DefaultAuthenticatorDisplayName
}

// waitForSelectionPresence asks for user presence for a selection (Selection
// itself or the CTAP 2.0 zero-length pinUvAuthParam idiom) and maps the
// outcome to the CTAP 2.1 §6.9 errors: a decline is ErrUserPresenceDenied
// (CTAP2_ERR_OPERATION_DENIED), no answer within UserPresenceTimeout is
// ErrUserPresenceTimeout (CTAP2_ERR_USER_ACTION_TIMEOUT), and CTAPHID_CANCEL
// is context.Canceled (CTAP2_ERR_KEEPALIVE_CANCEL). Approval grants presence
// to the next credential operation on the same channel.
func (a *Authenticator) waitForSelectionPresence(ctx context.Context, rpID, rpName, userName, operation string) error {
	a.clearPresenceGrant()

	waitCtx := ctx
	if a.config.UserPresenceTimeout > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, a.config.UserPresenceTimeout)
		defer cancel()
	}

	err := a.askUserPresence(waitCtx, rpID, rpName, userName, operation)
	switch {
	case err == nil:
		if !a.grantPresence(ctx) {
			return context.Canceled
		}
		return nil
	case ctx.Err() != nil:
		// The host cancelled the command (CTAPHID_CANCEL).
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return ErrUserPresenceTimeout
	case errors.Is(err, ErrUserPresenceRequired):
		return ErrUserPresenceDenied
	default:
		return err
	}
}

// handleEmptyPinUvAuthParam answers the CTAP 2.0 selection idiom: a
// MakeCredential with a zero-length pinUvAuthParam (CTAP 2.1 §6.1.2 step 1).
// It waits for user presence first, then returns CTAP2_ERR_PIN_INVALID when
// a PIN is set and CTAP2_ERR_PIN_NOT_SET when not; it never succeeds and
// never returns a PIN error before the touch.
func (a *Authenticator) handleEmptyPinUvAuthParam(rpID, rpName, userName string) error {
	if a.logger != nil {
		a.logger.Info("MakeCredential zero-length pinUvAuthParam: waiting for selection presence",
			slog.String("rp", rpID))
	}
	if err := a.waitForSelectionPresence(a.commandContext(), rpID, rpName, userName, "register"); err != nil {
		return err
	}
	if a.IsPINSet() {
		return ErrPINInvalid
	}
	return ErrPINNotSet
}
