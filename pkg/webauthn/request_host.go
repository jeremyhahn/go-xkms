package webauthn

import "context"

// requestHostKey is the context key of the request host a transport saw.
type requestHostKey struct{}

// ContextWithRequestHost returns ctx carrying the request host, so a service
// layer without the *http.Request can apply TenantRouter.ForRequest.
func ContextWithRequestHost(ctx context.Context, host string) context.Context {
	return context.WithValue(ctx, requestHostKey{}, host)
}

// RequestHostFromContext returns the host set by ContextWithRequestHost, or
// "" when none was set (gRPC and in-process callers).
func RequestHostFromContext(ctx context.Context) string {
	host, _ := ctx.Value(requestHostKey{}).(string)
	return host
}
