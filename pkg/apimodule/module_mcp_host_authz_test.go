package apimodule

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TestModule_HostMount_MCPFirstCallWiresServiceAuthorizer: an MCP tool call
// that reaches the module before any gRPC or REST call still runs the
// self-built service's authorization setup, so decisions made below the
// transport gate (users:invite on CreateUser) are not allowed by a nil
// authorizer.
func TestModule_HostMount_MCPFirstCallWiresServiceAuthorizer(t *testing.T) {
	client := newHostNodeClient(t)
	var backend *xkmsmcp.Server
	h := mountLikeHost(t, client, WithMCPServer(func() *xkmsmcp.Server { return backend }))
	srv, err := xkmsmcp.NewServer(&xkmsmcp.Config{
		XKMSService:   h.svc,
		Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)
	backend = srv
	h.svc.SetUserClients(client.Users(), client.Roles())
	require.Nil(t, h.svc.Authorizer(), "nothing has wired an authorizer yet")

	spec := xkmsmcp.MethodSpec{Method: "health", Tool: xkmsmcp.ToolName("health")}
	_, err = h.module.mcpToolHandler(spec)(context.Background(), toolCallRequest(""))
	require.NoError(t, err)
	require.NotNil(t, h.svc.Authorizer(), "the MCP path wires the service authorizer")
}
