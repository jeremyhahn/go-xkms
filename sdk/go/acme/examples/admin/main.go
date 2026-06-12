// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Example admin demonstrates using the Trusted CA SDK admin client to manage
// tenants, retrieve CA status, and list resources.
package main

import (
	"context"
	"fmt"
	"log"

	trustedca "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
)

func main() {
	// Connect to the CA admin server via REST.
	client, err := trustedca.NewClient("https://localhost:9443",
		trustedca.WithREST(),
		trustedca.WithInsecure(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()

	// Retrieve the CA status.
	status, err := client.Admin().Status().Status(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("CA Identity: %s\n", status.Identity)
	fmt.Printf("Initialized: %v\n", status.Initialized)

	// Create a tenant.
	tenant, err := client.Admin().Tenant().Create(ctx, &admin.CreateTenantRequest{
		ID:   "example-tenant",
		Name: "Example Corp",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created tenant: %s (%s)\n", tenant.Name, tenant.ID)

	// List tenants.
	resp, err := client.Admin().Tenant().List(ctx, &admin.ListTenantsRequest{
		Page:    1,
		PerPage: 10,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Total tenants: %d\n", len(resp.Tenants))

	// Clean up the example tenant.
	if err := client.Admin().Tenant().Delete(ctx, "example-tenant"); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Tenant deleted successfully")
}
