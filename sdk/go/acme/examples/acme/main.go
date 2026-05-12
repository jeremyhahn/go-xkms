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

// Example acme demonstrates the ACME workflow for account registration and
// certificate issuance using the Trusted CA SDK.
package main

import (
	"context"
	"fmt"
	"log"

	trustedca "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/workflow"
)

func main() {
	// Connect to the ACME server via REST.
	client, err := trustedca.NewClient("https://localhost:8443",
		trustedca.WithREST(),
		trustedca.WithInsecure(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()
	wf := client.Workflow()

	// Register an ACME account.
	reg, err := wf.Register(ctx, &workflow.RegisterRequest{
		Email:                "admin@example.com",
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Account registered: %s (status: %s)\n", reg.AccountURL, reg.Status)

	// To request a certificate, provide a CSR and a challenge handler:
	//
	//   cert, err := wf.RequestCertificate(ctx, &workflow.CertificateRequest{
	//       Domains:          []string{"example.com"},
	//       CSR:              csrDER,
	//       ChallengeType:    "http-01",
	//       ChallengeHandler: myHandler,
	//       AccountURL:       reg.AccountURL,
	//   })
	//
	// The ChallengeHandler interface requires a Setup method that provisions the
	// challenge response (e.g., HTTP server, DNS record) and returns a cleanup
	// function. See the workflow.ChallengeHandlerFunc adapter for using a plain
	// function.

	fmt.Println("See workflow package documentation for the full certificate request flow")
}
