// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

/*
Package admin provides a REST API for administrative operations on the ACME CA.

The admin API is separate from the ACME API and provides management capabilities
for certificates, accounts, orders, and CA monitoring.

# Authentication

All admin API endpoints require authentication using API keys passed in the
Authorization header:

	Authorization: Bearer <api-key>

# Authorization

The admin API supports role-based access control with three roles:

  - admin: Full access to all operations including revocation and account deletion
  - operator: Read and write access, cannot perform destructive operations
  - viewer: Read-only access to all resources

# Endpoints

Certificate Management:

	GET  /admin/certificates              - List all certificates (paginated)
	GET  /admin/certificates/{serial}     - Get certificate details by serial number
	POST /admin/certificates/{serial}/revoke - Revoke a certificate (admin only)
	GET  /admin/certificates/expiring     - List certificates expiring soon

Account Management:

	GET    /admin/accounts           - List all ACME accounts
	GET    /admin/accounts/{id}      - Get account details
	DELETE /admin/accounts/{id}      - Disable an account (admin only)

Order Management:

	GET /admin/orders                - List all orders (with filters)
	GET /admin/orders/{id}           - Get order details

CA Status and Statistics:

	GET /admin/status                - Get CA status and configuration
	GET /admin/stats                 - Get certificate and account statistics

# Response Format

All endpoints return JSON responses in a consistent format:

Success response:

	{
	  "success": true,
	  "data": {...},
	  "pagination": {
	    "page": 1,
	    "per_page": 20,
	    "total": 100
	  }
	}

Error response:

	{
	  "success": false,
	  "error": {
	    "code": "NOT_FOUND",
	    "message": "Certificate not found"
	  }
	}

# Pagination

List endpoints support pagination via query parameters:

  - page: Page number (default: 1)
  - per_page: Results per page (default: 20, max: 100)

# Filtering

List endpoints support various filters via query parameters:

Certificates:

  - status: Filter by certificate status (valid, revoked, expired)
  - subject: Filter by subject common name
  - expires_days: Filter certificates expiring within N days

Accounts:

  - status: Filter by account status (valid, deactivated, revoked)

Orders:

  - account_id: Filter by account ID
  - status: Filter by order status (pending, processing, valid, invalid)

# Example Usage

List all certificates:

	curl -H "Authorization: Bearer admin-key" \
	  https://ca.example.com/admin/certificates?page=1&per_page=20

Get certificate by serial number:

	curl -H "Authorization: Bearer viewer-key" \
	  https://ca.example.com/admin/certificates/123456789

Revoke a certificate:

	curl -X POST \
	  -H "Authorization: Bearer admin-key" \
	  -H "Content-Type: application/json" \
	  -d '{"reason":"keyCompromise"}' \
	  https://ca.example.com/admin/certificates/123456789/revoke

Get CA statistics:

	curl -H "Authorization: Bearer viewer-key" \
	  https://ca.example.com/admin/stats

# Configuration

The admin API is configured via the Config struct:

	config := &admin.Config{
	    Enabled:    true,
	    ListenAddr: ":8081",
	    TLSEnabled: true,
	    TLSCert:    "/path/to/cert.pem",
	    TLSKey:     "/path/to/key.pem",
	}

Authentication is handled via JWT tokens. The admin API validates
tokens against the Auth service and extracts role information
from the token claims.

# Security Considerations

  - Always use TLS in production to protect API keys in transit
  - Rotate API keys regularly
  - Use separate keys for different applications and users
  - Set appropriate expiration times for API keys
  - Monitor API access logs for suspicious activity
  - Grant minimum required privileges (principle of least privilege)
*/
package admin
