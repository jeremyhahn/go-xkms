# ACME Server Handlers

This directory contains the HTTP handlers for the ACME (Automatic Certificate Management Environment) server implementation per RFC 8555.

## Status

**Extraction: Complete (15/15 files)**
**Compilation: 85% (needs minor fixes)**
**Testing: Not Started**

## Files

### Core Service
- `service.go` - Core service infrastructure and helper functions

### RFC 8555 Compliant Handlers
- `directory.go` - ACME directory endpoint
- `new_nonce.go` - Nonce generation
- `new_account.go` - Account registration
- `account.go` - Account retrieval and modification
- `new_order.go` - Order creation
- `handler_order.go` - Order retrieval
- `order_finalize.go` - Order finalization with CSR
- `orders_list.go` - Orders listing
- `authorization.go` - Authorization status
- `challenge.go` - Challenge validation
- `certificate.go` - Certificate download
- `revoke_cert.go` - Certificate revocation
- `key_change.go` - Account key rollover

### Non-RFC Handlers
- `ca_bundle.go` - CA bundle download (optional)

## Documentation

- `EXTRACTION_SUMMARY.md` - Detailed extraction summary
- `COMPILATION_FIXES_NEEDED.md` - Specific fixes needed for compilation
- `README.md` - This file

## Next Steps

1. Fix remaining compilation errors (see COMPILATION_FIXES_NEEDED.md)
2. Create comprehensive unit tests
3. Integrate with ACME server router
4. End-to-end testing

## Dependencies

- `github.com/go-jose/go-jose/v4` - JOSE/JWS implementation
- `github.com/gorilla/mux` - HTTP router for URL parameters
- `github.com/peterhellberg/link` - Link header parsing
- `github.com/jeremyhahn/go-xkms` - Key encoding/decoding
- `github.com/jeremyhahn/go-trusted-ca/pkg/acme/common` - ACME common utilities
- `github.com/jeremyhahn/go-trusted-ca/pkg/acme/entities` - ACME domain models
- `github.com/jeremyhahn/go-trusted-ca/pkg/acme/storage` - DAO interfaces
- `github.com/jeremyhahn/go-trusted-ca/pkg/ca` - Certificate Authority interface

## Testing

No tests currently exist. Test coverage target: 90%+

See testing requirements in `/pkg/acme/server/EXTRACTION_ROADMAP.md`
