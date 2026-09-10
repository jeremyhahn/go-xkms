### Removed

- The `pkg/acme/server/ratelimit` package. It was a second `TenantRateLimiter` beside the one in `pkg/acme/server` that the ACME server actually wires, and nothing in the tree imported it. (#538)
