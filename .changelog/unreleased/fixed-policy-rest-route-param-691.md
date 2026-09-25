- **Every named-policy REST route answered 400 for every real request.**
  `pkg/api/rest/routes.go` registered `GET/DELETE /api/v1/policies/{id}`
  and the `/refresh`, `/verify`, `/export` sub-routes with an `{id}` chi
  path parameter, but `pkg/api/rest/policy_handlers.go`'s handlers all read
  `chi.URLParam(r, "name")` — a key chi never populated, so every call with
  a real policy name fell into the "Policy name is required" branch
  regardless of what the caller sent (go-xkms#691). Routes now register
  `{name}`. Found and pinned by
  `pkg/api/keyops_parity_test/policy_parity_test.go`, which drives the same
  request through REST and gRPC and requires both to agree.
