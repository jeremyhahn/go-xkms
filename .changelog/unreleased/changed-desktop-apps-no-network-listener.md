- **The desktop apps serve their REST API in-process and open no listener.**
  Both Wails applications bound a TCP listener on `127.0.0.1:0` and served
  their API from it: the ACME client's 18 routes and — with no guard at all —
  the admin app's 37, including tenant, user, role and CA creation. A loopback
  port is reachable by every local process and, through the user's browser, by
  every page the user visits, so the only consumer of that port was the app's
  own webview while the audience was the whole machine. Wails' `AssetServer`
  takes an `http.Handler` alongside `Assets`, so the existing router is now
  mounted there: a GET is served from the frontend bundle first and falls back
  to the router, every non-GET goes straight to it, and the webview reaches
  `/api/v1/...` same-origin. The listener, the per-launch bearer token minted
  for it, the `Host` allow list that defended it against DNS rebinding and the
  token plumbing through `GetApiBaseUrl` and the frontend transport are all
  gone; `GetApiBaseUrl` now returns an empty, same-origin base. The router
  stays transport-agnostic and `trusted-acme-client serve` keeps serving it
  over TCP, where the same-origin check still applies.
