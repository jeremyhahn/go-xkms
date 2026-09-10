- **Advertised URLs are configuration, never a host glued to a bind address (#140, cluster 4).**
  `trusted-acme-client serve` built the API base URL it hands the browser as
  `scheme + "://localhost" + addr`, so the command's own `--addr 0.0.0.0:9443`
  example advertised `https://localhost0.0.0.0:9443/api/v1`; the standalone
  `TrustedCA` did the same for the ACME directory's external URL, served to
  every ACME client. The client gains `serve.api_base_url` (`--api-base-url`,
  `ACME_CLIENT_SERVE_API_BASE_URL`), advertised verbatim once it parses as an
  absolute http(s) URL not ending in `/api/v1`, which the UI appends itself;
  the Wails `GetApiBaseUrl` bindings return the origin for the same reason,
  and `pkg/webui` renders the value into the page as an escaped JavaScript
  string literal. With nothing configured both derive the URL through the new
  `acmeclient.AdvertisedURL`, which splits host and port: a wildcard bind
  advertises `localhost`, a named or literal bind advertises itself, and an
  address with no port is an `AdvertisedURLError`. `DefaultExternalURLPrefix`
  is gone with the gluing it existed for.
