- **`make test` no longer dirties the working tree, and the web dependency
  trees install from the lockfiles (#454).** The vitest coverage reports of
  `sdk/ts`, `sdk/ts/svelte-auth` and `web/app` (132 files, HTML and
  `lcov.info`) were tracked and rewritten by every `npm run test:coverage`;
  they are untracked and ignored, along with `node_modules/`. Every
  `npm install` in the build and test paths is now `npm ci`, which installs
  exactly the lockfile and refuses to rewrite it, so the tested dependency
  set is the pinned one; all seven lockfiles were verified in sync. The
  embedded `xkey/frontend/dist` stays tracked: `//go:embed all:dist` reads
  it at compile time, so untracking it would break every plain `go build`
  of xkey; with `npm ci` the Vite build is reproducible, which is what
  removes that churn.
