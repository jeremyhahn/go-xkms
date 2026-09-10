### Fixed

- The nightly xkey race suite installed its cgo packages with a raw `apt-get install` after the pull-request workflow had moved to the idempotent, retrying dependency script; it now uses the same script, so an archive outage no longer reddens the nightly run either.
