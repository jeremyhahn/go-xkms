module github.com/jeremyhahn/go-xkms/web/desktop

go 1.26.6

// Intra-repo submodule resolution (valid in-workspace and standalone on GitHub).
// Cross-repo deps resolve via the parent go.work `use` directives; no cross-repo
// local-path replaces are committed here.
replace (
	github.com/jeremyhahn/go-xkms => ../../
	github.com/jeremyhahn/go-xkms/sdk/go => ../../sdk/go
)

require (
	github.com/jeremyhahn/go-xkms v0.0.0-00010101000000-000000000000
	github.com/wailsapp/wails/v2 v2.12.0
)
