// Package covfixture is the source the coverage-merge fixture profiles in
// coverage_merge_test.go describe, so go tool cover -func can resolve them.
package covfixture

// Sign reports whether x is positive.
func Sign(x int) int {
	if x > 0 {
		return 1
	}
	return 0
}

// Two returns 2.
func Two() int {
	return 2
}
