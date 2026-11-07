// Package buildgates holds the tests that keep the CI configuration true to
// its own rules: the tier every ci.yml job runs on, and the CI Gate line
// that accepts or rejects its result, and the apt layers of the CI images,
// which must use the shared retry configuration. It has no non-test code.
package buildgates
