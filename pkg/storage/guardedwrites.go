// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package storage

// GuardedWriteReporter is implemented by a Backend that knows whether its
// guarded writes — PutIfAbsent, CompareAndSwap, CompareAndDelete — can
// actually execute.
//
// # WHY DECLARING THE METHODS IS NOT ENOUGH
//
// Every Backend declares PutIfAbsent, and CompareAndSwapper /
// CompareAndDeleter are optional interfaces a backend either satisfies or does
// not. For most backends satisfying them is the whole story: the operation runs
// in this process against a store this process owns.
//
// It is not the whole story for a backend whose writes travel to a server. The
// qrdb backend implements all three and, built through the embedded
// constructors, fails every one of them at run time because the transport
// carries no transaction service (#125, measured through the constructors
// themselves). The methods are present, the operation is unavailable, and a
// caller reading the method set alone cannot tell — which turns a guarded
// write into a run-time failure on the path that needed the guard most.
//
// A capability that cannot be probed without writing has to be declared. This
// interface is that declaration, and it is deliberately OPTIONAL: a backend
// that does not implement it is taken at its word, so the common case (an
// in-process store that satisfies the two interfaces and can do the work)
// needs no change. Only a backend that KNOWS it cannot execute them has to say
// so.
type GuardedWriteReporter interface {
	// GuardedWritesAvailable reports whether the guarded writes this backend
	// declares can execute. It is a property of the backend's configuration,
	// fixed when the backend is constructed, not of any particular key.
	GuardedWritesAvailable() bool
}

// GuardedWritesAvailable reports whether b's guarded writes can execute.
//
// A backend that implements GuardedWriteReporter answers for itself. One that
// does not is reported as available, because that is what every in-process
// backend is: the alternative default would require every backend in the tree
// to opt in before a caller could use a guarded verb it has always been able
// to use.
//
// Note what this does NOT claim. It reports the backend's own answer about its
// configuration; it is not a promise that a specific call will succeed, and a
// caller must still handle the error. It exists so a caller that must CHOOSE
// between a guarded path and another design — as an adapter advertising
// go-qrdb's AtomicKVStore must — can make that choice from a declaration
// rather than from a failed write.
func GuardedWritesAvailable(b Backend) bool {
	reporter, ok := b.(GuardedWriteReporter)
	if !ok {
		return true
	}
	return reporter.GuardedWritesAvailable()
}

// GuardedWritesUsable reports whether b both OFFERS the guarded writes and can
// execute them: it satisfies CompareAndSwapper and CompareAndDeleter, and
// GuardedWritesAvailable says yes.
//
// Both halves are needed and neither implies the other. A backend can declare
// the methods and be unable to run them (the QRDB backends from the embedded
// constructors), and a backend can be perfectly able to run them and not
// declare them, in which case there is nothing to call.
//
// It exists as one function because two callers must agree on the answer:
// kvadapter.New, deciding whether to advertise go-qrdb's AtomicKVStore, and
// PrefixBackend, reporting for the backend it wraps. A condition spelled out
// twice is a condition that drifts, and the direction it drifts in here is a
// capability claimed and not delivered.
func GuardedWritesUsable(b Backend) bool {
	_, canSwap := b.(CompareAndSwapper)
	_, canDelete := b.(CompareAndDeleter)
	return canSwap && canDelete && GuardedWritesAvailable(b)
}
