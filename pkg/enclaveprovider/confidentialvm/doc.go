// Package confidentialvm is go-xkms's confidential-vm provider, moved from
// go-enclave by ruling 1234: attestation for a program inside an AMD SEV-SNP
// or Intel TDX confidential VM, and an SEV-SNP derived-key KeyProtector.
//
// A confidential VM is not a backend. The platform encrypts the whole guest
// against the host, so a handle inside it would be ordinary guest memory; the
// program keeps its material in go-enclave's backends, as on any host. What
// the platform adds is evidence about the guest, and this package gives it as
// a standalone [Attester]: [NewAttester] returns a value whose one method,
// Attest, returns the package's [Evidence]. Its evidence is the guest's SNP
// ATTESTATION_REPORT or TD quote, read through the Linux configfs-tsm report
// interface (/sys/kernel/config/tsm/report).
//
// Nothing imports it by default and importing it registers nothing. On any
// target other than linux/amd64 it compiles, and its constructor refuses with
// [ErrTSMReportUnavailable].
//
// docs/plans/2380.md is its design.
package confidentialvm
