package cmd

// shortTMPDIR runs run and returns its exit code.
func shortTMPDIR(run func() int) int {
	return run()
}
