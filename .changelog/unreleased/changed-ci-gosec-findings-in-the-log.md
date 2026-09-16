- **CI: gosec findings are printed to the job log.** The Security Scan wrote
  its findings only to a SARIF file that is uploaded on GitHub and skipped
  on Gitea, so a failing scan ended with exit code 1 and nothing in the log
  naming the finding (#334). gosec now also writes the
  findings to standard output.
