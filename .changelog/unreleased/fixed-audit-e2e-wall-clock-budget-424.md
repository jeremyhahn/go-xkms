- **The ACME audit end-to-end tests no longer fail on a contended runner.**
  `awaitEvents` polled the audit trail under a five-second wall-clock
  budget; the trail's `Flush` is synchronous (it hands the drain to the
  writer goroutine, waits, and syncs the file) and every handler records its
  event before answering, so the loop could never turn a wrong answer into a
  right one — it only measured how long an fsync and a file scan take on a
  saturated host, and failed reporting a page it never read when the first
  evaluation outlived the budget. The helper is now one flush and one query
  with no budget to expire, proven green under a full-core load generator.
