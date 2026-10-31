# Optional bounded audit events

Service v0.1.1 and v0.1.2 include `-audit-file`, `-audit-queue` and
`-audit-drain-timeout`. Older development records describe their original scope. With no audit file,
there is no audit worker, file or response wrapper. Existing request/response
payloads and headers are unchanged; client-provided request IDs are not trusted
or echoed by this feature.

Use a private file per process, for example `-audit-file ./audit.jsonl
-audit-queue 1024 -audit-drain-timeout 5s`. The path is trusted startup input.
New files use mode 0600 (Windows ACLs still apply); existing file permissions
are not changed. Only regular files are accepted. Do not share one file among
processes. Rotation/reopen and remote exporters are not implemented.

The file contains one JSONL completion event per parsed HTTP request, CONNECT
lifecycle or accepted gRPC RPC, plus `tcp_rejected` when an application-level
connection quota rejects a socket. HTTP parser/transport rejections which do
not reach these hooks (including H2 stream/header enforcement) do not invent
request completion events. Abrupt process termination cannot guarantee drain.

Schema version 1 contains a server-generated 128-bit hex `request_id`, optional
CONNECT `parent_id`, UTC `time`, `entry`, `kind`, `duration_us`, separately named
`downstream_protocol` and `upstream_protocol`, applicable HTTP statuses,
`rpc_code`, `error_code` and `timeout_phase`. Protocols and error labels are
allowlisted. Absent protocol/status means it was not available, not inferred.
A gRPC OK transport status can carry an upstream application failure, so its
`error_code` is separate. Ordinary gRPC context cleanup is not peer cancellation.

Events have no URL, host/IP, method, request headers, Cookie, authorization,
request/response body, application request ID, policy contents, raw error
message or arbitrary metadata map. This privacy contract applies to the audit
file; existing operational/debug logs are a separate output and are not claimed
to be globally redacted by this feature.

The queue defaults to 1024 pending events, accepts 1..65536 (0 selects the
default), and adds at most one event being written. Producers never wait for
file I/O: a full queue drops the newest event. A sticky output error discards
later events and makes shutdown return an error; it does not change response
status or retry the request. Short writes count as errors. There is no fsync or
power-loss durability guarantee and partial failed records are not repaired.

The CLI stops serving, waits for started operations to complete, and closes the queue; the complete drain takes at most 5 seconds
by default (0 selects that default; maximum 1 minute). A blocked OS file write
cannot be portably interrupted: drain expiry returns a failure within the
budget, while the single writer can remain blocked until I/O returns or the
process exits. Do not claim that a timeout completed or persisted those events.
On normal close, the worker owns closing the file. Concurrent producers cannot
send to a closed channel; late completions are counted as dropped.

The CLI prints `audit_stats` to stderr after drain: accepted, written,
dropped_full, dropped_closed, dropped_write and drain_expired. Written means
the write call succeeded, not disk fsync. The embedded Sink.Stats API exposes
the same counters. No public health/metrics endpoint or new network listener is
added. CONNECT shutdown waits for hijacked request completions before the CLI
drains the audit queue, within the existing server shutdown budget.

Package tests cover deterministic N/N+1 capacity, I/O failure and short writes,
bounded drain, concurrent producers/close, single completion, secrets, trailers
and response-controller forwarding. Cross-repository tests run real Fetch,
JSON-RPC, gRPC and MITM processes with success, truncation, decoding failure,
timeouts, cancellation, overload and message limits. Windows validates API
shutdown separately; POSIX additionally checks actual CLI signal-and-drain.
