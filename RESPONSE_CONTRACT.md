# Forwarding response contract

Both the default mode (no `-address-policy`) and the opt-in policy mode forward
response body bytes without content decoding. Repeated headers and Set-Cookie
remain separate values. Trailers are sent after a successful body EOF; an
upstream body error aborts the downstream response instead of writing a final
chunk that would claim success. Hop-by-hop headers are removed and framing is
generated for the downstream HTTP/1.1 connection.

Redirects are returned to the caller, including the plain HTTP default path.
The caller decides whether to follow them and owns the final URL. CONNECT
accepts HTTP/1.1 from the caller and may negotiate HTTP/1.1 or HTTP/2 with the
origin. The caller's reported protocol is therefore the proxy-facing protocol;
it does not describe the upstream TLS connection. No response metadata headers
are injected to pretend these protocols are identical.

The default CONNECT parser now supports normal HTTP/1.1 keepalive without an
explicit `Connection: keep-alive` header. Decrypted requests run through an
HTTP server and a cancellable ftransport connection rather than a blocking
read/forward loop. Disconnecting while waiting for upstream headers or a body
cancels upstream work. Requests use the existing 30 second total budget;
trusted `Delegate.BeforeRequest` hooks may change `Options.Timeout`. CONNECT
client TLS handshake, decrypted header reads and keepalive idle waits have a
30 second limit. MITM does not expose separate per-phase timeout flags. A
failure before response headers produces 502; a failure after response headers
aborts the connection. A successful status line alone never certifies the body.

Default CONNECT forwarding can make one additional RoundTrip when an actually
reused connection returns EOF or UnexpectedEOF before any response. This is
limited to GET/HEAD without a body, transfer encoding or trailers, and keeps
the original context, deadline and transport dial configuration. New-connection
failures, other methods, status codes and response-body errors are not replayed
by this recovery path; it is not a general retry policy.

Plain HTTP bodies are streamed through the core session API. The proxy does
not buffer a request body into an unbounded string. Policy mode retains its
separate bounded request buffering, origin checks and fail-closed startup.

`TestDefaultProxyWireContract` and `TestMITMBinaryDefaultWireContract` exercise
the actual HTTP, CONNECT-to-H1 and CONNECT-to-H2 network paths. They check
binary bodies, repeated headers, cookies, trailers, unknown-length H2-to-H1
framing, keepalive, redirects, gzip wire bytes, streaming POST, HEAD metadata,
fixed-length truncation, aborted chunked/H2 streams and cancellation before
headers and during a body. `TestDefaultProxyTotalDeadline` additionally checks
TLS stalls, header waits and stalled bodies with a short trusted total budget.
These fixtures test forwarding; browser fingerprint equivalence and HTTP
Upgrade/WebSocket tunneling are outside this contract.
