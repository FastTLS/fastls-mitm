# Consolidated Go candidate

This source candidate requires the pinned core revision in `go.mod`. The TLS
dialer compiles complete provider profiles with `fastls.ProfileToSpec`; invalid
profiles fail before dialing instead of falling back to the standard TLS stack.
An independent TLS peer verifies the configured cipher order and forced ALPN.

CONNECT accepts either an HTTP/1 request or a TLS handshake. Both preserve bytes
buffered after the CONNECT headers. Cleartext requests are bound to the outer
CONNECT authority, retain streaming/cancellation and strip proxy control headers.
Nested CONNECT and Upgrade are not supported in the cleartext inner server.
This does not add a generic opaque TCP/UDP tunnel.

In policy mode, admission checks the CONNECT authority before returning 200.
An HTTP-only policy can admit the authority without granting HTTPS permission;
the actual inner protocol is checked again before a target connection or TLS
handshake. Every request retains native DNS/origin binding and the existing
request/traffic/lifetime budgets. Proxy authentication remains on the outer
CONNECT and credentials are not forwarded to the target.

Development CI selects Linux/Windows on the current toolchain. Main and explicit
candidate checks retain all three platforms and both toolchains; policy-tagged
tests now run with the pinned standalone core as well as coordinated workspaces.
Race and coverage share one execution. Planned failures, cancellations, missing
jobs and unexpected skips fail the aggregate gate. A complete candidate does not
claim performance improvement or full browser H3/UDP-proxy support.

Signing archives are generated under RUNNER_TEMP, outside the checkout. Source
cleanliness is checked before and after all targets; VCS metadata is retained.
Published v0.1.1 binaries and their original evidence remain unchanged.
