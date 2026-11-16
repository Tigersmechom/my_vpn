# Availability component

A local, unprivileged CLI for Android and macOS. Configuration is newline-delimited
JSON on stdin (`routes: [{id, protocol, profile}]`); stdout has one JSON result per
request. Protocols are `HY2`, `HY2_OBFS`, `AWG`. At most 27 entries are accepted and
three requests run concurrently. It creates no system TUN, routes or DNS changes.

Each request makes exactly one HEAD to `https://www.google.com/generate_204` per
route. HTTP/TLS sessions and protocol transports are reused. No response body or
speed-test file is downloaded. History is five samples; changes to any profile
field reset that route's history. Slow rounds finish before the next round starts.

Hysteria checks the exact leaf certificate SHA-256 pin. HTTPS inside the tunnel
validates its hostname and trust chain. AWG uses a userspace netstack and requires
`probeAwg` (privateKey, presharedKey, address); using the normal client's key would
move its live endpoint and is rejected. A missing dedicated key is yellow.

The parent app owns scheduling and lifecycle. Closing stdin or SIGTERM tears down
all sessions. Android exports system CA roots with `--ca-file` and runs the CLI
from the extracted native library directory, avoiding writable-code execution and
multiple Go runtimes in the VPN process. Secrets are passed only through pipes.

Build: `bash health/build.sh mac` / `android` / `all` from the repository root.
Android uses NDK 27.2.12479018 by default; set `ANDROID_NDK_HOME` to override.
Run `cd health && go test -race ./...`. Tests exercise real HTTPS, certificate
rejection, connection reuse, bounded concurrency, route changes and cancellation.
