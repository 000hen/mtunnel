# mtunnel-libp2p

A lightweight reverse tunnelling binary built on top of [go-libp2p](https://github.com/libp2p/go-libp2p). One side (the *host*) exposes a local TCP or UDP service, while a remote *client* dials it through libp2p relays and hole punching, eliminating the need for public inbound connectivity.

libp2p handles discovery and signalling; the traffic itself rides whichever data plane the two peers can actually establish. By default they try WireGuard, then QUIC, then fall back to libp2p's own streams — see [Tunnel tiers](#tunnel-tiers).

## Features

- Peer discovery through the libp2p Kademlia DHT bootstrap network
- Automatic relays, hole punching, and NAT traversal helpers enabled out of the box
- A pluggable data plane that negotiates the best tunnel protocol both peers support, and degrades automatically when one can't be established
- Encoded connection tokens for bootstrapping clients without exposing raw peer IDs
- Optional JSON control channel for listing and disconnecting active sessions
- Single static binary that works for both host and client roles

## Prerequisites

- Go 1.25 or newer (the upgraded go-libp2p dependencies require the Go 1.25 language version)
- A reachable local service on the host side to forward traffic to (e.g. `localhost:8080`)

## Build

```powershell
# From the repository root
Go env GOPATH  # optional sanity check; not required for the build
go build ./cmd/tunnel
go build -ldflags "-s -w" ./cmd/tunnel  # stripped binary for distribution
```

## Usage

Both roles use the same binary. Omitting the `-token` flag starts host mode; providing it starts client mode.

### Host mode (expose a local service)

```powershell
# Forward localhost:8080 over the tunnel
./tunnel.exe -port 8080
```

- `-port` is the local port on the host that should receive forwarded traffic.
- `-network` controls the socket type (`tcp` default, or `udp`). UDP is carried as length-prefixed datagrams over one tunnel stream per source flow, with idle flows reaped automatically.
- The process prints a base64-encoded connection token to stdout and also emits a JSON event for automation. Share this token with clients.

### Client mode (consume a forwarded service)

```powershell
# Listen on an ephemeral local port; connect using the provided token
./tunnel.exe -token <PASTE-TOKEN> -port 0
```

- `-port` is the local listener port. Set `0` to let the OS pick a free port (the program prints the chosen port).
- `-network` must match the host's setting.
- Once connected, any TCP or UDP client hitting the local port will tunnel traffic to the host's service.

### Tunnel tiers

Discovery, authentication, and signalling always go over libp2p. What carries the
forwarded bytes is negotiated separately, once per peer session:

| Tier | Data plane | Needs |
| --- | --- | --- |
| `wireguard` | WireGuard (Noise-IK) over a directly punched UDP socket, terminating in an in-process netstack | A successful NAT punch |
| `quic` | QUIC over that same punched socket — streams for `-network tcp`, DATAGRAM frames for `-network udp` | A successful NAT punch |
| `libp2p` | Today's behaviour: one libp2p stream per forwarded connection, over a direct or relayed connection | Nothing extra; always available |

The punch is a `pion/ice` exchange against public STUN servers, signalled over a
dedicated libp2p stream. It is independent of libp2p's own DCUtR hole punching
and does not wait on it, so a session still relayed at the libp2p layer can carry
its traffic over a direct WireGuard or QUIC path.

`-tunnel-mode` (default `auto`) selects the policy:

- `auto` — try each tier in order and use the first that comes up. One punch
  serves both upper tiers: if the WireGuard handshake fails, QUIC is tried on the
  very same socket rather than punching again. If the punch itself fails, both
  upper tiers are skipped.
- `wireguard` / `quic` — force that tier and fail the session if it cannot be
  established, instead of silently degrading. For isolating a tier during testing.
- `libp2p` — skip the punch entirely and use libp2p streams, as before this
  feature existed.

Both peers advertise what they support and independently intersect the two lists,
so a forced mode on either side is enough to pin the result, and two incompatible
forced modes converge on `libp2p` (logged explicitly rather than silently).

Tier selection costs nothing when it resolves to `libp2p` up front — ICE gathering
only starts once both sides have agreed an upper tier is worth attempting. Worst
case, a session that tries everything and lands on `libp2p` anyway spends roughly
`-punch-timeout` plus two `-handshake-timeout` before forwarding its first byte.

Relevant flags:

- `-tunnel-mode auto|wireguard|quic|libp2p`
- `-stun-servers stun:host:port,...` — overrides the built-in Google/Cloudflare
  defaults; the punch is skipped if none are reachable.
- `-punch-gather-timeout 3s` — budget for candidate gathering (STUN). Kept short
  because a gather that is going to work finishes in well under a second; the
  full timeout is only ever spent waiting out an unreachable STUN server (an
  IPv4-only host probing over UDP6, for instance), and it is charged to the peer's
  exchange budget too.
- `-punch-timeout 8s` — budget for the punch's connectivity checks, separate from
  gathering.
- `-punch-attempts 2` — how many times each side punches before giving up on the
  upper tiers; the effective count is the lower of the two peers'. ICE against a
  real NAT is probabilistic, so a second attempt recovers a meaningful share of
  first-attempt failures. A peer built before this flag existed is treated as
  requesting one attempt, so mixed-version pairs still agree.
- `-handshake-timeout 6s` — budget for one tier's handshake before falling back.

Every session — with or without `-diagnostic` — logs a `tunnel_tier_selected`
record naming the tier it settled on, and one `tunnel_tier_fallback` warning per
rung that did not come up (tier, outcome, duration, cause), including a
`punch-failed` outcome when the NAT punch itself did not land. A punch retry
(see `-punch-attempts`) logs `tunnel_punch_retry` between attempts. This is
enough to tell *what* failed without adding `-diagnostic`; add it when you also
need candidate-level detail.

With `-diagnostic`, each session additionally logs a `tunnel_tier_negotiated`
record (both sides' advertised tiers and the resolved one), a
`tunnel_tier_attempt` record per rung attempted (including successes), and
`tunnel_nat_punch` with per-candidate detail for the punch itself. The
`CONNECTED` control event carries the winning tier in its `tier` field.

A rung's teardown normally hands the punched socket on to the next one intact.
When it cannot release its own read loop in time, it closes that socket instead
and logs an unconditional `tunnel_substrate_abandoned` warning — the cascade
then goes straight to the `libp2p` floor rather than trying the next tier on a
dead socket and reporting a misleading handshake failure against it. This is
rare and points at something holding a rung's teardown open, not at the next
tier.

### Connection stability and diagnostics

These flags govern the libp2p layer specifically — how the *signalling*
connection is established, and how traffic behaves on the `libp2p` tier. They are
independent of `-tunnel-mode`: a session on the WireGuard or QUIC tier still uses
libp2p to find its peer and negotiate, and still falls back to these settings if
that tier can't be established.

Latency-sensitive TCP traffic defaults to `-connection-mode direct-first`: a
new application stream waits up to `-direct-timeout` for a direct libp2p
connection, then records an explicit relay fallback. Existing streams never
migrate between relay and direct connections.

Useful controlled-test flags:

- `-connection-mode direct-only|direct-first|relay-only`
- `-transport default|quic|tcp|webrtc`
- `-dht-mode close-after-connect|no-refresh|current` (client role)
- `-direct-timeout 15s`
- `-relays <multiaddr>,<multiaddr>` selects a small dedicated server relay set;
  without it the server bounds fallback candidates to three bootstrap peers.
- `-diagnostic` emits JSON structured logs to stderr every 10 seconds, plus one
  path record for every opened or accepted tunnel stream, and the tier and punch
  records described above.

The recommended production baseline is `auto` tunnel mode, `direct-first`,
`default` transport, and `close-after-connect`. Use `direct-only` when a relayed
game session is less useful than a clear connection failure. See
[`docs/connection-stability.md`](docs/connection-stability.md) for the evidence,
test matrix, and exact long-run procedure.

### Monitoring and session control (optional)

Host mode reads JSON messages from stdin and writes JSON status events to stdout, enabling external supervisors to manage active peers:

- `{"action":"LIST"}` returns the currently connected peer IDs.
- `{"action":"DISCONNECT","session_id":"<peer-id>"}` terminates a specific peer connection.

Each event includes the action name plus auxiliary fields such as `token`, `addr`, `port`, or `error` depending on context.

## Development

- Use `go fmt ./...`, `go vet ./...`, and `go test ./...` before submitting changes.
- The tier packages test without any real network: `internal/wireguard` runs two
  real devices over an in-memory bind, and `internal/tunnel`'s cascade tests run
  the real fallback ladder over a loopback socket pair with only the NAT punch
  substituted. Run them with `-race`, since most of that code is concurrent.
- Control events use stdout. Diagnostic JSON logs use stderr so test runs can
  capture them independently.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
