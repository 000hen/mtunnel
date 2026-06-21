# mtunnel-libp2p

A lightweight reverse tunnelling binary built on top of [go-libp2p](https://github.com/libp2p/go-libp2p). One side (the *host*) exposes a local TCP or UDP service, while a remote *client* dials it through libp2p relays and hole punching, eliminating the need for public inbound connectivity.

## Features

- Peer discovery through the libp2p Kademlia DHT bootstrap network
- Automatic relays, hole punching, and NAT traversal helpers enabled out of the box
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

### Monitoring and session control (optional)

Host mode reads JSON messages from stdin and writes JSON status events to stdout, enabling external supervisors to manage active peers:

- `{"action":"LIST"}` returns the currently connected peer IDs.
- `{"action":"DISCONNECT","session_id":"<peer-id>"}` terminates a specific peer connection.

Each event includes the action name plus auxiliary fields such as `token`, `addr`, `port`, or `error` depending on context.

## Development

- Use `go fmt ./...` and `go test ./...` before submitting changes (no tests are defined yet, but the command ensures everything builds).
- Logs default to stdout; wrap the binary in a service manager if long-running.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
