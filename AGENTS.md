# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What this is

`mtunnel-libp2p` is a reverse tunnelling binary built on [go-libp2p](https://github.com/libp2p/go-libp2p). One **host** exposes a local TCP or UDP service; a remote **client** reaches it through libp2p relays and hole punching, with no public inbound connectivity required. A single binary plays both roles — passing `-token` selects client mode, omitting it selects host mode.

Requires **Go 1.25+** (the go-libp2p dependencies need the Go 1.25 language version).

## Commands

```bash
go build ./cmd/tunnel                      # build (produces tunnel.exe on Windows)
go build -ldflags "-s -w" ./cmd/tunnel     # stripped binary for distribution
go test ./...                              # run all tests (currently only internal/udp)
go test ./internal/udp -run TestDatagramRoundTrip   # run a single test
go fmt ./...                               # format
go vet ./...                               # vet
```

Run host: `./tunnel.exe -port 8080 [-network tcp|udp]` — prints a base64 token.
Run client: `./tunnel.exe -token <TOKEN> -port 0` — `-port 0` lets the OS pick the local listener port; `-network` must match the host.

## Architecture

The defining decision is a **layered dependency graph that quarantines libp2p**. `internal/p2p` is the *only* package that imports libp2p; the per-network forwarders (`tcp`, `udp`) never do. This keeps the forwarding logic testable and network-libp2p-agnostic.

```
cmd/tunnel ── flag parsing, role dispatch, signal-aware root context
   └── internal/tunnel ── orchestration: RunHost / RunClient wire everything together
         ├── internal/p2p       ── ONLY libp2p contact: host, DHT discovery, tokens, stream setup
         ├── internal/control   ── optional JSON control channel (stdin requests / stdout events)
         └── internal/transport ── network-agnostic interfaces (Stream, Opener, Transport, Forwarder)
               ├── internal/tcp ── raw byte-copy forwarder
               └── internal/udp ── length-prefixed datagram forwarder
```

`internal/transport` is the leaf — it imports only the stdlib. The seam that makes this work: **`transport.Stream` is satisfied *structurally* by libp2p's `network.Stream`**, so `tcp`/`udp` consume tunnel streams without importing libp2p. `tunnel/transport.go::transportFor` is the single source of truth for which networks are supported; add a network by adding a case there plus a package implementing `transport.Transport`.

### Role flows

- **Host** (`tunnel/host.go`): create host → DHT in `ModeAutoServer` → `WaitForNetworkReady` → encode token (`{network, peerID}` via gob+base64) → register the `/mtunnel/1.0.0` stream handler **before** announcing the token → per inbound stream, dial `localhost:<port>` and `Transport.Forward` bridges stream ↔ local conn.
- **Client** (`tunnel/client.go`): decode token → DHT in `ModeClient` → `FindPeer` (retried) → `Connect` → `Transport.Listen` opens the local socket; each local TCP connection / UDP source flow opens its own tunnel stream via `p2p.OpenStream` and pipes through it.

### Non-obvious invariants (read before changing the relevant area)

- **Limited-connection streams** (`p2p/stream.go`): `OpenStream` sets `network.WithAllowLimitedConn`. Without it libp2p refuses to open streams over a relay-only connection, so traffic silently fails until hole punching completes — the "connected but no data" trap. Do not remove it.
- **Network readiness gate** (`p2p/host.go::WaitForNetworkReady`): the host announces its token only once it has a dialable (public or circuit-relay) address, so clients can't discover an unreachable host. It is an upper-bound wait, not a fixed delay.
- **Disconnect detection** (`tunnel/watcher.go`): a single connection closing is **not** a disconnect — libp2p cycles connections during hole punching (relay → direct, and direct → relay fallback). The watcher treats the peer as gone only when `Connectedness == NotConnected`.
- **Session = one connection, many streams** (`tunnel/session.go`): a peer multiplexes one stream per forwarded connection over a single libp2p connection. `SessionManager` reference-counts streams per peer and emits exactly one `CONNECTED`/`DISCONNECT` event per peer, so one stream ending doesn't tear down its siblings. The `closing` flag is set under the same lock `BeginStream` takes, preventing a `handlers.Add`/`Wait` race at shutdown.
- **UDP flow ABA hazard** (`udp/flow.go`): one tunnel stream per client source address ("flow"). `flowTable.remove` checks flow *identity* before evicting, because a stale reverse-pump can fire its deferred `remove` after a new flow was already registered under the same source address — keying on address alone would kill the live replacement. Idle flows are reaped on a timer since UDP has no connection close.
- **Shutdown ordering** is deliberate in both roles: stop accepting new streams (`RemoveStreamHandler` / `Forwarder.Close`) → reset active streams and wait for handlers to drain → only then close the libp2p stack. Preserve this sequence when editing `RunHost`/`RunClient`.

### Control channel

`internal/control` is advisory and optional. Host mode reads newline-delimited JSON requests from stdin (`LIST`, `DISCONNECT`, `SHUTDOWN`) and both roles emit JSON events to stdout (`TOKEN`, `CONNECTED`, `DISCONNECT`, `LIST`, `ERROR`). Marshalling/write failures are logged, never propagated. The client passes `nil` sessions, so `LIST`/`DISCONNECT` are ignored there.
