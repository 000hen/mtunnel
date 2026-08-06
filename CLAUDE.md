# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`mtunnel-libp2p` is a reverse tunnelling binary built on [go-libp2p](https://github.com/libp2p/go-libp2p). One **host** exposes a local TCP or UDP service; a remote **client** reaches it through libp2p relays and hole punching, with no public inbound connectivity required. A single binary plays both roles — passing `-token` selects client mode, omitting it selects host mode.

libp2p provides discovery, authentication, and signalling. It does *not* necessarily carry the traffic: the data plane is a negotiated **tier**, defaulting to a WireGuard → QUIC → libp2p cascade over an independently punched socket. See "Tier cascade" below.

Requires **Go 1.25+** (the go-libp2p dependencies need the Go 1.25 language version).

This build is **protocol generation 2** and deliberately does not interoperate with the original `/mtunnel/1.0.0` build in either direction. That is by design, not an oversight — see the token/protocol invariants below for how each direction fails and why each failure is the readable one.

## Commands

```bash
go build ./cmd/tunnel                      # build (produces tunnel.exe on Windows)
go build -ldflags "-s -w" ./cmd/tunnel     # stripped binary for distribution
go test ./... -race                        # run all tests; -race matters, most of this is concurrent
go test ./internal/udp -run TestDatagramRoundTrip   # run a single test
go fmt ./...                               # format
go vet ./...                               # vet
```

Note `gofmt -l .` flags around ten pre-existing files purely for CRLF line endings. Check that a diff is more than line endings before "fixing" one.

Run host: `./tunnel.exe -port 8080 [-network tcp|udp]` — prints a base64 token.
Run client: `./tunnel.exe -token <TOKEN> -port 0` — `-port 0` lets the OS pick the local listener port; `-network` must match the host. `-tunnel-mode` does *not* need to match — it is negotiated.

## Architecture

The defining decision is a **layered dependency graph that keeps libp2p out of the data path**. `internal/p2p` and `internal/tunnel/*` import libp2p; nothing below them does — not the forwarders (`tcp`, `udp`), not `transport`, and not any of the tier packages. That boundary is what lets the whole data plane be swapped without touching the forwarding logic.

```
cmd/tunnel ── flag parsing, role dispatch, signal-aware root context
   └── internal/tunnel ── orchestration: RunHost / RunClient, plus tier.go's fallback ladder
         ├── internal/p2p       ── libp2p: host, DHT discovery, tokens, stream setup, negotiate stream
         ├── internal/control   ── optional JSON control channel (stdin requests / stdout events)
         ├── internal/negotiate ── tier wire format (gob) + the pure tier-intersection function
         ├── internal/tier      ── the tier contract and registry: Tier, Identity, Set
         │     ├── internal/wireguard ── WireGuard tier: custom conn.Bind over the substrate + netstack
         │     └── internal/quictun   ── QUIC tier: streams, or DATAGRAM frames, over the same substrate
         ├── internal/nat       ── pion/ice hole punch against public STUN → one net.Conn substrate
         ├── internal/flowmux   ── flow multiplexing for the datagram sub-modes of both tiers
         └── internal/transport ── network-agnostic interfaces (Stream, Opener, Transport, Forwarder)
               ├── internal/tcp ── raw byte-copy forwarder
               └── internal/udp ── length-prefixed datagram forwarder
```

`internal/transport` is the leaf — it imports only the stdlib. The seam that makes this work: **`transport.Stream` is satisfied *structurally* by libp2p's `network.Stream`**, so `tcp`/`udp` consume tunnel streams without importing libp2p — and equally by a netstack conn or a QUIC stream, which is why adding tiers cost those packages nothing. `tunnel/transport.go::transportFor` is the single source of truth for which networks are supported; add a network by adding a case there plus a package implementing `transport.Transport`.

`internal/tier` is the same idea one level up, for the data plane: `tier.Set` is the single source of truth for which tiers exist, and `tier.Tier` is what each one implements. `internal/tunnel` no longer imports `wireguard`, `quictun`, or `flowmux` at all — it asks a `Set` to `Dial`/`Serve` an ID. It still *names* tiers in two places, both of which are about policy rather than construction: mapping `-tunnel-mode` to a forced tier, and the `negotiate.TierLibp2p` floor, which is not in the `Set` because it is the libp2p stack both processes are already running rather than something to stand up.

### Role flows

- **Host** (`tunnel/host.go`): create host → DHT in `ModeAutoServer` → `WaitForNetworkReady` → `newTiers` (per-run `tier.Identities` + the `tier.Set` over them) → encode token (`{version, network, peerID, wgPubKey}` via gob+base64) → register the `/mtunnel/2.0.0` **and** `/mtunnel/negotiate/2.0.0` handlers **before** announcing the token → per inbound data stream, dial `localhost:<port>` and `Transport.Forward` bridges stream ↔ local conn.
- **Client** (`tunnel/client.go`): decode token (which rejects a version this build can't reach) → resolve the host's protocols from that version via `p2p.ProtocolsFor` → DHT in `ModeClient` → `FindPeer` (retried) → `Connect` → negotiate a tier (`tier.go`) → `Transport.Listen` opens the local socket; each local TCP connection / UDP source flow opens its own tunnel stream through **the winning tier's `Opener`** and pipes through it.

### Tier cascade

`internal/tunnel/tier.go` is the whole ladder: the negotiation, the walk down the cascade, and the point where a live `tier.Rung` is fed into the existing host/client flow. It no longer knows how to *build* any individual tier — it asks `ts.set` (a `*tier.Set`) to `Dial`/`Serve` an ID and gets a `tier.Rung` back. `-tunnel-mode` (`auto` default, or `wireguard`/`quic` forced, or `libp2p`) narrows each side's advertised tier list to `{forced, floor}`; both sides then compute the same intersection independently, so no extra round trip is needed and the libp2p floor is always reachable.

Sequence: exchange `Hello` → if an upper tier is mutually supported, exchange `PunchInfo` and punch (retrying in lockstep up to `-punch-attempts`, default 2, if it fails — see below) → try each agreed tier on that one substrate in order → fall back to libp2p if all fail. `internal/nat`'s `Agent` owns the substrate throughout and is closed last.

**Adding a tier** is three edits, none of them in `internal/tunnel`: a file in `internal/tier` implementing `tier.Tier` (`ID`, `Dial`, `Serve`, `SubstrateAbandoned`), one entry in `internal/tier/set.go`'s `implementations` table pairing its identity constructor with its build function, and one constant in `negotiate`'s `Cascade()`. `NewSet` panics at startup if those three disagree — a tier with no identity, a duplicate ID, or one the cascade never names — because the runtime symptom would otherwise be a tier that silently never runs.

The `implementations` table is deliberately one table rather than two: credentials and implementations used to be registered separately, and the credential is the easy half to forget, whose absence shows up as a handshake that never completes rather than as a compile error.

### Non-obvious invariants (read before changing the relevant area)

- **Limited-connection streams** (`p2p/stream.go`): `OpenStream` sets `network.WithAllowLimitedConn`. Without it libp2p refuses to open streams over a relay-only connection, so traffic silently fails until hole punching completes — the "connected but no data" trap. Do not remove it.
- **Network readiness gate** (`p2p/host.go::WaitForNetworkReady`): the host announces its token only once it has a dialable (public or circuit-relay) address, so clients can't discover an unreachable host. It is an upper-bound wait, not a fixed delay.
- **Disconnect detection** (`tunnel/watcher.go`): a single connection closing is **not** a disconnect — libp2p cycles connections during hole punching (relay → direct, and direct → relay fallback). The watcher treats the peer as gone only when `Connectedness == NotConnected`.
- **Session = one connection, many streams** (`tunnel/session.go`): a peer multiplexes one stream per forwarded connection over a single libp2p connection. `SessionManager` reference-counts streams per peer and emits exactly one `CONNECTED`/`DISCONNECT` event per peer, so one stream ending doesn't tear down its siblings. The `closing` flag is set under the same lock `BeginStream` takes, preventing a `handlers.Add`/`Wait` race at shutdown.
- **UDP flow ABA hazard** (`udp/flow.go`): one tunnel stream per client source address ("flow"). `flowTable.remove` checks flow *identity* before evicting, because a stale reverse-pump can fire its deferred `remove` after a new flow was already registered under the same source address — keying on address alone would kill the live replacement. Idle flows are reaped on a timer since UDP has no connection close.
- **Shutdown ordering** is deliberate in both roles: stop accepting new work → drain what is in flight → release the tier substrate → only then close the libp2p stack, which must be last because closing it is what unblocks anything still on the libp2p floor. Host: `RemoveStreamHandler` ×2 → `session.Shutdown()` → `negotiations.shutdown()` → `wg.Wait()` → `p2p.Close`. Client: `StopNotify` → `forwarder.Close()` → `tier.close()` → `p2p.Close` → `wg.Wait()`. On the host the two shutdown calls are **not** interchangeable: a negotiation handler serving a WireGuard tier does not return until the forwarded connections on it are done, and only `session.Shutdown` releases those — reversing them hangs. On the libp2p floor `tier.close()` is a no-op, so the client's shape is the same whichever tier won.
- **One substrate, many rungs** (`tunnel/tier.go::climbCascade`): the cascade punches once and runs each tier on that same `net.Conn` in turn. So a rung's teardown must return the substrate *usable*, not just release its own goroutines. Concretely: pion/ice's `SetReadDeadline` is a no-op stub, so `internal/nat`'s `deadlineConn` wrapper implements deadlines itself — a rung releases its read loop by setting a deadline in the past, which is the only way to unblock it without closing a conn it does not own. **Every rung must then restore the zero deadline**, or the next one inherits a permanently-expired deadline and every read it makes fails instantly. `wireguard.Bind.Close` and `quictun.packetConn.Close` both do this; `tunnel/cascade_test.go` is the regression test (it runs over `nat.WithDeadlines`, not a bare socket, specifically so this is exercised), and it fails without it. `deadlineConn.Read` also checks the deadline non-blockingly *before* selecting on `packets`, not only alongside it — a select with two ready cases picks between them pseudorandomly, so without the pre-check an expired deadline released only about half of a parked reader's calls, making a rung's teardown probabilistic instead of bounded.
- **The punch retry is lockstep, like `Hello.PunchProbe` before it.** Each side's ICE agent checks connectivity against its own NAT, so "did the punch work" has two independent answers; `negotiate.Hello.PunchAttempts` (effective count = `min(local, peer)`, `0` meaning `1` so an older peer still agrees) and `PunchOutcome` (`tier.go`'s `punch`/`ExchangePunchOutcome`) make the two sides swap verdicts and retry together only when *both* agree to. Without that swap, one side landing its `Connect` a moment before the other's context expires would have the two sides reading different message types off the same negotiate stream on the next attempt — a hang, not a fallback. A side whose own punch succeeded but whose peer disagreed must close that agent and retry, not keep the working substrate: a substrate the peer does not also hold is not usable. Each retry gets a fresh `nat.Agent`; it is documented as not reusable across attempts.
- **A rung that cannot release its read loop abandons the substrate, and that is terminal, not just a failure of that rung.** `Bind.Close`/`packetConn.Close` wait `closeGrace` (1s) for the deadline-past trick above to work; if it doesn't, they close the substrate themselves rather than hang forever, and return a sentinel (`wireguard.ErrSubstrateAbandoned` / `quictun.ErrSubstrateAbandoned`) instead of failing silently. Each tier folds its own sentinel into `tier.OutcomeSubstrateAbandoned` behind `Tier.SubstrateAbandoned`, which is a *method* rather than a shared package sentinel precisely because no tier owns the substrate and none depends on another — `Set.SubstrateAbandoned` asks every registered tier, because by the time the cascade has to act the error is often composed with unrelated teardown errors and which tier produced it is no longer the question. `climbCascade` and `serveUpperTiers` both check for that outcome and go straight to the libp2p floor instead of trying the next rung on a closed conn — which would otherwise surface as an unrelated handshake failure on whichever tier was tried next. This was a real field bug: it is what made an already-uncommon WireGuard failure present as "WireGuard *and* QUIC both didn't work."
- **The host acks a rung before standing it up** (`tier.go::serveUpperTiers`): `quictun.Accept` blocks until the peer dials, so a host that stood the tier up before acknowledging would deadlock against a client still waiting for the ack. A refused rung is signalled by *nothing* — the client is running the same tier on the same substrate and discovers the failure itself.
- **Datagram substrates are message-oriented** (`transport/datagram.go`): a netstack UDP conn or a QUIC `ReceiveDatagram` returns one whole message per call and truncates on a short buffer. `internal/udp`'s two-`io.ReadFull` length-prefix framing would break on that, so `NewDatagramStream` buffers the unread remainder across calls and presents a real byte stream. This is why `tcp`/`udp` needed no changes for the new tiers.
- **Nothing is persisted between runs.** The libp2p peer ID and every `tier.Identity` — the WireGuard keypair, the QUIC leaf certificate — are generated fresh per process, by `tier.NewIdentities` off the same `implementations` table that builds the tiers. All of them are generated whatever the `-tunnel-mode`, because the mode decides which tiers this side *offers*; a peer that withheld a credential would force the libp2p floor on a session that could have done better. The QUIC tier therefore has no CA to validate against: it pins the peer's certificate by SHA-256 fingerprint received over the (Noise-encrypted) negotiate stream, via `VerifyPeerCertificate`. `InsecureSkipVerify` is set but is not the whole story — do not remove the pinning callback with it.
- **The token's version and the protocol's generation are two axes, and `p2p.ProtocolsFor` is the only place they meet.** `TokenVersion` (currently 1; the unversioned original build is `TokenVersionLegacy = 0`) versions how the token is *written*; `ProtocolGeneration` (currently 2, i.e. `/mtunnel/2.0.0` and `/mtunnel/negotiate/2.0.0`) versions what the streams *speak*. They are different numbers on purpose and may move independently. `Token.Encode` has a value receiver and always stamps `TokenVersionCurrent` whatever the caller left in the field, so the emitted version is a property of the build rather than of what each call site remembered; `DecodeToken` does the version check itself, because every caller wants the same answer and the point of a version is to fail when the token is read rather than several round trips later. The client then feeds `ProtocolsFor`'s result into `p2p.Config.Protocols`, so which channel a stream opens on is *derived from the token* — the zero value means `CurrentProtocols()`, which is what makes a config built before any token is decoded already correct for the host.
- **Token compatibility rests on gob's semantics, not on framing of our own** (`p2p/token.go`): gob omits zero values (so an original token simply arrives with no version — that absence *is* the detection), ignores unknown fields (so the original build decodes a token from this one and fails at the protocol instead, which is the intended failure), and matches on the underlying kind (so `Network` moving from `string` to `transport.Network` changed no bytes). Adding a field is therefore compatible; changing a field's kind or reusing a name is not, and must go through a new `TokenVersion`. `token_test.go` pins all of this with shadow structs, which are the only way to write a version `Encode` will not produce.

### Control channel

`internal/control` is advisory and optional. Host mode reads newline-delimited JSON requests from stdin (`LIST`, `DISCONNECT`, `SHUTDOWN`) and both roles emit JSON events to stdout (`TOKEN`, `CONNECTED`, `DISCONNECT`, `LIST`, `ERROR`). `CONNECTED` carries the negotiated `tier`, typed as `negotiate.Tier` rather than a bare string so the one place a tier leaves the process cannot report one selection could never have chosen — both are named string types, so the JSON is byte-identical. Marshalling/write failures are logged, never propagated. The client passes `nil` sessions, so `LIST`/`DISCONNECT` are ignored there.

JSON here, gob everywhere else, is deliberate: the control channel's audience is an external, language-agnostic supervisor, while the token and the negotiate stream are only ever exchanged between two instances of this exact binary.

## Testing conventions

Stdlib `testing` only — table-driven, `t.Run`/`t.Parallel`, no testify. The tier work is testable without any real network, and new work there should stay that way:

- `internal/wireguard` runs two real `device.Device` instances against each other over an in-memory `conn.Bind`, so the Noise handshake is genuinely exercised.
- `internal/tunnel/cascade_test.go` runs the real ladder — real WireGuard, real QUIC handshake, real substrate hand-off — over a loopback UDP pair, with only the punch itself replaced. `climbCascade` takes its punch as an injected `punchFactory` for exactly this reason; keep new tier attempts injectable the same way.
- `internal/tier/identity_test.go` iterates `implementations` rather than naming tiers, checking that every entry's identity has the matching `Kind` and that the tier built from it has the matching `ID`. That is what makes the single registration table load-bearing: a new tier is covered by it the moment it is registered, and a mismatched entry fails here rather than as a handshake that never completes.

What genuinely needs field verification, and should not be faked: ICE against real NAT types, timeout tuning under real loss, and the cascade's real-world fallback timing.
