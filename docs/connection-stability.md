# Connection stability investigation

## Existing lifecycle (pre-change baseline)

The single binary created the same libp2p host for both roles. That host enabled
hole punching, AutoRelay over every default DHT bootstrap peer, NAT port mapping,
AutoNATv2, and the NAT service. The client then started a ModeClient Kademlia DHT,
discovered and connected to the target, and kept the DHT alive for the entire
Minecraft session. Every local TCP connection immediately called `NewStream`
with `network.WithAllowLimitedConn`, so a long-lived Minecraft stream could bind
to a relay before hole punching produced a direct connection. The stream then
remained on that connection. TCP forwarding used two symmetric `io.Copy` calls
with correct half-close behavior; the code contained no evidence that `io.Copy`
itself caused the latency change.

## Ranked hypotheses

| Rank | Suspected cause | Confidence before long-run tests | Evidence in the original code |
|---:|---|---|---|
| 1 | Minecraft stream opens on a limited relay and cannot migrate to a later direct connection | High | `OpenStream` unconditionally allowed limited connections; stream path was not logged |
| 2 | Client DHT/background peer activity contributes queueing or connection pressure near refresh time | Medium | client DHT remained bootstrapped and open for the whole session; no periodic metrics existed |
| 3 | Role-inappropriate AutoRelay/NAT work adds connections and churn on the client | Medium | host and client used the identical constructor and all default bootstrap peers as static relay candidates |
| 4 | One selected outer transport is sensitive to the user's NAT/router/loss pattern | Medium-low | default transport negotiation was uncontrolled and unlogged |
| 5 | Data-path writes stop progressing because queues or the remote endpoint stall | Unknown | only final `io.Copy` errors were visible; no progress or blocked-write timing existed |

These are hypotheses, not a claim that a 20–30 minute Minecraft run has already
validated the fix.

## Implemented instrumentation

With `-diagnostic`, stderr contains JSON records suitable for JSONL ingestion:

- `test_configuration`: commit SHA, role, network, connection mode, transport,
  DHT mode, direct timeout, and UTC start time.
- `tunnel_stream_path`: remote peer, connection ID, limited/direct state,
  transport, stream multiplexer, security protocol, local/remote multiaddresses,
  `/p2p-circuit` presence, process uptime, and connection age. It is emitted for
  every opened and accepted tunnel stream.
- `tunnel_diagnostics` every 10 seconds: peers, connections, streams, DHT table
  size, goroutines, heap use, GC cycles, cumulative/rate bytes, active tunnel
  transport/limited state, and direct/relay connection counts to the target.
- `tunnel_copy_progress` every 10 seconds per TCP direction: bytes and time since
  the last successful read/write.
- `tunnel_blocked_write` when a completed write took at least 250 ms. This is a
  measurement only; byte-stream semantics and buffer size are unchanged.

CPU is intentionally not estimated from portable runtime counters. Capture a
CPU profile or OS process counters alongside a run when CPU correlation is
needed.

## Isolated configurations and behavior changes

- `direct-only`: never permits a limited stream and waits for a direct
  connection before failing.
- `direct-first` (default): tries and waits for direct, then logs an explicit
  relay fallback. It never silently opts into a limited connection.
- `relay-only`: filters discovery addresses to circuit addresses and disables
  hole punching, making the relay A/B case intentional.
- `quic`, `tcp`, and `webrtc`: replace the default transport set and listen only
  on the selected transport. WebRTC retains TCP solely for public DHT discovery
  and filters the target connection to WebRTC Direct. `default` preserves
  libp2p negotiation.
- `close-after-connect` (default): closes the client DHT once discovery and the
  target connection succeed.
- `no-refresh`: keeps the client DHT but disables automatic routing-table
  refresh.
- `current`: preserves the prior client DHT lifecycle for a control run.
- Client host setup no longer runs AutoRelay, AutoNAT, or the NAT service. The
  server retains those functions, requests only one relay reservation, and uses
  at most three fallback candidates. `-relays` accepts a comma-separated,
  intentional dedicated relay set for production.

## Exact reproduction and A/B procedure

Build a uniquely identifiable binary:

```powershell
go build -o tunnel.exe ./cmd/tunnel
git rev-parse HEAD
```

For each row below, start the host and client with the same `-transport` and
`-connection-mode`, capture stderr separately, and keep the Minecraft TCP
connection alive for at least 30 minutes:

```powershell
# Host example
./tunnel.exe -port 25565 -network tcp -diagnostic `
  -connection-mode direct-first -transport quic 2> host-quic.jsonl

# Client example
./tunnel.exe -token <TOKEN> -port 25565 -diagnostic `
  -connection-mode direct-first -transport quic `
  -dht-mode close-after-connect 2> client-quic.jsonl
```

Change exactly one flag between runs. Record ping/latency percentiles and mark
the UTC time of joining, chunk loading, teleporting, entity-heavy activity, and
at least 60 seconds standing still. Also run the same Minecraft client directly
against the server without MTunnel and record server TPS/GC pauses.

Recommended order:

1. Direct Minecraft baseline without MTunnel.
2. MTunnel `default + direct-first + current` (old DHT control).
3. Change only DHT mode to `close-after-connect`.
4. Change only DHT mode to `no-refresh`.
5. Restore `close-after-connect`; run `quic`, then `tcp`, then `webrtc`.
6. Run `relay-only + default` as the explicit relay control.
7. If relay is unacceptable, confirm `direct-only` fails clearly rather than
   opening a latent game session.

## Results table

No credible 20–30 minute network result can be produced inside a unit-test
environment. Fill this table from the JSONL and Minecraft/server observations;
do not mark a variant fixed after a short run.

| Variant | Duration | Path/transport observed | DHT peak | Peer/conn peak | Bytes in/out | Latency p50/p95/p99 | Instability start | Minecraft activity | Result |
|---|---:|---|---:|---:|---:|---|---|---|---|
| Direct, no tunnel | pending | direct TCP | n/a | n/a | pending | pending | pending | pending | pending |
| default + direct-first + current | pending | diagnostic log | pending | pending | pending | pending | pending | pending | pending |
| default + direct-first + close-after-connect | pending | diagnostic log | 0 after connect | pending | pending | pending | pending | pending | pending |
| default + direct-first + no-refresh | pending | diagnostic log | pending | pending | pending | pending | pending | pending | pending |
| quic + direct-first | pending | QUIC/direct expected | 0 after connect | pending | pending | pending | pending | pending | pending |
| tcp + direct-first | pending | TCP/Yamux/direct expected | 0 after connect | pending | pending | pending | pending | pending | pending |
| webrtc + direct-first | pending | WebRTC Direct expected | 0 after connect | pending | pending | pending | pending | pending | pending |
| default + relay-only | pending | circuit relay expected | 0 after connect | pending | pending | pending | pending | pending | pending |

## Production recommendation and remaining uncertainty

The evidence available from code supports `direct-first`, `default` transport,
`close-after-connect`, a 15-second direct timeout, no client AutoRelay/NAT
service, and one server reservation from a small dedicated relay set as the
safest baseline. Use
`direct-only` for latency-sensitive Minecraft deployments that prefer a clear
failure to an unbounded relay-quality session. A dedicated, geographically close
relay remains preferable when fallback is required.

The outer transport recommendation is intentionally still `default`: without
long-run measurements on the affected ISP/router, selecting QUIC, TCP/Yamux, or
WebRTC by assertion would not be evidence-based. The diagnostics distinguish
tunnel queueing from server TPS/GC behavior and reveal whether the instability
coincides with DHT refresh, connection churn, relay use, transport choice, or a
stalled copy direction.
