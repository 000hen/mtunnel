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

### What the tier cascade changes about them

The pluggable data plane (see the README's "Tunnel tiers") was not built for this
investigation, but it bears on it directly, because on the WireGuard and QUIC
tiers the forwarded traffic **does not ride a libp2p stream at all** — it rides a
socket punched independently by `pion/ice`.

- Hypothesis 1 stops being reachable on an upper tier: there is no application
  stream bound to a relayed connection, so there is nothing that could fail to
  migrate. libp2p may still be relayed for signalling without affecting the data
  path.
- Hypothesis 4 changes shape: the tier, not `-transport`, now determines what
  carries the bytes, and the two are independent axes.
- Hypothesis 2 is untouched — the client DHT lifecycle is the same either way.
- Hypothesis 5 is untouched and still worth watching; `tunnel_copy_progress` and
  `tunnel_blocked_write` live in `internal/tcp` and fire identically on every
  tier.

This makes the tier rows a genuine discriminator rather than another variant: if
instability persists at the same onset time on WireGuard, hypotheses 1 and 4 are
effectively ruled out and the cause lies outside libp2p's data path entirely. If
it disappears, that is the strongest available evidence for them.

## Implemented instrumentation

Every session, `-diagnostic` or not, logs enough to say *which phase* fell back
without reproducing the failure:

- `tunnel_tier_selected` once per session: the tier the cascade settled on,
  including the libp2p floor.
- `tunnel_tier_fallback` (`slog.Warn`) once per rung that did not come up: tier,
  outcome (the phase that stopped it, or `substrate-abandoned` — see below),
  duration, and cause. A `punch-failed` outcome means the shared substrate never
  came up at all, so no upper tier was attempted.
- `tunnel_punch_retry` (`slog.Warn`) between punch attempts, when
  `-punch-attempts` allows more than one: attempt number, agreed attempt count,
  peer, and the cause of the attempt that just failed.
- `tunnel_substrate_abandoned` (`slog.Warn`) when a rung's teardown could not
  release its own read loop in time and closed the punched socket to break out.
  This is the one record that changes what happened next: the cascade treats it
  as terminal and goes straight to the libp2p floor rather than trying the next
  rung on a socket that is already gone. Before this existed, that sequence
  presented as an unrelated handshake failure on whichever tier was tried next —
  see "What it caught" in `plan/review/010-cascade-test-bypasses-deadlineconn.md`
  for the bug this uncovered.
- `tunnel_nat_punch` (`nat` package): outcome and duration always; candidate
  types and the selected pair only `if -diagnostic`.

With `-diagnostic`, stderr additionally contains JSON records suitable for JSONL
ingestion:

- `test_configuration`: commit SHA, role, network, connection mode, transport,
  DHT mode, tunnel mode, direct/punch-gather/punch/handshake timeouts, punch
  attempts, configured relay and STUN counts, and UTC start time.
- `tunnel_stream_path`: remote peer, connection ID, limited/direct state,
  transport, stream multiplexer, security protocol, local/remote multiaddresses,
  `/p2p-circuit` presence, process uptime, and connection age. It is emitted for
  every opened and accepted tunnel stream, and once per session for the negotiate
  stream (`event: negotiate-opened`).
- `tunnel_tier_negotiated` once per session: both sides' advertised tiers, the
  forced override if any, and the resolved tier.
- `tunnel_tier_attempt` once per rung *attempted*, including successes — a
  superset of the always-on `tunnel_tier_fallback`/`tunnel_tier_selected` pair
  above, useful for timing rather than triage.
- `tunnel_diagnostics` every 10 seconds: peers, connections, streams, DHT table
  size, goroutines, heap use, GC cycles, cumulative/rate bytes, active tunnel
  tier, active tunnel transport/limited state, and direct/relay connection counts
  to the target.
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

For each row below, start the host and client with the same `-transport`,
`-connection-mode`, and `-tunnel-mode`, capture stderr separately, and keep the
Minecraft TCP connection alive for at least 30 minutes:

```powershell
# Host example
./tunnel.exe -port 25565 -network tcp -diagnostic `
  -connection-mode direct-first -transport quic -tunnel-mode libp2p 2> host-quic.jsonl

# Client example
./tunnel.exe -token <TOKEN> -port 25565 -diagnostic `
  -connection-mode direct-first -transport quic -tunnel-mode libp2p `
  -dht-mode close-after-connect 2> client-quic.jsonl
```

**Pass `-tunnel-mode` explicitly on every run, including the `-transport` rows.**
The default is now `auto`, which may put the data on WireGuard or QUIC and leave
`-transport` describing only the signalling connection — which would silently
confound rows 2–8, since those were designed to compare libp2p data paths. Rows
2–8 therefore need `-tunnel-mode libp2p`. On a forced upper tier, hard-fail rather
than fallback is the point: a `wireguard` or `quic` run that cannot establish its
tier should abort, not quietly produce a libp2p row under a WireGuard label.

Change exactly one flag between runs. Record ping/latency percentiles and mark
the UTC time of joining, chunk loading, teleporting, entity-heavy activity, and
at least 60 seconds standing still. Also run the same Minecraft client directly
against the server without MTunnel and record server TPS/GC pauses.

Recommended order:

1. Direct Minecraft baseline without MTunnel.
2. MTunnel `libp2p + default + direct-first + current` (old DHT control).
3. Change only DHT mode to `close-after-connect`.
4. Change only DHT mode to `no-refresh`.
5. Restore `close-after-connect`; run `quic`, then `tcp`, then `webrtc`.
6. Run `relay-only + default` as the explicit relay control.
7. If relay is unacceptable, confirm `direct-only` fails clearly rather than
   opening a latent game session.
8. `-tunnel-mode wireguard`, holding transport/connection/DHT flags at the row-3
   values so the tier is the only difference from that row.
9. `-tunnel-mode quic`, same holding.
10. `-tunnel-mode auto`, to confirm the shipped default lands on the tier the
    forced runs showed to be best, and to time how long the cascade takes to get
    there.

### Confirming which tier actually carried the traffic

Do not take the flag's word for it. Per session the log should show:

- `tunnel_tier_selected` naming the expected tier — this one needs no
  `-diagnostic` and is the fastest check.
- `tunnel_tier_negotiated` with the expected `resolved` tier, on both sides
  (`-diagnostic` only).
- `tunnel_nat_punch` with `outcome: success` for any upper-tier row. With
  `-diagnostic`, it also carries the candidate types — a relayed or srflx-only
  pair is worth noting, since it predicts a worse path than a host-candidate
  pair.
- No `tunnel_tier_fallback` for the tier under test, and critically no
  `tunnel_substrate_abandoned` — the latter means an upper tier did not merely
  fail, it took the punched socket with it, so anything below it in the cascade
  never got a real attempt. Treat that as a run to redo, not a data point on the
  tier that was "tried" next.
- `tunnel_tier_attempt` per rung (`-diagnostic` only). On an `auto` run this is
  where the cascade's real cost shows up: sum the durations of the failed rungs.
  If `-punch-attempts` is above 1, `tunnel_punch_retry` shows how many of those
  attempts were spent on the punch itself before a rung was ever tried.
- `active_tunnel_tier` in every `tunnel_diagnostics` record, which is the check
  that matters most — it is the only one that would catch a tier changing, or
  never having been what the negotiation claimed, mid-session.
- On an upper tier, **no** `tunnel_stream_path` records with `event: opened` or
  `accepted`. Only `negotiate-opened` should appear. Their absence is the direct
  confirmation that the forwarded data left libp2p's stream path; if per-connection
  records keep appearing, the run is a libp2p row regardless of what was negotiated.

## Results table

No credible 20–30 minute network result can be produced inside a unit-test
environment. Fill this table from the JSONL and Minecraft/server observations;
do not mark a variant fixed after a short run.

Every row below except the direct baseline names the tier it must be run on. The
first eight are libp2p-tier rows — they compare libp2p data paths, and are only
comparable to each other if the data actually stayed on libp2p.

| Variant | Tier | Duration | Path/transport observed | DHT peak | Peer/conn peak | Bytes in/out | Latency p50/p95/p99 | Instability start | Minecraft activity | Result |
|---|---|---:|---|---:|---:|---:|---|---|---|---|
| Direct, no tunnel | n/a | pending | direct TCP | n/a | n/a | pending | pending | pending | pending | pending |
| default + direct-first + current | libp2p | pending | diagnostic log | pending | pending | pending | pending | pending | pending | pending |
| default + direct-first + close-after-connect | libp2p | pending | diagnostic log | 0 after connect | pending | pending | pending | pending | pending | pending |
| default + direct-first + no-refresh | libp2p | pending | diagnostic log | pending | pending | pending | pending | pending | pending | pending |
| quic + direct-first | libp2p | pending | QUIC/direct expected | 0 after connect | pending | pending | pending | pending | pending | pending |
| tcp + direct-first | libp2p | pending | TCP/Yamux/direct expected | 0 after connect | pending | pending | pending | pending | pending | pending |
| webrtc + direct-first | libp2p | pending | WebRTC Direct expected | 0 after connect | pending | pending | pending | pending | pending | pending |
| default + relay-only | libp2p | pending | circuit relay expected | 0 after connect | pending | pending | pending | pending | pending | pending |
| default + direct-first + close-after-connect | wireguard | pending | punched UDP, no per-conn stream_path expected | 0 after connect | pending | pending | pending | pending | pending | pending |
| default + direct-first + close-after-connect | quic | pending | punched UDP, no per-conn stream_path expected | 0 after connect | pending | pending | pending | pending | pending | pending |
| default + direct-first + close-after-connect | auto | pending | resolved tier + cascade duration | 0 after connect | pending | pending | pending | pending | pending | pending |

For the three tier rows, also record from `tunnel_nat_punch` whether the punch
succeeded and on what candidate types, whether `tunnel_punch_retry` fired (and
on which attempt it recovered), and from `tunnel_tier_attempt` how long the
cascade spent on rungs that failed. A `wireguard` or `quic` row where the punch
failed is not a data point about that tier — it is a data point about the
network, and should be recorded as such rather than left blank. Likewise, a row
where `tunnel_substrate_abandoned` fired is a data point about whatever kept
that rung's teardown from releasing its read loop, not about the tier tried
next — re-run rather than record the next tier as a failure.

Two runs worth doing specifically for this: one with `-punch-attempts 1` on a
connection that otherwise falls back, to confirm the retry is what changed the
outcome rather than run-to-run variance; and one with `-diagnostic` on a run
that still falls back, to get the candidate-level detail `tunnel_nat_punch`
only emits under that flag.

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

The tunnel-mode recommendation is `auto`, the shipped default — but note what
that is and is not claiming. It is a design argument: an upper tier removes
libp2p's stream multiplexer and, when the punch succeeds, the relay from the data
path entirely, which is a strictly shorter path than the libp2p tier can offer.
It is **not** a measurement. The tier rows above are exactly as unfilled as the
rest of the table, so nothing here should be read as evidence that the cascade
resolved the reported instability.

Two things would change the recommendation, and are worth watching for in the
first long run: a punch that fails on the affected network makes `auto` strictly
worse than `libp2p` by the cost of the failed attempts, and instability that
persists identically on WireGuard would locate the cause outside libp2p's data
path — the case where this whole line of investigation has been looking in the
wrong place.
