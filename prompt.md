The project tunnels TCP traffic, including Minecraft connections, through libp2p.

## Problem

The tunnel initially performs well:

* Latency is approximately 10 ms.
* The connection is stable for roughly 5–10 minutes.

After that period, latency becomes continuously unstable:

* It fluctuates between approximately 10 ms and 5000 ms.
* The instability continues for the rest of the connection.
* It is not a single short spike at the 5–10 minute mark.
* Minecraft exposes the problem clearly because it uses a long-lived TCP connection and is sensitive to latency and head-of-line blocking.

Your task is to investigate, instrument, and improve the connection stability.

## Important constraints

Do not assume that the problem is caused by `io.Copy`.

Do not make large architectural changes without evidence.

Do not hide the problem by adding large buffers, retries, arbitrary sleeps, or reconnect loops.

Do not automatically reconnect an existing Minecraft TCP connection unless there is no other viable option, because reconnecting would terminate the game session.

Prefer measurable, isolated changes and A/B testing.

Keep the code maintainable and modular.

## Areas that must be investigated

### 1. Actual transport path used by every tunnel stream

Determine whether the Minecraft stream is using:

* Direct QUIC
* Direct TCP with Yamux
* WebRTC Direct
* WebTransport
* Circuit relay

For every opened or accepted tunnel stream, log at least:

* Remote peer ID
* libp2p connection ID
* Whether the connection is limited
* Transport
* Stream multiplexer
* Local multiaddress
* Remote multiaddress
* Whether `/p2p-circuit` appears in the path
* Time since process startup
* Time since the peer connection was established

Use information from:

```go
stream.Conn()
stream.Conn().Stat()
stream.Conn().ConnState()
stream.Conn().LocalMultiaddr()
stream.Conn().RemoteMultiaddr()
```

The logs must clearly show whether the stream is direct or relayed.

### 2. Limited connection behavior

Review the current use of:

```go
network.WithAllowLimitedConn(...)
```

A long-lived Minecraft stream may be opened over a relay connection before hole punching completes. Once opened, that stream normally remains attached to its original libp2p connection and does not automatically migrate to a later direct connection.

Implement a direct-first stream policy:

1. Attempt to open the stream without allowing limited connections.
2. Wait for a reasonable direct-connection timeout.
3. Only use a limited relay connection when relay fallback is explicitly enabled.
4. Log whenever relay fallback is used.
5. Keep direct-only behavior configurable for testing.

Do not silently fall back to relay without recording it.

### 3. Client-side DHT lifecycle

The client currently appears to keep its Kademlia DHT running after peer discovery and connection establishment.

Investigate whether the active DHT causes:

* Routing-table growth
* Periodic routing-table refreshes
* Additional peer connections
* Background DHT queries
* Upload traffic
* Router queueing
* Connection-manager pressure
* Persistent latency instability after several minutes

The DHT has a default routing-table refresh interval close to 10 minutes, but the observed problem is persistent after it begins, not merely a short refresh spike.

Test at least these variants:

* Current behavior
* Close the client DHT immediately after successful peer discovery and connection
* Disable client DHT auto-refresh
* Use a lightweight or temporary discovery host if appropriate

The client should not participate in the public DHT longer than necessary unless there is a concrete reason.

### 4. Host and client libp2p configuration

Do not use one identical host configuration for both roles without evaluating the consequences.

Review whether the client actually needs:

* AutoRelay reservations
* NAT service
* Full DHT participation
* Public reachability advertisement
* Relay service-related background activity

Separate the configuration into explicit roles, for example:

```go
NewServerHost(...)
NewClientHost(...)
```

The client still needs to be able to dial a host through a relay when necessary, but it may not need to obtain relay reservations for itself.

### 5. AutoRelay configuration

Review this pattern:

```go
libp2p.EnableAutoRelayWithStaticRelays(
    dht.GetDefaultBootstrapPeerAddrInfos(),
)
```

Determine whether using all default DHT bootstrap peers as static relay candidates causes:

* Too many desired relay reservations
* Too many persistent connections
* Reservation refresh traffic
* Address updates
* Connection churn
* Non-latency-aware relay selection

If AutoRelay is required, limit it to a small, intentional relay set and a small desired relay count.

Prefer dedicated relays over arbitrary public bootstrap nodes for low-latency game traffic.

### 6. Transport-specific behavior

Create controlled test configurations for:

* QUIC-only direct
* TCP/Yamux-only direct
* WebRTC Direct-only where possible
* Relay-only
* Current default transport selection

Each test must log the selected transport.

Determine whether the persistent instability is associated with one transport.

In particular, consider:

* TCP-over-TCP head-of-line blocking when the outer transport is TCP
* Yamux stream flow control
* Ordered reliable WebRTC DataChannel behavior
* QUIC packet loss and retransmission
* Router or ISP UDP behavior
* NAT mapping changes
* Socket send and receive queue growth

Do not claim that QUIC eliminates head-of-line blocking inside a single ordered stream. Minecraft still uses one long-lived ordered byte stream.

### 7. Background activity and resource growth

Add lightweight periodic diagnostics, preferably every 10 seconds, including:

* Number of libp2p peers
* Number of libp2p connections
* Number of streams
* DHT routing-table size
* Number of goroutines
* Process memory usage
* CPU usage if practical
* Bytes sent and received
* Current active tunnel transport
* Whether the active connection is limited
* Current direct and relay connections to the target peer

Make it possible to correlate the exact point at which latency becomes unstable with changes in these metrics.

Avoid excessive logging in normal production mode. Put detailed metrics behind a debug or diagnostic option.

### 8. Data-path backpressure

Review the current bidirectional `io.Copy` implementation.

Determine whether either direction becomes blocked for long periods.

Add diagnostics around long-running writes without changing the byte-stream semantics.

Possible measurements include:

* Bytes transferred per direction
* Time since last successful read
* Time since last successful write
* Duration of blocked writes
* Whether one direction stops progressing while the other continues
* Socket-level TCP information where available

Do not introduce arbitrary application-level buffering unless measurements show that it is required.

Large buffering may make latency worse by increasing queueing delay.

### 9. Minecraft-specific traffic behavior

Test whether the instability correlates with:

* Loading new chunks
* Teleporting
* Joining the server
* Large plugin messages
* Entity-heavy areas
* Standing still for at least 60 seconds
* Server-side garbage collection
* Low server TPS

Compare:

1. Direct Minecraft connection without MTunnel
2. MTunnel using direct QUIC
3. MTunnel using direct TCP/Yamux
4. MTunnel using relay

This is required to distinguish tunnel latency from Minecraft server tick latency.

## Required implementation

Implement a diagnostic mode, such as:

```text
--diagnostic
```

It should produce structured logs suitable for comparing test runs.

Also implement configurable connection policies, for example:

```text
--connection-mode=direct-only
--connection-mode=direct-first
--connection-mode=relay-only
--transport=quic
--transport=tcp
--transport=webrtc
--transport=default
```

Exact CLI names may be changed to match the existing architecture, but the capabilities must exist.

## Recommended connection behavior

For Minecraft and other latency-sensitive TCP traffic:

* Prefer direct connections.
* Do not open the application stream over a limited relay connection while a direct connection is still being established.
* Make relay fallback explicit.
* Record the selected path.
* Do not expect an existing stream to migrate automatically from relay to direct.
* If the only available path is relay, expose that state clearly to the caller or UI.

## Experimental method

Change one variable at a time.

For each test run, record:

* Commit SHA
* Client and host configuration
* Transport
* Direct or relay status
* Network type
* Start time
* Time when instability begins
* Peer count over time
* Connection count over time
* DHT routing-table size over time
* Bytes transferred
* Minecraft activity at the time
* Latency distribution

Run each meaningful configuration for at least 20–30 minutes.

Do not conclude that a change fixed the issue based on a short test.

## Expected output

Provide:

1. A concise explanation of the likely root causes, ranked by confidence.
2. Evidence from the current code for each suspected cause.
3. The diagnostic instrumentation you added.
4. The isolated A/B test configurations you added.
5. The code changes used to improve stability.
6. Any remaining uncertainty.
7. Exact steps for reproducing and testing the issue.
8. A table comparing the test results.
9. A recommendation for the default production configuration.

The final recommendation should be evidence-based.

Start by inspecting the repository and documenting the existing connection lifecycle before modifying code.
