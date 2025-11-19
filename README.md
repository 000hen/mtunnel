# mtunnel

A minimal Go playground for a simple tunneling/port-forwarding concept plus a tiny test web server. The project has two entry points:

- `cmd/tunnel`: CLI that can act as a host or client and forward a port.
- `cmd/webserver`: Simple HTTP server for testing the tunnel and providing health/echo endpoints.

## Features

### Tunnel CLI (`cmd/tunnel`)

Flags:

- `-port <int>`: Port to forward. In client mode this is the local port to connect to.
- `-network <tcp|udp>`: Network type for the local connection. Default: `tcp`.
- `-actas <host|client>`: Role to run as. Default: `host`.
- `-token <string>`: Connection token (required in client mode).

Behavior:

- Host mode creates a forwarding endpoint for the specified port using the selected network.
- Client mode connects using a provided token and forwards traffic to the local port.

### Test Web Server (`cmd/webserver`)

Endpoints:

- `/` Main HTML page showing request metadata (method, path, remote address, etc.).
- `/health` Health probe returning `{"status":"ok"}`.
- `/api/echo` Simple JSON echo with a timestamp.

Default listen port: `8080`.

## Requirements

- Go 1.22+ (module file present; adjust if needed)

## Building

From repository root:

```powershell
# Build tunnel CLI
go build ./cmd/tunnel

# Build webserver
go build ./cmd/webserver
```

Artifacts will be placed in the current directory (e.g., `tunnel.exe`, `webserver.exe` on Windows).

## Running

### Start the test web server

```powershell
./webserver.exe
# or without prior build
go run ./cmd/webserver
```

It will listen on `http://localhost:8080`.

### Run tunnel in host mode

```powershell
# Example: host forwarding TCP port 8080
./tunnel.exe -actas host -network tcp -port 8080
```

### Run tunnel in client mode

```powershell
# Replace TOKEN with a valid token and choose a local port
./tunnel.exe -actas client -token TOKEN -port 8080
```

If `-token` is missing in client mode the program will panic.

## Development Tips

- Use `go fmt ./...` and `go vet ./...` for formatting and static checks.
- Add tests under a new `internal/` or `pkg/` structure if functionality grows.

## Folder Structure

```text
go.mod
cmd/
  tunnel/
    client.go
    forward.go
    host.go
    main.go
    network.go
  webserver/
    main.go
```

## License

Licensed under the MIT License. See `LICENSE` for full text.

---
Feel free to extend or refine this README as the tunnel logic evolves.
