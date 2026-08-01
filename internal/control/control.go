// Package control implements the optional JSON control channel: status events
// written to stdout and management requests (list, disconnect, shutdown) read from
// stdin. It lets an external supervisor observe and steer a running tunnel.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Action names a control message exchanged over the JSON channel.
type Action string

const (
	TOKEN      Action = "TOKEN"
	DISCONNECT Action = "DISCONNECT"
	CONNECTED  Action = "CONNECTED"
	LIST       Action = "LIST"
	ERROR      Action = "ERROR"
	SHUTDOWN   Action = "SHUTDOWN"
)

// Input is a control request read from stdin.
type Input struct {
	Action    Action  `json:"action"`
	SessionId peer.ID `json:"session_id"`
}

// Output is a status event written to stdout. Fields are omitted when empty so
// each event carries only what is relevant to its action.
type Output struct {
	Action    Action    `json:"action"`
	SessionId peer.ID   `json:"session_id,omitempty"`
	Sessions  []peer.ID `json:"sessions,omitempty"`
	Token     string    `json:"token,omitempty"`
	Addr      string    `json:"addr,omitempty"`
	Port      int       `json:"port,omitempty"`
	Error     string    `json:"error,omitempty"`
	// Tier reports the negotiated tunnel data-plane tier on CONNECTED events.
	Tier string `json:"tier,omitempty"`
}

// Sessions is the subset of session management the control channel drives in
// response to LIST and DISCONNECT requests. The host role supplies a real
// implementation; the client role passes nil.
type Sessions interface {
	List() []peer.ID
	Remove(peer.ID)
}

// Emitter writes status events as newline-delimited JSON to an underlying writer
// (stdout in production). It is safe for concurrent use, so events from different
// goroutines never interleave on the wire.
type Emitter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewEmitter returns an Emitter that writes events to w.
func NewEmitter(w io.Writer) *Emitter {
	return &Emitter{w: w}
}

// Emit marshals out to JSON and writes it as a single line. The control channel is
// advisory, so marshalling and write errors are logged rather than propagated.
func (e *Emitter) Emit(out Output) {
	data, err := json.Marshal(out)
	if err != nil {
		log.Printf("Error marshaling output action: %v", err)
		return
	}

	data = append(data, '\n')

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.w.Write(data); err != nil {
		log.Printf("Error writing output action: %v", err)
	}
}

// Handle reads control requests from in and dispatches them until in is exhausted,
// a decode error occurs, or ctx is cancelled. sessions may be nil when session
// management is unavailable (client mode), in which case LIST and DISCONNECT are
// ignored. A SHUTDOWN request invokes requestShutdown and returns.
func Handle(ctx context.Context, in io.Reader, e *Emitter, sessions Sessions, requestShutdown func(reason string)) {
	decoder := json.NewDecoder(in)

	// Buffered so the reader goroutine's final send never blocks once this function
	// has returned (e.g. on ctx cancellation), letting that goroutine exit on its
	// next decode instead of leaking forever on the send.
	inputChan := make(chan Input, 1)
	errChan := make(chan error, 1)

	go func() {
		for {
			var input Input
			if err := decoder.Decode(&input); err != nil {
				errChan <- err
				return
			}
			inputChan <- input
		}
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("IO handler shutting down...")
			return

		case err := <-errChan:
			if errors.Is(err, io.EOF) {
				log.Println("Input stream closed, stopping IO action handler")
				return
			}
			// The reader goroutine has already exited on this error, and a
			// json.Decoder cannot resync after a malformed value, so no further
			// input can arrive. Stop the handler rather than looping on a channel
			// that will never receive again.
			log.Printf("Error decoding input action, stopping IO action handler: %v", err)
			return

		case input := <-inputChan:
			switch input.Action {
			case LIST:
				if sessions == nil {
					log.Println("LIST action ignored: session management not available in this mode")
					continue
				}
				e.Emit(Output{
					Action:   LIST,
					Sessions: sessions.List(),
				})

			case DISCONNECT:
				if sessions == nil {
					log.Println("DISCONNECT action ignored: session management not available in this mode")
					continue
				}
				// Remove emits the DISCONNECT event itself (once), so we do not send
				// another here.
				sessions.Remove(input.SessionId)
				log.Printf("Disconnect requested for session %s", input.SessionId)

			case SHUTDOWN:
				log.Println("Shutdown action received from stdin")
				if requestShutdown != nil {
					requestShutdown("shutdown action from stdin")
				}
				return

			default:
				log.Printf("Unknown action received: %s", input.Action)
			}
		}
	}
}
