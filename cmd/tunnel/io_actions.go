package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"

	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	TOKEN      = "TOKEN"
	DISCONNECT = "DISCONNECT"
	CONNECTED  = "CONNECTED"
	LIST       = "LIST"
	ERROR      = "ERROR"
	SHUTDOWN   = "SHUTDOWN"
)

type InputAction struct {
	Action    string  `json:"action"`
	SessionId peer.ID `json:"session_id"`
}

type OutputAction struct {
	Action    string    `json:"action"`
	SessionId peer.ID   `json:"session_id,omitempty"`
	Sessions  []peer.ID `json:"sessions,omitempty"`
	Token     string    `json:"token,omitempty"`
	Addr      string    `json:"addr,omitempty"`
	Port      int       `json:"port,omitempty"`
	Error     string    `json:"error,omitempty"`
}

func handleIOAction(ctx context.Context, sessionManager *SessionManager, requestShutdown func(reason string)) {
	decoder := json.NewDecoder(os.Stdin)

	inputChan := make(chan InputAction)
	errChan := make(chan error)

	go func() {
		for {
			var input InputAction
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
			log.Printf("Error decoding input action: %v", err)
			continue

		case input := <-inputChan:
			switch input.Action {
			case LIST:
				if sessionManager == nil {
					log.Println("LIST action ignored: session management not available in this mode")
					continue
				}
				sessions := sessionManager.ListSessions()
				sendOutputAction(OutputAction{
					Action:   LIST,
					Sessions: sessions,
				})

			case DISCONNECT:
				if sessionManager == nil {
					log.Println("DISCONNECT action ignored: session management not available in this mode")
					continue
				}
				sessionManager.RemoveSession(input.SessionId, true)
				log.Printf("Session %s disconnected successfully", input.SessionId)
				sendOutputAction(OutputAction{
					Action:    DISCONNECT,
					SessionId: input.SessionId,
				})

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

func sendOutputAction(output OutputAction) {
	data, err := json.Marshal(output)
	if err != nil {
		log.Printf("Error marshaling output action: %v", err)
		return
	}

	data = append(data, '\n')

	_, err = os.Stdout.Write(data)
	if err != nil {
		log.Printf("Error writing output action to stdout: %v", err)
		return
	}
}
