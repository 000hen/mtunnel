package main

import (
	"encoding/json"
	"log"
	"os"
)

var (
	TOKEN      = "TOKEN"
	DISCONNECT = "DISCONNECT"
	CONNECTED  = "CONNECTED"
	LIST       = "LIST"
)

type InputAction struct {
	Action    string `json:"action"`
	SessionId string `json:"session_id"`
}

type OutputAction struct {
	Action    string   `json:"action"`
	SessionId string   `json:"session_id,omitempty"`
	Sessions  []string `json:"sessions,omitempty"`
	Token     string   `json:"token,omitempty"`
}

func handleIOAction(sessionManager *SessionManager) {
	decoder := json.NewDecoder(os.Stdin)

	for {
		var input InputAction
		err := decoder.Decode(&input)
		if err != nil {
			if err.Error() == "EOF" {
				log.Println("Input stream closed, stopping IO action handler")
				return
			}

			log.Printf("Error decoding input action: %v", err)
			continue
		}

		switch input.Action {
		case LIST:
			sessions := sessionManager.ListSessions()
			output := OutputAction{
				Action:   LIST,
				Sessions: sessions,
			}

			sendOutputAction(output)
		case DISCONNECT:
			err := sessionManager.ForceCloseSession(input.SessionId)
			if err != nil {
				log.Printf("Failed to disconnect session %s: %v", input.SessionId, err)
				continue
			}

			sessionManager.RemoveSession(input.SessionId)
			log.Printf("Session %s disconnected successfully", input.SessionId)

			output := OutputAction{
				Action:    DISCONNECT,
				SessionId: input.SessionId,
			}

			sendOutputAction(output)
		default:
			log.Printf("Unknown action received: %s", input.Action)
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
