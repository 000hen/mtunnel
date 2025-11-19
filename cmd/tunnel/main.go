package main

import (
	"flag"
	"net"
)

type ConnectionToken struct {
	Fingerprint [32]byte
	Network     string
	Host        net.IP
	Port        int
}

func main() {
	port := flag.Int("port", 0, "Port to forward, in client mode this is the local port to connect to")
	network := flag.String("network", "tcp", "Network type for local connection: tcp or udp")
	actas := flag.String("actas", "host", "Role to act as: host or client")
	token := flag.String("token", "", "Connection token for client mode")

	flag.Parse()

	switch *actas {
	case "host":
		runHost(*network, *port)
	case "client":
		if *token == "" {
			panic("Token is required in client mode")
		}
		runClient(*token, *port)
	default:
		panic("Invalid actas value, must be 'host' or 'client'")
	}
}
