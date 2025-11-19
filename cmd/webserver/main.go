package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	// Simple handler that shows request information
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		response := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Tunnel Test Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .info { background: #e7f3ff; padding: 15px; border-radius: 4px; margin: 10px 0; }
        .label { font-weight: bold; color: #555; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚇 Tunnel Test Server</h1>
        <div class="info">
            <p><span class="label">Time:</span> %s</p>
            <p><span class="label">Method:</span> %s</p>
            <p><span class="label">Path:</span> %s</p>
            <p><span class="label">Remote Address:</span> %s</p>
            <p><span class="label">Host:</span> %s</p>
            <p><span class="label">User-Agent:</span> %s</p>
        </div>
        <p>✅ Your tunnel is working correctly!</p>
    </div>
</body>
</html>`, timestamp, r.Method, r.URL.Path, r.RemoteAddr, r.Host, r.UserAgent())

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, response)

		// Log to console
		log.Printf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	})

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	// API endpoint for testing
	http.HandleFunc("/api/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"message":"Echo from server","timestamp":"%s"}`, time.Now().Format(time.RFC3339))
	})

	port := ":8080"
	log.Printf("🚀 Starting test server on http://localhost%s", port)
	log.Printf("   Main page: http://localhost%s/", port)
	log.Printf("   Health: http://localhost%s/health", port)
	log.Printf("   API: http://localhost%s/api/echo", port)

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}
