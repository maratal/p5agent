// Hello World demo — Go, standard library only.
//
// GET shows a name form; POST answers "Hello, <name>!" in the middle of the page.
// GET /api/info answers the product info a control panel polls for liveness.
// Listens on $HOST:$PORT (default 0.0.0.0:8080) and serves HTTPS when the
// installer has put TLS_CERT_PATH / TLS_KEY_PATH in the environment.
package main

import (
	"encoding/json"
	"html"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	runtimeName = "Go"
	version     = "1.0.0"
)

const form = `<h1>Hello World</h1><form method="post">` +
	`<input name="name" placeholder="Your name" autofocus required>` +
	`<button type="submit">Say hello</button></form>`

var template string

func greeting(name string) string {
	return "<h1>Hello, " + html.EscapeString(name) + `!</h1><a href="/">Say hello again</a>`
}

func page(content string) string {
	return strings.ReplaceAll(strings.ReplaceAll(template, "{{runtime}}", runtimeName), "{{content}}", content)
}

func handler(w http.ResponseWriter, r *http.Request) {
	content := form
	if r.Method == http.MethodPost {
		name := strings.TrimSpace(r.PostFormValue("name"))
		if name == "" {
			name = "World"
		}
		content = greeting(name)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page(content)))
}

func info(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// A struct, not a map: the panel lists the keys in the order they come.
	json.NewEncoder(w).Encode(struct {
		ProductName string `json:"productName"`
		Version     string `json:"version"`
		Runtime     string `json:"runtime"`
	}{"Hello " + runtimeName, version, "Go " + strings.TrimPrefix(runtime.Version(), "go")})
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	// The template sits next to the binary (the installer runs it from there);
	// fall back to the working directory for "go run .".
	dir := "."
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}
	data, err := os.ReadFile(filepath.Join(dir, "hello.html"))
	if err != nil {
		if data, err = os.ReadFile("hello.html"); err != nil {
			log.Fatal(err)
		}
	}
	template = string(data)

	addr := net.JoinHostPort(env("HOST", "0.0.0.0"), env("PORT", "8080"))
	http.HandleFunc("/", handler)
	http.HandleFunc("/api/info", info)
	cert, key := os.Getenv("TLS_CERT_PATH"), os.Getenv("TLS_KEY_PATH")
	if cert != "" && key != "" {
		log.Printf("Hello World (%s) listening on https://%s", runtimeName, addr)
		log.Fatal(http.ListenAndServeTLS(addr, cert, key, nil))
	}
	log.Printf("Hello World (%s) listening on http://%s", runtimeName, addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
