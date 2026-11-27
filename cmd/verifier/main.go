package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"imgsign/pkg/keys"
	"imgsign/pkg/store"
	"imgsign/pkg/verifier"
)

func main() {
	certFile := requiredEnv("TLS_CERT_FILE")
	keyFile := requiredEnv("TLS_KEY_FILE")
	publicKeyFile := requiredEnv("IMGSIGN_PUBLIC_KEY_FILE")
	publicKey, err := keys.LoadPublic(publicKeyFile)
	if err != nil {
		log.Fatalf("load public key: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		log.Fatalf("invalid PORT: %q", port)
	}

	registryStore := store.NewORASStore()
	handler := &verifierHandler{
		verify: func(ctx context.Context, image string) error {
			return verifier.Verify(ctx, registryStore, publicKey, publicKey.Algorithm(), image)
		},
		logger: log.New(os.Stdout, "", 0),
	}

	mux := http.NewServeMux()
	mux.Handle("/validate", handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("verifier listening on %s", server.Addr)
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatal(err)
	}
}

func requiredEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}
