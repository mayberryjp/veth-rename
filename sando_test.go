package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"veth-rename/internal/firewall"
)

func TestSandoPollingRepeatsAndCancelsInFlightRequest(t *testing.T) {
	dir := t.TempDir()
	c := firewall.Config{SandoDirection: "both",
		ManualRules: filepath.Join(dir, "manual.yaml"), SandoRules: filepath.Join(dir, "sando.yaml")}
	if err := os.WriteFile(c.ManualRules, []byte("rules: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	requests := make(chan struct{}, 4)
	canceled := make(chan struct{})
	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		requests <- struct{}{}
		if count == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else if count == 2 {
			_, _ = w.Write([]byte("[]"))
		} else {
			<-r.Context().Done()
			close(canceled)
		}
	}))
	defer server.Close()
	c.SandoEndpoint = server.URL
	results, stop := startSandoPolling(context.Background(), c, server.Client(), 10*time.Millisecond)
	defer stop()
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if (result.err != nil) != (i == 0) {
				t.Fatalf("poll %d: %v", i, result.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("periodic polling stopped")
		}
	}
	for i := 0; i < 3; i++ {
		select {
		case <-requests:
		case <-time.After(5 * time.Second):
			t.Fatal("next request did not start")
		}
	}
	stop()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown left HTTP request running")
	}
}
