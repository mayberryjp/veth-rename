package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testDockerServer(t *testing.T, handler http.HandlerFunc) *dockerClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Transport = rewriteTransport{base: client.Transport, baseURL: server.URL}
	return &dockerClient{client: client, stream: client}
}

type rewriteTransport struct {
	base    http.RoundTripper
	baseURL string
}

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copy := req.Clone(req.Context())
	parsed, err := http.NewRequest(req.Method, rt.baseURL+req.URL.RequestURI(), nil)
	if err != nil {
		return nil, err
	}
	copy.URL = parsed.URL
	return rt.base.RoundTrip(copy)
}

func TestDockerEndpoints(t *testing.T) {
	d := testDockerServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			io.WriteString(w, `[{"Id":"abc"}]`)
		case "/containers/abc/json":
			io.WriteString(w, `{"Id":"abc","Name":"/test","State":{"Running":true,"Pid":123},"Config":{"Labels":{"host-veth-name":"veth_test"}},"NetworkSettings":{"Networks":{"lan":{"NetworkID":"net1","EndpointID":"ep1","MacAddress":"02:00:00:00:00:01","IPAddress":"172.18.0.2","GlobalIPv6Address":"fd00::2"}}}}`)
		case "/networks/net1":
			io.WriteString(w, `{"Id":"net1","Name":"lan","Driver":"bridge","Options":{"com.docker.network.bridge.name":"lan0"}}`)
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	ids, err := d.containers(ctx)
	if err != nil || len(ids) != 1 || ids[0] != "abc" {
		t.Fatalf("list: %v %v", ids, err)
	}
	c, err := d.inspect(ctx, "abc")
	if err != nil || c.ID != "abc" || c.State.Pid != 123 || c.Config.Labels[labelKey] != "veth_test" ||
		c.NetworkSettings.Networks["lan"].GlobalIPv6Address != "fd00::2" {
		t.Fatalf("inspect: %+v %v", c, err)
	}
	n, err := d.network(ctx, "net1")
	if err != nil || n.Driver != "bridge" || n.Options["com.docker.network.bridge.name"] != "lan0" {
		t.Fatalf("network: %+v %v", n, err)
	}
}

func TestDockerErrors(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusInternalServerError, http.StatusOK} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			d := testDockerServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
				io.WriteString(w, "not-json")
			})
			if _, err := d.containers(context.Background()); err == nil {
				t.Fatal("Docker failure hidden")
			}
		})
	}
}

func TestDockerCancellation(t *testing.T) {
	d := newDocker("unused")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.containers(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not propagated: %v", err)
	}
}

func TestEventStream(t *testing.T) {
	d := testDockerServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("filters"), `"container","network"`) {
			t.Errorf("missing event filters: %s", r.URL.RawQuery)
		}
		io.WriteString(w, `{"Type":"network","Action":"connect"}`+"\n")
	})
	changes := make(chan struct{}, 1)
	err := d.readEvents(context.Background(), changes)
	if !errors.Is(err, io.EOF) || len(changes) != 1 {
		t.Fatalf("events: %v notifications=%d", err, len(changes))
	}
}

func TestEventWatcherStopsOnCancellation(t *testing.T) {
	d := testDockerServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		d.watch(ctx, changes, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	select {
	case <-changes:
	case <-time.After(5 * time.Second):
		t.Fatal("event subscription did not connect")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("event watcher did not stop")
	}
}

func TestNotifyCoalesces(t *testing.T) {
	ch := make(chan struct{}, 1)
	notify(ch)
	notify(ch)
	if len(ch) != 1 {
		t.Fatal("notifications not coalesced")
	}
}
