package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type endpoint struct {
	NetworkID         string
	EndpointID        string
	MacAddress        string
	IPAddress         string
	GlobalIPv6Address string
}

type container struct {
	ID     string `json:"Id"`
	Name   string
	Config struct {
		Labels map[string]string
	}
	State struct {
		Running bool
		Pid     int
	}
	HostConfig struct {
		NetworkMode string
	}
	NetworkSettings struct {
		Networks map[string]endpoint
	}
}

type network struct {
	ID      string `json:"Id"`
	Name    string
	Driver  string
	Options map[string]string
}

type dockerAPI interface {
	containers(context.Context) ([]string, error)
	inspect(context.Context, string) (container, error)
	network(context.Context, string) (network, error)
}

type dockerClient struct {
	client *http.Client
	stream *http.Client
}

func newDocker(socket string) *dockerClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "unix", socket)
		},
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &dockerClient{
		client: &http.Client{Transport: transport, Timeout: 15 * time.Second},
		stream: &http.Client{Transport: transport},
	}
}

func dockerRequest(ctx context.Context, client *http.Client, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return nil, fmt.Errorf("Docker %s: HTTP %d (reading error: %w)", path, resp.StatusCode, readErr)
		}
		return nil, fmt.Errorf("Docker %s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return resp, nil
}

func (d *dockerClient) get(ctx context.Context, path string, out interface{}) error {
	resp, err := dockerRequest(ctx, d.client, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode Docker %s: %w", path, err)
	}
	return nil
}

func (d *dockerClient) containers(ctx context.Context) ([]string, error) {
	var list []struct {
		ID string `json:"Id"`
	}
	if err := d.get(ctx, "/containers/json", &list); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(list))
	for _, c := range list {
		ids = append(ids, c.ID)
	}
	return ids, nil
}

func (d *dockerClient) inspect(ctx context.Context, id string) (container, error) {
	var c container
	err := d.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &c)
	return c, err
}

func (d *dockerClient) network(ctx context.Context, id string) (network, error) {
	var n network
	err := d.get(ctx, "/networks/"+url.PathEscape(id), &n)
	return n, err
}

func notify(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// Subscribe before reconciliation; periodic scans cover the subscription/reconnect gap.
func (d *dockerClient) watch(ctx context.Context, changes chan<- struct{}, log *slog.Logger) {
	for ctx.Err() == nil {
		err := d.readEvents(ctx, changes)
		if ctx.Err() != nil {
			return
		}
		log.Error("Docker event stream disconnected; retrying in 3s", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func (d *dockerClient) readEvents(ctx context.Context, changes chan<- struct{}) error {
	filter := url.QueryEscape(`{"type":["container","network"]}`)
	resp, err := dockerRequest(ctx, d.stream, "/events?filters="+filter)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	notify(changes)
	decoder := json.NewDecoder(resp.Body)
	for {
		var event json.RawMessage
		if err := decoder.Decode(&event); err != nil {
			return err
		}
		notify(changes)
	}
}
