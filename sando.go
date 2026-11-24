package main

import (
	"context"
	"net/http"
	"time"

	"veth-manager/internal/firewall"
)

type sandoResult struct {
	update *firewall.SandoUpdate
	err    error
}

func startSandoPolling(ctx context.Context, c firewall.Config, client *http.Client, interval time.Duration) (<-chan sandoResult, func()) {
	ctx, cancel := context.WithCancel(ctx)
	results := make(chan sandoResult)
	done := make(chan struct{})
	go func() {
		defer close(done)
		poller := firewall.SandoPoller{Config: c, Client: client}
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			update, err := poller.Poll(ctx)
			select {
			case <-ctx.Done():
				return
			case results <- sandoResult{update: update, err: err}:
			}
			timer.Reset(interval)
		}
	}()
	return results, func() {
		cancel()
		<-done
	}
}
