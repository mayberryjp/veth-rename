package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"veth-rename/internal/firewall"
)

func proposeRules(out io.Writer, path, since, sortBy string, now time.Time) error {
	lookback, err := firewall.ParseLookback(since)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open firewall log: %w", err)
	}
	rows, readErr := firewall.AnalyzeDrops(f, now, lookback, sortBy)
	if err := errors.Join(readErr, f.Close()); err != nil {
		return err
	}
	return firewall.WriteDropSummary(out, rows, now)
}
