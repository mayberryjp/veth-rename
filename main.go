package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

func writeSnapshot(path string, result snapshot) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.CreateTemp(filepath.Dir(path), ".veth-renamer-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0644); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("veth-renamer stopped", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	socket := flag.String("socket", "/var/run/docker.sock", "local rootful Docker Unix socket")
	mode := flag.String("mode", "primary", "primary or alternative")
	interval := flag.Duration("interval", 30*time.Second, "full reconciliation interval (at least 1s)")
	mappingFile := flag.String("mapping-file", "", "atomic JSON snapshot path; parent directory must exist")
	once := flag.Bool("once", false, "reconcile once, print JSON, then exit (nonzero on errors)")
	dryRun := flag.Bool("dry-run", false, "inspect and plan without modifying interfaces")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *mode != "primary" && *mode != "alternative" {
		return fmt.Errorf("mode must be primary or alternative")
	}
	if *interval < time.Second {
		return fmt.Errorf("interval must be at least 1s")
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("this daemon must run directly on a Linux Docker host")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		return fmt.Errorf("iproute2 is required: %w", err)
	}
	nsenter, err := exec.LookPath("nsenter")
	if err != nil {
		return fmt.Errorf("util-linux nsenter is required: %w", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	docker := newDocker(*socket)
	r := reconciler{docker: docker, links: commandLinks{ip: ip, nsenter: nsenter}, mode: *mode, dryRun: *dryRun}
	reconcile := func() error {
		result, scanErr := r.run(ctx)
		if scanErr != nil {
			log.Error("reconciliation incomplete", "error", scanErr)
		}
		// A top-level discovery failure must not overwrite the last useful snapshot.
		if scanErr != nil && len(result.Mappings) == 0 {
			return scanErr
		}
		for _, m := range result.Mappings {
			if m.Status == "applied" || m.Status == "would-change" || m.Status == "skipped" {
				log.Info("endpoint", "container", m.Container, "network", m.Network, "interface", m.Interface,
					"requested_name", m.RequestedName, "status", m.Status, "detail", m.Error)
			}
		}
		var outputErr error
		if *mappingFile != "" {
			outputErr = writeSnapshot(*mappingFile, result)
		}
		if *once {
			outputErr = errors.Join(outputErr, json.NewEncoder(os.Stdout).Encode(result))
		}
		return errors.Join(scanErr, outputErr)
	}
	if *once {
		return reconcile()
	}
	changes := make(chan struct{}, 1)
	go docker.watch(ctx, changes, log)
	if err := reconcile(); err != nil {
		log.Error("initial scan failed; daemon will retry", "error", err)
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-changes:
			// Coalesce bursts from starts and network attachments.
			timer := time.NewTimer(300 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
		if err := reconcile(); err != nil {
			log.Error("scan failed; daemon will retry", "error", err)
		}
	}
}
