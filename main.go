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

func logEndpoints(log *slog.Logger, mappings []mapping, previousSkipped map[mapping]struct{}) map[mapping]struct{} {
	skipped := make(map[mapping]struct{})
	for _, m := range mappings {
		if m.Status == "skipped" || m.Status == "monitored" {
			skipped[m] = struct{}{}
			if _, seen := previousSkipped[m]; seen {
				continue
			}
		}
		if m.Status == "applied" || m.Status == "would-change" || m.Status == "skipped" || m.Status == "monitored" || m.VNStatStatus == "applied" || m.VNStatStatus == "would-change" {
			log.Info("endpoint", "container", m.Container, "network", m.Network, "interface", m.Interface,
				"namespace", m.Namespace, "requested_name", m.RequestedName, "status", m.Status, "detail", m.Error,
				"naming_warning", m.NamingWarning, "vnstat_status", m.VNStatStatus, "vnstat_error", m.VNStatError)
		}
	}
	return skipped
}

func logScanError(log *slog.Logger, err, previous error) error {
	if err != nil && (previous == nil || err.Error() != previous.Error()) {
		log.Error("scan failed; daemon will retry", "error", err)
	}
	return err
}

func run(log *slog.Logger) error {
	socket := flag.String("socket", "/var/run/docker.sock", "local rootful Docker Unix socket")
	mode := flag.String("mode", "auto", "auto (alternative names with vnStat collision fallback), primary or alternative")
	vnstat := flag.String("vnstat", "auto", "auto-detect vnStat, off, or path to a vnStat 2.x executable")
	interval := flag.Duration("interval", 30*time.Second, "full reconciliation interval (at least 1s)")
	mappingFile := flag.String("mapping-file", "", "atomic JSON snapshot path; parent directory must exist")
	once := flag.Bool("once", false, "reconcile once, print JSON, then exit (nonzero on errors)")
	dryRun := flag.Bool("dry-run", false, "inspect and plan without modifying interfaces")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *mode != "auto" && *mode != "primary" && *mode != "alternative" {
		return fmt.Errorf("mode must be auto, primary or alternative")
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
	if *vnstat != "off" {
		program := *vnstat
		if program == "auto" {
			program = "vnstat"
		}
		path, err := exec.LookPath(program)
		if err != nil && *vnstat != "auto" {
			return fmt.Errorf("vnStat executable is required: %w", err)
		}
		if err == nil {
			r.vnstat = &vnstatClient{path: path, exec: command}
			log.Info("vnStat reconciliation enabled", "executable", path)
		} else {
			log.Info("vnStat not installed; monitoring reconciliation disabled")
		}
	}
	var skipped map[mapping]struct{}
	reconcile := func() error {
		result, scanErr := r.run(ctx)
		// A top-level discovery failure must not overwrite the last useful snapshot.
		if scanErr != nil && len(result.Mappings) == 0 {
			return scanErr
		}
		skipped = logEndpoints(log, result.Mappings, skipped)
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
	var previousError error
	scan := func() {
		previousError = logScanError(log, reconcile(), previousError)
	}
	scan()
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
		scan()
	}
}
