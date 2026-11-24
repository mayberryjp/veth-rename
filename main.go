package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"veth-manager/internal/firewall"
	"veth-manager/internal/flow"
)

func writeSnapshot(path string, result snapshot) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.CreateTemp(filepath.Dir(path), ".veth-manager-*")
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
		log.Error("veth-manager stopped", "error", err)
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

func monitoredInterfaces(mappings []mapping) []flow.Interface {
	var interfaces []flow.Interface
	for _, m := range mappings {
		if m.Namespace != "host" || m.IfIndex <= 0 ||
			(m.Status != "applied" && m.Status != "unchanged" && m.Status != "monitored") {
			continue
		}
		interfaces = append(interfaces, flow.Interface{Index: m.IfIndex, Name: m.Interface,
			Identity: m.ContainerID + "/" + m.NetworkID, IPv4: m.IPv4, IPv6: m.IPv6})
	}
	return interfaces
}

func run(log *slog.Logger) (runErr error) {
	socket := flag.String("socket", "/var/run/docker.sock", "local rootful Docker Unix socket")
	mode := flag.String("mode", "primary-repair", "primary-repair (brief host-veth interruption), auto, primary or alternative")
	vnstat := flag.String("vnstat", "auto", "auto-detect vnStat, off, or path to a vnStat 2.x executable")
	interval := flag.Duration("interval", 30*time.Second, "full reconciliation interval (at least 1s)")
	mappingFile := flag.String("mapping-file", "", "atomic JSON snapshot path; parent directory must exist")
	once := flag.Bool("once", false, "reconcile once, print JSON, then exit (nonzero on errors)")
	dryRun := flag.Bool("dry-run", false, "inspect and plan without modifying interfaces")
	ipfixConfig := flag.String("ipfix-config", "", "opt-in eBPF/IPFIX YAML configuration file (daemon mode only)")
	firewallConfig := flag.String("firewall-config", "", "firewall YAML configuration (enabled defaults to false)")
	sandoSync := flag.Bool("sando-sync", false, "download Sando ignore list, replace generated rules, print YAML, and exit")
	sandoDump := flag.Bool("sando-dump", false, "print saved Sando rules YAML and exit")
	sandoDirection := flag.String("sando-direction", "", "override generated rule direction for sando-sync: ingress, egress or both")
	propose := flag.Bool("propose-rules", false, "summarize logged firewall denies by traffic tuple and exit; does not change policy")
	firewallLog := flag.String("firewall-log", "", "drop log to analyze (defaults to firewall-config drop_log)")
	since := flag.String("since", "24h", "propose-rules lookback, e.g. 24h, 7d or 168h")
	sortBy := flag.String("sort", "packets", "propose-rules ranking: packets or bytes")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	sandoDirectionSet := false
	analysisOptionsSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "sando-direction" {
			sandoDirectionSet = true
		}
		if f.Name == "firewall-log" || f.Name == "since" || f.Name == "sort" {
			analysisOptionsSet = true
		}
	})
	if analysisOptionsSet && !*propose {
		return fmt.Errorf("firewall-log, since and sort require propose-rules")
	}
	if sandoDirectionSet && (!*sandoSync || *sandoDump) {
		return fmt.Errorf("sando-direction requires sando-sync and cannot be combined with sando-dump")
	}
	var firewallSettings firewall.Config
	if *firewallConfig != "" {
		var err error
		firewallSettings, err = firewall.LoadConfig(*firewallConfig)
		if err != nil {
			return err
		}
	}
	if *propose {
		if *sandoSync || *sandoDump || *once || *dryRun || *ipfixConfig != "" {
			return fmt.Errorf("propose-rules cannot be combined with Sando commands, once, dry-run or ipfix-config")
		}
		path := *firewallLog
		if path == "" {
			path = firewallSettings.DropLog
		}
		if path == "" {
			return fmt.Errorf("propose-rules requires firewall-log or firewall-config with drop_log")
		}
		return proposeRules(os.Stdout, path, *since, *sortBy, time.Now())
	}
	if *sandoSync || *sandoDump {
		if *firewallConfig == "" || *once || *dryRun || *ipfixConfig != "" {
			return fmt.Errorf("Sando commands require firewall-config and cannot be combined with once, dry-run or ipfix-config")
		}
		var data []byte
		var err error
		if *sandoSync {
			if sandoDirectionSet {
				firewallSettings.SandoDirection = *sandoDirection
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			data, err = firewall.Sync(ctx, firewallSettings, &http.Client{Timeout: 30 * time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
		} else {
			if firewallSettings.SandoRules == "" {
				return fmt.Errorf("sando_rules is required for dump")
			}
			data, err = os.ReadFile(firewallSettings.SandoRules)
		}
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(data)
		return err
	}
	var firewallPolicy *firewall.Policy
	if firewallSettings.Enabled {
		if *ipfixConfig == "" || *once || *dryRun {
			return fmt.Errorf("enabled firewall requires ipfix-config in daemon mode")
		}
		var err error
		firewallPolicy, err = firewall.LoadPolicy(firewallSettings)
		if err != nil {
			return err
		}
	}
	if *mode != "primary-repair" && *mode != "auto" && *mode != "primary" && *mode != "alternative" {
		return fmt.Errorf("mode must be primary-repair, auto, primary or alternative")
	}
	if *interval < time.Second {
		return fmt.Errorf("interval must be at least 1s")
	}
	var monitoringConfig flow.Config
	if *ipfixConfig != "" {
		if *once || *dryRun {
			return fmt.Errorf("ipfix-config cannot be used with once or dry-run")
		}
		var err error
		monitoringConfig, err = flow.LoadConfig(*ipfixConfig)
		if err != nil {
			return err
		}
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("this daemon must run directly on a Linux Docker host")
	}
	if !*dryRun {
		lock, err := net.Listen("unix", "@veth-manager-interface-owner")
		if err != nil {
			return fmt.Errorf("another interface renamer instance may be running: %w", err)
		}
		defer lock.Close()
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
	var monitoring *flow.Service
	var flowTicks <-chan time.Time
	if *ipfixConfig != "" {
		var err error
		monitoring, err = flow.New(ctx, monitoringConfig)
		if err != nil {
			return err
		}
		defer func() { runErr = errors.Join(runErr, monitoring.Close()) }()
		if firewallPolicy != nil {
			if err := monitoring.EnableFirewall(firewallPolicy); err != nil {
				return err
			}
			log.Info("eBPF firewall enabled", "rules", len(firewallPolicy.Rules),
				"audit_mode", firewallSettings.AuditMode,
				"enforcement_direction", firewallSettings.EnforcementDirection,
				"sando_assignment", firewallSettings.SandoAssignment,
				"permit_all_icmp", firewallSettings.PermitAllICMP, "drop_log", firewallSettings.DropLog)
		}
		ticker := time.NewTicker(monitoring.PollInterval())
		defer ticker.Stop()
		flowTicks = ticker.C
		log.Info("eBPF IPFIX monitoring enabled", "collector", monitoringConfig.Collector,
			"observation_domain_id", monitoringConfig.ObservationDomainID,
			"sampling_rate", monitoringConfig.SamplingRate, "capture_filter", monitoringConfig.CaptureFilter)
	}
	if *mode == "primary-repair" && !*dryRun {
		log.Warn("controlled primary repair enabled; verified managed host veths may be briefly taken DOWN and restored UP")
	}
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
		if monitoring != nil {
			outputErr = monitoring.Sync(monitoredInterfaces(result.Mappings))
		}
		if *mappingFile != "" {
			outputErr = errors.Join(outputErr, writeSnapshot(*mappingFile, result))
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
	var sandoResults <-chan sandoResult
	if firewallSettings.SandoPoll {
		pollInterval, err := time.ParseDuration(firewallSettings.SandoPollInterval)
		if err != nil {
			return err
		}
		var stop func()
		sandoResults, stop = startSandoPolling(ctx, firewallSettings, &http.Client{Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, pollInterval)
		defer stop()
		log.Info("Sando policy polling enabled", "interval", pollInterval.String())
	}
	var previousFlowError error
	var previousSandoError error
	for {
		select {
		case <-ctx.Done():
			return nil
		case result := <-sandoResults:
			err := result.err
			if err == nil {
				var updated int
				updated, err = monitoring.ReloadFirewall(result.update.Policy, result.update.Save)
				if updated > 0 {
					log.Info("Sando policy applied", "updated_veths", updated)
				}
			}
			if err != nil && (previousSandoError == nil || err.Error() != previousSandoError.Error()) {
				log.Error("Sando policy update failed; daemon will retry", "error", err)
			} else if err == nil && previousSandoError != nil {
				log.Info("Sando policy polling recovered")
			}
			previousSandoError = err
			continue
		case <-flowTicks:
			err := monitoring.Poll()
			if err != nil && (previousFlowError == nil || err.Error() != previousFlowError.Error()) {
				log.Error("IPFIX monitoring failed; daemon will retry", "error", err)
			}
			previousFlowError = err
			continue
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
