package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type vnstatClient struct {
	path string
	exec func(context.Context, string, ...string) ([]byte, error)
}

func (v vnstatClient) interfaces(ctx context.Context) (map[string]string, error) {
	output, err := v.exec(ctx, v.path, "--json", "s")
	if err != nil {
		if strings.TrimSpace(string(output)) == "Error: Database is empty." {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read vnStat database (vnstatd must initialize it first): %w", err)
	}
	var database struct {
		Interfaces *[]struct {
			Name  string `json:"name"`
			Alias string `json:"alias"`
		} `json:"interfaces"`
	}
	if err := json.Unmarshal(output, &database); err != nil {
		return nil, fmt.Errorf("decode vnStat database: %w", err)
	}
	if database.Interfaces == nil {
		return nil, fmt.Errorf("vnStat JSON has no interfaces array; vnStat 2.x is required")
	}
	aliases := map[string]string{}
	for _, entry := range *database.Interfaces {
		aliases[entry.Name] = entry.Alias
	}
	return aliases, nil
}

func (v vnstatClient) sync(ctx context.Context, mappings []mapping, dryRun bool) error {
	var targets []int
	for index, record := range mappings {
		if record.Namespace == "host" && record.Interface != "" &&
			(record.Status == "applied" || record.Status == "unchanged" || record.Status == "monitored" || record.Status == "would-change") {
			targets = append(targets, index)
		}
	}
	if len(targets) == 0 {
		return nil
	}
	var problems []error
	fail := func(index int, err error) {
		record := &mappings[index]
		record.VNStatStatus, record.VNStatError = "error", err.Error()
		if record.Status == "monitored" {
			record.Status = "error"
		}
		problems = append(problems, fmt.Errorf("vnStat %s/%s: %w", record.Container, record.Network, err))
	}
	aliases, err := v.interfaces(ctx)
	if err != nil {
		for _, index := range targets {
			fail(index, err)
		}
		return errors.Join(problems...)
	}
	var updated []int
	for _, index := range targets {
		record := &mappings[index]
		alias, exists := aliases[record.Interface]
		record.VNStatStatus = "unchanged"
		if exists && alias == record.RequestedName {
			continue
		}
		if dryRun {
			record.VNStatStatus = "would-change"
			continue
		}
		var updateErr error
		if !exists {
			_, updateErr = v.exec(ctx, v.path, "--add", "-i", record.Interface)
		}
		if updateErr == nil {
			_, updateErr = v.exec(ctx, v.path, "-i", record.Interface, "--setalias", record.RequestedName)
		}
		if updateErr != nil {
			fail(index, updateErr)
			continue
		}
		aliases[record.Interface] = record.RequestedName
		updated = append(updated, index)
	}
	if len(updated) > 0 {
		verified, err := v.interfaces(ctx)
		for _, index := range updated {
			record := &mappings[index]
			if err != nil {
				fail(index, err)
			} else if verified[record.Interface] != record.RequestedName {
				fail(index, fmt.Errorf("vnStat registration or alias missing after update; will retry"))
			} else {
				record.VNStatStatus = "applied"
			}
		}
	}
	return errors.Join(problems...)
}
