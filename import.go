// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/zeebo/errs"
	"go.uber.org/zap"
)

// ImportConfig holds configuration for the import command.
type ImportConfig struct {
	FusionAuthURL string
	TenantID      string
	APIKey        string
	InputFile     string
	BatchSize     int
	DryRun        bool
}

// VerifyFlags validates the import configuration.
func (c *ImportConfig) VerifyFlags() error {
	var g errs.Group
	if c.FusionAuthURL == "" {
		g.Add(errs.New("--fusionauth-url is required"))
	}
	if c.TenantID == "" {
		g.Add(errs.New("--fusionauth-tenant-id is required"))
	}
	if c.APIKey == "" {
		g.Add(errs.New("--api-key is required"))
	}
	if c.InputFile == "" {
		g.Add(errs.New("--input is required"))
	}
	if c.BatchSize <= 0 {
		g.Add(errs.New("--batch-size must be positive"))
	}
	return g.Err()
}

// Import reads the export JSON file and imports users into FusionAuth in batches.
func Import(ctx context.Context, log *zap.Logger, cfg *ImportConfig) error {
	data, err := os.ReadFile(cfg.InputFile)
	if err != nil {
		return errs.New("failed to read input file: %w", err)
	}

	var importData FusionAuthImport
	if err := json.Unmarshal(data, &importData); err != nil {
		return errs.New("failed to parse input file: %w", err)
	}

	total := len(importData.Users)
	log.Info("Loaded users from import file",
		zap.String("file", cfg.InputFile),
		zap.Int("total_users", total),
		zap.Int("batch_size", cfg.BatchSize))

	if cfg.DryRun {
		batches := (total + cfg.BatchSize - 1) / cfg.BatchSize
		log.Info("Dry run complete",
			zap.Int("total_users", total),
			zap.Int("batches", batches))
		return nil
	}

	url := strings.TrimRight(cfg.FusionAuthURL, "/") + "/api/user/import"
	client := &http.Client{}

	imported := 0
	for batchNum, start := 1, 0; start < total; batchNum, start = batchNum+1, start+cfg.BatchSize {
		end := start + cfg.BatchSize
		if end > total {
			end = total
		}
		batch := importData.Users[start:end]

		if err := sendImportBatch(ctx, client, url, cfg.TenantID, cfg.APIKey, batch); err != nil {
			return errs.New("batch %d (users %d-%d) failed: %w", batchNum, start+1, end, err)
		}

		imported += len(batch)
		log.Info("Batch imported",
			zap.Int("batch", batchNum),
			zap.Int("imported", imported),
			zap.Int("total", total))
	}

	log.Info("Import complete", zap.Int("total_imported", imported))
	return nil
}

func sendImportBatch(ctx context.Context, client *http.Client, url, tenantID, apiKey string, users []FusionAuthUser) (err error) {
	body, err := json.Marshal(FusionAuthImport{
		Users:            users,
		ValidateDBSchema: true,
	})
	if err != nil {
		return errs.New("marshal batch: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return errs.New("create request: %w", err)
	}
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-FusionAuth-TenantId", tenantID)

	resp, err := client.Do(req)
	if err != nil {
		return errs.New("http request: %w", err)
	}
	defer func() { err = errs.Combine(err, resp.Body.Close()) }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return errs.New("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	return nil
}
