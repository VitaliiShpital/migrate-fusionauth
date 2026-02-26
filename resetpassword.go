// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"

	"github.com/zeebo/errs"
	"go.uber.org/zap"
)

// SendPasswordResetsConfig holds configuration for the send-password-resets command.
type SendPasswordResetsConfig struct {
	FusionAuthURL string
	APIKey        string
	ConflictFile  string
	DryRun        bool
}

// VerifyFlags validates the configuration.
func (c *SendPasswordResetsConfig) VerifyFlags() error {
	var g errs.Group
	if c.FusionAuthURL == "" {
		g.Add(errs.New("--fusionauth-url is required"))
	}
	if c.APIKey == "" {
		g.Add(errs.New("--api-key is required"))
	}
	return g.Err()
}

// SendPasswordResets reads conflict-users.json and triggers FusionAuth forgot-password for each entry.
func SendPasswordResets(ctx context.Context, log *zap.Logger, cfg *SendPasswordResetsConfig) error {
	data, err := os.ReadFile(cfg.ConflictFile)
	if err != nil {
		return errs.New("failed to read conflict file %q: %w", cfg.ConflictFile, err)
	}

	var entries []ConflictUserEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return errs.New("failed to parse conflict file: %w", err)
	}

	log.Info("Sending password resets", zap.Int("count", len(entries)), zap.Bool("dry_run", cfg.DryRun))

	client := &http.Client{}
	url := cfg.FusionAuthURL + "/api/user/forgot-password"

	var succeeded, failed int
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}

		if cfg.DryRun {
			log.Info("Would send password reset",
				zap.String("email", entry.Email),
				zap.String("applicationId", entry.ApplicationID))
			continue
		}

		if err := sendForgotPassword(ctx, client, url, cfg.APIKey, entry); err != nil {
			log.Error("Failed to send password reset", zap.String("email", entry.Email), zap.Error(err))
			failed++
		} else {
			log.Info("Password reset sent", zap.String("email", entry.Email))
			succeeded++
		}
	}

	if cfg.DryRun {
		log.Info("Dry run complete", zap.Int("would_send", len(entries)))
		return nil
	}

	log.Info("Password resets complete", zap.Int("succeeded", succeeded), zap.Int("failed", failed))
	if failed > 0 {
		return errs.New("%d password resets failed (see logs above)", failed)
	}
	return nil
}

func sendForgotPassword(ctx context.Context, client *http.Client, url, apiKey string, entry ConflictUserEntry) (err error) {
	body, err := json.Marshal(map[string]interface{}{
		"loginId":                 entry.Email,
		"applicationId":           entry.ApplicationID,
		"sendForgotPasswordEmail": true,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { err = errs.Combine(err, resp.Body.Close()) }()

	if resp.StatusCode != http.StatusOK {
		return errs.New("unexpected status %d for %s", resp.StatusCode, entry.Email)
	}
	return nil
}
