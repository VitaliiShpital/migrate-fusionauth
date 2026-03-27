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

// SendPasswordResetsConfig holds configuration for the send-password-resets command.
type SendPasswordResetsConfig struct {
	FusionAuthURL string
	TenantID      string
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
	if c.TenantID == "" {
		g.Add(errs.New("--fusionauth-tenant-id is required"))
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
	baseURL := strings.TrimRight(cfg.FusionAuthURL, "/")
	forgotPasswordURL := baseURL + "/api/user/forgot-password"

	var succeeded, failed, patchFailed int
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

		if err := sendForgotPassword(ctx, client, forgotPasswordURL, cfg.APIKey, cfg.TenantID, entry); err != nil {
			log.Error("Failed to send password reset", zap.String("email", entry.Email), zap.Error(err))
			failed++
			continue
		}
		log.Info("Password reset sent", zap.String("email", entry.Email))
		succeeded++

		userID, err := lookupUserID(ctx, client, baseURL, cfg.TenantID, cfg.APIKey, entry.Email)
		if err != nil {
			log.Warn("Failed to look up user for conflict flag, skipping patch", zap.String("email", entry.Email), zap.Error(err))
			patchFailed++
			continue
		}
		if err := patchUserConflictEmailSent(ctx, client, baseURL, cfg.TenantID, cfg.APIKey, userID); err != nil {
			log.Warn("Failed to set conflictEmailSent on user", zap.String("email", entry.Email), zap.Error(err))
			patchFailed++
		}
	}

	if cfg.DryRun {
		log.Info("Dry run complete", zap.Int("would_send", len(entries)))
		return nil
	}

	log.Info("Password resets complete",
		zap.Int("succeeded", succeeded),
		zap.Int("failed", failed),
		zap.Int("patch_failed", patchFailed))
	if failed > 0 {
		return errs.New("%d password resets failed (see logs above)", failed)
	}
	return nil
}

func sendForgotPassword(ctx context.Context, client *http.Client, url, apiKey, tenantID string, entry ConflictUserEntry) (err error) {
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
	req.Header.Set("X-FusionAuth-TenantId", tenantID)

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

func patchUserConflictEmailSent(ctx context.Context, client *http.Client, baseURL, tenantID, apiKey, userID string) (err error) {
	body, err := json.Marshal(map[string]interface{}{
		"user": map[string]interface{}{
			"data": map[string]interface{}{
				"conflictEmailSent": true,
			},
		},
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, baseURL+"/api/user/"+userID, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-FusionAuth-TenantId", tenantID)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { err = errs.Combine(err, resp.Body.Close()) }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return errs.New("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}
