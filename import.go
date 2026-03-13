// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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
// For users that carry a Link field (identity provider link), it performs a
// two-step process: first importing the user, then calling the link API.
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
	linkedCount := 0
	for _, u := range importData.Users {
		if u.Link != nil {
			linkedCount++
		}
	}
	log.Info("Loaded users from import file",
		zap.String("file", cfg.InputFile),
		zap.Int("total_users", total),
		zap.Int("with_identity_link", linkedCount),
		zap.Int("batch_size", cfg.BatchSize))

	if cfg.DryRun {
		batches := (total + cfg.BatchSize - 1) / cfg.BatchSize
		log.Info("Dry run complete",
			zap.Int("total_users", total),
			zap.Int("batches", batches))
		return nil
	}

	baseURL := strings.TrimRight(cfg.FusionAuthURL, "/")
	importURL := baseURL + "/api/user/import"
	client := &http.Client{}

	imported := 0
	linked := 0
	linkFailed := 0
	for batchNum, start := 1, 0; start < total; batchNum, start = batchNum+1, start+cfg.BatchSize {
		end := start + cfg.BatchSize
		if end > total {
			end = total
		}
		batch := importData.Users[start:end]

		// Strip Link before sending to the import API — it is not supported there.
		stripped := make([]FusionAuthUser, len(batch))
		copy(stripped, batch)
		for i := range stripped {
			stripped[i].Link = nil
		}

		if err := sendImportBatch(ctx, client, importURL, cfg.TenantID, cfg.APIKey, stripped); err != nil {
			return errs.New("batch %d (users %d-%d) failed: %w", batchNum, start+1, end, err)
		}

		imported += len(batch)
		log.Info("Batch imported",
			zap.Int("batch", batchNum),
			zap.Int("imported", imported),
			zap.Int("total", total))

		// Step 2: link identity provider accounts for users that carry a Link field.
		for _, u := range batch {
			if u.Link == nil {
				continue
			}
			faUserID, err := lookupUserID(ctx, client, baseURL, cfg.TenantID, cfg.APIKey, u.Email)
			if err != nil {
				log.Warn("Failed to look up user for identity linking, skipping",
					zap.String("email", u.Email), zap.Error(err))
				linkFailed++
				continue
			}
			if err := linkIdentityProvider(ctx, client, baseURL, cfg.TenantID, cfg.APIKey, faUserID, u.Link); err != nil {
				log.Warn("Failed to link identity provider, skipping",
					zap.String("email", u.Email), zap.String("fa_user_id", faUserID), zap.Error(err))
				linkFailed++
				continue
			}
			linked++
		}
	}

	log.Info("Import complete",
		zap.Int("total_imported", imported),
		zap.Int("identity_links_created", linked),
		zap.Int("identity_links_failed", linkFailed))
	return nil
}

func sendImportBatch(ctx context.Context, client *http.Client, importURL, tenantID, apiKey string, users []FusionAuthUser) (err error) {
	body, err := json.Marshal(FusionAuthImport{
		Users:            users,
		ValidateDBSchema: true,
	})
	if err != nil {
		return errs.New("marshal batch: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, importURL, bytes.NewReader(body))
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

// lookupUserID retrieves the FusionAuth user ID for a given email.
func lookupUserID(ctx context.Context, client *http.Client, baseURL, tenantID, apiKey, email string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		baseURL+"/api/user?email="+url.QueryEscape(email), nil)
	if err != nil {
		return "", errs.New("create request: %w", err)
	}
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("X-FusionAuth-TenantId", tenantID)

	resp, err := client.Do(req)
	if err != nil {
		return "", errs.New("http request: %w", err)
	}
	defer func() { err = errs.Combine(err, resp.Body.Close()) }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", errs.New("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var result struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", errs.New("decode response: %w", err)
	}
	if result.User.ID == "" {
		return "", errs.New("user not found for email %q", email)
	}
	return result.User.ID, nil
}

// linkIdentityProviderRequest is the request body for POST /api/identity-provider/link.
type linkIdentityProviderRequest struct {
	IdentityProviderLink linkIdentityProviderBody `json:"identityProviderLink"`
}

type linkIdentityProviderBody struct {
	DisplayName            string `json:"displayName,omitempty"`
	IdentityProviderID     string `json:"identityProviderId"`
	IdentityProviderUserID string `json:"identityProviderUserId"`
	UserID                 string `json:"userId"`
}

// linkIdentityProvider calls POST /api/identity-provider/link to attach an IdP identity to an existing user.
func linkIdentityProvider(ctx context.Context, client *http.Client, baseURL, tenantID, apiKey, faUserID string, link *FusionAuthIdentityProviderLink) (err error) {
	body, err := json.Marshal(linkIdentityProviderRequest{
		IdentityProviderLink: linkIdentityProviderBody{
			DisplayName:            link.DisplayName,
			IdentityProviderID:     link.IdentityProviderID,
			IdentityProviderUserID: link.IdentityProviderUserID,
			UserID:                 faUserID,
		},
	})
	if err != nil {
		return errs.New("marshal link request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/api/identity-provider/link", bytes.NewReader(body))
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
