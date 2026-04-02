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
	FusionAuthURL    string
	TenantID         string
	APIKey           string
	InputFile        string
	FailedOutputFile string
	BatchSize        int
	DryRun           bool
	SkipExisting     bool
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
	var allFailed []FailedImportUser
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

		if cfg.SkipExisting {
			skipped, failed, err := importWithSkipConflicts(ctx, log, client, importURL, cfg.TenantID, cfg.APIKey, stripped)
			if err != nil {
				return errs.New("batch %d (users %d-%d) failed: %w", batchNum, start+1, end, err)
			}
			allFailed = append(allFailed, failed...)
			if skipped > 0 {
				log.Info("Skipped users in batch", zap.Int("batch", batchNum), zap.Int("skipped", skipped), zap.Int("failed", len(failed)))
			}
		} else if err := sendImportBatch(ctx, client, importURL, cfg.TenantID, cfg.APIKey, stripped); err != nil {
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
		zap.Int("identity_links_failed", linkFailed),
		zap.Int("failed_users", len(allFailed)))

	if len(allFailed) > 0 && cfg.FailedOutputFile != "" {
		failedData, err := json.MarshalIndent(allFailed, "", "  ")
		if err != nil {
			return errs.New("failed to marshal failed users: %w", err)
		}
		if err := os.WriteFile(cfg.FailedOutputFile, failedData, 0600); err != nil {
			return errs.New("failed to write failed users file: %w", err)
		}
		log.Info("Failed users written", zap.String("output", cfg.FailedOutputFile), zap.Int("count", len(allFailed)))
	}

	return nil
}

// postImportBatch executes the HTTP POST to the FA import endpoint and returns the
// status code and response body. The caller is responsible for interpreting the result.
func postImportBatch(ctx context.Context, client *http.Client, importURL, tenantID, apiKey string, payload FusionAuthImport) (status int, respBody []byte, err error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, errs.New("marshal batch: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, importURL, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, errs.New("create request: %w", err)
	}
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-FusionAuth-TenantId", tenantID)

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, errs.New("http request: %w", err)
	}
	defer func() { err = errs.Combine(err, resp.Body.Close()) }()

	respBody, _ = io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, respBody, nil
}

func sendImportBatch(ctx context.Context, client *http.Client, importURL, tenantID, apiKey string, users []FusionAuthUser) error {
	status, respBody, err := postImportBatch(ctx, client, importURL, tenantID, apiKey, FusionAuthImport{
		Users:            users,
		ValidateDBSchema: true,
	})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return errs.New("unexpected status %d: %s", status, strings.TrimSpace(string(respBody)))
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

// importWithSkipConflicts sends a batch using validateDbConstraints so FA identifies
// which users already exist. Those users are logged and dropped, then the trimmed
// batch is retried. Returns the number of users skipped and any users that failed
// for non-conflict reasons.
func importWithSkipConflicts(ctx context.Context, log *zap.Logger, client *http.Client, importURL, tenantID, apiKey string, users []FusionAuthUser) (int, []FailedImportUser, error) {
	skipped := 0
	const maxRetries = 50
	for attempt := 0; attempt < maxRetries; attempt++ {
		status, respBody, err := postImportBatch(ctx, client, importURL, tenantID, apiKey, FusionAuthImport{
			Users:                 users,
			ValidateDBSchema:      true,
			ValidateDbConstraints: true,
		})
		if err != nil {
			return skipped, nil, err
		}
		if status == http.StatusOK {
			return skipped, nil, nil
		}
		if status != http.StatusBadRequest {
			return skipped, nil, errs.New("unexpected status %d: %s", status, strings.TrimSpace(string(respBody)))
		}

		// Parse fieldErrors to find which emails FA flagged as conflicts.
		// FA returns them under "user.email" with messages like:
		//   "A user with email [foo@example.com] already exists."
		var errResp struct {
			FieldErrors map[string][]struct {
				Message string `json:"message"`
			} `json:"fieldErrors"`
		}
		if jsonErr := json.Unmarshal(respBody, &errResp); jsonErr != nil || len(errResp.FieldErrors) == 0 {
			// validateDbConstraints found nothing, but the DB insert still failed.
			// Fall back to importing one user at a time to isolate the failures.
			log.Warn("Batch import failed with no field-level errors, falling back to individual imports",
				zap.Int("remaining_users", len(users)),
				zap.String("response", strings.TrimSpace(string(respBody))))
			failed, err := importUsersIndividually(ctx, log, client, importURL, tenantID, apiKey, users)
			return skipped + len(failed), failed, err
		}

		conflicting := make(map[string]bool)
		for _, fieldErrs := range errResp.FieldErrors {
			for _, e := range fieldErrs {
				// Extract email between the first '[' and ']'.
				if start := strings.Index(e.Message, "["); start >= 0 {
					if end := strings.Index(e.Message[start:], "]"); end >= 0 {
						conflicting[strings.ToLower(e.Message[start+1:start+end])] = true
					}
				}
			}
		}
		if len(conflicting) == 0 {
			log.Warn("Batch import failed with unparseable field errors, falling back to individual imports",
				zap.Int("remaining_users", len(users)),
				zap.String("response", strings.TrimSpace(string(respBody))))
			failed, err := importUsersIndividually(ctx, log, client, importURL, tenantID, apiKey, users)
			return skipped + len(failed), failed, err
		}

		trimmed := make([]FusionAuthUser, 0, len(users)-len(conflicting))
		for _, u := range users {
			if conflicting[strings.ToLower(u.Email)] {
				log.Debug("Skipping existing user", zap.String("email", u.Email))
			} else {
				trimmed = append(trimmed, u)
			}
		}
		skipped += len(conflicting)
		if len(trimmed) == 0 {
			return skipped, nil, nil
		}
		users = trimmed
	}
	return skipped, nil, errs.New("exceeded %d retry attempts with %d users remaining", maxRetries, len(users))
}

// FailedImportUser records a user that could not be imported and the reason.
type FailedImportUser struct {
	Email string         `json:"email"`
	Error string         `json:"error"`
	User  FusionAuthUser `json:"user"`
}

// importUsersIndividually imports users one at a time, collecting any that fail.
// Returns (failed_users, error). The error is non-nil only if the context is canceled.
func importUsersIndividually(ctx context.Context, log *zap.Logger, client *http.Client, importURL, tenantID, apiKey string, users []FusionAuthUser) ([]FailedImportUser, error) {
	var failed []FailedImportUser
	imported := 0
	for i, u := range users {
		if ctx.Err() != nil {
			return failed, errs.New("context canceled after importing %d/%d users individually (%d failed)", imported, len(users), len(failed))
		}
		if err := sendImportBatch(ctx, client, importURL, tenantID, apiKey, []FusionAuthUser{u}); err != nil {
			log.Warn("Skipping user that failed individual import",
				zap.String("email", u.Email),
				zap.Error(err))
			failed = append(failed, FailedImportUser{Email: u.Email, Error: err.Error(), User: u})
		} else {
			imported++
			if imported%50 == 0 || i == len(users)-1 {
				log.Info("Individual import progress",
					zap.Int("imported", imported),
					zap.Int("failed", len(failed)),
					zap.Int("remaining", len(users)-i-1))
			}
		}
	}
	log.Info("Individual import complete",
		zap.Int("imported", imported),
		zap.Int("failed", len(failed)))
	return failed, nil
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
