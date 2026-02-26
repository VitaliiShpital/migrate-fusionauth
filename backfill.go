// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"
)

// BackfillConfig holds configuration for the backfill-external-ids command.
type BackfillConfig struct {
	FusionAuthURL          string
	APIKey                 string
	OutputDir              string
	ExcludeEmailDomainList string
	DryRun                 bool

	// CSV inputs — reuse the same per-satellite flags as the export command.
	CSVUS1 string
	CSVEU1 string
	CSVAP1 string
	CSVQA  string
}

// ExcludeEmailDomains returns the parsed list of excluded email domains.
func (c *BackfillConfig) ExcludeEmailDomains() []string {
	var result []string
	for _, d := range strings.Split(c.ExcludeEmailDomainList, ",") {
		if d = strings.TrimSpace(d); d != "" {
			result = append(result, d)
		}
	}
	return result
}

// VerifyFlags validates the configuration.
func (c *BackfillConfig) VerifyFlags() error {
	var g errs.Group
	if c.FusionAuthURL == "" {
		g.Add(errs.New("--fusionauth-url is required"))
	}
	if c.APIKey == "" {
		g.Add(errs.New("--api-key is required"))
	}
	if c.CSVUS1 == "" && c.CSVEU1 == "" && c.CSVAP1 == "" && c.CSVQA == "" {
		g.Add(errs.New("at least one --csv-{name} flag is required"))
	}
	return g.Err()
}

// satellites returns the configured (name, csvPath) pairs.
func (c *BackfillConfig) satellites() []struct{ name, csv string } {
	all := []struct{ name, csv string }{
		{"us1", c.CSVUS1},
		{"eu1", c.CSVEU1},
		{"ap1", c.CSVAP1},
		{"qa", c.CSVQA},
	}
	var result []struct{ name, csv string }
	for _, s := range all {
		if s.csv != "" {
			result = append(result, s)
		}
	}
	return result
}

// faUserSearchRequest is the FA user search request body.
type faUserSearchRequest struct {
	Search faUserSearchParams `json:"search"`
}

type faUserSearchParams struct {
	QueryString     string `json:"queryString"`
	NumberOfResults int    `json:"numberOfResults"`
	StartRow        int    `json:"startRow"`
}

// faUserSearchResponse is the FA user search response body.
type faUserSearchResponse struct {
	Total int `json:"total"`
	Users []struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"users"`
}

const faSearchPageSize = 10000

// BackfillExternalIDs fetches all users from FusionAuth, then for each
// satellite CSV writes a SQL file with UPDATE statements to populate external_id.
func BackfillExternalIDs(ctx context.Context, log *zap.Logger, cfg *BackfillConfig) error {
	log.Info("Fetching users from FusionAuth", zap.String("url", cfg.FusionAuthURL))

	emailToFAID, err := fetchAllFAUsers(ctx, cfg.FusionAuthURL, cfg.APIKey)
	if err != nil {
		return errs.New("fetch FusionAuth users: %w", err)
	}
	log.Info("Fetched FusionAuth users", zap.Int("count", len(emailToFAID)))

	if cfg.OutputDir != "" {
		if err := os.MkdirAll(cfg.OutputDir, 0700); err != nil {
			return errs.New("create output dir: %w", err)
		}
	}

	excludeDomains := cfg.ExcludeEmailDomains()
	for _, sat := range cfg.satellites() {
		users, err := ReadCSV(sat.csv, sat.name)
		if err != nil {
			return errs.New("read CSV for %s: %w", sat.name, err)
		}

		var matched, missing int
		var statements []string
		for _, u := range users {
			if isExcludedDomain(u.Email, excludeDomains) {
				continue
			}
			faID, ok := emailToFAID[strings.ToUpper(u.Email)]
			if !ok {
				log.Debug("User not found in FusionAuth", zap.String("email", u.Email), zap.String("satellite", sat.name))
				missing++
				continue
			}
			statements = append(statements,
				fmt.Sprintf("UPDATE users SET external_id = '%s' WHERE normalized_email = '%s';",
					faID, strings.ReplaceAll(u.NormalizedEmail, "'", "''")),
			)
			matched++
		}

		log.Info("Satellite processed",
			zap.String("satellite", sat.name),
			zap.Int("matched", matched),
			zap.Int("missing_in_fa", missing))

		if cfg.DryRun {
			continue
		}

		outPath := sat.name + "-backfill-external-ids.sql"
		if cfg.OutputDir != "" {
			outPath = cfg.OutputDir + "/" + outPath
		}
		if err := writeSQLFile(outPath, sat.name, statements); err != nil {
			return errs.New("write SQL for %s: %w", sat.name, err)
		}
		log.Info("SQL file written", zap.String("file", outPath), zap.Int("statements", len(statements)))
	}

	return nil
}

func fetchAllFAUsers(ctx context.Context, baseURL, apiKey string) (map[string]string, error) {
	client := &http.Client{}
	url := baseURL + "/api/user/search"
	emailToFAID := make(map[string]string)

	for startRow := 0; ; startRow += faSearchPageSize {
		body, err := json.Marshal(faUserSearchRequest{
			Search: faUserSearchParams{
				QueryString:     "*",
				NumberOfResults: faSearchPageSize,
				StartRow:        startRow,
			},
		})
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		var result faUserSearchResponse
		err = func() (err error) {
			defer func() { err = errs.Combine(err, resp.Body.Close()) }()
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return errs.New("unexpected status %d from FA search: %s", resp.StatusCode, body)
			}
			return json.NewDecoder(resp.Body).Decode(&result)
		}()
		if err != nil {
			return nil, err
		}

		for _, u := range result.Users {
			emailToFAID[strings.ToUpper(u.Email)] = u.ID
		}

		if startRow+faSearchPageSize >= result.Total {
			break
		}
	}

	return emailToFAID, nil
}

func writeSQLFile(path, satellite string, statements []string) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "-- Satellite: %s\n", satellite)
	fmt.Fprintf(&sb, "-- Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&sb, "-- %d statements\n\n", len(statements))
	for _, s := range statements {
		sb.WriteString(s)
		sb.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(sb.String()), 0600)
}
