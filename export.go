// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"
)

// ExportStats tracks export statistics.
type ExportStats struct {
	TotalUniqueEmails int
	NoConflictUsers   int
	ConflictUsers     int
	SkippedSSO        int
	SkippedNoHash     int
	SkippedParseErr   int
	SkippedDomain     int
	UsersWithMFA      int
}

// Export reads CSV files for each satellite, detects conflicts, and writes
// the FusionAuth import JSON and conflict-users JSON files.
func Export(log *zap.Logger, cfg *Config) error {
	bySatellite := make(map[string][]RawUser)
	for _, sat := range cfg.Satellites() {
		users, err := ReadCSV(sat.CSV, sat.Name)
		if err != nil {
			return errs.New("failed to read CSV for satellite %s: %w", sat.Name, err)
		}
		log.Info("Read satellite CSV", zap.String("satellite", sat.Name), zap.Int("users", len(users)))
		bySatellite[sat.Name] = users
	}

	idx := BuildIndex(bySatellite)

	appIDs := make(map[string]string)
	for _, sat := range cfg.Satellites() {
		appIDs[sat.Name] = sat.ApplicationID
	}

	faUsers, conflictEntries, stats := buildAllFusionAuthUsers(log, idx, appIDs, cfg.Precedence(), cfg.FusionAuthTenantID, cfg.ExcludeEmailDomains())

	log.Info("Export statistics",
		zap.Int("total_unique_emails", stats.TotalUniqueEmails),
		zap.Int("no_conflict_users", stats.NoConflictUsers),
		zap.Int("conflict_users", stats.ConflictUsers),
		zap.Int("users_with_mfa", stats.UsersWithMFA),
		zap.Int("skipped_sso", stats.SkippedSSO),
		zap.Int("skipped_no_hash", stats.SkippedNoHash),
		zap.Int("skipped_parse_error", stats.SkippedParseErr),
		zap.Int("skipped_domain", stats.SkippedDomain))

	if cfg.DryRun {
		log.Info("Dry run complete, no files written")
		return nil
	}

	importData := FusionAuthImport{
		Users:            faUsers,
		ValidateDBSchema: true,
	}
	jsonData, err := json.MarshalIndent(importData, "", "  ")
	if err != nil {
		return errs.New("failed to marshal import JSON: %w", err)
	}
	if err := os.WriteFile(cfg.OutputFile, jsonData, 0600); err != nil {
		return errs.New("failed to write output file: %w", err)
	}
	log.Info("Import file written", zap.String("output", cfg.OutputFile), zap.Int("users", len(faUsers)))

	if len(conflictEntries) > 0 {
		conflictData, err := json.MarshalIndent(conflictEntries, "", "  ")
		if err != nil {
			return errs.New("failed to marshal conflict JSON: %w", err)
		}
		if err := os.WriteFile(cfg.ConflictOutputFile, conflictData, 0600); err != nil {
			return errs.New("failed to write conflict output file: %w", err)
		}
		log.Info("Conflict users file written", zap.String("output", cfg.ConflictOutputFile), zap.Int("conflict_users", len(conflictEntries)))
	}

	return nil
}

func buildAllFusionAuthUsers(
	log *zap.Logger,
	idx UserIndex,
	appIDs map[string]string,
	precedence []string,
	tenantID string,
	excludeDomains []string,
) (faUsers []FusionAuthUser, conflictEntries []ConflictUserEntry, stats ExportStats) {
	emails := make([]string, 0, len(idx.ByNormalizedEmail))
	for email := range idx.ByNormalizedEmail {
		emails = append(emails, email)
	}
	sort.Strings(emails)

	for _, normalizedEmail := range emails {
		usersForEmail := idx.ByNormalizedEmail[normalizedEmail]
		stats.TotalUniqueEmails++

		isConflict := idx.IsConflict(normalizedEmail)
		primary := PrimaryUser(usersForEmail, precedence)

		if isExcludedDomain(primary.Email, excludeDomains) {
			stats.SkippedDomain++
			log.Debug("Skipping excluded domain", zap.String("email", primary.Email))
			continue
		}

		// Skip SSO users on the non-conflict path (they have no satellite password).
		if !isConflict && primary.ExternalID != "" {
			stats.SkippedSSO++
			log.Debug("Skipping SSO user", zap.String("email", primary.Email))
			continue
		}

		faUser, skip, reason := buildFusionAuthUser(log, primary, usersForEmail, isConflict, appIDs, tenantID)
		if skip {
			switch reason {
			case "no_hash":
				stats.SkippedNoHash++
			case "parse_error":
				stats.SkippedParseErr++
			}
			continue
		}

		if isConflict {
			stats.ConflictUsers++
			conflictEntries = append(conflictEntries, ConflictUserEntry{
				Email:         primary.Email,
				Satellites:    distinctSatellites(usersForEmail),
				ApplicationID: appIDs[primary.SatelliteName],
			})
		} else {
			stats.NoConflictUsers++
		}
		if faUser.TwoFactor != nil {
			stats.UsersWithMFA++
		}
		faUsers = append(faUsers, faUser)
	}
	return faUsers, conflictEntries, stats
}

// buildFusionAuthUser constructs a single FusionAuthUser.
// Returns (user, skip=true, reason) if the user should be skipped.
func buildFusionAuthUser(
	log *zap.Logger,
	primary RawUser,
	allInstances []RawUser,
	isConflict bool,
	appIDs map[string]string,
	tenantID string,
) (FusionAuthUser, bool, string) {
	if len(primary.PasswordHash) == 0 {
		log.Debug("No password hash, skipping", zap.String("email", primary.Email))
		return FusionAuthUser{}, true, "no_hash"
	}

	verified := primary.Status == 1
	faUser := FusionAuthUser{
		Active:        true,
		Email:         primary.Email,
		FullName:      primary.FullName,
		InsertInstant: primary.CreatedAt.UnixMilli(),
		TenantID:      tenantID,
		Verified:      verified,
		Data: map[string]interface{}{
			"storjUserId":    primary.ID.String(),
			"storjStatus":    primary.Status,
			"sourceSatellite": primary.SatelliteName,
			"isConflictUser": isConflict,
			"mfaEnabled":     primary.MFAEnabled,
			"migratedFrom":   "storj-satellite",
			"migratedAt":     time.Now().UTC().Format(time.RFC3339),
		},
	}

	appID := appIDs[primary.SatelliteName]
	if !isConflict {
		parsed, err := ParseBcryptHash(primary.PasswordHash)
		if err != nil {
			log.Debug("Failed to parse bcrypt hash, skipping", zap.String("email", primary.Email), zap.Error(err))
			return FusionAuthUser{}, true, "parse_error"
		}
		faUser.EncryptionScheme = "bcrypt"
		faUser.Factor = parsed.Factor
		faUser.Salt = parsed.Salt
		faUser.Password = parsed.Hash
		if appID != "" {
			faUser.Registrations = []FusionAuthRegistration{
				{ApplicationID: appID, Verified: verified},
			}
		}
	} else {
		faUser.Data["conflictSatellites"] = distinctSatellites(allInstances)
		if appID != "" {
			faUser.Registrations = []FusionAuthRegistration{
				{ApplicationID: appID, Verified: verified},
			}
		} else {
			log.Warn("No app ID configured for primary satellite, skipping registration",
				zap.String("satellite", primary.SatelliteName),
				zap.String("email", primary.Email))
		}
	}

	if primary.MFAEnabled && primary.MFASecretKey != "" && len(primary.MFARecoveryCodes) > 0 {
		b64Secret, err := totpSecretToBase64(primary.MFASecretKey)
		if err != nil {
			log.Warn("Failed to convert TOTP secret, skipping MFA", zap.String("email", primary.Email), zap.Error(err))
		} else {
			faUser.TwoFactor = &FusionAuthTwoFactor{
				Methods: []FusionAuthTwoFactorMethod{
					{
						Method: "authenticator",
						Secret: b64Secret,
						Authenticator: &FusionAuthAuthenticatorConfig{
							Algorithm:  "HmacSHA1",
							CodeLength: 6,
							TimeStep:   30,
						},
					},
				},
				RecoveryCodes: primary.MFARecoveryCodes,
			}
		}
	}

	return faUser, false, ""
}

// isExcludedDomain returns true if the email belongs to one of the excluded domains.
func isExcludedDomain(email string, domains []string) bool {
	lower := strings.ToLower(email)
	for _, d := range domains {
		if strings.HasSuffix(lower, "@"+strings.ToLower(d)) {
			return true
		}
	}
	return false
}
