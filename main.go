// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/process"
)

// SatelliteConfig holds per-satellite CSV configuration.
type SatelliteConfig struct {
	Name string
	CSV  string
}

// Config holds all configuration for the export command.
type Config struct {
	CSVUS1 string
	CSVEU1 string
	CSVAP1 string
	CSVQA  string

	FusionAuthTenantID     string
	FusionAuthAppID        string
	OutputFile             string
	ConflictOutputFile     string
	ConflictPrecedence     string
	ExcludeEmailDomainList string
	DryRun                 bool
}

// Satellites returns the list of configured satellites (those with a non-empty CSV path).
func (c *Config) Satellites() []SatelliteConfig {
	all := []SatelliteConfig{
		{"us1", c.CSVUS1},
		{"eu1", c.CSVEU1},
		{"ap1", c.CSVAP1},
		{"qa", c.CSVQA},
	}
	var result []SatelliteConfig
	for _, s := range all {
		if s.CSV != "" {
			result = append(result, s)
		}
	}
	return result
}

// Precedence returns the parsed conflict precedence list.
func (c *Config) Precedence() []string {
	var result []string
	for _, p := range strings.Split(c.ConflictPrecedence, ",") {
		if p = strings.TrimSpace(p); p != "" {
			result = append(result, p)
		}
	}
	return result
}

// ExcludeEmailDomains returns the parsed list of excluded email domains.
func (c *Config) ExcludeEmailDomains() []string {
	var result []string
	for _, d := range strings.Split(c.ExcludeEmailDomainList, ",") {
		if d = strings.TrimSpace(d); d != "" {
			result = append(result, d)
		}
	}
	return result
}

// VerifyFlags validates the export configuration.
func (c *Config) VerifyFlags() error {
	var g errs.Group
	if len(c.Satellites()) == 0 {
		g.Add(errs.New("at least one satellite must be configured (use --csv-NAME flags)"))
	}
	if c.FusionAuthTenantID == "" {
		g.Add(errs.New("--fusionauth-tenant-id is required"))
	}
	if c.FusionAuthAppID == "" {
		g.Add(errs.New("--app-id is required"))
	}
	return g.Err()
}

var (
	rootCmd = &cobra.Command{
		Use:   "migrate-fusionauth",
		Short: "Migrate Storj satellite users to FusionAuth",
	}

	exportCmd = &cobra.Command{
		Use:   "export",
		Short: "Build FusionAuth import JSON from per-satellite Redash CSV exports",
		RunE:  runExport,
	}

	sendPasswordResetsCmd = &cobra.Command{
		Use:   "send-password-resets",
		Short: "Trigger FusionAuth forgot-password emails for conflict users",
		RunE:  runSendPasswordResets,
	}

	backfillCmd = &cobra.Command{
		Use:   "backfill-external-ids",
		Short: "Generate SQL to populate external_id in satellite DBs from FusionAuth user IDs",
		RunE:  runBackfill,
	}

	cfg                   Config
	sendPasswordResetsCfg SendPasswordResetsConfig
	backfillCfg           BackfillConfig
)

func init() {
	f := exportCmd.Flags()
	f.StringVar(&cfg.CSVUS1, "csv-us1", "", "CSV file path for us1 satellite")
	f.StringVar(&cfg.CSVEU1, "csv-eu1", "", "CSV file path for eu1 satellite")
	f.StringVar(&cfg.CSVAP1, "csv-ap1", "", "CSV file path for ap1 satellite")
	f.StringVar(&cfg.CSVQA, "csv-qa", "", "CSV file path for qa satellite")
	f.StringVar(&cfg.FusionAuthTenantID, "fusionauth-tenant-id", "", "FusionAuth tenant ID")
	f.StringVar(&cfg.FusionAuthAppID, "app-id", "", "FusionAuth Application ID")
	f.StringVar(&cfg.OutputFile, "output", "fusionauth-import.json", "Output file for FusionAuth import JSON")
	f.StringVar(&cfg.ConflictOutputFile, "conflict-output", "conflict-users.json", "Output file listing conflict users")
	f.StringVar(&cfg.ConflictPrecedence, "conflict-precedence", "us1,eu1,ap1", "Comma-separated satellite precedence for conflict users (highest first)")
	f.StringVar(&cfg.ExcludeEmailDomainList, "exclude-email-domains", "", "Comma-separated email domains to skip (e.g. storj.io)")
	f.BoolVar(&cfg.DryRun, "dry-run", false, "Print statistics without writing files")
	rootCmd.AddCommand(exportCmd)

	sf := sendPasswordResetsCmd.Flags()
	sf.StringVar(&sendPasswordResetsCfg.FusionAuthURL, "fusionauth-url", "", "FusionAuth base URL (e.g. https://auth.example.com)")
	sf.StringVar(&sendPasswordResetsCfg.APIKey, "api-key", "", "FusionAuth API key")
	sf.StringVar(&sendPasswordResetsCfg.ConflictFile, "conflict-file", "conflict-users.json", "Path to conflict-users.json from the export step")
	sf.BoolVar(&sendPasswordResetsCfg.DryRun, "dry-run", false, "Print what would be sent without making HTTP requests")
	rootCmd.AddCommand(sendPasswordResetsCmd)

	bf := backfillCmd.Flags()
	bf.StringVar(&backfillCfg.FusionAuthURL, "fusionauth-url", "", "FusionAuth base URL (e.g. https://auth.example.com)")
	bf.StringVar(&backfillCfg.APIKey, "api-key", "", "FusionAuth API key")
	bf.StringVar(&backfillCfg.CSVUS1, "csv-us1", "", "CSV file path for us1 satellite")
	bf.StringVar(&backfillCfg.CSVEU1, "csv-eu1", "", "CSV file path for eu1 satellite")
	bf.StringVar(&backfillCfg.CSVAP1, "csv-ap1", "", "CSV file path for ap1 satellite")
	bf.StringVar(&backfillCfg.CSVQA, "csv-qa", "", "CSV file path for qa satellite")
	bf.StringVar(&backfillCfg.OutputDir, "output-dir", "", "Directory for generated SQL files (default: current dir)")
	bf.BoolVar(&backfillCfg.DryRun, "dry-run", false, "Print match statistics without writing SQL files")
	rootCmd.AddCommand(backfillCmd)
}

func runExport(cmd *cobra.Command, _ []string) error {
	if err := cfg.VerifyFlags(); err != nil {
		return err
	}
	log := zap.L()
	return Export(log, &cfg)
}

func runSendPasswordResets(cmd *cobra.Command, _ []string) error {
	if err := sendPasswordResetsCfg.VerifyFlags(); err != nil {
		return err
	}
	ctx, _ := process.Ctx(cmd)
	log := zap.L()
	return SendPasswordResets(ctx, log, &sendPasswordResetsCfg)
}

func runBackfill(cmd *cobra.Command, _ []string) error {
	if err := backfillCfg.VerifyFlags(); err != nil {
		return err
	}
	ctx, _ := process.Ctx(cmd)
	log := zap.L()
	return BackfillExternalIDs(ctx, log, &backfillCfg)
}

func main() {
	logger, _, _ := process.NewLogger("migrate-fusionauth")
	zap.ReplaceGlobals(logger)
	process.Exec(rootCmd)
}
