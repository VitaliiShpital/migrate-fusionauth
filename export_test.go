// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testrand"
)

func TestBcryptAndTOTP(t *testing.T) {
	t.Run("parse valid bcrypt hash", func(t *testing.T) {
		got, err := ParseBcryptHash([]byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"))
		require.NoError(t, err)
		require.Equal(t, "2a", got.Algorithm)
		require.Equal(t, 10, got.Factor)
		require.Equal(t, "N9qo8uLOickgx2ZMRZoMye", got.Salt)
		require.Equal(t, "IjZAgcfl7p92ldGxad68LJZdL17lhWy", got.Hash)
	})

	t.Run("reject invalid bcrypt", func(t *testing.T) {
		for _, input := range []string{"", "not-a-hash", "$1$10$abc"} {
			_, err := ParseBcryptHash([]byte(input))
			require.Error(t, err, "input: %q", input)
		}
	})

	t.Run("convert TOTP base32 to base64", func(t *testing.T) {
		b64, err := totpSecretToBase64("JBSWY3DPEHPK3PXP")
		require.NoError(t, err)
		require.NotEmpty(t, b64)
	})

	t.Run("reject invalid TOTP secret", func(t *testing.T) {
		_, err := totpSecretToBase64("!!!invalid!!!")
		require.Error(t, err)
	})
}

func TestReadCSV(t *testing.T) {
	hash := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

	t.Run("parses byte columns and redash timestamp format", func(t *testing.T) {
		id := testrand.UUID()
		path := writeCSV(t, [][]string{
			{"id", "email", "normalized_email", "full_name", "created_at", "external_id", "mfa_enabled", "mfa_secret_key", "mfa_recovery_codes", "password_hash", "status"},
			{plainHex(id[:]), "alice@example.com", "ALICE@EXAMPLE.COM", "Alice", "04/13/21 22:38", "", "false", "", "", plainHex([]byte(hash)), "1"},
		})
		users, err := ReadCSV(path, "us1")
		require.NoError(t, err)
		require.Len(t, users, 1)
		u := users[0]
		require.Equal(t, id, u.ID)
		require.Equal(t, "alice@example.com", u.Email)
		require.Equal(t, []byte(hash), u.PasswordHash)
		require.Equal(t, 1, u.Status)
		require.Equal(t, 2021, u.CreatedAt.Year())
		require.Equal(t, "us1", u.SatelliteName)
		require.Nil(t, u.MFARecoveryCodes)
	})

	t.Run("parses mfa_recovery_codes as JSON array", func(t *testing.T) {
		mfaID := testrand.UUID()
		path := writeCSV(t, [][]string{
			{"id", "email", "password_hash", "status", "created_at", "mfa_enabled", "mfa_secret_key", "mfa_recovery_codes"},
			{plainHex(mfaID[:]), "mfa@example.com", plainHex([]byte(hash)), "1", "04/13/21 22:38", "true", "JBSWY3DPEHPK3PXP", `["code1","code2"]`},
		})
		users, err := ReadCSV(path, "us1")
		require.NoError(t, err)
		require.True(t, users[0].MFAEnabled)
		require.Equal(t, []string{"code1", "code2"}, users[0].MFARecoveryCodes)
	})

	t.Run("computes normalized_email from email when column absent", func(t *testing.T) {
		normID := testrand.UUID()
		path := writeCSV(t, [][]string{
			{"id", "email", "password_hash", "status", "created_at", "mfa_enabled"},
			{plainHex(normID[:]), "Test@Example.COM", plainHex([]byte(hash)), "1", "04/13/21 22:38", "false"},
		})
		users, err := ReadCSV(path, "us1")
		require.NoError(t, err)
		require.Equal(t, "TEST@EXAMPLE.COM", users[0].NormalizedEmail)
	})
}

func TestConflictDetectionAndPrecedence(t *testing.T) {
	bySatellite := map[string][]RawUser{
		"us1": {
			{Email: "alice@example.com", NormalizedEmail: "ALICE@EXAMPLE.COM", SatelliteName: "us1"},
			{Email: "bob@example.com", NormalizedEmail: "BOB@EXAMPLE.COM", SatelliteName: "us1"},
		},
		"eu1": {
			{Email: "alice@example.com", NormalizedEmail: "ALICE@EXAMPLE.COM", SatelliteName: "eu1"},
			{Email: "charlie@example.com", NormalizedEmail: "CHARLIE@EXAMPLE.COM", SatelliteName: "eu1"},
		},
	}
	idx := BuildIndex(bySatellite)

	t.Run("cross-satellite email is conflict", func(t *testing.T) {
		require.True(t, idx.IsConflict("ALICE@EXAMPLE.COM"))
	})

	t.Run("single-satellite email is not conflict", func(t *testing.T) {
		require.False(t, idx.IsConflict("BOB@EXAMPLE.COM"))
		require.False(t, idx.IsConflict("CHARLIE@EXAMPLE.COM"))
	})

	t.Run("same satellite duplicates not a conflict", func(t *testing.T) {
		dupeIdx := BuildIndex(map[string][]RawUser{
			"us1": {
				{NormalizedEmail: "DUP@EXAMPLE.COM", SatelliteName: "us1"},
				{NormalizedEmail: "DUP@EXAMPLE.COM", SatelliteName: "us1"},
			},
		})
		require.False(t, dupeIdx.IsConflict("DUP@EXAMPLE.COM"))
	})

	t.Run("precedence selects correct satellite", func(t *testing.T) {
		users := []RawUser{{SatelliteName: "eu1"}, {SatelliteName: "ap1"}, {SatelliteName: "us1"}}
		require.Equal(t, "us1", PrimaryUser(users, []string{"us1", "eu1", "ap1"}).SatelliteName)
		require.Equal(t, "ap1", PrimaryUser(users, []string{"ap1", "eu1", "us1"}).SatelliteName)
		require.Equal(t, "eu1", PrimaryUser(users, []string{"qa"}).SatelliteName) // fallback to first
	})

	t.Run("distinct satellites sorted", func(t *testing.T) {
		users := []RawUser{{SatelliteName: "eu1"}, {SatelliteName: "us1"}, {SatelliteName: "eu1"}, {SatelliteName: "ap1"}}
		require.Equal(t, []string{"ap1", "eu1", "us1"}, distinctSatellites(users))
	})
}

func TestBuildFusionAuthUsers(t *testing.T) {
	log := zaptest.NewLogger(t)
	appIDs := map[string]string{"us1": "app-us1-id", "eu1": "app-eu1-id", "ap1": "app-ap1-id"}
	tenantID := "tenant-id"
	precedence := []string{"us1", "eu1", "ap1"}
	hash := []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")

	t.Run("no conflict exports password and single registration", func(t *testing.T) {
		id := testrand.UUID()
		primary := RawUser{
			ID: id, Email: "alice@example.com", NormalizedEmail: "ALICE@EXAMPLE.COM",
			FullName: "Alice Smith", PasswordHash: hash,
			Status: 1, CreatedAt: time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC), SatelliteName: "us1",
		}
		faUser, skip, _ := buildFusionAuthUser(log, primary, []RawUser{primary}, false, appIDs, tenantID)
		require.False(t, skip)
		require.Equal(t, "bcrypt", faUser.EncryptionScheme)
		require.Equal(t, 10, faUser.Factor)
		require.Equal(t, "N9qo8uLOickgx2ZMRZoMye", faUser.Salt)
		require.Len(t, faUser.Registrations, 1)
		require.Equal(t, "app-us1-id", faUser.Registrations[0].ApplicationID)
		require.Equal(t, id.String(), faUser.Data["storjUserId"])
	})

	t.Run("conflict exports no password and single registration for primary satellite", func(t *testing.T) {
		users := []RawUser{
			{ID: testrand.UUID(), Email: "bob@example.com", NormalizedEmail: "BOB@EXAMPLE.COM",
				PasswordHash: hash, Status: 1, SatelliteName: "us1"},
			{ID: testrand.UUID(), Email: "bob@example.com", NormalizedEmail: "BOB@EXAMPLE.COM",
				PasswordHash: hash, Status: 1, SatelliteName: "eu1"},
		}
		primary := PrimaryUser(users, precedence)
		faUser, skip, _ := buildFusionAuthUser(log, primary, users, true, appIDs, tenantID)
		require.False(t, skip)
		require.Empty(t, faUser.Password)
		require.Len(t, faUser.Registrations, 1)
		require.Equal(t, "app-us1-id", faUser.Registrations[0].ApplicationID)
		require.Equal(t, true, faUser.Data["isConflictUser"])
		conflictSats, ok := faUser.Data["conflictSatellites"].([]string)
		require.True(t, ok)
		require.ElementsMatch(t, []string{"us1", "eu1"}, conflictSats)
	})

	t.Run("skip user without password hash", func(t *testing.T) {
		primary := RawUser{ID: testrand.UUID(), Email: "nohash@example.com", Status: 1, SatelliteName: "us1"}
		_, skip, reason := buildFusionAuthUser(log, primary, []RawUser{primary}, false, appIDs, tenantID)
		require.True(t, skip)
		require.Equal(t, "no_hash", reason)
	})

	t.Run("MFA exported with TOTP secret and recovery codes", func(t *testing.T) {
		primary := RawUser{
			ID: testrand.UUID(), Email: "mfa@example.com", PasswordHash: hash,
			Status: 1, MFAEnabled: true, MFASecretKey: "JBSWY3DPEHPK3PXP",
			MFARecoveryCodes: []string{"code1", "code2"}, SatelliteName: "us1",
		}
		faUser, skip, _ := buildFusionAuthUser(log, primary, []RawUser{primary}, false, appIDs, tenantID)
		require.False(t, skip)
		require.NotNil(t, faUser.TwoFactor)
		require.Len(t, faUser.TwoFactor.Methods, 1)
		require.Equal(t, "authenticator", faUser.TwoFactor.Methods[0].Method)
		require.Equal(t, []string{"code1", "code2"}, faUser.TwoFactor.RecoveryCodes)
	})

	t.Run("SSO user skipped", func(t *testing.T) {
		idx := BuildIndex(map[string][]RawUser{
			"us1": {{
				ID: testrand.UUID(), ExternalID: "enterprise-entra:some-oid",
				Email: "sso@enterprise.com", NormalizedEmail: "SSO@ENTERPRISE.COM",
				PasswordHash: hash, Status: 1, SatelliteName: "us1",
			}},
		})
		faUsers, _, stats := buildAllFusionAuthUsers(log, idx, appIDs, precedence, tenantID, nil)
		require.Empty(t, faUsers)
		require.Equal(t, 1, stats.SkippedSSO)
	})

	t.Run("excluded domain skipped", func(t *testing.T) {
		idx := BuildIndex(map[string][]RawUser{
			"us1": {
				{ID: testrand.UUID(), Email: "internal@storj.io", NormalizedEmail: "INTERNAL@STORJ.IO",
					PasswordHash: hash, Status: 1, SatelliteName: "us1"},
				{ID: testrand.UUID(), Email: "external@example.com", NormalizedEmail: "EXTERNAL@EXAMPLE.COM",
					PasswordHash: hash, Status: 1, SatelliteName: "us1"},
			},
		})
		faUsers, _, stats := buildAllFusionAuthUsers(log, idx, appIDs, precedence, tenantID, []string{"storj.io"})
		require.Len(t, faUsers, 1)
		require.Equal(t, "external@example.com", faUsers[0].Email)
		require.Equal(t, 1, stats.SkippedDomain)
	})

	t.Run("excluded domain matching is case insensitive", func(t *testing.T) {
		require.True(t, isExcludedDomain("User@STORJ.IO", []string{"storj.io"}))
		require.True(t, isExcludedDomain("user@storj.io", []string{"STORJ.IO"}))
		require.False(t, isExcludedDomain("user@example.com", []string{"storj.io"}))
		require.False(t, isExcludedDomain("user@notstorj.io", []string{"storj.io"}))
	})
}

// writeCSV writes rows to a temp CSV file and returns its path.
func writeCSV(t *testing.T, rows [][]string) string {
	t.Helper()
	path := t.TempDir() + "/users.csv"
	f, err := os.Create(path)
	require.NoError(t, err)
	w := csv.NewWriter(f)
	require.NoError(t, w.WriteAll(rows))
	w.Flush()
	require.NoError(t, f.Close())
	return path
}

// plainHex encodes bytes as plain lowercase hex, matching Redash's Spanner BYTES export format.
func plainHex(b []byte) string {
	return fmt.Sprintf("%x", b)
}

