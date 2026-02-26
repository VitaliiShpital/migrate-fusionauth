// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zeebo/errs"
	"storj.io/common/uuid"
)

// RawUser holds user data read from a satellite CSV export.
type RawUser struct {
	ID               uuid.UUID
	ExternalID       string
	Email            string
	NormalizedEmail  string
	FullName         string
	PasswordHash     []byte
	Status           int
	CreatedAt        time.Time
	MFAEnabled       bool
	MFASecretKey     string
	MFARecoveryCodes []string
	SatelliteName    string
}

// redashTimestampLayout is the format Redash uses when exporting Spanner timestamps.
const redashTimestampLayout = "01/02/06 15:04"

// ReadCSV reads users from a CSV file exported from Redash (Spanner backend).
//
// Expected columns (header names, case-insensitive):
//
//	id, external_id, email, normalized_email, full_name, password_hash,
//	status, created_at, mfa_enabled, mfa_secret_key, mfa_recovery_codes
//
// Byte columns (id, password_hash) are plain hex as exported by Redash from Spanner.
func ReadCSV(path, satelliteName string) (users []RawUser, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer func() { err = errs.Combine(err, f.Close()) }()

	r := csv.NewReader(f)
	headers, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read header from %q: %w", path, err)
	}

	col := make(map[string]int, len(headers))
	for i, h := range headers {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}

	get := func(record []string, name string) string {
		i, ok := col[name]
		if !ok || i >= len(record) {
			return ""
		}
		return strings.TrimSpace(record[i])
	}

	lineNum := 1
	for {
		lineNum++
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read line %d from %q: %w", lineNum, path, err)
		}

		rawID, err := parseBytes(get(record, "id"))
		if err != nil {
			return nil, fmt.Errorf("line %d: parse id: %w", lineNum, err)
		}
		id, err := uuid.FromBytes(rawID)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid uuid: %w", lineNum, err)
		}

		passwordHash, err := parseBytes(get(record, "password_hash"))
		if err != nil {
			return nil, fmt.Errorf("line %d: parse password_hash: %w", lineNum, err)
		}

		status, _ := strconv.Atoi(get(record, "status"))
		mfaEnabled, _ := strconv.ParseBool(get(record, "mfa_enabled"))
		createdAt, _ := time.Parse(redashTimestampLayout, get(record, "created_at"))

		normalizedEmail := get(record, "normalized_email")
		if normalizedEmail == "" {
			normalizedEmail = strings.ToUpper(get(record, "email"))
		}

		users = append(users, RawUser{
			ID:               id,
			ExternalID:       get(record, "external_id"),
			Email:            get(record, "email"),
			NormalizedEmail:  normalizedEmail,
			FullName:         get(record, "full_name"),
			PasswordHash:     passwordHash,
			Status:           status,
			CreatedAt:        createdAt,
			MFAEnabled:       mfaEnabled,
			MFASecretKey:     get(record, "mfa_secret_key"),
			MFARecoveryCodes: parseRecoveryCodes(get(record, "mfa_recovery_codes")),
			SatelliteName:    satelliteName,
		})
	}
	return users, nil
}

// parseBytes decodes a plain-hex byte column as exported by Redash from Spanner.
func parseBytes(s string) ([]byte, error) {
	if s == "" || s == "NULL" || s == "null" {
		return nil, nil
	}
	return hex.DecodeString(s)
}


// parseRecoveryCodes parses the JSON string array stored in mfa_recovery_codes.
func parseRecoveryCodes(s string) []string {
	if s == "" || s == "NULL" || s == "null" {
		return nil
	}
	var codes []string
	if err := json.Unmarshal([]byte(s), &codes); err != nil {
		return nil
	}
	return codes
}
