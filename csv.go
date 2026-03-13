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
	TenantID         string
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

// rawTimestampLayout is the format used by direct satellite DB exports.
const rawTimestampLayout = "2006-01-02 15:04:05.999999 -07:00"

// ReadCSV reads users from a satellite CSV export.
//
// Expected columns (header names, case-insensitive):
//
//	id, external_id, email, normalized_email, full_name, password_hash,
//	status, created_at, mfa_enabled, mfa_secret_key, mfa_recovery_codes
//
// When redash is true (default), byte columns (id, password_hash) are treated
// as plain hex as exported by Redash from Spanner, and the Redash timestamp
// format is used. When redash is false, id and password_hash are read as plain
// strings and the raw satellite timestamp format is used.
func ReadCSV(path, satelliteName string, redash bool) (users []RawUser, err error) {
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
		v := strings.TrimSpace(record[i])
		if v == "null" || v == "NULL" {
			return ""
		}
		return v
	}

	tsLayout := redashTimestampLayout
	if !redash {
		tsLayout = rawTimestampLayout
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

		var id uuid.UUID
		if redash {
			rawID, err := parseHexBytes(get(record, "id"))
			if err != nil {
				return nil, fmt.Errorf("line %d: parse id: %w", lineNum, err)
			}
			id, err = uuid.FromBytes(rawID)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid uuid: %w", lineNum, err)
			}
		} else {
			id, err = uuid.FromString(get(record, "id"))
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid uuid: %w", lineNum, err)
			}
		}

		var passwordHash []byte
		if redash {
			passwordHash, err = parseHexBytes(get(record, "password_hash"))
			if err != nil {
				return nil, fmt.Errorf("line %d: parse password_hash: %w", lineNum, err)
			}
		} else {
			raw := get(record, "password_hash")
			if raw != "" && raw != "NULL" && raw != "null" {
				passwordHash = []byte(raw)
			}
		}

		status, _ := strconv.Atoi(get(record, "status"))
		mfaEnabled, _ := strconv.ParseBool(get(record, "mfa_enabled"))
		createdAt, err := time.Parse(tsLayout, get(record, "created_at"))
		if err != nil {
			return nil, fmt.Errorf("line %d: parse created_at %q: %w", lineNum, get(record, "created_at"), err)
		}

		normalizedEmail := get(record, "normalized_email")
		if normalizedEmail == "" {
			normalizedEmail = strings.ToUpper(get(record, "email"))
		}

		users = append(users, RawUser{
			ID:               id,
			ExternalID:       get(record, "external_id"),
			TenantID:         get(record, "tenant_id"),
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

// parseHexBytes decodes a plain-hex byte column as exported by Redash from Spanner.
func parseHexBytes(s string) ([]byte, error) {
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
