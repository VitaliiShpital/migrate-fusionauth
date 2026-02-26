// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// BcryptComponents holds the parsed parts of a bcrypt hash.
type BcryptComponents struct {
	Algorithm string
	Factor    int
	Salt      string
	Hash      string
}

// ParseBcryptHash splits a bcrypt hash of the form $2a$10$<22-char-salt><31-char-hash>.
func ParseBcryptHash(raw []byte) (BcryptComponents, error) {
	s := strings.TrimRight(string(raw), "\x00")

	parts := strings.SplitN(s, "$", 4)
	if len(parts) != 4 || parts[0] != "" {
		return BcryptComponents{}, fmt.Errorf("unrecognised bcrypt format")
	}

	algo := parts[1]
	if algo != "2a" && algo != "2b" {
		return BcryptComponents{}, fmt.Errorf("unsupported bcrypt variant %q", algo)
	}

	factor, err := strconv.Atoi(parts[2])
	if err != nil {
		return BcryptComponents{}, fmt.Errorf("invalid cost factor: %w", err)
	}

	tail := parts[3]
	if len(tail) < 53 {
		return BcryptComponents{}, fmt.Errorf("bcrypt tail too short (%d chars)", len(tail))
	}

	return BcryptComponents{
		Algorithm: algo,
		Factor:    factor,
		Salt:      tail[:22],
		Hash:      tail[22:],
	}, nil
}

// totpSecretToBase64 converts a base32-encoded TOTP secret to base64 as required by FusionAuth.
func totpSecretToBase64(base32Secret string) (string, error) {
	raw, err := base32.StdEncoding.DecodeString(strings.ToUpper(base32Secret))
	if err != nil {
		return "", fmt.Errorf("decode base32 TOTP secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
