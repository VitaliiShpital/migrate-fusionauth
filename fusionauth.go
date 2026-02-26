// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package main

// FusionAuthUser represents a user in FusionAuth import format.
// For conflict users, Password/Salt/Factor/EncryptionScheme are omitted (zero values + omitempty).
type FusionAuthUser struct {
	Active           bool                     `json:"active"`
	Email            string                   `json:"email"`
	EncryptionScheme string                   `json:"encryptionScheme,omitempty"`
	Factor           int                      `json:"factor,omitempty"`
	FullName         string                   `json:"fullName,omitempty"`
	InsertInstant    int64                    `json:"insertInstant,omitempty"`
	Password         string                   `json:"password,omitempty"`
	Salt             string                   `json:"salt,omitempty"`
	TenantID         string                   `json:"tenantId,omitempty"`
	Verified         bool                     `json:"verified"`
	Data             map[string]interface{}   `json:"data,omitempty"`
	Registrations    []FusionAuthRegistration `json:"registrations,omitempty"`
	TwoFactor        *FusionAuthTwoFactor     `json:"twoFactor,omitempty"`
}

// FusionAuthRegistration represents a per-application registration.
type FusionAuthRegistration struct {
	ApplicationID string `json:"applicationId"`
	Verified      bool   `json:"verified"`
}

// FusionAuthTwoFactor holds TOTP import data.
type FusionAuthTwoFactor struct {
	Methods       []FusionAuthTwoFactorMethod `json:"methods"`
	RecoveryCodes []string                    `json:"recoveryCodes,omitempty"`
}

// FusionAuthTwoFactorMethod describes a single 2FA method.
type FusionAuthTwoFactorMethod struct {
	Method        string                         `json:"method"`
	Secret        string                         `json:"secret,omitempty"`
	Authenticator *FusionAuthAuthenticatorConfig `json:"authenticator,omitempty"`
}

// FusionAuthAuthenticatorConfig holds TOTP authenticator parameters.
type FusionAuthAuthenticatorConfig struct {
	Algorithm  string `json:"algorithm"`
	CodeLength int    `json:"codeLength"`
	TimeStep   int    `json:"timeStep"`
}

// FusionAuthImport represents the FusionAuth import request body.
type FusionAuthImport struct {
	Users            []FusionAuthUser `json:"users"`
	ValidateDBSchema bool             `json:"validateDbSchema"`
}

// ConflictUserEntry describes a conflict user for the follow-up forgot-password step.
type ConflictUserEntry struct {
	Email         string   `json:"email"`
	Satellites    []string `json:"satellites"`
	ApplicationID string   `json:"applicationId"`
}
