// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestImportVerifyFlags(t *testing.T) {
	t.Run("missing fusionauth url", func(t *testing.T) {
		err := (&ImportConfig{TenantID: "tid", APIKey: "key", InputFile: "f.json", BatchSize: 1000}).VerifyFlags()
		require.ErrorContains(t, err, "--fusionauth-url is required")
	})
	t.Run("missing tenant id", func(t *testing.T) {
		err := (&ImportConfig{FusionAuthURL: "http://fa", APIKey: "key", InputFile: "f.json", BatchSize: 1000}).VerifyFlags()
		require.ErrorContains(t, err, "--fusionauth-tenant-id is required")
	})
	t.Run("missing api key", func(t *testing.T) {
		err := (&ImportConfig{FusionAuthURL: "http://fa", TenantID: "tid", InputFile: "f.json", BatchSize: 1000}).VerifyFlags()
		require.ErrorContains(t, err, "--api-key is required")
	})
	t.Run("invalid batch size", func(t *testing.T) {
		err := (&ImportConfig{FusionAuthURL: "http://fa", TenantID: "tid", APIKey: "key", InputFile: "f.json", BatchSize: 0}).VerifyFlags()
		require.ErrorContains(t, err, "--batch-size must be positive")
	})
}

func TestImport(t *testing.T) {
	t.Run("dry run does not send requests", func(t *testing.T) {
		f := writeImportFile(t, makeTestImportUsers(5))
		log := zaptest.NewLogger(t)
		cfg := &ImportConfig{
			FusionAuthURL: "http://fa",
			TenantID:      "tid",
			APIKey:        "key",
			InputFile:     f,
			BatchSize:     1000,
			DryRun:        true,
		}
		require.NoError(t, Import(t.Context(), log, cfg))
	})

	t.Run("users split into correct batches", func(t *testing.T) {
		f := writeImportFile(t, makeTestImportUsers(25))

		var received [][]FusionAuthUser
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "testkey", r.Header.Get("Authorization"))
			require.Equal(t, "testtenantid", r.Header.Get("X-FusionAuth-TenantId"))
			var body FusionAuthImport
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			received = append(received, body.Users)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		cfg := &ImportConfig{
			FusionAuthURL: srv.URL,
			TenantID:      "testtenantid",
			APIKey:        "testkey",
			InputFile:     f,
			BatchSize:     10,
		}
		require.NoError(t, Import(t.Context(), zaptest.NewLogger(t), cfg))

		// 25 users / 10 per batch = 3 batches (10, 10, 5).
		require.Len(t, received, 3)
		require.Len(t, received[0], 10)
		require.Len(t, received[1], 10)
		require.Len(t, received[2], 5)
	})

	t.Run("server error is propagated", func(t *testing.T) {
		f := writeImportFile(t, makeTestImportUsers(3))

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Invalid API key"}`))
		}))
		defer srv.Close()

		cfg := &ImportConfig{
			FusionAuthURL: srv.URL,
			TenantID:      "tid",
			APIKey:        "wrong",
			InputFile:     f,
			BatchSize:     1000,
		}
		err := Import(t.Context(), zaptest.NewLogger(t), cfg)
		require.ErrorContains(t, err, "401")
		require.ErrorContains(t, err, "Invalid API key")
	})
}

func makeTestImportUsers(n int) []FusionAuthUser {
	users := make([]FusionAuthUser, n)
	for i := range users {
		users[i] = FusionAuthUser{Active: true, Email: fmt.Sprintf("user%d@example.com", i)}
	}
	return users
}

func writeImportFile(t *testing.T, users []FusionAuthUser) string {
	t.Helper()
	data, err := json.Marshal(FusionAuthImport{Users: users, ValidateDBSchema: true})
	require.NoError(t, err)
	f, err := os.CreateTemp(t.TempDir(), "import-*.json")
	require.NoError(t, err)
	_, err = f.Write(data)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}
