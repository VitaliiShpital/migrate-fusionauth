// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import "sort"

// UserIndex indexes users from all satellites by normalized email.
type UserIndex struct {
	ByNormalizedEmail map[string][]RawUser
}

// BuildIndex constructs a UserIndex from per-satellite user slices.
func BuildIndex(bySatellite map[string][]RawUser) UserIndex {
	idx := UserIndex{
		ByNormalizedEmail: make(map[string][]RawUser),
	}
	for _, users := range bySatellite {
		for _, u := range users {
			idx.ByNormalizedEmail[u.NormalizedEmail] = append(
				idx.ByNormalizedEmail[u.NormalizedEmail], u,
			)
		}
	}
	return idx
}

// IsConflict returns true if the normalized email appears on more than one satellite.
func (idx *UserIndex) IsConflict(normalizedEmail string) bool {
	seen := make(map[string]struct{})
	for _, u := range idx.ByNormalizedEmail[normalizedEmail] {
		seen[u.SatelliteName] = struct{}{}
	}
	return len(seen) > 1
}

// PrimaryUser returns the RawUser to use as the identity source for a conflict user,
// applying the precedence list (e.g. us1 > eu1 > ap1).
// Falls back to the first entry if no satellite matches.
func PrimaryUser(users []RawUser, precedence []string) RawUser {
	for _, satName := range precedence {
		for _, u := range users {
			if u.SatelliteName == satName {
				return u
			}
		}
	}
	return users[0]
}

// distinctSatellites returns a sorted, deduplicated list of satellite names from the given users.
func distinctSatellites(users []RawUser) []string {
	seen := make(map[string]struct{})
	for _, u := range users {
		seen[u.SatelliteName] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
