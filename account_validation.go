package gosnowflake

import (
	"strings"
)

// Account and region are concatenated into the driver-derived hostname
// (DSN, fillMissingConfigParameters, transformAccountToHost). Allowed values
// are a non-empty list of non-empty labels, each made of ASCII letters, digits,
// '_' and '-'. Dots remain legal as label separators, so locators, org-account,
// underscores, dotted regional/org forms, and consecutive hyphens keep working.

// isValidAccountIdentifierRune reports whether r may appear inside a single
// dot-separated label of an account identifier or a region.
func isValidAccountIdentifierRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '_' || r == '-':
		return true
	default:
		return false
	}
}

// isValidAccountIdentifier reports whether value is a non-empty sequence of
// non-empty dot-separated labels made only of runes accepted by
// isValidAccountIdentifierRune. Ranging over each label yields runes, so
// non-ASCII input is rejected as well.
func isValidAccountIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" {
			return false
		}
		for _, r := range label {
			if !isValidAccountIdentifierRune(r) {
				return false
			}
		}
	}
	return true
}

// validateAccountAndRegion checks user-supplied account and region values before
// they are used as hostname components. Empty accounts retain the existing error.
func validateAccountAndRegion(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Space trimming mirrors the empty-account check further down in
	// fillMissingConfigParameters (strings.Trim(cfg.Account, " ")), so
	// surrounding spaces remain exactly as tolerated as they are today and an
	// all-spaces account still produces ErrEmptyAccount rather than this error.
	// Only spaces are trimmed, not all whitespace.
	if account := strings.Trim(cfg.Account, " "); account != "" {
		if !isValidAccountIdentifier(account) {
			return ErrInvalidAccountIdentifier("account", account)
		}
	}
	if region := strings.Trim(cfg.Region, " "); region != "" {
		if !isValidAccountIdentifier(region) {
			return ErrInvalidAccountIdentifier("region", region)
		}
	}
	return nil
}
