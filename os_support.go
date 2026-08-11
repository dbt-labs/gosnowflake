package gosnowflake

// TODO(versusfacit): Should instead use compile-time build flags to
// not runtime checks
func isCacheSupportedGOOS(goos string) bool {
	switch goos {
	case "windows", "darwin", "linux":
		return true
	default:
		return false
	}
}
