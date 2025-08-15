package version

import (
	"fmt"
	"runtime"
	"time"
)

// Version information - these can be overridden at build time using ldflags
var (
	// Version is the semantic version of golang-fbom-generator
	Version = "v1.0.0-beta"

	// GitCommit is the git commit hash (set at build time)
	GitCommit = "unknown"

	// GitBranch is the git branch (set at build time)
	GitBranch = "unknown"

	// BuildTime is when the binary was built (set at build time)
	BuildTime = "unknown"

	// BuildUser is who built the binary (set at build time)
	BuildUser = "unknown"
)

// BuildInfo contains comprehensive build and version information
type BuildInfo struct {
	Version     string    `json:"version"`
	GitCommit   string    `json:"git_commit"`
	GitBranch   string    `json:"git_branch"`
	BuildTime   string    `json:"build_time"`
	BuildUser   string    `json:"build_user"`
	GoVersion   string    `json:"go_version"`
	Platform    string    `json:"platform"`
	Compiler    string    `json:"compiler"`
	CompileTime time.Time `json:"compile_time"`
}

// GetBuildInfo returns comprehensive build information
func GetBuildInfo() *BuildInfo {
	compileTime, _ := time.Parse(time.RFC3339, BuildTime)
	if BuildTime == "unknown" {
		// Fallback to a reasonable default for development builds
		compileTime = time.Now()
	}

	return &BuildInfo{
		Version:     Version,
		GitCommit:   GitCommit,
		GitBranch:   GitBranch,
		BuildTime:   BuildTime,
		BuildUser:   BuildUser,
		GoVersion:   runtime.Version(),
		Platform:    fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		Compiler:    runtime.Compiler,
		CompileTime: compileTime,
	}
}

// GetVersion returns the semantic version string
func GetVersion() string {
	return Version
}

// GetVersionWithCommit returns version with git commit info
func GetVersionWithCommit() string {
	if GitCommit != "unknown" && len(GitCommit) >= 7 {
		return fmt.Sprintf("%s (%s)", Version, GitCommit[:7])
	}
	return Version
}

// GetFullVersionString returns a comprehensive version string for CLI display
func GetFullVersionString() string {
	info := GetBuildInfo()
	return fmt.Sprintf("golang-fbom-generator %s\nBuilt: %s\nCommit: %s\nBranch: %s\nGo: %s\nPlatform: %s",
		info.Version,
		info.BuildTime,
		info.GitCommit,
		info.GitBranch,
		info.GoVersion,
		info.Platform,
	)
}

// IsBeta returns true if this is a beta/prerelease version
func IsBeta() bool {
	return Version == "v1.0.0-beta" ||
		Version == "v1-beta" ||
		contains(Version, "beta") ||
		contains(Version, "alpha") ||
		contains(Version, "rc")
}

// IsProduction returns true if this is a stable production release
func IsProduction() bool {
	return !IsBeta()
}

// contains checks if a string contains a substring (helper function)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && s[len(s)-len(substr):] == substr ||
		(len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
