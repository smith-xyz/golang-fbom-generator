package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// GetCurrentGoModule returns the current Go module name by running 'go list -m'
func GetCurrentGoModule() (string, error) {
	cmd := exec.Command("go", "list", "-m")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get current module: %w", err)
	}

	module := strings.TrimSpace(string(output))
	if module == "" {
		return "", fmt.Errorf("no module found - not in a Go module directory")
	}

	return module, nil
}

// GetModuleVersions returns all module versions, with optional vendor mode support
func GetModuleVersions(useVendorMode bool) ([]string, error) {
	var cmd *exec.Cmd
	if useVendorMode {
		cmd = exec.Command("go", "list", "-mod=mod", "-m", "all")
	} else {
		cmd = exec.Command("go", "list", "-m", "all")
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute 'go list -m all': %w", err)
	}

	lines := strings.Split(string(output), "\n")
	var modules []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			modules = append(modules, line)
		}
	}

	return modules, nil
}

// GovulncheckResult represents the result of a govulncheck execution
type GovulncheckResult struct {
	Output   []byte
	ExitCode int
	Error    error
}

// CheckGovulncheckAvailable checks if govulncheck is available in PATH
func CheckGovulncheckAvailable(verbose bool) error {
	if verbose {
		fmt.Fprintf(os.Stderr, "Checking availability of govulncheck\n")
	}

	if _, err := exec.LookPath("govulncheck"); err != nil {
		return fmt.Errorf("govulncheck not found in PATH. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest")
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "govulncheck is available\n")
	}

	return nil
}

// ExecuteGovulncheck runs govulncheck with the specified arguments and working directory
func ExecuteGovulncheck(args []string, workingDir string, verbose bool) *GovulncheckResult {
	if verbose {
		fmt.Fprintf(os.Stderr, "Executing govulncheck: %v in %s\n", args, workingDir)
	}

	cmd := exec.Command("govulncheck", args...)
	if workingDir != "" {
		cmd.Dir = workingDir
	}

	output, err := cmd.Output()

	result := &GovulncheckResult{
		Output: output,
		Error:  err,
	}

	// Extract exit code
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = -1 // Unknown exit code
		}
	} else {
		result.ExitCode = 0
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "govulncheck completed with exit code: %d\n", result.ExitCode)
		if result.Error != nil && result.ExitCode != 0 {
			fmt.Fprintf(os.Stderr, "govulncheck error (non-fatal if output exists): %v\n", result.Error)
		}
	}

	return result
}

// IsGovulncheckSuccessOrExpectedFailure determines if a govulncheck result should be considered successful
// For govulncheck, exit code != 0 is expected when vulnerabilities are found
func IsGovulncheckSuccessOrExpectedFailure(result *GovulncheckResult) bool {
	// Success case
	if result.ExitCode == 0 {
		return true
	}

	// Expected failure case: govulncheck ran but found vulnerabilities (and produced output)
	if result.ExitCode != 0 && len(result.Output) > 0 {
		return true
	}

	return false
}
