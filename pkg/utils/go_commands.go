package utils

import (
	"fmt"
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
