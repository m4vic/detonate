package acquire

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// validateInertFetch rejects manifest forms that can cause a package manager
// to prepare source code while resolving dependencies. Unsupported is safer
// than assuming --ignore-scripts or --only-binary covers a form it was not
// designed to cover.
func validateInertFetch(targetDir string, m Manifest) error {
	switch m.Ecosystem {
	case EcosystemPython:
		return validateWheelRequirements(filepath.Join(targetDir, m.File))
	case EcosystemNode:
		return validateNodeDependencies(filepath.Join(targetDir, "package.json"))
	default:
		return nil
	}
}

func validateWheelRequirements(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading requirements for safe acquisition: %w", err)
	}
	logical := strings.ReplaceAll(string(data), "\\\r\n", " ")
	logical = strings.ReplaceAll(logical, "\\\n", " ")
	for number, raw := range strings.Split(logical, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		unsafeOnlyBinary := strings.Contains(lower, "--only-binary") &&
			!strings.Contains(lower, "--only-binary=:all:") &&
			!strings.Contains(lower, "--only-binary :all:")
		unsafe := strings.HasPrefix(lower, "-e ") ||
			strings.HasPrefix(lower, "--editable") ||
			strings.HasPrefix(lower, "-r ") ||
			strings.HasPrefix(lower, "--requirement") ||
			strings.HasPrefix(lower, "-c ") ||
			strings.HasPrefix(lower, "--constraint") ||
			strings.Contains(lower, "--no-binary") ||
			strings.Contains(lower, "git+") ||
			strings.Contains(lower, "hg+") ||
			strings.Contains(lower, "svn+") ||
			strings.Contains(lower, "bzr+") ||
			strings.Contains(lower, "file:") ||
			strings.Contains(lower, "${") ||
			strings.HasPrefix(lower, ".") ||
			strings.HasPrefix(lower, "/") || unsafeOnlyBinary
		if unsafe {
			return fmt.Errorf("requirements.txt line %d is not an inert wheel requirement: %q",
				number+1, line)
		}
		if (strings.HasPrefix(lower, "http://") ||
			strings.HasPrefix(lower, "https://") || strings.Contains(lower, " @ http")) &&
			!strings.Contains(strings.SplitN(lower, "#", 2)[0], ".whl") {
			return fmt.Errorf("requirements.txt line %d is a direct non-wheel URL: %q",
				number+1, line)
		}
	}
	return nil
}

func validateNodeDependencies(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading package.json for safe acquisition: %w", err)
	}
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return fmt.Errorf("parsing package.json for safe acquisition: %w", err)
	}
	sets := []map[string]string{
		pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies,
	}
	for _, dependencies := range sets {
		names := make([]string, 0, len(dependencies))
		for name := range dependencies {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			spec := dependencies[name]
			lower := strings.ToLower(strings.TrimSpace(spec))
			if strings.HasPrefix(lower, "git+") ||
				strings.HasPrefix(lower, "git://") ||
				strings.HasPrefix(lower, "github:") ||
				strings.HasPrefix(lower, "gitlab:") ||
				strings.HasPrefix(lower, "bitbucket:") ||
				strings.HasPrefix(lower, "file:") ||
				strings.HasPrefix(lower, "link:") ||
				strings.HasPrefix(lower, "http://") ||
				strings.HasPrefix(lower, "https://") {
				return fmt.Errorf("dependency %q uses source/direct spec %q", name, spec)
			}
		}
	}
	lockPath := filepath.Join(filepath.Dir(path), "package-lock.json")
	lockData, err := os.ReadFile(lockPath)
	if err == nil {
		var lock any
		if err := json.Unmarshal(lockData, &lock); err != nil {
			return fmt.Errorf("parsing package-lock.json for safe acquisition: %w", err)
		}
		if source, ok := findUnsafeLockSource(lock); ok {
			return fmt.Errorf("package-lock resolves from executable source %q", source)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("reading package-lock.json for safe acquisition: %w", err)
	}
	return nil
}

// findUnsafeLockSource walks both modern package-lock "packages" entries and
// the recursively nested "dependencies" entries used by lockfileVersion 1.
func findUnsafeLockSource(value any) (string, bool) {
	switch current := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(current))
		for key := range current {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := current[key]
			if text, ok := child.(string); ok &&
				(key == "resolved" || key == "version") && isExecutableNodeSource(text) {
				return text, true
			}
			if source, ok := findUnsafeLockSource(child); ok {
				return source, true
			}
		}
	case []any:
		for _, child := range current {
			if source, ok := findUnsafeLockSource(child); ok {
				return source, true
			}
		}
	}
	return "", false
}

func isExecutableNodeSource(spec string) bool {
	lower := strings.ToLower(strings.TrimSpace(spec))
	return strings.HasPrefix(lower, "git+") ||
		strings.HasPrefix(lower, "git://") ||
		strings.HasPrefix(lower, "github:") ||
		strings.HasPrefix(lower, "gitlab:") ||
		strings.HasPrefix(lower, "bitbucket:") ||
		strings.HasPrefix(lower, "file:") ||
		strings.HasPrefix(lower, "link:")
}
