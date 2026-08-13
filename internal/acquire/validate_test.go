package acquire

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateWheelRequirementsRejectsExecutableSourceForms(t *testing.T) {
	cases := []string{
		"--no-binary :all:\nexample==1.0\n",
		"--only-binary=:none:\nexample==1.0\n",
		"-e ./local-project\n",
		"example @ git+https://example.invalid/repo.git\n",
		"example @ https://example.invalid/example.tar.gz\n",
		"-r nested.txt\n",
	}
	for _, contents := range cases {
		t.Run(contents, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "requirements.txt")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validateWheelRequirements(path); err == nil {
				t.Fatalf("accepted unsafe requirements: %q", contents)
			}
		})
	}
}

func TestValidateWheelRequirementsAcceptsPinnedWheelsAndHashes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.txt")
	contents := "six==1.17.0 \\\n    --hash=sha256:fixture\nhttps://example.invalid/pkg-1.0-py3-none-any.whl\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateWheelRequirements(path); err != nil {
		t.Fatalf("safe requirements rejected: %v", err)
	}
}

func TestValidateNodeDependenciesRejectsSourceSpecs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.json")
	if err := os.WriteFile(path, []byte(`{
		"dependencies":{"bad":"git+https://example.invalid/repo.git"}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateNodeDependencies(path); err == nil {
		t.Fatal("accepted a git dependency whose prepare hook could run during fetch")
	}
}

func TestValidateNodeDependenciesAcceptsRegistryAndWorkspaceSpecs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.json")
	if err := os.WriteFile(path, []byte(`{
		"dependencies":{"one":"^1.2.3","two":"npm:other@2","local":"workspace:*"}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateNodeDependencies(path); err != nil {
		t.Fatalf("safe dependency specs rejected: %v", err)
	}
}

func TestValidateNodeDependenciesRejectsGitInLockfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(`{"dependencies":{"one":"1.0.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"packages":{"node_modules/one":{"resolved":"git+https://example.invalid/repo.git"}}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateNodeDependencies(path); err == nil {
		t.Fatal("accepted a git package-lock entry")
	}
}

func TestValidateNodeDependenciesRejectsGitInLegacyLockfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(`{"dependencies":{"one":"1.0.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion":1,
		"dependencies":{"one":{"version":"git+https://example.invalid/repo.git"}}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateNodeDependencies(path); err == nil {
		t.Fatal("accepted a git dependency in a legacy package-lock")
	}
}
