package acquire

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFiles(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name    string
		files   []string
		wantEco Ecosystem
		wantF   string
	}{
		{"python requirements", []string{"requirements.txt", "server.py"}, EcosystemPython, "requirements.txt"},
		{"python pyproject", []string{"pyproject.toml", "server.py"}, EcosystemPython, "pyproject.toml"},
		{"python setup.py", []string{"setup.py"}, EcosystemPython, "setup.py"},
		{"node", []string{"package.json", "index.js"}, EcosystemNode, "package.json"},
		{"stdlib only", []string{"server.py"}, EcosystemNone, ""},
		{"empty dir", nil, EcosystemNone, ""},

		// requirements.txt wins: a project with both is telling us exactly
		// what to install rather than merely how it is packaged.
		{"both python manifests", []string{"pyproject.toml", "requirements.txt"}, EcosystemPython, "requirements.txt"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect(writeFiles(t, tc.files...))
			if got.Ecosystem != tc.wantEco {
				t.Errorf("Ecosystem = %q, want %q", got.Ecosystem, tc.wantEco)
			}
			if got.File != tc.wantF {
				t.Errorf("File = %q, want %q", got.File, tc.wantF)
			}
		})
	}
}

func TestDetectIgnoresDirectories(t *testing.T) {
	// A directory named requirements.txt is not a manifest. Treating it as one
	// would make the install phase fail on a target that needs no install.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "requirements.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := Detect(dir); got.Ecosystem != EcosystemNone {
		t.Errorf("Ecosystem = %q, want none", got.Ecosystem)
	}
}

func TestEnvFor(t *testing.T) {
	py := Manifest{Ecosystem: EcosystemPython}.EnvFor("/deps")
	if py["PYTHONPATH"] != "/deps" {
		t.Errorf("PYTHONPATH = %q; the interpreter cannot find installed deps without it", py["PYTHONPATH"])
	}

	node := Manifest{Ecosystem: EcosystemNode}.EnvFor("/deps")
	if !strings.Contains(node["NODE_PATH"], "node_modules") {
		t.Errorf("NODE_PATH = %q, want it to point at node_modules", node["NODE_PATH"])
	}

	if none := (Manifest{Ecosystem: EcosystemNone}).EnvFor("/deps"); none != nil {
		t.Errorf("EnvFor(none) = %v, want nil", none)
	}
}

func TestInstallCommand(t *testing.T) {
	t.Run("requirements.txt installs from the file", func(t *testing.T) {
		cmd := strings.Join(Manifest{Ecosystem: EcosystemPython, File: "requirements.txt"}.installCommand("/deps"), " ")
		if !strings.Contains(cmd, "-r /target/requirements.txt") {
			t.Errorf("command = %q", cmd)
		}
		if !strings.Contains(cmd, "--target /deps") {
			t.Errorf("deps must install into the shared volume, got %q", cmd)
		}
	})

	t.Run("pyproject installs the project, never editable", func(t *testing.T) {
		cmd := strings.Join(Manifest{Ecosystem: EcosystemPython, File: "pyproject.toml"}.installCommand("/deps"), " ")
		// -e writes into the target directory, which is mounted read-only
		// precisely so a target cannot modify itself mid-scan.
		if strings.Contains(cmd, " -e ") {
			t.Errorf("editable install would write into the read-only target: %q", cmd)
		}
	})

	t.Run("node does not suppress lifecycle scripts", func(t *testing.T) {
		cmd := strings.Join(Manifest{Ecosystem: EcosystemNode, File: "package.json"}.installCommand("/deps"), " ")
		// Lifecycle scripts are the supply-chain surface we exist to observe.
		// Suppressing them would hide the most valuable thing this phase finds.
		if strings.Contains(cmd, "--ignore-scripts") {
			t.Errorf("install must let lifecycle scripts run so they can be observed: %q", cmd)
		}
	})

	if cmd := (Manifest{Ecosystem: EcosystemNone}).installCommand("/deps"); cmd != nil {
		t.Errorf("installCommand(none) = %v, want nil", cmd)
	}
}
