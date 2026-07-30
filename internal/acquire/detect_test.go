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

// writeJSON writes a file into a fresh temp dir and returns the dir.
func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestNodeEntry(t *testing.T) {
	cases := []struct {
		name string
		pkg  string
		want string
	}{
		{"bin as a string", `{"bin":"./dist/cli.js"}`, "dist/cli.js"},
		{"main fallback", `{"main":"index.js"}`, "index.js"},

		// bin wins: a published MCP server declares bin because that is how an
		// agent host launches it.
		{"bin beats main", `{"bin":"dist/cli.js","main":"lib/index.js"}`, "dist/cli.js"},

		// Sorted, so the same package always yields the same entry point.
		{"bin object picks lowest name", `{"bin":{"z":"z.js","a":"a.js"}}`, "a.js"},

		{"neither declared", `{"name":"x"}`, ""},
		{"malformed json", `{`, ""},

		// Found on a real file: a BOM makes encoding/json reject an otherwise
		// valid manifest, and the entry point silently comes back empty.
		{"utf-8 BOM", "\uFEFF" + `{"main":"index.js"}`, "index.js"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeProject(t, map[string]string{"package.json": tc.pkg})
			if got := NodeEntry(dir); got != tc.want {
				t.Errorf("NodeEntry = %q, want %q", got, tc.want)
			}
		})
	}
}

// The TypeScript case: package.json points at compiled output that is not in
// the source tree. Without a build phase this target fails phase 2 with
// MODULE_NOT_FOUND, which reports nothing about its safety.
func TestDetectNeedsBuildWhenEntryIsMissing(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": `{"main":"dist/index.js","scripts":{"build":"tsc"}}`,
		"src/index.ts": `console.log(1)`,
	})

	m := Detect(dir)
	if m.Ecosystem != EcosystemNode {
		t.Fatalf("Ecosystem = %q, want node", m.Ecosystem)
	}
	if m.Entry != "dist/index.js" {
		t.Errorf("Entry = %q, want dist/index.js", m.Entry)
	}
	if !m.NeedsBuild {
		t.Error("NeedsBuild = false; a declared entry that is absent needs building")
	}
}

// A project shipping its compiled output already runs. Building it anyway
// would pull a whole devDependency tree for nothing.
func TestDetectSkipsBuildWhenEntryExists(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":  `{"main":"dist/index.js","scripts":{"build":"tsc"}}`,
		"dist/index.js": `console.log(1)`,
	})
	if Detect(dir).NeedsBuild {
		t.Error("NeedsBuild = true for a project whose entry point is present")
	}
}

// No build script means we cannot fix a missing entry, and pretending
// otherwise would fail with a confusing error instead of an honest one.
func TestDetectSkipsBuildWithoutABuildScript(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": `{"main":"dist/index.js"}`,
	})
	if Detect(dir).NeedsBuild {
		t.Error("NeedsBuild = true for a project with no build script")
	}
}

// Python MCP servers keep their code in src/<package>/ and are started
// through the installed module, so there is no top-level file to guess. Every
// official Python reference server (fetch, git, time) reported "no
// recognisable entry point" until this was read.
func TestPythonEntryModule(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want string
	}{
		{
			"the shape the reference servers use",
			"[project]\nname = \"mcp-server-fetch\"\n\n[project.scripts]\nmcp-server-fetch = \"mcp_server_fetch:main\"\n",
			"mcp_server_fetch:main",
		},
		{
			// Sorted, so a project declaring several always yields the same one.
			"several scripts pick the lowest name",
			"[project.scripts]\nzeta = \"zeta_mod:main\"\nalpha = \"alpha_mod:go\"\n",
			"alpha_mod:go",
		},
		{
			"dotted module path",
			"[project.scripts]\nsrv = \"pkg.cli:run\"\n",
			"pkg.cli:run",
		},
		{
			// A later table must not leak into the one we care about.
			"following table ends the section",
			"[project.scripts]\nsrv = \"real_mod:main\"\n\n[build-system]\nrequires = [\"hatchling\"]\n",
			"real_mod:main",
		},
		{"comments and blanks ignored", "[project.scripts]\n# a comment\n\nsrv = \"m:main\"\n", "m:main"},
		{"no scripts table", "[project]\nname = \"x\"\n", ""},
		// A bare module with no function cannot be turned into a console-script
		// call, so it is not an entry point.
		{"module without a function is not an entry point", "[project.scripts]\nsrv = \"justamodule\"\n", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeProject(t, map[string]string{"pyproject.toml": tc.toml})
			if got := Detect(dir).PyEntry; got != tc.want {
				t.Errorf("PyEntry = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStartCommand(t *testing.T) {
	// python -c, not -m: the console-script "module:function" form means
	// "call function", and -m fails on any package without a __main__.py —
	// which is most FastMCP servers, e.g. mcp-atlassian.
	py := Manifest{Ecosystem: EcosystemPython, PyEntry: "mcp_server_fetch:main"}
	want := `python -c "from mcp_server_fetch import main; main()"`
	if got := py.StartCommand(); got != want {
		t.Errorf("StartCommand = %q, want %q", got, want)
	}

	node := Manifest{Ecosystem: EcosystemNode, Entry: "dist/index.js"}
	if got := node.StartCommand(); got != "node /target/dist/index.js" {
		t.Errorf("StartCommand = %q", got)
	}

	// Nothing declared must stay empty so the caller can say so plainly
	// rather than launching a command it invented.
	if got := (Manifest{Ecosystem: EcosystemPython}).StartCommand(); got != "" {
		t.Errorf("StartCommand = %q, want empty", got)
	}
}

func TestBuildInstallCommand(t *testing.T) {
	m := Manifest{Ecosystem: EcosystemNode, File: "package.json",
		Entry: "dist/index.js", NeedsBuild: true}
	cmd := strings.Join(m.installCommand("/deps", ""), " ")

	// The whole project must move into the volume: a build writes next to the
	// source, and /target is a read-only host mount.
	if !strings.Contains(cmd, "cp -a /target/. /deps/app/") {
		t.Errorf("build must copy the project into the volume: %q", cmd)
	}
	if !strings.Contains(cmd, "npm run build") {
		t.Errorf("build command missing: %q", cmd)
	}
	// The compiler is a devDependency, so omitting them makes the build fail.
	if strings.Contains(cmd, "--omit=dev") {
		t.Errorf("build needs devDependencies: %q", cmd)
	}
	if strings.Contains(cmd, "--ignore-scripts") {
		t.Errorf("lifecycle scripts must still be observable: %q", cmd)
	}
	// A host node_modules holds native modules built for the wrong OS.
	if !strings.Contains(cmd, "rm -rf /deps/app/node_modules") {
		t.Errorf("stale host node_modules must be dropped: %q", cmd)
	}
	// Phase 2 runs as a uid unrelated to the root uid that wrote these files.
	if !strings.Contains(cmd, "chmod -R a+rX /deps/app") {
		t.Errorf("built files must be readable by the detonation uid: %q", cmd)
	}
	if !strings.HasPrefix(cmd, "sh -c set -e") {
		t.Errorf("a failed build must fail the container: %q", cmd)
	}
}

// A package inside a monorepo cannot be built alone. The official memory
// server's tsconfig is four lines and an extends of ../../tsconfig.json, and
// the root config supplies esModuleInterop and skipLibCheck. Copying only the
// package left tsc without either, so it type-checked node_modules and failed
// on errors from zod — a failure with no connection to the scanned code.
func TestBuildContextClimbsToTheInheritedConfig(t *testing.T) {
	root := writeProject(t, map[string]string{
		"tsconfig.json":            `{"compilerOptions":{"esModuleInterop":true}}`,
		"package.json":             `{"workspaces":["src/*"]}`,
		"src/memory/tsconfig.json": `{"extends":"../../tsconfig.json"}`,
		"src/memory/package.json":  `{"bin":"dist/index.js","scripts":{"build":"tsc"}}`,
		"src/memory/index.ts":      `console.log(1)`,
	})
	target := filepath.Join(root, "src", "memory")

	bc := buildContextFor(target)
	if bc.Root != root {
		t.Errorf("Root = %q, want the repository root %q", bc.Root, root)
	}
	if bc.Sub != "src/memory" {
		t.Errorf("Sub = %q, want src/memory", bc.Sub)
	}

	// The build has to run in the package, not the copy root, or its tsconfig
	// resolves against the wrong directory.
	cmd := strings.Join(Manifest{Ecosystem: EcosystemNode, NeedsBuild: true}.
		installCommand("/deps", bc.Sub), " ")
	if !strings.Contains(cmd, "cd /deps/app/src/memory") {
		t.Errorf("build must run in the package directory: %q", cmd)
	}
	// The copy still starts at the root so the inherited config comes along.
	if !strings.Contains(cmd, "cp -a /target/. /deps/app/") {
		t.Errorf("copy must start at the build root: %q", cmd)
	}
}

// A standalone package must keep the existing behaviour exactly: copy its own
// directory, build in place.
func TestBuildContextLeavesStandaloneProjectsAlone(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"tsconfig.json": `{"compilerOptions":{"outDir":"dist"}}`,
		"package.json":  `{"main":"dist/index.js","scripts":{"build":"tsc"}}`,
	})

	bc := buildContextFor(dir)
	if bc.Root != dir || bc.Sub != "" {
		t.Errorf("buildContextFor = %+v, want the target itself with no sub", bc)
	}
}

// A bare specifier resolves from node_modules, which the install step
// provides. Climbing for it would copy an unrelated parent directory.
func TestBuildContextIgnoresPackageExtends(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"tsconfig.json": `{"extends":"@tsconfig/node20/tsconfig.json"}`,
		"package.json":  `{"main":"dist/index.js","scripts":{"build":"tsc"}}`,
	})
	if bc := buildContextFor(dir); bc.Sub != "" {
		t.Errorf("Sub = %q, want empty for a package extends", bc.Sub)
	}
}

// Widening the copy widens what phase 1 can read, and phase 1 is the phase
// WITH a network. A package shipping a doctored `extends` must not be able to
// nominate an arbitrary parent directory for a postinstall to exfiltrate, so
// the root has to look like a project root rather than merely hold a tsconfig.
func TestBuildContextRefusesARootThatIsNotAProject(t *testing.T) {
	root := writeProject(t, map[string]string{
		// A tsconfig and nothing else that marks a project boundary.
		"tsconfig.json":     `{"compilerOptions":{}}`,
		"pkg/tsconfig.json": `{"extends":"../tsconfig.json"}`,
		"pkg/package.json":  `{"main":"dist/i.js","scripts":{"build":"tsc"}}`,
	})
	target := filepath.Join(root, "pkg")

	if bc := buildContextFor(target); bc.Sub != "" {
		t.Errorf("Sub = %q; climbed into a directory with no package.json or .git", bc.Sub)
	}
}

// An extends pointing at a config that is not there must not drag a parent
// directory into the container on the strength of a broken path.
func TestBuildContextRequiresTheConfigToExist(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "pkg")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "tsconfig.json"),
		[]byte(`{"extends":"../tsconfig.json"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if bc := buildContextFor(target); bc.Sub != "" {
		t.Errorf("Sub = %q, want empty when the inherited config is absent", bc.Sub)
	}
}

func TestResultCommandRewrite(t *testing.T) {
	built := &Result{Root: "/deps/app"}
	got := built.Command("node /target/dist/index.js")
	if got != "node /deps/app/dist/index.js" {
		t.Errorf("Command = %q, want the built path", got)
	}

	// Nothing was built, so nothing moved. The common path must be untouched.
	plain := &Result{}
	if got := plain.Command("python /target/server.py"); got != "python /target/server.py" {
		t.Errorf("Command = %q, want it unchanged", got)
	}
}

// A built project's node_modules sits beside its source, not at the volume
// root, so NODE_PATH has to follow it.
func TestEnvForFollowsTheBuiltRoot(t *testing.T) {
	env := Manifest{Ecosystem: EcosystemNode}.EnvFor(appDir("/deps"))
	if env["NODE_PATH"] != "/deps/app/node_modules" {
		t.Errorf("NODE_PATH = %q, want /deps/app/node_modules", env["NODE_PATH"])
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
		cmd := strings.Join(Manifest{Ecosystem: EcosystemPython, File: "requirements.txt"}.installCommand("/deps", ""), " ")
		if !strings.Contains(cmd, "-r /target/requirements.txt") {
			t.Errorf("command = %q", cmd)
		}
		if !strings.Contains(cmd, "--target /deps") {
			t.Errorf("deps must install into the shared volume, got %q", cmd)
		}
	})

	t.Run("pyproject installs the project, never editable", func(t *testing.T) {
		cmd := strings.Join(Manifest{Ecosystem: EcosystemPython, File: "pyproject.toml"}.installCommand("/deps", ""), " ")
		// -e writes into the target directory, which is mounted read-only
		// precisely so a target cannot modify itself mid-scan.
		if strings.Contains(cmd, " -e ") {
			t.Errorf("editable install would write into the read-only target: %q", cmd)
		}
	})

	t.Run("node does not suppress lifecycle scripts", func(t *testing.T) {
		cmd := strings.Join(Manifest{Ecosystem: EcosystemNode, File: "package.json"}.installCommand("/deps", ""), " ")
		// Lifecycle scripts are the supply-chain surface we exist to observe.
		// Suppressing them would hide the most valuable thing this phase finds.
		if strings.Contains(cmd, "--ignore-scripts") {
			t.Errorf("install must let lifecycle scripts run so they can be observed: %q", cmd)
		}
	})

	if cmd := (Manifest{Ecosystem: EcosystemNone}).installCommand("/deps", ""); cmd != nil {
		t.Errorf("installCommand(none) = %v, want nil", cmd)
	}
}
