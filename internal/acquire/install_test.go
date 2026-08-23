package acquire

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/dockertest"
	"github.com/m4vic/detonate/internal/sandbox"
	"github.com/m4vic/detonate/internal/trace"
)

// requireDocker delegates to the shared gate so that this package cannot
// drift from the others on what "Docker is available" means.
func requireDocker(t *testing.T) {
	t.Helper()
	dockertest.Require(t)
}

// A target with no manifest must skip the install entirely rather than
// failing. A stdlib-only server is a perfectly good target.
func TestInstallSkipsWhenNothingToInstall(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.py"), []byte("print(1)"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Install(context.Background(), dir, sandbox.DefaultPolicy())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Volume != "" {
		t.Errorf("created a volume for a target with no dependencies: %q", res.Volume)
	}
	if len(res.Mounts()) != 0 {
		t.Errorf("Mounts() = %v, want none", res.Mounts())
	}
	if err := res.Cleanup(context.Background()); err != nil {
		t.Errorf("Cleanup on an empty result should be a no-op: %v", err)
	}
}

func TestInstallReportsWorkspacePrepareBuildAsUnsupportedBeforeDocker(t *testing.T) {
	root := writeProject(t, map[string]string{
		"package.json":                 `{"private":true,"workspaces":["src/*"]}`,
		"package-lock.json":            `{}`,
		"tsconfig.json":                `{"compilerOptions":{"target":"ES2022"}}`,
		"src/everything/tsconfig.json": `{"extends":"../../tsconfig.json","compilerOptions":{"outDir":"dist"}}`,
		"src/everything/package.json": `{
			"main":"dist/index.js",
			"scripts":{"build":"tsc && cp -r docs dist/","prepare":"npm run build"}
		}`,
	})
	target := filepath.Join(root, "src", "everything")
	_, err := Install(context.Background(), target, sandbox.DefaultPolicy())
	var unsupported *UnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error = %v, want UnsupportedError", err)
	}
	if !strings.Contains(unsupported.Error(), "monorepo workspace lifecycle") ||
		!strings.Contains(unsupported.Error(), "repository-root lockfile") {
		t.Fatalf("unsupported reason is not actionable: %v", unsupported)
	}
}

func TestAcquisitionPoliciesNeverCombineTargetExecutionRootAndNetwork(t *testing.T) {
	m := Manifest{Ecosystem: EcosystemNode, File: "package.json", NeedsBuild: true}
	fetch := fetchPolicy(sandbox.DefaultPolicy(), m)
	offline := offlinePolicy(sandbox.DefaultPolicy(), m)

	if !fetch.NetworkEnabled || fetch.User != "0:0" {
		t.Fatalf("fetch policy lost required package-manager access: %+v", fetch)
	}
	if !strings.Contains(strings.Join(m.fetchCommand(DepsDir, ""), " "), "--ignore-scripts") {
		t.Fatal("privileged networked fetch does not suppress target scripts")
	}
	if offline.NetworkEnabled {
		t.Fatal("target-controlled offline phase has network access")
	}
	if offline.User == "0:0" || offline.User == "0" || offline.User == "root" {
		t.Fatalf("target-controlled offline phase runs as root: %q", offline.User)
	}
	if !strings.Contains(strings.Join(m.offlineCommand(DepsDir, ""), " "), "npm run build") {
		t.Fatal("test setup does not exercise a target-controlled command")
	}
}

func TestLocalPythonProjectIsExplicitlyUnsupported(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pyproject.toml": "[project]\nname='fixture'\nversion='1.0.0'\n",
	})

	_, err := Install(context.Background(), dir, sandbox.DefaultPolicy())
	var unsupported *UnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error = %v, want UnsupportedError", err)
	}
	if !strings.Contains(err.Error(), "build backend") {
		t.Fatalf("unsupported reason is not actionable: %v", err)
	}
}

func TestLifecycleHookRunsOfflineNonRootAndEgressIsReported(t *testing.T) {
	requireDocker(t)

	dir := writeProject(t, map[string]string{
		"package.json": `{
			"name":"hostile-acquisition-fixture",
			"version":"1.0.0",
			"main":"index.js",
			"scripts":{
				"postinstall":"node -e \"if(process.getuid()===0){console.error('HOOK_RAN_AS_ROOT');process.exit(9)};require('dns').lookup('exfil.invalid',(e)=>{console.error(e?e.code:'NETWORK_REACHED');process.exit(e?7:8)})\""
			}
		}`,
		"index.js": "console.log('fixture')\n",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	_, err := Install(ctx, dir, sandbox.DefaultPolicy())
	var unsupported *UnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("Install error = %v, want UnsupportedError with egress evidence", err)
	}

	var networkFinding bool
	for _, event := range unsupported.Events {
		if event.Kind == trace.KindNetwork &&
			event.Severity == trace.SeverityCritical &&
			event.During == "acquire-offline" {
			networkFinding = true
		}
	}
	if !networkFinding {
		t.Fatalf("blocked lifecycle egress was not reported: %+v", unsupported.Events)
	}
}

func TestOfflineNetworkFailureIsClassifiedUnsupported(t *testing.T) {
	events := []trace.Event{{Kind: trace.KindNetwork, During: "acquire-offline"}}
	if !hasNetworkAttempt(events) {
		t.Fatal("offline network attempt was not recognized for unsupported classification")
	}
	if hasNetworkAttempt([]trace.Event{{Kind: trace.KindNetwork, During: "acquire-fetch"}}) {
		t.Fatal("expected network use during inert fetch was classified as unsupported")
	}
}

// The end-to-end claim: a package installed in phase 1 is importable in phase
// 2, which has no network. Without this the sandbox can only run stdlib-only
// servers, and almost every real MCP server imports something.
func TestInstallMakesPackagesImportableWithoutNetwork(t *testing.T) {
	requireDocker(t)

	dir := t.TempDir()
	// A tiny, dependency-free package so the test does not depend on a large
	// tree resolving correctly.
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"),
		[]byte("six==1.17.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	policy := sandbox.DefaultPolicy()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	if err := sandbox.EnsureImage(ctx, policy.Image); err != nil {
		dockertest.Unavailable(t, "cannot pull sandbox image: %v", err)
	}

	res, err := Install(ctx, dir, policy)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	defer res.Cleanup(context.Background())

	if res.Volume == "" {
		t.Fatal("no dependency volume created")
	}
	if res.Env["PYTHONPATH"] != DepsDir+"/site" {
		t.Errorf("PYTHONPATH = %q, want %q", res.Env["PYTHONPATH"], DepsDir+"/site")
	}

	// Now the actual proof: import it in a container with the network OFF.
	p := sandbox.DefaultPolicy()
	p.Env = res.Env
	p.Timeout = 60 * time.Second

	name, err := sandbox.NewName()
	if err != nil {
		t.Fatal(err)
	}
	c, err := sandbox.Start(ctx, name, p, res.Mounts(),
		[]string{"python", "-c", "import six; print('IMPORT_OK', six.__version__)"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Close()

	out := readAll(t, c)
	if !strings.Contains(out, "IMPORT_OK") {
		t.Fatalf("package not importable in the offline sandbox.\nstdout: %q\nstderr: %q",
			out, c.Stderr())
	}
}

// The TypeScript claim, end to end: a project whose entry point exists only
// after compilation is fetched without scripts, built offline as non-root,
// and then runs in the network-disabled detonation sandbox.
//
// This is the shape of most published MCP servers — package.json points at
// dist/, dist/ is gitignored, and the compiler is a devDependency. Before the
// build phase every one of them failed with MODULE_NOT_FOUND, which is a scan
// that reports nothing about the target's safety.
func TestInstallBuildsATypeScriptProject(t *testing.T) {
	requireDocker(t)

	dir := writeProject(t, map[string]string{
		// Pinned so the test does not start failing when a new compiler ships.
		"package.json": `{
			"name": "buildable", "version": "1.0.0",
			"main": "dist/index.js",
			"scripts": {"build": "tsc"},
			"devDependencies": {"typescript": "5.6.3"}
		}`,
		"tsconfig.json": `{
			"compilerOptions": {
				"outDir": "dist", "module": "commonjs",
				"target": "es2020", "rootDir": "src"
			},
			"include": ["src"]
		}`,
		"src/index.ts": `const marker: string = "BUILD_OK"; console.log(marker);`,
	})

	m := Detect(dir)
	if !m.NeedsBuild {
		t.Fatal("Detect did not flag this project as needing a build")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	res, err := Install(ctx, dir, sandbox.DefaultPolicy())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	defer res.Cleanup(context.Background())

	if res.Root != DepsDir+"/app" {
		t.Fatalf("Root = %q, want %q", res.Root, DepsDir+"/app")
	}

	// The command detection produced before the build pointed at a file that
	// did not exist. It must now point into the volume.
	command := res.Command("node /target/dist/index.js")
	if command != "node "+DepsDir+"/app/dist/index.js" {
		t.Fatalf("Command = %q, want it rewritten into the volume", command)
	}

	p := sandbox.DefaultPolicy()
	p.Image = res.Image
	p.Env = res.Env
	p.Timeout = 90 * time.Second

	if err := sandbox.EnsureImage(ctx, p.Image); err != nil {
		dockertest.Unavailable(t, "cannot pull %s: %v", p.Image, err)
	}

	name, err := sandbox.NewName()
	if err != nil {
		t.Fatal(err)
	}
	c, err := sandbox.Start(ctx, name, p, res.Mounts(), strings.Fields(command))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Close()

	out := readAll(t, c)
	if !strings.Contains(out, "BUILD_OK") {
		t.Fatalf("compiled entry point did not run in the offline sandbox.\n"+
			"stdout: %q\nstderr: %q", out, c.Stderr())
	}
}

func TestInstallBuildsATypeScriptMonorepoPackage(t *testing.T) {
	requireDocker(t)

	root := writeProject(t, map[string]string{
		"package.json": `{"name":"fixture-root","version":"1.0.0","private":true}`,
		"tsconfig.json": `{
			"compilerOptions":{"module":"commonjs","target":"es2020"}
		}`,
		"packages/server/package.json": `{
			"name":"fixture-server","version":"1.0.0",
			"main":"dist/index.js","scripts":{"build":"tsc"},
			"devDependencies":{"typescript":"5.6.3"}
		}`,
		"packages/server/tsconfig.json": `{
			"extends":"../../tsconfig.json",
			"compilerOptions":{"outDir":"dist","rootDir":"src"},
			"include":["src"]
		}`,
		"packages/server/src/index.ts": `const marker: string = "MONOREPO_BUILD_OK"; console.log(marker);`,
	})
	targetDir := filepath.Join(root, "packages", "server")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	res, err := Install(ctx, targetDir, sandbox.DefaultPolicy())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	defer res.Cleanup(context.Background())

	wantRoot := DepsDir + "/app/packages/server"
	if res.Root != wantRoot {
		t.Fatalf("Root = %q, want %q", res.Root, wantRoot)
	}
	command := res.Command("node /target/dist/index.js")
	p := sandbox.DefaultPolicy()
	p.Image = res.Image
	p.Env = res.Env
	p.Timeout = 90 * time.Second
	name, err := sandbox.NewName()
	if err != nil {
		t.Fatal(err)
	}
	c, err := sandbox.Start(ctx, name, p, res.Mounts(), strings.Fields(command))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Close()
	if out := readAll(t, c); !strings.Contains(out, "MONOREPO_BUILD_OK") {
		t.Fatalf("monorepo build output did not run in detonation sandbox: %q", out)
	}
}

// The dependency mount must be read-only in phase 2: a target that can rewrite
// its own dependencies while being observed means the code we report on is not
// the code that ran.
func TestDependencyMountIsReadOnly(t *testing.T) {
	res := &Result{Volume: "some-volume"}
	mounts := res.Mounts()
	if len(mounts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(mounts))
	}
	if !mounts[0].ReadOnly {
		t.Error("dependencies must be mounted read-only during detonation")
	}
	if mounts[0].ContainerPath != DepsDir {
		t.Errorf("ContainerPath = %q, want %q", mounts[0].ContainerPath, DepsDir)
	}
}

// A failed build reported nothing useful until this was fixed, twice over.
//
// Scanning a real server showed both faults in one run: npm writes only
// "command failed" to stderr while tsc puts the actual diagnostic on stdout,
// and cutting output from the front buried the reason under three screens of
// deprecation warnings.
func TestFailureOutputShowsTheReason(t *testing.T) {
	t.Run("includes stdout, where build tools write diagnostics", func(t *testing.T) {
		got := failureOutput("error TS5083: Cannot read file '/tsconfig.json'.", "npm error command failed")
		if !strings.Contains(got, "TS5083") {
			t.Errorf("the actual reason was dropped: %q", got)
		}
		if !strings.Contains(got, "npm error command failed") {
			t.Errorf("stderr was dropped: %q", got)
		}
	})

	t.Run("keeps the tail, where the reason lives", func(t *testing.T) {
		noise := strings.Repeat("npm warn deprecated glob@7.2.3 blah blah\n", 200)
		got := failureOutput(noise+"error TS5083: the real problem", "")
		if !strings.Contains(got, "TS5083") {
			t.Error("truncation cut the reason and kept the warnings")
		}
	})

	t.Run("empty streams produce nothing", func(t *testing.T) {
		if got := failureOutput("  ", "\n"); got != "" {
			t.Errorf("failureOutput = %q, want empty", got)
		}
	})
}

func TestCleanupIsIdempotent(t *testing.T) {
	requireDocker(t)

	res := &Result{}
	if err := res.Cleanup(context.Background()); err != nil {
		t.Errorf("first cleanup: %v", err)
	}
	if err := res.Cleanup(context.Background()); err != nil {
		t.Errorf("second cleanup should be a no-op: %v", err)
	}
}

func readAll(t *testing.T, c *sandbox.Container) string {
	t.Helper()
	ch := make(chan string, 1)
	go func() {
		b := make([]byte, 0, 4096)
		buf := make([]byte, 1024)
		for {
			n, err := c.Stdout().Read(buf)
			b = append(b, buf[:n]...)
			if err != nil {
				break
			}
		}
		ch <- string(b)
	}()
	select {
	case s := <-ch:
		return s
	case <-time.After(90 * time.Second):
		t.Fatal("timed out reading container output")
		return ""
	}
}
