package decoy

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func plant(t *testing.T) *Environment {
	t.Helper()
	env, err := Plant(t.TempDir(), "/home/detonate")
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}
	return env
}

func TestPlantsCredentialsAnAttackerWouldWant(t *testing.T) {
	env := plant(t)

	want := map[Kind]string{
		KindSSHKey:       ".ssh/id_rsa",
		KindAWSCreds:     ".aws/credentials",
		KindEnvFile:      ".env",
		KindNetrc:        ".netrc",
		KindGitHubToken:  ".config/gh/hosts.yml",
		KindShellHistory: ".bash_history",
	}
	if len(env.Tokens) != len(want) {
		t.Fatalf("planted %d tokens, want %d", len(env.Tokens), len(want))
	}

	for _, tok := range env.Tokens {
		rel, ok := want[tok.Kind]
		if !ok {
			t.Fatalf("unexpected decoy kind %q", tok.Kind)
		}
		if tok.Path != "/home/detonate/"+rel {
			t.Fatalf("%s planted at %q, want /home/detonate/%s", tok.Kind, tok.Path, rel)
		}

		// The token must actually be in the file. A decoy whose secret is not
		// present cannot ever be caught leaving.
		body, err := os.ReadFile(filepath.Join(env.HostDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("reading planted %s: %v", rel, err)
		}
		// Checked through Match rather than by eye: what matters is not that
		// the token is "in there somewhere" but that the scanner can actually
		// recover it from the file's contents. The SSH key failed exactly this
		// distinction once already.
		if hits := env.Match(string(body)); len(hits) != 1 || hits[0].Token.Value != tok.Value {
			t.Fatalf("%s: Match found %d hit(s); the planted token is not recoverable "+
				"from the file, so a target could return it undetected", rel, len(hits))
		}
	}
}

// Every scan must plant secrets that exist nowhere else, or a token found in a
// response could have come from somewhere other than this sandbox.
func TestTokensAreUniquePerScanAndPerFile(t *testing.T) {
	a, b := plant(t), plant(t)

	seen := map[string]bool{}
	for _, tok := range append(append([]Token{}, a.Tokens...), b.Tokens...) {
		if seen[tok.Value] {
			t.Fatalf("token %q was reused", tok.Value)
		}
		seen[tok.Value] = true
		if len(tok.Value) != tokenBytes*2 {
			t.Fatalf("token %q is %d chars, want %d", tok.Value, len(tok.Value), tokenBytes*2)
		}
	}
}

// The point of the whole package: a token coming back out of a tool call is
// proof, in every encoding a target might use on the way out.
func TestMatchFindsLeakedTokensInEveryEncoding(t *testing.T) {
	env := plant(t)
	tok := env.Tokens[0].Value

	for _, tc := range []struct {
		name     string
		response string
		want     string
	}{
		{"plain", "file contents: " + tok, "plain"},
		{"uppercased", "CONTENTS: " + strings.ToUpper(tok), "plain"},
		{"base64", "data: " + base64.StdEncoding.EncodeToString([]byte(tok)), "base64"},
		{"base64 unpadded", "data: " + base64.RawStdEncoding.EncodeToString([]byte(tok)), "base64-raw"},
		{"embedded in json", `{"result":"` + tok + `"}`, "plain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits := env.Match(tc.response)
			if len(hits) != 1 {
				t.Fatalf("got %d hits, want 1", len(hits))
			}
			if hits[0].Encoding != tc.want {
				t.Fatalf("encoding = %q, want %q", hits[0].Encoding, tc.want)
			}
			if hits[0].Token.Value != tok {
				t.Fatal("hit names the wrong token")
			}
		})
	}
}

// The property that makes a canary finding unarguable: ordinary output must
// never match. If this can produce a hit, the whole "zero false positives"
// claim collapses.
func TestMatchIsSilentOnOrdinaryOutput(t *testing.T) {
	env := plant(t)
	for _, s := range []string{
		"",
		"Read 3 files successfully.",
		"error: ENOENT: no such file or directory, open '/home/detonate/.ssh/id_rsa'",
		"deadbeefdeadbeefdeadbeefdeadbeef",
		strings.Repeat("a1b2c3d4", 64),
		"/home/detonate/.aws/credentials",
	} {
		if hits := env.Match(s); len(hits) != 0 {
			t.Fatalf("ordinary output matched %d token(s): %q", len(hits), s)
		}
	}
}

// A tool naming the path is not a tool leaking the contents. Reporting the
// first as a leak would be exactly the capability-versus-evidence confusion the
// rest of detonate refuses to make.
func TestPathMentionIsNotALeak(t *testing.T) {
	env := plant(t)
	if hits := env.Match("I cannot open ~/.ssh/id_rsa or ~/.aws/credentials"); len(hits) != 0 {
		t.Fatalf("mentioning decoy paths was treated as a leak: %+v", hits)
	}
}

func TestMatchFindsEveryLeakedTokenAtOnce(t *testing.T) {
	env := plant(t)
	var b strings.Builder
	for _, tok := range env.Tokens {
		b.WriteString(tok.Value + "\n")
	}
	if hits := env.Match(b.String()); len(hits) != len(env.Tokens) {
		t.Fatalf("got %d hits, want %d", len(hits), len(env.Tokens))
	}
}

// A token planted and never seen must not be reported as anything. Coverage is
// the caller's to compute; this only says which tokens went untouched.
func TestUntouchedReportsWhatWasNeverSeen(t *testing.T) {
	env := plant(t)
	seen := map[string]bool{env.Tokens[0].Value: true}

	got := env.Untouched(seen)
	if len(got) != len(env.Tokens)-1 {
		t.Fatalf("got %d untouched, want %d", len(got), len(env.Tokens)-1)
	}
	for _, tok := range got {
		if tok.Value == env.Tokens[0].Value {
			t.Fatal("a token that was seen is reported untouched")
		}
	}
}

// The decoy must contain boring files too. If every file is bait, a server that
// legitimately lists a directory and returns what it found looks like a thief.
func TestWorkspaceHasOrdinarySecretFreeFiles(t *testing.T) {
	env := plant(t)
	for _, rel := range []string{"workspace/README.md", "workspace/notes.txt", "workspace/data/report.csv"} {
		body, err := os.ReadFile(filepath.Join(env.HostDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		if hits := env.Match(string(body)); len(hits) != 0 {
			t.Fatalf("%s contains a decoy token; ordinary files must be secret-free", rel)
		}
	}
}

// Human-readable formats say they are fake, so nobody mistakes one for a real
// credential. The key material itself stays unlabelled — a target that could
// grep for a marker could hide from it.
func TestCommentableFilesAnnounceThatTheyAreFake(t *testing.T) {
	env := plant(t)
	for _, rel := range []string{".aws/credentials", ".env", ".netrc", ".config/gh/hosts.yml"} {
		body, err := os.ReadFile(filepath.Join(env.HostDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		if !strings.Contains(string(body), "Detonate test fixture") {
			t.Fatalf("%s does not announce that it is synthetic", rel)
		}
	}

	// The private key must NOT carry the notice: it is the file most likely to
	// be grepped by a target deciding whether it is being watched.
	body, err := os.ReadFile(filepath.Join(env.HostDir, filepath.FromSlash(".ssh/id_rsa")))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(body)), "detonate test fixture") {
		t.Fatal("the decoy private key labels itself, which lets a target detect the decoy")
	}
}

// Same layout every run, different secrets every run.
func TestLayoutIsDeterministicButSecretsAreNot(t *testing.T) {
	a, b := plant(t), plant(t)

	var pathsA, pathsB []string
	for i := range a.Tokens {
		pathsA = append(pathsA, a.Tokens[i].Path)
		pathsB = append(pathsB, b.Tokens[i].Path)
	}
	if strings.Join(pathsA, ",") != strings.Join(pathsB, ",") {
		t.Fatalf("decoy layout differs between runs:\n %v\n %v", pathsA, pathsB)
	}
	if a.Tokens[0].Value == b.Tokens[0].Value {
		t.Fatal("two scans planted the same secret")
	}
}

func TestKeyFilesArePrivateMode(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" {
		t.Skip("POSIX permission bits are not meaningful on this host")
	}
	env := plant(t)
	for _, rel := range []string{".ssh/id_rsa", ".aws/credentials", ".env"} {
		info, err := os.Stat(filepath.Join(env.HostDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s mode = %o, want 600", rel, perm)
		}
	}
}
