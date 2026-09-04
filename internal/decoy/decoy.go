// Package decoy furnishes the sandbox with a plausible developer machine.
//
// The sandbox was sterile: an empty tmpfs home, no credentials, no documents,
// no network. A target was placed in an empty room and asked whether it
// misbehaved — and there was nothing to misbehave with. The measured effect was
// concrete: scanning the official file-system server, 12 of its 14 tools
// returned an error on a benign call because there were no directories to
// operate on, so the scan learned nothing about a server that works fine.
//
// So this plants what an attacker would actually want: SSH keys, cloud
// credentials, a .env, a shell history, a workspace. Every secret is a unique
// random token that exists nowhere else in the world, which turns a vague
// suspicion into an unarguable fact — if that exact token comes back out of a
// tool call, the tool read a credential and handed it to its caller. There is
// no benign explanation and no false positive to argue about.
//
// Two properties make this cheap:
//
//   - It needs no network. Exfiltration through the tool's own response is the
//     common shape, because returning data to the agent is how a tool talks.
//     Catching data that leaves by some other route needs a sinkhole; catching
//     data handed straight back does not.
//   - It is a pure filesystem construction. Planting and matching are testable
//     without Docker; only mounting the result needs a sandbox.
//
// The tokens are opaque hex rather than a labelled marker like
// "DETONATE_CANARY_...". A label would let a target grep for it and behave
// differently while being watched, which is the one thing a decoy must not
// allow. Human-readable files carry a comment saying they are fake wherever the
// file format has comments, so nobody mistakes one for a real credential in a
// log; the key material itself stays unlabelled.
package decoy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// tokenBytes is the entropy behind one planted secret. 16 bytes is 128 bits —
// far past any chance of a target emitting one by coincidence, which is the
// property the whole "no false positive" claim rests on.
const tokenBytes = 16

// Kind names what a planted secret is pretending to be, so a finding can say
// "read your SSH private key" rather than "read a file we were watching".
type Kind string

const (
	KindSSHKey       Kind = "ssh-private-key"
	KindAWSCreds     Kind = "aws-credentials"
	KindEnvFile      Kind = "env-file"
	KindNetrc        Kind = "netrc"
	KindGitHubToken  Kind = "github-token"
	KindShellHistory Kind = "shell-history"
)

// Token is one planted secret and where it lives inside the sandbox.
type Token struct {
	// Value is the secret itself: opaque hex, unique to this scan.
	Value string
	Kind  Kind

	// Path is where it was planted, as the target sees it.
	Path string
}

// Environment is a furnished home directory plus everything planted in it.
type Environment struct {
	// HostDir is mounted into the sandbox. It is writable, so a server that
	// stores state under ~ behaves normally, and so the filesystem can be
	// diffed afterwards to see what the target wrote.
	HostDir string

	// ContainerHome is where HostDir appears to the target.
	ContainerHome string

	Tokens []Token
}

// Hit is a planted token found somewhere it should not be.
type Hit struct {
	Token Token

	// Encoding is how the token appeared: plain, base64 or hex. A target that
	// base64s a key before returning it has demonstrated intent rather than
	// accident, so the encoding is part of the evidence.
	Encoding string
}

// The decoy is planted by detonate and read inside the sandbox, and those are
// two different users.
//
// The sandbox runs as uid 1000 (see sandbox.Policy). The files are created by
// whoever ran detonate — uid 1001 on a GitHub runner, some other number on a
// developer's laptop — so POSIX ownership never matches, and a 0600 file is
// simply unreadable from inside the container. The decoy was planted, mounted,
// and invisible.
//
// It went unnoticed because Docker Desktop on Windows and macOS serves bind
// mounts through a VM that ignores POSIX ownership, so every local run could
// read the files regardless of mode. On Linux — CI, and most real users — the
// most important mechanism in the tool caught nothing. The positive control in
// internal/scan is what surfaced it.
//
// 0600 was chosen because a real ~/.ssh/id_rsa is 0600. That realism is worth
// nothing if the target cannot open the file: a thief that respects permissions
// it was never granted is not a threat model, it is a broken fixture.
const (
	fileMode = 0o644
	dirMode  = 0o755

	// writableDirMode makes the home writable by the sandbox user, not just
	// traversable. The decoy directories are owned by whoever ran detonate, so
	// at 0755 the sandbox uid (1000, not the owner) may enter them but cannot
	// create files in them. On Linux that silently blocks a target from writing
	// anywhere under ~, so exfiltration staged to a file could never happen and
	// so could never be caught. Docker Desktop's VM ignores POSIX ownership and
	// hid this on macOS. World-writable is safe here: the home is an ephemeral
	// per-scan tmpdir that is deleted with the scan.
	writableDirMode = 0o777
)

// makeReadableInSandbox forces the mode after creation.
//
// os.WriteFile and os.MkdirAll both mask the mode they are given by the
// process umask, so passing 0644 under `umask 077` still yields 0600. An
// explicit chmod is the only way to state the requirement rather than request
// it. Windows has no POSIX modes and Chmod is close to a no-op there, which is
// harmless: the mount layer already ignores ownership.
func makeReadableInSandbox(path string) error {
	if err := os.Chmod(path, fileMode); err != nil {
		return fmt.Errorf("making decoy %s readable inside the sandbox: %w", path, err)
	}
	return nil
}

// Plant builds a decoy home under dir and returns what it planted.
//
// dir must already exist and should be a per-scan temporary directory: the
// target can write here, and nothing in it survives the scan.
func Plant(dir, containerHome string) (*Environment, error) {
	env := &Environment{HostDir: dir, ContainerHome: containerHome}

	// Ordered, so two scans plant the same layout and only the secrets differ.
	// A decoy whose shape changed per run would make reports incomparable.
	for _, f := range layout {
		token, err := newToken()
		if err != nil {
			return nil, err
		}

		full := filepath.Join(dir, filepath.FromSlash(f.path))
		if err := os.MkdirAll(filepath.Dir(full), dirMode); err != nil {
			return nil, fmt.Errorf("creating decoy directory for %s: %w", f.path, err)
		}
		if err := os.WriteFile(full, []byte(f.render(token)), f.mode); err != nil {
			return nil, fmt.Errorf("planting decoy %s: %w", f.path, err)
		}
		if err := makeReadableInSandbox(full); err != nil {
			return nil, err
		}

		env.Tokens = append(env.Tokens, Token{
			Value: token,
			Kind:  f.kind,
			Path:  containerHome + "/" + f.path,
		})
	}

	// A workspace with ordinary, secret-free content. Without it every file in
	// the home is bait, and a server that lists a directory and returns what it
	// found would look like it had exfiltrated something. Real machines have
	// boring files; the decoy needs them so that reading one is unremarkable.
	if err := plantWorkspace(dir); err != nil {
		return nil, err
	}

	// Directories last, and over the whole tree: a file the sandbox user can
	// read is still unreachable behind a directory it cannot traverse, and
	// MkdirAll masks its mode by the umask exactly as WriteFile does.
	if err := openDirectories(dir); err != nil {
		return nil, err
	}

	return env, nil
}

func openDirectories(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return nil
		}
		if err := os.Chmod(path, writableDirMode); err != nil {
			return fmt.Errorf("making decoy directory %s writable inside the sandbox: %w", path, err)
		}
		return nil
	})
}

// BenignInput is a value a file-shaped tool can plausibly succeed on.
//
// The probe engine opens every tool with a benign call to establish what normal
// looks like. That call used the fixed string "hello", which is not a filename,
// so a well-behaved file reader answered isError and the whole tool was written
// off as target_error — a working server scored as broken, and completeness
// dropped for a defect that was ours.
//
// The decoy plants real files, so there is now a correct answer to give.
//
// Absolute, not a bare filename. A relative "notes.txt" was tried first and the
// official MCP filesystem server still answered "Access denied" for all 12 of
// its file tools: servers that take an allowed-directory argument compare
// against a resolved absolute path, so a relative name never matches. An
// absolute path inside the decoy workspace satisfies both — a server that joins
// it onto its own root still lands in the right place.
//
// It carries no token, so a tool returning it proves nothing and triggers
// nothing.
func (e *Environment) BenignInput() string {
	return e.ContainerHome + "/workspace/notes.txt"
}

// dirParam matches a parameter name that unambiguously wants a directory.
var dirParam = regexp.MustCompile(`(?i)(^|[_-])(dir|dirs|directory|directories|folder|folders)($|[_-])`)

// dirTool matches a tool name whose operation is directory-shaped.
//
// The tool name is needed because the parameter name is often not enough: the
// official MCP filesystem server calls the argument "path" on both read_file
// and list_directory, meaning a file in one and a directory in the other. Only
// the operation disambiguates them.
var dirTool = regexp.MustCompile(`(?i)(^|[_-])(dir|directory|directories|folder|tree|list|ls|search|find|walk|glob)($|[_-]|$)`)

// BenignFor is the benign value for one parameter of one tool.
//
// A single benign string is wrong for half of a filesystem server: handing a
// file path to list_directory makes a working tool answer isError, and the
// whole tool is then written off as target_error. Measured on
// servers/src/filesystem, six of fourteen tools failed for exactly this reason
// — they were directory operations given a file.
//
// The parameter name decides when it is explicit; otherwise the tool's own name
// does. Both fall back to the file path, because most tools take files.
func (e *Environment) BenignFor(tool, param string) string {
	if dirParam.MatchString(param) {
		return e.WorkspaceDir()
	}
	if dirTool.MatchString(tool) {
		return e.WorkspaceDir()
	}
	return e.BenignInput()
}

// WorkspaceDir is the decoy's ordinary, secret-free working directory.
func (e *Environment) WorkspaceDir() string { return e.ContainerHome + "/workspace" }

// Match reports every planted token found in text, in any encoding it checks.
//
// Deterministic: tokens are scanned in plant order and encodings in a fixed
// order, so the same response always produces the same evidence.
func (e *Environment) Match(text string) []Hit {
	if text == "" {
		return nil
	}

	// The secret might be hiding in more than the text as sent. Two views are
	// scanned: the text itself, and the text with all whitespace removed, so a
	// value broken up on the way out — a space between every character, a key
	// split across lines — is contiguous again. Stripping whitespace cannot
	// manufacture a 64-hex-character nonce that was not already there, so the
	// extra view adds recall without adding false positives.
	views := []string{text, stripWhitespace(text)}
	lowerViews := make([]string, len(views))
	for i, v := range views {
		lowerViews[i] = strings.ToLower(v)
	}

	var hits []Hit
	for _, t := range e.Tokens {
	encodingLoop:
		for _, enc := range encodings(t.Value) {
			// fold encodings (plain, reversed, rot13) are matched
			// case-insensitively because a hex secret is routinely upper-cased
			// in transit; base64 and hex alphabets are case-significant and
			// matched exactly.
			scan := views
			needle := enc.value
			if enc.fold {
				scan = lowerViews
				needle = strings.ToLower(enc.value)
			}
			for _, v := range scan {
				if strings.Contains(v, needle) {
					hits = append(hits, Hit{Token: t, Encoding: enc.name})
					break encodingLoop // one hit per token is enough
				}
			}
		}
	}
	return hits
}

// stripWhitespace removes every Unicode space rune, collapsing a value that was
// spread across spaces or newlines back into one contiguous string.
func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// reverseString reverses s by rune, so a secret returned back-to-front is still
// recoverable.
func reverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// rot13 applies the classic letter rotation. A hex secret survives it (its a-f
// letters shift, its digits do not), so rot13 of the secret is a distinct,
// recoverable form worth checking.
func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		default:
			return r
		}
	}, s)
}

// Tokens planted but never touched must yield no finding AND no coverage
// credit. Untouched reports which tokens were not seen anywhere, so a caller
// can say what the scan did not manage to test rather than implying it proved
// the target ignored them.
func (e *Environment) Untouched(seen map[string]bool) []Token {
	var out []Token
	for _, t := range e.Tokens {
		if !seen[t.Value] {
			out = append(out, t)
		}
	}
	return out
}

// FileLeak is a planted token found in a file that is not the decoy it was
// planted in — a secret the target copied somewhere new.
type FileLeak struct {
	// Path is where the copy was found, as the target saw it.
	Path string
	Hit  Hit
}

// maxLeakScanBytes bounds how much of one file is read when hunting for a
// staged secret. A copied credential is small; a target that buries the token
// megabytes into a file is not the common case and not worth reading a whole
// large file per scan to catch.
const maxLeakScanBytes = 1 << 20

// FileLeaks walks the furnished home and reports planted tokens found in files
// that are NOT the decoys themselves. That is exfiltration staged to disk: a
// target reads a secret and writes it to a new file instead of returning it, so
// a scan of stdout and stderr sees nothing. Because the home is a bind mount,
// what the sandbox wrote is right here on the host to be read back.
//
// The decoy files are skipped — they legitimately hold their own tokens. Any
// other file that contains one was written by the target.
//
// Best-effort by design: a file the host cannot read (a sandbox may run as a
// different uid, and a bind mount can preserve that ownership on some
// platforms) is skipped rather than failing the scan, so a leak that cannot be
// read back is a missed finding, never a broken run.
func (e *Environment) FileLeaks() ([]FileLeak, error) {
	if e.HostDir == "" {
		return nil, nil
	}

	skip := make(map[string]bool, len(e.Tokens))
	for _, t := range e.Tokens {
		rel := strings.TrimPrefix(t.Path, e.ContainerHome+"/")
		skip[filepath.Join(e.HostDir, filepath.FromSlash(rel))] = true
	}

	var leaks []FileLeak
	err := filepath.Walk(e.HostDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || skip[path] {
			return nil
		}
		if info.Size() > maxLeakScanBytes {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		hits := e.Match(string(data))
		if len(hits) == 0 {
			return nil
		}
		rel, err := filepath.Rel(e.HostDir, path)
		if err != nil {
			return nil
		}
		seen := e.ContainerHome + "/" + filepath.ToSlash(rel)
		for _, hit := range hits {
			leaks = append(leaks, FileLeak{Path: seen, Hit: hit})
		}
		return nil
	})
	// Deterministic order so evidence is stable across runs.
	sort.Slice(leaks, func(i, j int) bool {
		if leaks[i].Path != leaks[j].Path {
			return leaks[i].Path < leaks[j].Path
		}
		return leaks[i].Hit.Token.Value < leaks[j].Hit.Token.Value
	})
	return leaks, err
}

type encoded struct {
	name, value string
	// fold matches the value case-insensitively. True for the forms that stay
	// human-readable text (plain, reversed, rot13), which a target routinely
	// upper- or lower-cases; false for base64/hex, whose alphabets are
	// case-significant.
	fold bool
}

// encodings are the forms a token can plausibly come back in.
//
// URL encoding is deliberately absent: a token is pure hex, so percent-encoding
// it is the identity function and would only duplicate the plain match.
//
// reversed and rot13 catch the cheapest obfuscations a thief reaches for to
// dodge a substring scan. They are safe to add precisely because the token is a
// unique 64-hex-character nonce: no honest output contains the reverse or the
// rot13 of that string by chance.
func encodings(token string) []encoded {
	return []encoded{
		{name: "plain", value: token, fold: true},
		{name: "base64", value: base64.StdEncoding.EncodeToString([]byte(token))},
		{name: "base64-raw", value: base64.RawStdEncoding.EncodeToString([]byte(token))},
		{name: "hex", value: hex.EncodeToString([]byte(token))},
		{name: "reversed", value: reverseString(token), fold: true},
		{name: "rot13", value: rot13(token), fold: true},
	}
}

func newToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating decoy token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// decoyFile is one planted file.
type decoyFile struct {
	path string
	kind Kind
	mode os.FileMode

	// render builds the file's contents around the token.
	render func(token string) string
}

// fakeNotice is carried by every file whose format has comments. The token
// itself stays unlabelled so a target cannot detect the decoy, but a human who
// finds one of these in a log should know instantly that it is not real.
const fakeNotice = "# Detonate test fixture. Synthetic credential, not a real secret."

var layout = []decoyFile{
	{
		path: ".ssh/id_rsa",
		kind: KindSSHKey,
		mode: fileMode,
		// The body carries base64(token) verbatim, on its own line.
		//
		// An earlier version encoded "detonate-decoy-key-"+token, which read as
		// a realistic key and could never have been caught: the file then held
		// no string Match looks for, so a target could return the private key in
		// full and the scan would report nothing. The most important decoy in
		// the set was undetectable, and only checking recoverability rather than
		// mere presence found it. base64 of a 32-character token is 44
		// characters, so it never wraps and stays one contiguous match.
		render: func(t string) string {
			return "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
				sshFillerHead + "\n" +
				base64.StdEncoding.EncodeToString([]byte(t)) + "\n" +
				sshFillerTail + "\n" +
				"-----END OPENSSH PRIVATE KEY-----\n"
		},
	},
	{
		path: ".aws/credentials",
		kind: KindAWSCreds,
		mode: fileMode,
		render: func(t string) string {
			return fakeNotice + "\n[default]\naws_access_key_id = AKIA" +
				strings.ToUpper(t[:16]) + "\naws_secret_access_key = " + t + "\n"
		},
	},
	{
		path: ".env",
		kind: KindEnvFile,
		mode: fileMode,
		render: func(t string) string {
			return fakeNotice + "\nDATABASE_URL=postgres://app:" + t +
				"@db.internal:5432/app\nSTRIPE_SECRET_KEY=sk_live_" + t + "\n"
		},
	},
	{
		path: ".netrc",
		kind: KindNetrc,
		mode: fileMode,
		render: func(t string) string {
			return fakeNotice + "\nmachine api.internal\n  login deploy\n  password " + t + "\n"
		},
	},
	{
		path: ".config/gh/hosts.yml",
		kind: KindGitHubToken,
		mode: fileMode,
		render: func(t string) string {
			return fakeNotice + "\ngithub.com:\n    user: example\n    oauth_token: ghp_" + t + "\n"
		},
	},
	{
		path: ".bash_history",
		kind: KindShellHistory,
		mode: fileMode,
		render: func(t string) string {
			return "ls -la\ncd ~/workspace\ngit status\n" +
				"export INTERNAL_API_TOKEN=" + t + "\nnpm test\n"
		},
	},
}

// plantWorkspace writes ordinary files with no secrets in them.
func plantWorkspace(dir string) error {
	files := map[string]string{
		"workspace/README.md":       "# Project\n\nInternal tooling.\n",
		"workspace/notes.txt":       "Remember to update the changelog before release.\n",
		"workspace/data/report.csv": "date,requests,errors\n2026-08-01,1204,3\n",
	}

	// Sorted for the same reason the layout is ordered: a deterministic decoy.
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return fmt.Errorf("creating workspace directory for %s: %w", p, err)
		}
		if err := os.WriteFile(full, []byte(files[p]), 0o644); err != nil {
			return fmt.Errorf("writing workspace file %s: %w", p, err)
		}
	}
	return nil
}

// sshFiller pads the decoy key to a realistic length. Deliberately opaque: it
// decodes to nothing meaningful, so a target cannot base64-decode the key and
// discover that it is being watched.
const (
	sshFillerHead = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz"
	sshFillerTail = "c2gtZWQyNTUxOQAAACA3TXhQa1ZuUmpMd0hkQ2ZFbVpVYVlPcVJ0d0JnU3hLZA"
)
