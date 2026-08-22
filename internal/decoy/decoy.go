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
	"sort"
	"strings"
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
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return nil, fmt.Errorf("creating decoy directory for %s: %w", f.path, err)
		}
		if err := os.WriteFile(full, []byte(f.render(token)), f.mode); err != nil {
			return nil, fmt.Errorf("planting decoy %s: %w", f.path, err)
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

	return env, nil
}

// BenignInput is a value a file-shaped tool can plausibly succeed on.
//
// The probe engine opens every tool with a benign call to establish what normal
// looks like. That call used the fixed string "hello", which is not a filename,
// so a well-behaved file reader answered isError and the whole tool was written
// off as target_error — a working server scored as broken, and completeness
// dropped for a defect that was ours.
//
// The decoy plants real files, so there is now a correct answer to give: a bare
// name that resolves both as a workspace-relative path and as a plain filename.
// It carries no token, so a tool returning it proves nothing and triggers
// nothing.
func BenignInput() string { return "notes.txt" }

// Match reports every planted token found in text, in any encoding it checks.
//
// Deterministic: tokens are scanned in plant order and encodings in a fixed
// order, so the same response always produces the same evidence.
func (e *Environment) Match(text string) []Hit {
	if text == "" {
		return nil
	}
	lower := strings.ToLower(text)

	var hits []Hit
	for _, t := range e.Tokens {
		for _, enc := range encodings(t.Value) {
			// Case-insensitive on the plain form because hex is often
			// upper-cased in transit; the encoded forms are matched exactly,
			// since their alphabets are case-significant.
			found := strings.Contains(text, enc.value)
			if enc.name == "plain" {
				found = strings.Contains(lower, strings.ToLower(enc.value))
			}
			if found {
				hits = append(hits, Hit{Token: t, Encoding: enc.name})
				break // one hit per token; the first encoding found is enough
			}
		}
	}
	return hits
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

type encoded struct{ name, value string }

// encodings are the forms a token can plausibly come back in.
//
// URL encoding is deliberately absent: a token is pure hex, so percent-encoding
// it is the identity function and would only duplicate the plain match.
func encodings(token string) []encoded {
	return []encoded{
		{"plain", token},
		{"base64", base64.StdEncoding.EncodeToString([]byte(token))},
		{"base64-raw", base64.RawStdEncoding.EncodeToString([]byte(token))},
		{"hex", hex.EncodeToString([]byte(token))},
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
		mode: 0o600,
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
		mode: 0o600,
		render: func(t string) string {
			return fakeNotice + "\n[default]\naws_access_key_id = AKIA" +
				strings.ToUpper(t[:16]) + "\naws_secret_access_key = " + t + "\n"
		},
	},
	{
		path: ".env",
		kind: KindEnvFile,
		mode: 0o600,
		render: func(t string) string {
			return fakeNotice + "\nDATABASE_URL=postgres://app:" + t +
				"@db.internal:5432/app\nSTRIPE_SECRET_KEY=sk_live_" + t + "\n"
		},
	},
	{
		path: ".netrc",
		kind: KindNetrc,
		mode: 0o600,
		render: func(t string) string {
			return fakeNotice + "\nmachine api.internal\n  login deploy\n  password " + t + "\n"
		},
	},
	{
		path: ".config/gh/hosts.yml",
		kind: KindGitHubToken,
		mode: 0o600,
		render: func(t string) string {
			return fakeNotice + "\ngithub.com:\n    user: example\n    oauth_token: ghp_" + t + "\n"
		},
	},
	{
		path: ".bash_history",
		kind: KindShellHistory,
		mode: 0o600,
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
