# Demo fixtures

Two MCP servers that exist to be scanned. They are a matched pair: the same
tool, the same description, the same schema, and opposite verdicts.

```bash
detonate dynamic ./testdata/fixtures/vulnerable-file-server   # exit 3
detonate dynamic ./testdata/fixtures/benign-file-server       # exit 0
```

Both need Docker. Each takes under a minute, most of it `npm install`.

## Expected results

| Fixture | Risk | Completeness | Exit |
|---|---|---|---|
| `vulnerable-file-server` | `dangerous`, 1 finding | `complete` | 3 |
| `benign-file-server` | `no_findings` | `complete` | 0 |

Verified 2026-08-05. **Any other result is a bug**, and which half fails says
what kind:

- The vulnerable server coming back clean is a **false negative** — the probe
  stopped reaching a flaw it used to find.
- The benign server reporting a finding is a **false positive** — a detector
  has started scoring capability as malice, which is the failure that gets
  security tools switched off.
- Either reporting `inconclusive` means the probe never actually reached the
  tool, so the verdict is not evidence of anything.

## Why the pair

`vulnerable-file-server` joins caller input onto a base directory with
`path.join`, so `../` walks straight out of it:

```js
const target = path.join(DATA_DIR, request.params.arguments.filename);
```

Ask it for `../../../../etc/passwd` and it returns the file. The manifest, the
tool name, and the schema are all unremarkable — the flaw is in behaviour, and
behaviour is only visible if you run the thing. A scanner that reads metadata
reports this server clean.

`benign-file-server` offers the identical tool and resolves the path first:

```js
const target = path.resolve(DATA_DIR, request.params.arguments.filename);
if (target !== DATA_DIR && !target.startsWith(DATA_DIR + path.sep)) { /* refuse */ }
```

It reads the filesystem, takes arbitrary filenames, and is safe. Without it,
"detonate flagged the vulnerable server" would prove nothing: a detector that
flags every tool touching the filesystem also flags this one, and a scanner
that flags everything has said nothing. An earlier revision did exactly that
to 30 of 59 real published skills.

## Two details that matter

**`DATA_DIR` is `/target/data`.** detonate mounts the fixture read-only at
`/target`, so a path like `/app/data` would not exist in the container and
every call would fail. A tool that cannot answer a benign call is reported as
broken rather than as safe or vulnerable, and coverage never reaches
`complete`.

**`data/hello` exists on purpose.** The probe makes a benign baseline call
before any hostile one, and it asks for `hello`. Without that file the baseline
errors, the tool is scored `target_error`, and both fixtures report
`inconclusive` no matter how the traversal behaves.

Both are consequences of the same rule: a probe result only means something if
the tool was working when it was probed.

## Do not reuse this code

`vulnerable-file-server` is a working path-traversal vulnerability. It is here
to be detonated in a sandbox, and nowhere else.
