# Packaging

Package-manager manifests for detonate. Neither file is consumed from this
repository — both are templates that get copied into their own repositories
when a release is cut.

| File | Goes to | Installs with |
|---|---|---|
| [homebrew/detonate.rb](homebrew/detonate.rb) | `m4vic/homebrew-tap`, as `Formula/detonate.rb` | `brew install m4vic/tap/detonate` |
| [scoop/detonate.json](scoop/detonate.json) | `m4vic/scoop-bucket`, as `bucket/detonate.json` | `scoop install detonate` |

## Cutting a release

1. Tag the release. The [release workflow](../.github/workflows/release.yml)
   cross-compiles five targets and publishes them with `checksums.txt`.
2. Take the SHA-256 values from `checksums.txt` and replace every
   `REPLACE_WITH_SHA256_FROM_checksums.txt` placeholder.
3. Bump `version` in both files.
4. Copy each into its tap or bucket repository and push.

The placeholders are deliberate. A manifest with a wrong hash fails loudly at
install time, which is the correct behaviour for a security tool — a package
manager that silently accepts a binary whose checksum does not match is exactly
the supply-chain problem detonate exists to look for.

## Artifact names

The manifests hard-code the names the release workflow produces. If those
change, both files break:

```text
detonate-v<version>-linux-amd64.tar.gz     contains: detonate
detonate-v<version>-linux-arm64.tar.gz     contains: detonate
detonate-v<version>-darwin-amd64.tar.gz    contains: detonate
detonate-v<version>-darwin-arm64.tar.gz    contains: detonate
detonate-v<version>-windows-amd64.zip      contains: detonate.exe
checksums.txt
```

Note the tag carries a leading `v` and the manifest `version` fields do not,
which is why the URLs interpolate `v#{version}` and `v$version` rather than the
bare value.

## Why Docker is not a dependency

Neither manifest declares Docker as a requirement. It is needed to execute a
target, not to install or run detonate: prompt and skill analysis read text
rather than run it and work with no container runtime present. Requiring it
would block installation for the users best served by the half that does not
need it. Both manifests say so in their caveats, and `detonate doctor` reports
what the machine can actually do.
