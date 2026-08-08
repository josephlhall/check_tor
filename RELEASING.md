# Releasing check_tor

Releases use Semantic Versioning and have both an annotated Git tag and a
GitHub Release record. The repository source is the distribution; do not attach
generated packages or archives.

## Choose the version

Use tags in the form `vX.Y.Z`:

- Increment `X` for incompatible changes to the command, inputs, or output.
- Increment `Y` for backward-compatible scanner capabilities or other
  substantial user-facing improvements.
- Increment `Z` for backward-compatible fixes, documentation, tests, and
  maintenance.

Review every commit since the latest tag before selecting the version:

```zsh
git fetch origin --tags
git tag --list --sort=-version:refname
git log --oneline <previous-tag>..origin/main
git diff --stat <previous-tag>..origin/main
```

## Prepare the release commit

Start from a clean checkout of `main`, update it with a fast-forward-only pull,
and make any release-specific documentation changes through the normal review
process. Stage files by explicit path. Do not use broad staging commands such
as `git add .` or `git add -A`.

Before committing, inspect both the worktree and the exact staged paths:

```zsh
git status --short
git diff --check
git diff --cached --name-only
```

Do not stage or publish `targets.txt`, anything under `scans/`, or any
`*.private.txt` file. Real operational target lists should remain outside the
repository.

Run the complete local validation:

```zsh
test -x check_tor.zsh
zsh -n check_tor.zsh check_tor_core.zsh tests/*.zsh
zsh tests/check_tor_test.zsh
zsh tests/check_tor_integration_test.zsh
git diff --check
```

After the release changes are merged, update local `main` and confirm that it
exactly matches `origin/main`:

```zsh
git switch main
git pull --ff-only origin main
git status --short
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
```

The release commit must have a successful **Offline tests** workflow run on
both `ubuntu-latest` and `macos-latest`. Inspect the run associated with the
exact release commit:

```zsh
gh run list \
  --repo josephlhall/check_tor \
  --workflow "Offline tests" \
  --branch main \
  --commit "$(git rev-parse HEAD)" \
  --limit 5
gh run view <run-id> --repo josephlhall/check_tor
```

Do not publish while either job is missing, pending, or unsuccessful.

## Publish

Set the selected version and a short release title, then create an annotated
tag on the validated release commit:

```zsh
version=vX.Y.Z
git tag --annotate "$version" --message "check_tor $version"
git show --no-patch "$version"
git push origin "$version"
```

Create the corresponding GitHub Release from that existing tag as a draft:

```zsh
gh release create "$version" \
  --repo josephlhall/check_tor \
  --verify-tag \
  --title "check_tor $version" \
  --draft \
  --generate-notes
```

Review the draft's title and generated notes for completeness and accuracy.
Edit the draft as needed, then publish it:

```zsh
gh release view "$version" --repo josephlhall/check_tor
reviewed_notes=/path/to/reviewed-release-notes.md
gh release edit "$version" \
  --repo josephlhall/check_tor \
  --notes-file "$reviewed_notes"
gh release edit "$version" \
  --repo josephlhall/check_tor \
  --draft=false
```

Verify both publication records:

```zsh
git ls-remote --tags origin "refs/tags/$version"
gh release view "$version" --repo josephlhall/check_tor
```

## Recover from a failed release

If an annotated tag is wrong but has not been pushed, delete and recreate the
local tag on the correct commit:

```zsh
git tag --delete "$version"
```

If the tag was pushed or its GitHub Release was published, do not routinely
move or replace it. Correct release-note metadata in the existing GitHub
Release when the tagged code is sound. If the tagged code is wrong, fix the
problem through the normal review process and publish a new patch version.

If the tag push succeeded but GitHub Release creation failed, keep the tag,
resolve the publication problem, and rerun `gh release create` for that same
tag. Do not create a second tag merely because the release-record step failed.
