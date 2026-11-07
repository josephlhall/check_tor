# Releasing check_tor

Release the reviewed `main` commit after both jobs in the **Offline tests**
workflow pass for that commit. A release consists of an annotated Git tag
and a GitHub Release. Users receive the repository source, so leave
generated packages and archives out of the release assets. If a tag is
intended only as a source checkpoint, record that decision before tagging.

## Choose the version

Use Semantic Versioning and tag the release `vMAJOR.MINOR.PATCH`.

- Increment MAJOR for an incompatible change to the command, inputs, behavior,
  or output contract.
- Increment MINOR for a backward-compatible scanner capability or other
  substantial user-facing improvement.
- Increment PATCH for backward-compatible fixes, documentation, tests, and
  maintenance.

A release can include several accepted changes. Review the full range
since the last release before choosing the version. Replace `v1.5.0` in
this example with the previous release tag.

```zsh
git fetch origin --tags
git tag --list --sort=-version:refname
previous_tag=v1.5.0
git log --oneline "$previous_tag"..origin/main
git diff --stat "$previous_tag"..origin/main
```

## Prepare and verify the release commit

Make any release documentation changes through the normal review process.
Stage changes by explicit path and inspect the staged diff before committing.
Keep real target lists and raw results outside the repository. Leave
`targets.txt`, `scans/`, and `*.private.txt` out of the staged changes.

```zsh
git status --short
git diff --check
git diff --cached --check
git diff --cached --name-only
```

After confirming the staged paths are safe to inspect, review the changes.

```zsh
git diff --cached
```

Run the [local offline checks](README.md#testing) for the proposed changes.
Once they are merged, update a clean checkout of `main` and record the commit
SHA. Confirm that `git status --short` is empty and the SHA check passes
before continuing. Keep using this `release_commit` in the following steps
so CI verification and tagging refer to the same revision.

```zsh
git switch main
git pull --ff-only origin main
git status --short
release_commit=$(git rev-parse HEAD)
test "$release_commit" = "$(git rev-parse origin/main)"
```

Find the **Offline tests** run for this commit. Set `run_id` to the ID
shown by `gh run list`. Check that the `ubuntu-latest` and `macos-latest`
jobs both succeeded. Wait to publish if either job is missing, pending,
or unsuccessful.

```zsh
gh run list \
  --repo josephlhall/check_tor \
  --workflow "Offline tests" \
  --branch main \
  --commit "$release_commit" \
  --limit 5
run_id=123456789
gh run view "$run_id" --repo josephlhall/check_tor
```

## Publish

Replace the example `version` with the chosen tag. Create an annotated
tag on `release_commit` and confirm it resolves to that SHA.

```zsh
version=v1.5.1
git tag --annotate "$version" --message "check_tor $version" "$release_commit"
git show --no-patch "$version"
test "$(git rev-parse "refs/tags/${version}^{commit}")" = "$release_commit"
```

Once that check passes, push the tag and create the GitHub Release as a
draft. `--verify-tag` requires the tag to exist on the remote.

```zsh
git push origin "refs/tags/$version"
gh release create "$version" \
  --repo josephlhall/check_tor \
  --verify-tag \
  --title "check_tor $version" \
  --draft \
  --generate-notes
```

Review the draft's title and generated notes for completeness and accuracy.
Edit them as needed before publishing. If you saved revised notes in a
file, pass that file to `gh release edit` with `--notes-file`.

```zsh
gh release view "$version" --repo josephlhall/check_tor
```

Publish the reviewed draft.

```zsh
gh release edit "$version" --repo josephlhall/check_tor --draft=false
```

Verify that the remote annotated tag resolves to `release_commit` and the
GitHub Release reports the expected `tagName` with `isDraft: false`.
The `^{}` suffix asks Git for the commit referenced by the annotated tag.

```zsh
remote_commit=$(git ls-remote --exit-code --tags origin "refs/tags/${version}^{}" | cut -f1)
test "$remote_commit" = "$release_commit"
gh release view "$version" --repo josephlhall/check_tor --json tagName,isDraft,url
```

## Recover from a failed release

If a tag points to the wrong commit and is still local, delete it with
`git tag --delete "$version"` and recreate it on the validated commit.

Keep pushed tags in place during routine recovery. If the tagged code is
sound, correct release notes or other metadata on the existing GitHub
Release. If the tagged code needs a fix, review the fix and release it
as a new patch version.

If the tag push succeeded but GitHub Release creation failed, fix the
publication problem and rerun `gh release create` for the same tag.
