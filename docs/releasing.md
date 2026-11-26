# Releasing

The packages in this repository are versioned together and published to npm
from a GitHub release. Nothing is published when a pull request merges, so a
release is always a decision that a maintainer makes.

## Steps

1. Every change that affects a published package carries a changeset, which is
   created with `npx changeset` and describes the change for the changelog.
2. When changesets reach `main`, the version workflow opens or updates a pull
   request titled "chore(release): version packages" that bumps the versions and
   writes the changelogs. A pull request opened by a workflow does not start other
   workflows, so push an empty commit to its branch, or close and reopen it, to
   run the required checks.
3. A maintainer reviews that pull request, reads the changelog text as a
   reader of the public repository would, and merges it.
4. A maintainer then drafts a GitHub release whose tag is `v` followed by the
   new version, such as `v0.2.0`, created on the merge commit on `main`, adds the
   release notes and publishes it.
5. Publishing the release starts the release workflow. It checks the release,
   runs the full check and then waits for a reviewer to approve the `release`
   deployment before anything is sent to npm.
6. After approval the workflow publishes every package version that is not yet on
   npm, with a provenance attestation, and nothing is pushed back to the
   repository.

## What the release workflow checks

The workflow treats the tag as untrusted input and stops before building
anything unless all of the following hold.

- The tag names a plain version, such as `v1.2.3`.
- The tagged commit is on `main`.
- Every package manifest carries exactly the version in the tag.
- No changeset is pending, which means the release pull request has been merged.

## Credentials

There is no npm token anywhere in this repository or its settings. Each
package on npm is configured to trust only this repository's release workflow
running in the `release` environment, and npm accepts the short-lived identity
that GitHub issues to that job. The job that opens the release pull request has
no access to that identity, and the job that publishes has no permission to write
to the repository.
