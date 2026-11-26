# Repository security settings

The controls that keep a malicious contribution from reaching users are split
between files in this repository and settings on GitHub. The files travel with a
clone, but the settings do not, so this page records what the settings are and
why.

## What the settings enforce

| Control | Setting | Why |
| --- | --- | --- |
| Write access | Only the `maintainers` team can push | Everyone else contributes from a fork, so a branch in this repository was always pushed by a maintainer |
| Pull requests only | The `Protect main` ruleset blocks direct pushes, deletion and force pushes, with no bypass actors | Nobody, including an administrator, can change `main` without review |
| Review | 1 approval from a code owner, approval of the last push, stale approvals dismissed, threads resolved | The reviewer sees the final code, and a later push cannot ride on an earlier approval |
| Verified authorship | Signed commits and linear history | Every commit on `main` is attributable and the history cannot be rewritten |
| Squash merges only | Merge commits and rebases are disabled | One reviewed unit per change |
| Required checks | `check`, `packaging`, `audit`, `zizmor`, `CodeQL` and `dependency-review`, on an up-to-date branch | Nothing merges that fails build, tests, lint, vulnerability audit, workflow analysis or code scanning |
| Tags | The `Protect tags` ruleset blocks moving and deleting tags | A published version cannot be silently repointed |
| Actions | Only GitHub-owned actions and the OpenSSF Scorecard action are allowed, every action is pinned by SHA, read-only default token, no pull request approval by workflows | A compromised or retagged action cannot run, and a workflow cannot approve its own change |
| Fork pull requests | A maintainer approves workflow runs from every outside contributor | Untrusted code does not run on repository runners unreviewed |
| Publishing | npm trusts only the `release` environment of this repository's release workflow, there is no npm token, and the environment requires approval from a maintainer | A merge to `main` alone can never publish and there is no long-lived credential to steal |
| Secrets | Secret scanning and push protection | A committed credential is blocked or reported |
| Reporting | Private vulnerability reporting and Dependabot alerts and security updates | Researchers have a private channel and known-vulnerable dependencies are raised |

The organisation also requires two-factor authentication for every member, and
that is configured at organisation level rather than here.

## What lives in the repository

`.github/workflows` holds the pinned CI, CodeQL, dependency review, workflow
analysis and release workflows. The workflow analysis runs the zizmor command line tool from an install pinned by version and by the hash of every release file in `.github/zizmor/requirements.txt`. `.github/CODEOWNERS` lists the paths
that decide what runs and what ships, and `.github/dependabot.yml` waits 7 days
before proposing a new dependency version. CI installs with `--ignore-scripts`
and verifies package signatures and provenance.
