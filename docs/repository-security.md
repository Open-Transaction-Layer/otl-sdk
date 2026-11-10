# Repository security settings

The controls that keep a malicious contribution from reaching users are split
between files in this repository and settings on GitHub. The files travel with a
clone, but the settings do not, so `scripts/configure-github.sh` records every
setting and applies it with the GitHub CLI. It is idempotent and can be re-run
at any time to correct drift.

```bash
scripts/configure-github.sh Open-Transaction-Layer/otl-sdk
```

Run it as an organisation owner. Settings that GitHub offers only on public
repositories or with Advanced Security are attempted and reported rather than
aborting the run.

## What the settings enforce

| Control | Setting | Why |
| --- | --- | --- |
| Pull requests only | The `Protect main` ruleset blocks direct pushes, deletion and force pushes, with no bypass actors | Nobody, including an administrator, can change `main` without review |
| Review | 1 approval from a code owner, approval of the last push, stale approvals dismissed, threads resolved | The reviewer sees the final code, and a later push cannot ride on an earlier approval |
| Verified authorship | Signed commits and linear history | Every commit on `main` is attributable and the history cannot be rewritten |
| Squash merges only | Merge commits and rebases are disabled | One reviewed unit per change |
| Required checks | `check`, `packaging`, `audit`, `zizmor`, `CodeQL` and `dependency-review`, on an up-to-date branch | Nothing merges that fails build, tests, lint, vulnerability audit, workflow analysis or code scanning |
| Tags | The `Protect tags` ruleset blocks moving and deleting tags | A published version cannot be silently repointed |
| Actions | Only GitHub-owned actions plus three named ones, every action pinned by SHA, read-only default token, no pull request approval by workflows | A compromised or retagged action cannot run, and a workflow cannot approve its own change |
| Fork pull requests | A maintainer approves workflow runs from every outside contributor | Untrusted code does not run on repository runners unreviewed |
| Publishing | The `release` environment holds the npm token and requires approval from a maintainer | A merge to `main` alone can never publish |
| Secrets | Secret scanning and push protection | A committed credential is blocked or reported |
| Reporting | Private vulnerability reporting and Dependabot alerts and security updates | Researchers have a private channel and known-vulnerable dependencies are raised |

The organisation also requires two-factor authentication for every member, and
that is configured at organisation level rather than here.

## What lives in the repository

`.github/workflows` holds the pinned CI, CodeQL, dependency review, workflow
analysis, Scorecard and release workflows. `.github/CODEOWNERS` lists the paths
that decide what runs and what ships, and `.github/dependabot.yml` waits 7 days
before proposing a new dependency version. CI installs with `--ignore-scripts`
and verifies package signatures and provenance.

## What needs a person

The script cannot hold a secret, so add the npm publish token to the `release`
environment, which the script prints a command for. Two settings are also
deliberate choices for the owners: how many approvals `main` requires, which is
1 in the script, and who the `release` environment reviewers are.
