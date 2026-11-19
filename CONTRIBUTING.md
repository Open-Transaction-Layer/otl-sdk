# Contributing

Thanks for your interest in the OTL Identity layer.

## Getting set up

You need Node 22.12.0 or later, which is the oldest Node line still receiving
security updates.

```bash
npm install
npm run check
```

`npm run check` runs the build, typecheck, lint, format check and the full test
suite, which is the same set of steps CI runs.

The workspace runs straight off TypeScript with no build step, through a custom
`otl-source` export condition, so `npm test` is fast and needs nothing compiled
first. The build exists to produce what gets published.

## Where to make your change

All changes reach `main` through a pull request, and nobody pushes to `main`
directly, including maintainers. Only maintainers can push branches to this
repository, so everyone else, including members of the Open-Transaction-Layer
organisation, contributes from a fork.

Fork the repository on GitHub, clone your fork and push a branch there, then
open the pull request from your fork against `main` here. Keep your fork
current by adding this repository as a second remote:

```bash
git remote add upstream https://github.com/Open-Transaction-Layer/otl-sdk.git
git fetch upstream
git switch -c my-change upstream/main
```

Maintainers push branches to this repository instead of forking.

Either way, start from the current `main` rather than from an older branch,
and keep one change to one pull request so that it can be reviewed and reverted
on its own. Workflows triggered from a fork run without access to repository
secrets, so a change that needs a secret to test will be run by a maintainer
once it has been reviewed.

## Working on a change

Every protocol rule is traceable to the specification, and source comments cite
sections as `§3.2.1`. If you change behaviour that a section mandates, say
which section in the commit message, and if you believe a section is wrong,
raise that separately rather than diverging quietly.

Tests are the argument that a change is correct, so a behavioural change needs
one. For anything touching verification, prefer a test written from the
attacker's side: issuance-time checks are not a substitute, because an attacker
does not use our issuer.

The repository vendors the official `did:webvh` conformance corpus under
`packages/core/test/vectors`. Those files are the ecosystem's definition of
correct rather than ours, so do not edit them to make a test pass. Refresh them
deliberately and read the diff when you do.

## Before you open a pull request

```bash
npm run check
npx changeset
```

The changeset records which packages changed and how, and it is what drives
versioning and the changelog. A change with no user-visible effect does not
need one.

## Commit messages and pull requests

Write prose in complete sentences. Explain why the change is being made rather
than restating what the diff shows, since the diff is already there.

## Licence

Contributions are accepted under the Apache License 2.0, the same licence the
project is distributed under.
