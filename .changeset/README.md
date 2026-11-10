# Changesets

This folder holds [changesets](https://github.com/changesets/changesets): one
small file per change, recording which packages it touches and how, written by
whoever makes the change rather than reconstructed later from commit messages.

Add one with `npx changeset` before opening a pull request. A change with no
user-visible effect does not need one.

The packages are configured as `fixed`, so they all carry the same version and
are released together. That is deliberate because the SDK tracks a versioned
specification, and a single version number for the whole SDK is far easier to
reason about than several drifting ones, and it
means a consumer can match an SDK version against a specification version
without consulting a table.
