# Vendored: didwebvh-test-suite vectors

Source: https://github.com/decentralized-identity/didwebvh-test-suite
Commit: 0f03983c61ff3ed80d37239105d5b1a02e3f13dd (2026-08-26)
Licence: Apache-2.0 (LICENSE included alongside)

Signed `did.jsonl` logs and expected resolution results produced by six
independent did:webvh implementations across 30 scenarios, of which 13 are
positive and 17 are negative.[^counts]

Vendored rather than fetched at test time so the suite is reproducible offline
and pinned to a known commit. Refresh deliberately, and re-read the diff: a
change in these files is a change in what the ecosystem considers correct.

Consumed by `packages/core/test/conformance-vectors.test.ts`.

[^counts]: Counted from this directory at the pinned commit. The 30 scenarios
are the immediate subdirectories, 17 of which are prefixed `negative-` and 13
of which are not, so `ls -d */ | grep -c '^negative-'` gives 17 and the
complement gives 13. The 6 implementations are the distinct parent directory
names of the `did.jsonl` files, namely dart, java, java-eecc, python, rust and
ts, and there are 98 such files in total because coverage is uneven: most
negative scenarios were produced by ts alone, whereas the positive scenarios
were produced by five or six implementations each. The numbers therefore
describe the vendored corpus and not the upstream repository, which may have
grown since the pinned commit.
