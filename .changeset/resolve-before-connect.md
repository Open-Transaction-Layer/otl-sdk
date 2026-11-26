---
"@open-transaction-layer/resolver": minor
"@open-transaction-layer/cli": minor
---

**Breaking:** private-address refusal is now on by default, so a resolver no longer fetches from a loopback, link-local, private or otherwise non-public address unless it is told to. Pass `blockPrivateAddresses: false` to the resolver functions, or `--allow-private-addresses` on the command line, to reach `localhost` during development. The command line flag `--block-private-addresses` is replaced by that opt-out and is now ignored.

The check also now covers where a name actually resolves, where it previously compared only the text of the hostname and so let through any DNS name an attacker had pointed at an internal address such as the cloud metadata service. The built-in transport resolves the name once, checks every address returned and connects to the address it checked, so a second lookup cannot return something different. The address check works on parsed addresses, which closes spellings such as `::ffff:127.0.0.1`, `0177.0.0.1`, and NAT64 and 6to4 forms, and adds the carrier-grade NAT, multicast and reserved ranges. A caller-supplied `fetch` replaces the transport and so only receives the literal-address check.
