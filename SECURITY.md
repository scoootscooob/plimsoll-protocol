# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security vulnerabilities by emailing:

**security@plimsoll.network**

You should receive a response within 48 hours. If for some reason you do not,
please follow up to ensure we received your original message.

Please include:

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Any potential mitigations you've identified

## Disclosure Policy

- We will acknowledge receipt within 48 hours
- We will confirm the vulnerability and determine its impact within 7 days
- We will release a patch within 30 days of confirmation
- We will publicly disclose the vulnerability after the patch is released

## Scope

The following are in scope:

- `plimsoll` Python SDK (all engines, firewall, vault, proxy)
- `plimsoll-rpc` Rust proxy
- Solidity smart contracts (`contracts/`)
- Solana programs (`contracts/solana/`)
- Bitcoin Taproot vault (`contracts/bitcoin/`)

The following are out of scope:

- The demo applications (`demo/`)
- The documentation website
- Third-party dependencies (report these to their maintainers)
