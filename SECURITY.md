# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| `1.0.x` | :white_check_mark: |
| `< 1.0` | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report them privately instead:

- **Email:** [notbadtb2@gmail.com](mailto:notbadtb2@gmail.com)
- **Telegram:** [@Voobrazhenie_20](https://t.me/Voobrazhenie_20)

Include a description of the issue, affected version(s), steps to reproduce, and
your suggested fix if available.

## Response Timeline

- **Acknowledgement:** within 48 hours.
- **Initial assessment:** within 7 days.
- **Resolution / mitigation:** as fast as practicable, depending on severity.

## Disclosure Policy

We follow **coordinated disclosure**: reporter and maintainer agree on a public
disclosure date (typically within 90 days of the initial report, or sooner once
a fix is released). Credit will be given to the reporter unless anonymity is
requested.

## Handling API Keys

ThreatPulse supports the `ABUSEIPDB_API_KEY` environment variable. **Never commit
API keys.** If you accidentally commit a key, revoke it immediately at the
provider and rotate to a new one — Git history retains secrets even after
deletion.
