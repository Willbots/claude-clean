# claude-clean

A CLI tool to scan and redact secrets and sensitive information from [Claude Code](https://docs.anthropic.com/en/docs/claude-code) session files.

Claude Code stores conversation sessions as JSONL files in `~/.claude/projects/`. These sessions may inadvertently contain API keys, passwords, tokens, and other sensitive data. `claude-clean` helps you find and redact them.

## Installation

```bash
pip install .
```

Or for development:

```bash
pip install -e ".[dev]"
```

## Quick Start

### Scan for secrets (dry run)

```bash
# Scan with default settings (medium sensitivity)
claude-clean scan

# Scan with high sensitivity
claude-clean scan -s high

# Scan a specific directory
claude-clean scan -p /path/to/projects

# Scan a single file
claude-clean scan -f ~/.claude/projects/myproject/session.jsonl

# Verbose output with context
claude-clean scan -v
```

### Redact secrets

```bash
# Preview what would be redacted (dry run)
claude-clean redact --dry-run

# Redact with backups (default)
claude-clean redact

# Redact without creating backups
claude-clean redact --no-backup

# Redact with high sensitivity
claude-clean redact -s high
```

## Sensitivity Levels

| Level | Description | Patterns |
|-------|-------------|----------|
| `low` | High-confidence only | AWS keys, OpenAI/Anthropic API keys, GitHub tokens, private key headers, Stripe keys, Slack tokens, etc. |
| `medium` (default) | Moderate confidence | All `low` patterns + passwords, generic secrets/tokens, Bearer/Basic auth, database URLs, JWTs, env var assignments |
| `high` | Broad detection | All `medium` patterns + URLs with credentials, IP addresses, email addresses, high-entropy hex strings, SSH connections |

## Configuration

Create a `~/.claude-clean.toml` file to set defaults:

```toml
# Default sensitivity level: "low", "medium", or "high"
sensitivity = "medium"

# Default path to scan
projects_path = "~/.claude/projects"

# Whether to create backups before redaction
backup = true

# Additional regex patterns to detect
extra_patterns = [
    "my-company-[a-z]{20}",
]

# Patterns to exclude from detection (allowlist)
exclude_patterns = [
    "example\\.com",
    "localhost",
]
```

## Commands

### `claude-clean scan`

Scans for secrets without modifying any files. This is effectively a dry run that reports all findings.

| Option | Description |
|--------|-------------|
| `-s, --sensitivity` | Detection sensitivity: `low`, `medium`, `high` |
| `-p, --path` | Directory to scan (default: `~/.claude/projects`) |
| `-f, --file` | Scan a single JSONL file |
| `-v, --verbose` | Show detailed context for each finding |
| `--config` | Path to config file |

### `claude-clean redact`

Redacts detected secrets from session files, replacing them with `[REDACTED]`.

| Option | Description |
|--------|-------------|
| `-s, --sensitivity` | Detection sensitivity: `low`, `medium`, `high` |
| `-p, --path` | Directory to redact (default: `~/.claude/projects`) |
| `-f, --file` | Redact a single JSONL file |
| `-n, --dry-run` | Preview redactions without modifying files |
| `--no-backup` | Skip creating `.bak` backup files |
| `-v, --verbose` | Show detailed output |
| `--config` | Path to config file |

## Detected Secret Types

### Low Sensitivity
- AWS Access Key IDs and Secret Keys
- OpenAI API Keys (`sk-...`)
- Anthropic API Keys (`sk-ant-...`)
- GitHub Tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- GitLab Personal Access Tokens (`glpat-...`)
- Stripe API Keys (`sk_live_`, `pk_live_`, etc.)
- Private Key Headers (`-----BEGIN ... PRIVATE KEY-----`)
- Slack Tokens and Webhooks
- Google API Keys (`AIza...`)
- Heroku API Keys
- npm Access Tokens
- SendGrid API Keys
- Twilio API Keys

### Medium Sensitivity (includes Low)
- Password assignments
- Generic secret/token assignments
- Bearer and Basic authorization headers
- Database connection strings (PostgreSQL, MySQL, MongoDB, Redis, etc.)
- JWT tokens
- Environment variable assignments with sensitive names

### High Sensitivity (includes Medium)
- URLs with embedded credentials
- IPv4 addresses
- Email addresses
- High-entropy hexadecimal strings
- Generic credential assignments
- SSH connection strings

## License

MIT
