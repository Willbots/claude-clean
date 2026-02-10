# claude-clean

Scan and redact sensitive data from Claude Code session files stored in `~/.claude/projects`.

## What it does

Claude Code stores full conversation histories as JSONL files. These sessions often contain sensitive data that was discussed or used during development — API keys, SSH keys, passwords, tokens, database credentials, etc.

`claude-clean` scans every file in your Claude Code projects directory, detects sensitive patterns, and redacts them by keeping only a few identifying characters and replacing the rest with asterisks.

**Example:** `sk-ant-api03-abcdef123456...` → `sk-ant-api03-a**************`

## Detected Patterns

- **API Keys**: Anthropic, OpenAI, AWS, Google, Stripe, GitHub, Slack, SendGrid, Cloudflare, Vercel, Heroku, npm, Docker Hub
- **SSH/PEM Private Keys**: RSA, ED25519, ECDSA, DSA, OpenSSH
- **Auth Tokens**: Bearer tokens, JWT/Supabase tokens, OAuth secrets
- **Database URLs**: PostgreSQL, MySQL, MongoDB, Redis, AMQP connection strings with passwords
- **Environment Secrets**: PASSWORD, SECRET, TOKEN, API_KEY, and similar variable assignments
- **Webhooks**: Slack and Discord webhook URLs with tokens
- **Hex Secrets**: 64-char hex strings (SHA256 keys/signatures)

## Usage

```bash
# Dry run — see what would be redacted without changing anything
npm run scan

# Redact with backup (.bak files created)
npm run redact

# Redact without backup
npm run redact:no-backup
```

### CLI Options

```bash
node src/redactor.js [options]

  --dry-run       Show what would be redacted without modifying files
  --dir <path>    Custom directory (default: ~/.claude/projects)
  --verbose       Show match previews in output
  --backup        Create .bak files before modifying
```

### Examples

```bash
# Scan a specific project directory
node src/redactor.js --dry-run --dir ~/.claude/projects/-my-project

# Full verbose scan
node src/redactor.js --dry-run --verbose

# Redact everything with backups
node src/redactor.js --backup
```

## Claude Code Session Structure

```
~/.claude/projects/
├── -Project-Path-Name/          # One dir per project (path encoded with dashes)
│   ├── sessions-index.json      # Index of all sessions
│   ├── memory/
│   │   └── MEMORY.md            # Project memory
│   ├── {session-uuid}.jsonl     # Session conversation log
│   └── {session-uuid}/          # Session artifacts
│       ├── subagents/           # Sub-agent sessions
│       └── tool-results/        # Stored tool outputs
│           └── toolu_*.txt
```

## Safety

- **Always run `--dry-run` first** to review what will be redacted
- Use `--backup` to create `.bak` files before any modifications
- The redaction preserves enough characters to identify the key type (e.g., the `sk-ant-api03-` prefix remains)
- No external dependencies — pure Node.js

## License

MIT
