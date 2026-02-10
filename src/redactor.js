#!/usr/bin/env node

/**
 * Claude Code Session Redactor
 * 
 * Scans all files in ~/.claude/projects for sensitive data and redacts them,
 * preserving a few characters for identification while masking the rest.
 * 
 * Sensitive items detected:
 * - API keys (OpenAI, Anthropic, AWS, Google, Stripe, GitHub, etc.)
 * - SSH private keys (RSA, ED25519, ECDSA, DSA)
 * - Passwords and secrets in env vars / config
 * - Bearer tokens / JWT tokens
 * - Database connection strings with credentials
 * - PEM certificates and private keys
 * - Webhook URLs with tokens
 * 
 * Usage:
 *   node src/redactor.js [options]
 * 
 *   --dry-run       Show what would be redacted without modifying files
 *   --dir <path>    Custom directory (default: ~/.claude/projects)
 *   --verbose       Show detailed match info
 *   --backup        Create .bak files before modifying
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// ============================================================
// Configuration
// ============================================================

const DEFAULT_DIR = path.join(os.homedir(), '.claude', 'projects');

/**
 * Redaction helper: keeps first `keep` chars visible, masks the rest.
 * Example: redact("sk-abc123xyz", 6) => "sk-abc*****"
 */
function redact(value, keep = 6) {
  if (!value || value.length <= keep) return '*'.repeat(value?.length || 4);
  return value.slice(0, keep) + '*'.repeat(value.length - keep);
}

/**
 * Redaction patterns — order matters (more specific first).
 * Each pattern returns null for no match, or the redacted string.
 */
const PATTERNS = [
  // ── SSH / PEM Private Keys (multi-line block) ──
  {
    name: 'SSH/PEM Private Key',
    // Matches entire key block including header and footer
    regex: /-----BEGIN\s+(RSA |EC |DSA |OPENSSH |ED25519 )?PRIVATE KEY-----[\s\S]*?-----END\s+(RSA |EC |DSA |OPENSSH |ED25519 )?PRIVATE KEY-----/g,
    replace: (match) => {
      const header = match.split('\n')[0];
      return `${header}\n[REDACTED PRIVATE KEY]\n-----END PRIVATE KEY-----`;
    }
  },

  // ── API Keys with known prefixes ──
  {
    name: 'Anthropic API Key',
    regex: /\b(sk-ant-api03-[A-Za-z0-9_-]{20,})/g,
    replace: (m) => redact(m, 14)
  },
  {
    name: 'Anthropic Session Key',
    regex: /\b(sk-ant-sid01-[A-Za-z0-9_-]{20,})/g,
    replace: (m) => redact(m, 14)
  },
  {
    name: 'OpenAI API Key',
    regex: /\b(sk-[A-Za-z0-9]{20,})/g,
    replace: (m) => redact(m, 6)
  },
  {
    name: 'OpenAI Project Key',
    regex: /\b(sk-proj-[A-Za-z0-9_-]{20,})/g,
    replace: (m) => redact(m, 10)
  },
  {
    name: 'AWS Access Key',
    regex: /\b(AKIA[0-9A-Z]{12,})/g,
    replace: (m) => redact(m, 8)
  },
  {
    name: 'AWS Secret Key',
    regex: /(?<=aws_secret_access_key\s*[=:]\s*["']?)[A-Za-z0-9/+=]{30,}/g,
    replace: (m) => redact(m, 6)
  },
  {
    name: 'GitHub Token (ghp/gho/ghs/ghr)',
    regex: /\b(gh[posr]_[A-Za-z0-9_]{30,})/g,
    replace: (m) => redact(m, 8)
  },
  {
    name: 'GitHub Fine-grained PAT',
    regex: /\b(github_pat_[A-Za-z0-9_]{30,})/g,
    replace: (m) => redact(m, 14)
  },

  {
    name: 'Stripe Key',
    regex: /\b([sr]k_(test|live)_[A-Za-z0-9]{20,})/g,
    replace: (m) => redact(m, 12)
  },
  {
    name: 'Slack Token',
    regex: /\b(xox[bpsa]-[A-Za-z0-9-]{20,})/g,
    replace: (m) => redact(m, 8)
  },
  {
    name: 'Slack Webhook',
    regex: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+)/g,
    replace: (m) => redact(m, 40)
  },
  {
    name: 'Discord Webhook',
    regex: /(https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+)/g,
    replace: (m) => redact(m, 45)
  },
  {
    name: 'Twilio Auth Token',
    regex: /(?<=twilio[_\s]*(?:auth[_\s]*)?(?:token|sid)\s*[=:]\s*["']?)[A-Za-z0-9]{20,}/gi,
    replace: (m) => redact(m, 6)
  },
  {
    name: 'SendGrid API Key',
    regex: /\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})/g,
    replace: (m) => redact(m, 6)
  },
  {
    name: 'Google API Key',
    regex: /\b(AIza[A-Za-z0-9_-]{30,})/g,
    replace: (m) => redact(m, 8)
  },
  {
    name: 'Google OAuth Client Secret',
    regex: /(?<=client_secret["']?\s*[=:]\s*["']?)[A-Za-z0-9_-]{20,}/g,
    replace: (m) => redact(m, 6)
  },
  {
    name: 'Supabase Key',
    regex: /\b(eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,})/g,
    replace: (m) => redact(m, 10)
  },

  {
    name: 'Cloudflare API Token',
    regex: /\b(cf[_-]?[A-Za-z0-9_-]{35,})/gi,
    replace: (m) => redact(m, 6)
  },
  {
    name: 'Vercel Token',
    regex: /(?<=vercel[_\s]*(?:token|api[_\s]*key)\s*[=:]\s*["']?)[A-Za-z0-9]{20,}/gi,
    replace: (m) => redact(m, 6)
  },
  {
    name: 'Heroku API Key',
    regex: /(?<=heroku[_\s]*api[_\s]*key\s*[=:]\s*["']?)[0-9a-f-]{30,}/gi,
    replace: (m) => redact(m, 6)
  },
  {
    name: 'npm Token',
    regex: /\b(npm_[A-Za-z0-9]{30,})/g,
    replace: (m) => redact(m, 8)
  },
  {
    name: 'Docker Hub Token',
    regex: /\b(dckr_pat_[A-Za-z0-9_-]{20,})/g,
    replace: (m) => redact(m, 12)
  },

  // ── Bearer / Authorization Tokens ──
  {
    name: 'Bearer Token',
    regex: /(?<=Bearer\s+)[A-Za-z0-9_.\-\/+=]{20,}/g,
    replace: (m) => redact(m, 8)
  },

  // ── Database Connection Strings ──
  {
    name: 'Database URL with Password',
    regex: /((?:mysql|postgres|postgresql|mongodb|mongodb\+srv|redis|amqp):\/\/[^:]+:)([^@]+)(@)/g,
    replace: (full, prefix, password, suffix) => `${prefix}${redact(password, 3)}${suffix}`
  },

  // ── Generic ENV-style secrets ──
  // Matches KEY=VALUE patterns for common secret variable names
  {
    name: 'Env Secret (PASSWORD/SECRET/TOKEN/KEY)',
    regex: /(?<=(?:PASSWORD|_SECRET|_TOKEN|_API_KEY|_AUTH_KEY|_PRIVATE_KEY|_ACCESS_KEY|WEBHOOK_SECRET|SIGNING_SECRET|ENCRYPTION_KEY|_CREDENTIALS)\s*[=:]\s*["']?)([A-Za-z0-9_.\-\/+=]{8,})(?=["']?\s*$|["']\s*[,;}\]])/gm,
    replace: (m) => redact(m, 4)
  },

  // ── Specific .env style assignments ──
  {
    name: 'Generic Secret Assignment',
    regex: /(?<=(?:secret|password|passwd|token|apikey|api_key|auth_token|access_token|refresh_token|private_key|signing_key)["']?\s*[=:]\s*["']?)([^\s"']{12,})/gi,
    replace: (m) => redact(m, 4)
  },

  // ── Hex-encoded secrets (64-char hex strings — likely SHA256 keys) ──
  {
    name: 'Hex Secret (64 chars)',
    regex: /(?<=(?:key|secret|token|hash|signature)\s*[=:]\s*["']?)([0-9a-f]{64})(?=["']?\s)/gi,
    replace: (m) => redact(m, 8)
  },

  // ── SSH connection strings with embedded passwords ──
  {
    name: 'SSH Pass',
    regex: /(sshpass\s+-p\s+)["']?([^\s"']+)/g,
    replace: (full, prefix, password) => `${prefix}"${redact(password, 3)}"`
  },
];

// ============================================================
// File Scanner
// ============================================================

/**
 * Recursively collect all files in a directory
 */
function walkDir(dir) {
  const results = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...walkDir(fullPath));
      } else if (entry.isFile()) {
        // Skip binary-looking files, .DS_Store
        if (entry.name === '.DS_Store') continue;
        results.push(fullPath);
      }
    }
  } catch (err) {
    console.error(`⚠ Cannot read directory: ${dir} — ${err.message}`);
  }
  return results;
}

/**
 * Apply all redaction patterns to a string.
 * Returns { content, findings } where findings is an array of matches.
 */
function redactContent(content, filePath, verbose = false) {
  const findings = [];
  let redacted = content;

  for (const pattern of PATTERNS) {
    // Reset regex state
    pattern.regex.lastIndex = 0;

    // For patterns with capture groups in replace function
    if (pattern.replace.length > 1) {
      // Multi-capture-group replacer
      redacted = redacted.replace(pattern.regex, (...args) => {
        const fullMatch = args[0];
        findings.push({
          pattern: pattern.name,
          file: filePath,
          preview: fullMatch.length > 60 ? fullMatch.slice(0, 60) + '...' : fullMatch,
        });
        return pattern.replace(...args);
      });
    } else {
      // Single match replacer
      redacted = redacted.replace(pattern.regex, (match) => {
        findings.push({
          pattern: pattern.name,
          file: filePath,
          preview: match.length > 60 ? match.slice(0, 60) + '...' : match,
        });
        return pattern.replace(match);
      });
    }
  }

  return { content: redacted, findings };
}

// ============================================================
// Main Runner
// ============================================================

async function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes('--dry-run');
  const verbose = args.includes('--verbose');
  const backup = args.includes('--backup');

  // Parse --dir
  let targetDir = DEFAULT_DIR;
  const dirIdx = args.indexOf('--dir');
  if (dirIdx !== -1 && args[dirIdx + 1]) {
    targetDir = path.resolve(args[dirIdx + 1]);
  }

  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║        Claude Code Session Redactor                 ║');
  console.log('╚══════════════════════════════════════════════════════╝');
  console.log(`\n📁 Target directory: ${targetDir}`);
  console.log(`🔧 Mode: ${dryRun ? 'DRY RUN (no changes)' : 'LIVE (will modify files)'}`);
  if (backup) console.log('💾 Backup: enabled (.bak files will be created)');
  console.log('');

  if (!fs.existsSync(targetDir)) {
    console.error(`❌ Directory not found: ${targetDir}`);
    process.exit(1);
  }

  // Collect all files
  console.log('🔍 Scanning for files...');
  const files = walkDir(targetDir);
  console.log(`   Found ${files.length} files to scan\n`);

  let totalFindings = 0;
  let filesModified = 0;
  let filesScanned = 0;
  const findingsByType = {};
  const errors = [];

  for (const filePath of files) {
    filesScanned++;

    // Progress indicator every 100 files
    if (filesScanned % 100 === 0) {
      process.stdout.write(`\r   Scanned ${filesScanned}/${files.length} files...`);
    }

    let content;
    try {
      // Skip files > 50MB (likely not text)
      const stat = fs.statSync(filePath);
      if (stat.size > 50 * 1024 * 1024) {
        if (verbose) console.log(`⏭  Skipping (too large): ${filePath}`);
        continue;
      }
      content = fs.readFileSync(filePath, 'utf-8');
    } catch (err) {
      errors.push({ file: filePath, error: err.message });
      continue;
    }

    const { content: redacted, findings } = redactContent(content, filePath, verbose);

    if (findings.length === 0) continue;

    totalFindings += findings.length;
    filesModified++;

    // Tally by type
    for (const f of findings) {
      findingsByType[f.pattern] = (findingsByType[f.pattern] || 0) + 1;
    }

    // Show per-file findings
    const relPath = path.relative(targetDir, filePath);
    console.log(`\n🔐 ${relPath}`);
    for (const f of findings) {
      if (verbose) {
        console.log(`   ├─ ${f.pattern}: ${f.preview}`);
      } else {
        console.log(`   ├─ ${f.pattern}`);
      }
    }

    // Write changes
    if (!dryRun) {
      try {
        if (backup) {
          fs.copyFileSync(filePath, filePath + '.bak');
        }
        fs.writeFileSync(filePath, redacted, 'utf-8');
        console.log(`   └─ ✅ Redacted (${findings.length} items)`);
      } catch (err) {
        console.log(`   └─ ❌ Write failed: ${err.message}`);
        errors.push({ file: filePath, error: err.message });
      }
    } else {
      console.log(`   └─ 🔍 Would redact ${findings.length} items`);
    }
  }

  // ── Summary ──
  console.log('\n');
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║                    Summary                          ║');
  console.log('╚══════════════════════════════════════════════════════╝');
  console.log(`   Files scanned:     ${filesScanned}`);
  console.log(`   Files with secrets: ${filesModified}`);
  console.log(`   Total redactions:  ${totalFindings}`);
  console.log(`   Mode:              ${dryRun ? 'DRY RUN' : 'LIVE'}`);

  if (Object.keys(findingsByType).length > 0) {
    console.log('\n   Findings by type:');
    const sorted = Object.entries(findingsByType).sort((a, b) => b[1] - a[1]);
    for (const [type, count] of sorted) {
      console.log(`     ${count.toString().padStart(5)}  ${type}`);
    }
  }

  if (errors.length > 0) {
    console.log(`\n   ⚠ Errors: ${errors.length}`);
    if (verbose) {
      for (const e of errors) {
        console.log(`     ${e.file}: ${e.error}`);
      }
    }
  }

  console.log('');
  if (dryRun && totalFindings > 0) {
    console.log('💡 Run without --dry-run to apply redactions.');
    console.log('💡 Use --backup to create .bak files before modifying.');
  }
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
