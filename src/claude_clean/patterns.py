"""Secret detection patterns organized by sensitivity level."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class Sensitivity(Enum):
    """Sensitivity levels for secret detection."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class SecretPattern:
    """A pattern for detecting a specific type of secret."""

    name: str
    pattern: re.Pattern[str]
    sensitivity: Sensitivity
    description: str


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# ── Low sensitivity: high-confidence, specific key formats ──────────

_LOW_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="aws_access_key",
        pattern=_compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
        sensitivity=Sensitivity.LOW,
        description="AWS Access Key ID",
    ),
    SecretPattern(
        name="aws_secret_key",
        pattern=_compile(
            r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key"
            r"|aws[_-]?secret[_-]?key)"
            r"""\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"""
        ),
        sensitivity=Sensitivity.LOW,
        description="AWS Secret Access Key",
    ),
    SecretPattern(
        name="openai_api_key",
        pattern=_compile(r"sk-(?!ant-)[A-Za-z0-9_-]{20,}"),
        sensitivity=Sensitivity.LOW,
        description="OpenAI API Key",
    ),
    SecretPattern(
        name="anthropic_api_key",
        pattern=_compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
        sensitivity=Sensitivity.LOW,
        description="Anthropic API Key",
    ),
    SecretPattern(
        name="github_token",
        pattern=_compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"),
        sensitivity=Sensitivity.LOW,
        description="GitHub Token",
    ),
    SecretPattern(
        name="gitlab_token",
        pattern=_compile(r"glpat-[A-Za-z0-9_-]{20,}"),
        sensitivity=Sensitivity.LOW,
        description="GitLab Personal Access Token",
    ),
    SecretPattern(
        name="stripe_key",
        pattern=_compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}"),
        sensitivity=Sensitivity.LOW,
        description="Stripe API Key",
    ),
    SecretPattern(
        name="private_key_block",
        pattern=_compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?"
            r"PRIVATE KEY-----"
        ),
        sensitivity=Sensitivity.LOW,
        description="Private Key Header",
    ),
    SecretPattern(
        name="slack_token",
        pattern=_compile(r"xox[bporas]-[A-Za-z0-9-]{10,}"),
        sensitivity=Sensitivity.LOW,
        description="Slack Token",
    ),
    SecretPattern(
        name="slack_webhook",
        pattern=_compile(
            r"https://hooks\.slack\.com/services/"
            r"T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"
        ),
        sensitivity=Sensitivity.LOW,
        description="Slack Webhook URL",
    ),
    SecretPattern(
        name="google_api_key",
        pattern=_compile(r"AIza[0-9A-Za-z_-]{35}"),
        sensitivity=Sensitivity.LOW,
        description="Google API Key",
    ),
    SecretPattern(
        name="heroku_api_key",
        pattern=_compile(
            r"(?i)(?:heroku[_-]?api[_-]?key"
            r"|heroku[_-]?auth[_-]?token)"
            r"""\s*[=:]\s*['"]?"""
            r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
            r"""-[0-9a-f]{4}-[0-9a-f]{12})['"]?"""
        ),
        sensitivity=Sensitivity.LOW,
        description="Heroku API Key",
    ),
    SecretPattern(
        name="npm_token",
        pattern=_compile(r"npm_[A-Za-z0-9]{36}"),
        sensitivity=Sensitivity.LOW,
        description="npm Access Token",
    ),
    SecretPattern(
        name="sendgrid_api_key",
        pattern=_compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        sensitivity=Sensitivity.LOW,
        description="SendGrid API Key",
    ),
    SecretPattern(
        name="twilio_api_key",
        pattern=_compile(r"SK[0-9a-fA-F]{32}"),
        sensitivity=Sensitivity.LOW,
        description="Twilio API Key",
    ),
]

# ── Medium: passwords, tokens, auth headers, connection strings ─────

_MEDIUM_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="generic_password",
        pattern=_compile(
            r"(?i)(?:password|passwd|pwd|pass)"
            r"""\s*[=:]\s*['"]([^'"]{8,})['"]"""
        ),
        sensitivity=Sensitivity.MEDIUM,
        description="Password assignment",
    ),
    SecretPattern(
        name="generic_secret",
        pattern=_compile(
            r"(?i)(?:secret|secret_key|secret[-_]token)"
            r"""\s*[=:]\s*['"]([^'"]{8,})['"]"""
        ),
        sensitivity=Sensitivity.MEDIUM,
        description="Generic secret assignment",
    ),
    SecretPattern(
        name="generic_api_key",
        pattern=_compile(
            r"(?i)(?:api[_-]?key|apikey)"
            r"""\s*[=:]\s*['"]([^'"]{8,})['"]"""
        ),
        sensitivity=Sensitivity.MEDIUM,
        description="Generic API key assignment",
    ),
    SecretPattern(
        name="generic_token",
        pattern=_compile(
            r"(?i)(?:access[_-]?token|auth[_-]?token"
            r"|bearer[_-]?token|refresh[_-]?token)"
            r"""\s*[=:]\s*['"]([^'"]{8,})['"]"""
        ),
        sensitivity=Sensitivity.MEDIUM,
        description="Generic token assignment",
    ),
    SecretPattern(
        name="bearer_auth",
        pattern=_compile(
            r"(?i)(?:authorization|bearer)"
            r"""\s*[=:]\s*['"]?Bearer\s+"""
            r"""[A-Za-z0-9_.-]{20,}['"]?"""
        ),
        sensitivity=Sensitivity.MEDIUM,
        description="Bearer authorization header",
    ),
    SecretPattern(
        name="basic_auth",
        pattern=_compile(
            r"(?i)(?:authorization)"
            r"""\s*[=:]\s*['"]?Basic\s+"""
            r"""[A-Za-z0-9+/=]{10,}['"]?"""
        ),
        sensitivity=Sensitivity.MEDIUM,
        description="Basic authorization header",
    ),
    SecretPattern(
        name="database_url",
        pattern=_compile(
            r"(?:postgres(?:ql)?|mysql"
            r"|mongodb(?:\+srv)?|redis|amqp|mssql)"
            r"""://[^\s'"<>]{10,}"""
        ),
        sensitivity=Sensitivity.MEDIUM,
        description="Database connection string",
    ),
    SecretPattern(
        name="jwt_token",
        pattern=_compile(
            r"eyJ[A-Za-z0-9_-]{10,}"
            r"\.eyJ[A-Za-z0-9_-]{10,}"
            r"\.[A-Za-z0-9_-]{10,}"
        ),
        sensitivity=Sensitivity.MEDIUM,
        description="JWT Token",
    ),
    SecretPattern(
        name="env_secret_assignment",
        pattern=_compile(
            r"(?i)(?:export\s+)?"
            r"(?:[A-Z_]*(?:SECRET|PASSWORD|TOKEN"
            r"|KEY|CREDENTIAL|AUTH)[A-Z_]*)"
            r"""\s*=\s*['"]?([^\s'"]{8,})['"]?"""
        ),
        sensitivity=Sensitivity.MEDIUM,
        description="Environment variable with sensitive name",
    ),
    SecretPattern(
        name="private_key_content",
        pattern=_compile(r"(?:[A-Za-z0-9+/]{64,}={0,2}\n?){2,}"),
        sensitivity=Sensitivity.MEDIUM,
        description="Base64 block (potential private key content)",
    ),
]

# ── High sensitivity: broad / heuristic patterns ───────────────────

_HIGH_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="url_with_credentials",
        pattern=_compile(r"""https?://[^:@\s]+:[^:@\s]+@[^\s'"<>]+"""),
        sensitivity=Sensitivity.HIGH,
        description="URL with embedded credentials",
    ),
    SecretPattern(
        name="ip_address",
        pattern=_compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
        ),
        sensitivity=Sensitivity.HIGH,
        description="IPv4 address",
    ),
    SecretPattern(
        name="email_address",
        pattern=_compile(
            r"\b[A-Za-z0-9._%+-]+"
            r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
        sensitivity=Sensitivity.HIGH,
        description="Email address",
    ),
    SecretPattern(
        name="high_entropy_hex",
        pattern=_compile(r"\b[0-9a-f]{32,}\b"),
        sensitivity=Sensitivity.HIGH,
        description="High-entropy hex string (potential secret)",
    ),
    SecretPattern(
        name="generic_credential_value",
        pattern=_compile(
            r"(?i)(?:credential|cred|auth|login)"
            r"""\s*[=:]\s*['"]([^'"]{4,})['"]"""
        ),
        sensitivity=Sensitivity.HIGH,
        description="Generic credential assignment",
    ),
    SecretPattern(
        name="ssh_connection",
        pattern=_compile(r"ssh\s+(?:-[A-Za-z]\s+\S+\s+)*\S+@\S+"),
        sensitivity=Sensitivity.HIGH,
        description="SSH connection string",
    ),
]


def get_patterns(
    sensitivity: Sensitivity,
) -> list[SecretPattern]:
    """Return all patterns at or below the given sensitivity level.

    Low  -> only low-confidence patterns
    Medium -> low + medium patterns
    High -> low + medium + high patterns
    """
    patterns: list[SecretPattern] = list(_LOW_PATTERNS)
    if sensitivity in (Sensitivity.MEDIUM, Sensitivity.HIGH):
        patterns.extend(_MEDIUM_PATTERNS)
    if sensitivity is Sensitivity.HIGH:
        patterns.extend(_HIGH_PATTERNS)
    return patterns
