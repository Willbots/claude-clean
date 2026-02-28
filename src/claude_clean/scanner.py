"""JSONL file scanner for secrets."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from claude_clean.patterns import SecretPattern, Sensitivity, get_patterns


@dataclass(frozen=True)
class Finding:
    """A single secret finding in a file."""

    file: Path
    line_number: int
    pattern_name: str
    pattern_description: str
    matched_text: str
    context: str  # surrounding text for display
    sensitivity: Sensitivity

    @property
    def masked_match(self) -> str:
        """Return the matched text with the middle portion masked."""
        text = self.matched_text
        if len(text) <= 8:
            return text[:2] + "***" + text[-1:]
        show = max(2, len(text) // 4)
        return text[:show] + "***" + text[-show:]


def _extract_strings(obj: object) -> list[str]:
    """Recursively extract all string values from a JSON object."""
    strings: list[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            strings.extend(_extract_strings(key))
            strings.extend(_extract_strings(value))
    elif isinstance(obj, list):
        for item in obj:
            strings.extend(_extract_strings(item))
    return strings


def _build_exclude_regex(exclude_patterns: list[str]) -> re.Pattern[str] | None:
    """Build a combined regex from exclude patterns."""
    if not exclude_patterns:
        return None
    combined = "|".join(f"(?:{p})" for p in exclude_patterns)
    return re.compile(combined)


def scan_text(
    text: str,
    patterns: list[SecretPattern],
    exclude_regex: re.Pattern[str] | None = None,
) -> list[tuple[SecretPattern, re.Match[str]]]:
    """Scan a text string for secret patterns."""
    matches: list[tuple[SecretPattern, re.Match[str]]] = []
    for pat in patterns:
        for match in pat.pattern.finditer(text):
            matched_text = match.group(0)
            if exclude_regex and exclude_regex.search(matched_text):
                continue
            matches.append((pat, match))
    return matches


def _dedup_matches(
    matches: list[tuple[SecretPattern, re.Match[str]]],
) -> list[tuple[SecretPattern, re.Match[str]]]:
    """Deduplicate overlapping matches, keeping the longest span."""
    if not matches:
        return matches
    # Sort by span length descending so longest wins during dedup
    sorted_matches = sorted(
        matches,
        key=lambda x: x[1].end() - x[1].start(),
        reverse=True,
    )
    kept: list[tuple[SecretPattern, re.Match[str]]] = []
    for pat, match in sorted_matches:
        start, end = match.start(), match.end()
        overlaps = False
        for _, existing in kept:
            es, ee = existing.start(), existing.end()
            if start < ee and end > es:
                overlaps = True
                break
        if not overlaps:
            kept.append((pat, match))
    return kept


def scan_file(
    file_path: Path,
    sensitivity: Sensitivity,
    extra_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
) -> list[Finding]:
    """Scan a single JSONL file for secrets."""
    patterns = get_patterns(sensitivity)

    # Add any extra user-defined patterns
    if extra_patterns:
        for i, pat_str in enumerate(extra_patterns):
            patterns.append(
                SecretPattern(
                    name=f"custom_{i}",
                    pattern=re.compile(pat_str),
                    sensitivity=sensitivity,
                    description=f"Custom pattern: {pat_str}",
                )
            )

    exclude_regex = _build_exclude_regex(exclude_patterns or [])
    findings: list[Finding] = []

    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings

    for line_num, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        # Try to parse as JSON and extract strings
        try:
            obj = json.loads(line)
            strings = _extract_strings(obj)
        except json.JSONDecodeError:
            # If not valid JSON, scan the raw line
            strings = [line]

        for text in strings:
            matches = _dedup_matches(scan_text(text, patterns, exclude_regex))
            for pat, match in matches:
                matched_text = match.group(0)
                # Build context: show a window around the match
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end]
                if start > 0:
                    context = "..." + context
                if end < len(text):
                    context = context + "..."

                findings.append(
                    Finding(
                        file=file_path,
                        line_number=line_num,
                        pattern_name=pat.name,
                        pattern_description=pat.description,
                        matched_text=matched_text,
                        context=context,
                        sensitivity=pat.sensitivity,
                    )
                )

    return findings


def scan_directory(
    directory: Path,
    sensitivity: Sensitivity,
    extra_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
) -> list[Finding]:
    """Scan all JSONL files in a directory recursively."""
    findings: list[Finding] = []

    if not directory.exists():
        return findings

    for jsonl_file in sorted(directory.rglob("*.jsonl")):
        if jsonl_file.is_file():
            file_findings = scan_file(
                jsonl_file,
                sensitivity,
                extra_patterns=extra_patterns,
                exclude_patterns=exclude_patterns,
            )
            findings.extend(file_findings)

    return findings
