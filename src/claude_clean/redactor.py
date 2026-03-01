"""Redact secrets from JSONL files."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from claude_clean.patterns import SecretPattern, Sensitivity, get_patterns
from claude_clean.scanner import _build_exclude_regex, scan_text

REDACTED = "[REDACTED]"


@dataclass
class RedactionResult:
    """Result of redacting a single file."""

    file: Path
    original_lines: int
    redactions_made: int
    backup_path: Path | None


def _redact_in_object(
    obj: object,
    patterns: list[SecretPattern],
    exclude_regex: re.Pattern[str] | None,
) -> tuple[object, int]:
    """Recursively redact secrets in a JSON object. Returns (modified_obj, count)."""
    count = 0

    if isinstance(obj, str):
        new_text = obj
        # Find all matches and replace them
        all_matches: list[tuple[int, int, str]] = []
        for pat in patterns:
            for match in pat.pattern.finditer(new_text):
                matched_text = match.group(0)
                if exclude_regex and exclude_regex.search(matched_text):
                    continue
                all_matches.append((match.start(), match.end(), matched_text))

        if not all_matches:
            return obj, 0

        # Sort by span length descending to prioritize longest matches during dedup
        all_matches.sort(key=lambda x: x[1] - x[0], reverse=True)

        # Deduplicate overlapping matches (keep the longest)
        filtered: list[tuple[int, int, str]] = []
        for start, end, text in all_matches:
            overlaps = False
            for fs, fe, _ in filtered:
                if start < fe and end > fs:
                    overlaps = True
                    break
            if not overlaps:
                filtered.append((start, end, text))

        # Sort by start descending for safe end-to-start replacement
        filtered.sort(key=lambda x: x[0], reverse=True)

        for start, end, _ in filtered:
            new_text = new_text[:start] + REDACTED + new_text[end:]
            count += 1

        return new_text, count

    if isinstance(obj, dict):
        new_dict: dict[str, object] = {}
        for key, value in obj.items():
            new_key, kc = _redact_in_object(key, patterns, exclude_regex)
            new_value, vc = _redact_in_object(value, patterns, exclude_regex)
            key_str = str(new_key)
            # Disambiguate colliding redacted keys to prevent data loss
            if key_str in new_dict:
                i = 2
                while f"{key_str}_{i}" in new_dict:
                    i += 1
                key_str = f"{key_str}_{i}"
            new_dict[key_str] = new_value
            count += kc + vc
        return new_dict, count

    if isinstance(obj, list):
        new_list: list[object] = []
        for item in obj:
            new_item, c = _redact_in_object(item, patterns, exclude_regex)
            new_list.append(new_item)
            count += c
        return new_list, count

    return obj, 0


def redact_file(
    file_path: Path,
    sensitivity: Sensitivity,
    backup: bool = True,
    extra_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
) -> RedactionResult:
    """Redact secrets from a single JSONL file.

    Reads the file, replaces secrets with [REDACTED], and writes back.
    """
    patterns = get_patterns(sensitivity)

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

    raw = file_path.read_bytes()
    content = raw.decode("utf-8", errors="replace")
    line_ending = "\r\n" if "\r\n" in content else "\n"
    had_trailing_newline = content.endswith(("\n", "\r"))
    lines = content.splitlines()
    original_count = len(lines)

    new_lines: list[str] = []
    total_redactions = 0

    for line in lines:
        if not line.strip():
            new_lines.append(line)
            continue

        try:
            obj = json.loads(line)
            redacted_obj, count = _redact_in_object(obj, patterns, exclude_regex)
            total_redactions += count
            if count > 0:
                new_lines.append(json.dumps(redacted_obj, ensure_ascii=False))
            else:
                new_lines.append(line)
        except json.JSONDecodeError:
            # For non-JSON lines, do regex replacement directly
            new_text = line
            matches_found = scan_text(line, patterns, exclude_regex)
            # Sort by span length descending to keep longest match during dedup
            sorted_matches = sorted(
                matches_found,
                key=lambda x: x[1].end() - x[1].start(),
                reverse=True,
            )
            seen_spans: list[tuple[int, int]] = []
            for _, match in sorted_matches:
                start, end = match.start(), match.end()
                overlaps = False
                for ss, se in seen_spans:
                    if start < se and end > ss:
                        overlaps = True
                        break
                if not overlaps:
                    seen_spans.append((start, end))
                    total_redactions += 1
            # Sort kept spans by start descending for safe end-to-start replacement
            seen_spans.sort(key=lambda x: x[0], reverse=True)
            for start, end in seen_spans:
                new_text = new_text[:start] + REDACTED + new_text[end:]
            new_lines.append(new_text)

    backup_path: Path | None = None
    if total_redactions > 0:
        if backup:
            backup_path = file_path.with_suffix(file_path.suffix + ".bak")
            shutil.copy2(file_path, backup_path)
        output = line_ending.join(new_lines)
        if had_trailing_newline:
            output += line_ending
        file_path.write_text(output, encoding="utf-8")

    return RedactionResult(
        file=file_path,
        original_lines=original_count,
        redactions_made=total_redactions,
        backup_path=backup_path,
    )


def redact_directory(
    directory: Path,
    sensitivity: Sensitivity,
    backup: bool = True,
    extra_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
) -> list[RedactionResult]:
    """Redact secrets from all JSONL files in a directory recursively."""
    results: list[RedactionResult] = []

    if not directory.exists():
        return results

    for jsonl_file in sorted(directory.rglob("*.jsonl")):
        if jsonl_file.is_file():
            result = redact_file(
                jsonl_file,
                sensitivity,
                backup=backup,
                extra_patterns=extra_patterns,
                exclude_patterns=exclude_patterns,
            )
            results.append(result)

    return results
