"""Configuration loading and management."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[import-not-found]

from claude_clean.patterns import Sensitivity

DEFAULT_CONFIG_PATH = Path.home() / ".claude-clean.toml"
DEFAULT_PROJECTS_PATH = Path.home() / ".claude" / "projects"


@dataclass
class Config:
    """Application configuration."""

    sensitivity: Sensitivity = Sensitivity.MEDIUM
    projects_path: Path = field(default_factory=lambda: DEFAULT_PROJECTS_PATH)
    backup: bool = True
    extra_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, config_path: Path | None = None) -> Config:
        """Load configuration from a TOML file, falling back to defaults."""
        path = config_path or DEFAULT_CONFIG_PATH
        if not path.exists():
            return cls()

        with open(path, "rb") as f:
            data = tomllib.load(f)

        sensitivity_str = data.get("sensitivity", "medium")
        try:
            sensitivity = Sensitivity(sensitivity_str)
        except ValueError:
            sensitivity = Sensitivity.MEDIUM

        projects_path_str = data.get("projects_path")
        projects_path = Path(projects_path_str) if projects_path_str else DEFAULT_PROJECTS_PATH

        return cls(
            sensitivity=sensitivity,
            projects_path=projects_path,
            backup=data.get("backup", True),
            extra_patterns=data.get("extra_patterns", []),
            exclude_patterns=data.get("exclude_patterns", []),
        )
