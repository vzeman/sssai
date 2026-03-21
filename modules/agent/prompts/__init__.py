"""Prompt loader — reads scan-type prompt templates and fills in variables."""

import os

_DIR = os.path.dirname(__file__)


def get_prompt(scan_type: str, *, target: str, config: dict | None = None) -> str:
    """Return the system prompt for a given scan type with variables substituted."""
    config = config or {}
    path = os.path.join(_DIR, f"{scan_type}.txt")
    if not os.path.exists(path):
        path = os.path.join(_DIR, "security.txt")

    with open(path) as f:
        template = f.read()

    return template.format(target=target, **config)
