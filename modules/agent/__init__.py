from pathlib import Path

PROMPTS_DIR = Path(__file__).parent / "prompts"

SCAN_TYPES = [
    "security", "pentest", "performance", "seo", "uptime", "compliance", "full",
    "api_security", "cloud", "recon", "privacy",
]


def get_prompt(scan_type: str, target: str, config: dict = None) -> str:
    config = config or {}
    prompt_file = PROMPTS_DIR / f"{scan_type}.txt"
    if not prompt_file.exists():
        prompt_file = PROMPTS_DIR / "security.txt"

    template = prompt_file.read_text()
    return template.format(target=target, **config)
