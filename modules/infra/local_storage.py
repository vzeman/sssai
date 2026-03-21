import json
import os
from pathlib import Path


class LocalStorage:
    def __init__(self):
        self.base = Path(os.getenv("OUTPUT_DIR", "/output"))
        self.base.mkdir(parents=True, exist_ok=True)

    def put(self, key: str, data: str | bytes):
        path = self.base / key
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(path, mode) as f:
            f.write(data)

    def get(self, key: str) -> str | None:
        path = self.base / key
        if not path.exists():
            return None
        return path.read_text()

    def put_json(self, key: str, data: dict):
        self.put(key, json.dumps(data, indent=2))

    def get_json(self, key: str) -> dict | None:
        raw = self.get(key)
        return json.loads(raw) if raw else None

    def list_keys(self, prefix: str = "") -> list[str]:
        target = self.base / prefix
        if not target.exists():
            return []
        return [
            str(p.relative_to(self.base))
            for p in target.rglob("*") if p.is_file()
        ]
