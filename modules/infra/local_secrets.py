import os


class EnvSecrets:
    def get(self, key: str) -> str | None:
        return os.getenv(key)
