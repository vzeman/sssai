import json
import boto3


class SecretsManagerStore:
    def __init__(self):
        self.client = boto3.client("secretsmanager")
        self._cache = {}

    def get(self, key: str) -> str | None:
        if key in self._cache:
            return self._cache[key]
        try:
            resp = self.client.get_secret_value(SecretId=key)
            val = resp["SecretString"]
            # Try to parse as JSON and return individual key
            try:
                data = json.loads(val)
                self._cache.update(data)
                return data.get(key, val)
            except json.JSONDecodeError:
                self._cache[key] = val
                return val
        except Exception:
            return None
