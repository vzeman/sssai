import json
import os
import boto3


class S3Storage:
    def __init__(self):
        self.s3 = boto3.client("s3")
        self.bucket = os.getenv("S3_BUCKET", "security-scanner-results")

    def put(self, key: str, data: str | bytes):
        body = data.encode() if isinstance(data, str) else data
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=body)

    def get(self, key: str) -> str | None:
        try:
            resp = self.s3.get_object(Bucket=self.bucket, Key=key)
            return resp["Body"].read().decode()
        except self.s3.exceptions.NoSuchKey:
            return None

    def put_json(self, key: str, data: dict):
        self.put(key, json.dumps(data, indent=2))

    def get_json(self, key: str) -> dict | None:
        raw = self.get(key)
        return json.loads(raw) if raw else None

    def list_keys(self, prefix: str = "") -> list[str]:
        resp = self.s3.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
        return [obj["Key"] for obj in resp.get("Contents", [])]
