import json
import os
import redis


class RedisQueue:
    def __init__(self):
        self.r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))

    def send(self, queue_name: str, message: dict):
        self.r.lpush(queue_name, json.dumps(message))

    def receive(self, queue_name: str, timeout: int = 30) -> dict | None:
        result = self.r.brpop(queue_name, timeout=timeout)
        if result:
            return json.loads(result[1])
        return None

    def publish(self, channel: str, message: dict):
        self.r.publish(channel, json.dumps(message))
