import json
import os
import boto3


class SQSQueue:
    def __init__(self):
        self.sqs = boto3.client("sqs")
        self.queue_urls = {
            "scan-jobs": os.getenv("SQS_SCAN_QUEUE_URL"),
            "scan-results": os.getenv("SQS_RESULTS_QUEUE_URL"),
        }

    def send(self, queue_name: str, message: dict):
        self.sqs.send_message(
            QueueUrl=self.queue_urls[queue_name],
            MessageBody=json.dumps(message),
        )

    def receive(self, queue_name: str, timeout: int = 20) -> dict | None:
        resp = self.sqs.receive_message(
            QueueUrl=self.queue_urls[queue_name],
            MaxNumberOfMessages=1,
            WaitTimeSeconds=min(timeout, 20),
        )
        messages = resp.get("Messages", [])
        if not messages:
            return None
        msg = messages[0]
        self.sqs.delete_message(
            QueueUrl=self.queue_urls[queue_name],
            ReceiptHandle=msg["ReceiptHandle"],
        )
        return json.loads(msg["Body"])

    def publish(self, channel: str, message: dict):
        # For real-time updates in AWS, use API Gateway WebSocket or SNS
        self.send(channel, message)
