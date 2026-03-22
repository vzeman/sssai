import os

RUNTIME = os.getenv("RUNTIME", "local")


def get_queue():
    if RUNTIME == "aws":
        from modules.infra.aws_queue import SQSQueue
        return SQSQueue()
    from modules.infra.local_queue import RedisQueue
    return RedisQueue()


def get_storage():
    if RUNTIME == "aws":
        from modules.infra.aws_storage import S3Storage
        return S3Storage()
    from modules.infra.local_storage import LocalStorage
    return LocalStorage()


def get_secrets():
    if RUNTIME == "aws":
        from modules.infra.aws_secrets import SecretsManagerStore
        return SecretsManagerStore()
    from modules.infra.local_secrets import EnvSecrets
    return EnvSecrets()


def get_es():
    """Return the Elasticsearch client singleton."""
    from modules.infra.elasticsearch import get_client
    return get_client()


def setup_es():
    """Create ES indices and ILM policies."""
    from modules.infra.elasticsearch import setup_indices
    return setup_indices()
