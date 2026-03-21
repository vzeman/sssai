"""Notification system — multi-channel alerts for scan results, monitoring, and incidents."""


def __getattr__(name):
    if name == "NotificationDispatcher":
        from modules.notifications.dispatcher import NotificationDispatcher
        return NotificationDispatcher
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
