"""
Sandbox integration — OpenShell/NemoClaw/OpenClaw secure agent execution.

Provides:
- OpenShell policy generation for sandboxed tool execution
- NemoClaw agent runtime configuration
- OpenClaw multi-channel gateway integration
"""


def __getattr__(name):
    if name == "OpenShellPolicy":
        from modules.sandbox.openshell import OpenShellPolicy
        return OpenShellPolicy
    elif name == "NemoClawConfig":
        from modules.sandbox.nemoclaw import NemoClawConfig
        return NemoClawConfig
    elif name == "OpenClawGateway":
        from modules.sandbox.openclaw import OpenClawGateway
        return OpenClawGateway
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
