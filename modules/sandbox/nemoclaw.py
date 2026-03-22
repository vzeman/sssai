"""
NVIDIA NemoClaw integration — OpenClaw agents running inside OpenShell with managed inference.

NemoClaw = OpenClaw + OpenShell + Nemotron models
Provides secure, sandboxed execution of AI-driven security scanning agents
with policy-governed network/file/process access.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from modules.config import AI_MODEL
from modules.sandbox.openshell import OpenShellPolicy

log = logging.getLogger(__name__)


@dataclass
class NemoClawConfig:
    """
    NemoClaw runtime configuration.

    Orchestrates:
    - OpenShell sandbox with security policies
    - Inference provider (Anthropic Claude or Nemotron)
    - Agent tools and capabilities
    - Network policies scoped to scan target
    """
    name: str = "security-scanner-agent"
    sandbox_policy: OpenShellPolicy = field(default_factory=OpenShellPolicy)

    # Inference configuration
    inference_provider: str = "anthropic"  # "anthropic" | "nemotron" | "local"
    model: str = AI_MODEL
    nemotron_model: str = "nemotron-3-super-120b"
    local_inference_port: int = 8081

    # Agent configuration
    max_tool_calls: int = 200
    max_retries: int = 3
    enable_skill_learning: bool = False  # OpenClaw skill evolution

    # Credentials (injected via OpenShell, never in filesystem)
    credential_env_vars: list[str] = field(default_factory=lambda: [
        "ANTHROPIC_API_KEY",
    ])

    def to_nemoclaw_yaml(self) -> str:
        """Export as NemoClaw CLI configuration."""
        import yaml

        config = {
            "apiVersion": "nemoclaw.nvidia.com/v1alpha1",
            "kind": "AgentConfig",
            "metadata": {
                "name": self.name,
            },
            "spec": {
                "sandbox": {
                    "policy": self.sandbox_policy.name,
                    "timeout": f"{self.sandbox_policy.timeout_seconds}s",
                },
                "inference": {
                    "provider": self.inference_provider,
                    "model": self.model if self.inference_provider == "anthropic" else self.nemotron_model,
                },
                "agent": {
                    "maxToolCalls": self.max_tool_calls,
                    "maxRetries": self.max_retries,
                    "skillLearning": self.enable_skill_learning,
                },
                "credentials": {
                    "envVars": self.credential_env_vars,
                },
            },
        }
        return yaml.dump(config, default_flow_style=False, sort_keys=False)

    @classmethod
    def for_scan(cls, scan_type: str, target: str, use_nemotron: bool = False) -> "NemoClawConfig":
        """Create a NemoClaw config for a specific scan."""
        policy = OpenShellPolicy.for_scan_type(scan_type, target)
        config = cls(
            name=f"scanner-{scan_type}-agent",
            sandbox_policy=policy,
        )

        if use_nemotron:
            config.inference_provider = "nemotron"
            config.model = config.nemotron_model

        return config

    def save(self, path: str | Path):
        """Save config to YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Save sandbox policy alongside agent config
        policy_path = path.parent / f"{self.sandbox_policy.name}-policy.yaml"
        self.sandbox_policy.save(policy_path)

        path.write_text(self.to_nemoclaw_yaml())
        log.info("NemoClaw config saved to %s (policy: %s)", path, policy_path)

    def generate_cli_command(self) -> str:
        """Generate the nemoclaw CLI command to run this agent."""
        return (
            f"nemoclaw run "
            f"--config {self.name}.yaml "
            f"--policy {self.sandbox_policy.name}-policy.yaml "
            f"--provider {self.inference_provider} "
            f"--model {self.model if self.inference_provider == 'anthropic' else self.nemotron_model}"
        )
