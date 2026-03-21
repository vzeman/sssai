"""
NVIDIA OpenShell integration — secure sandbox runtime for AI-driven security agents.

OpenShell provides:
- Out-of-process policy enforcement
- Sandboxed execution with controlled network access
- Credential management (injected as env vars, never leaked to filesystem)
- GPU passthrough for local inference
- Declarative YAML policies for file/network/process restrictions
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger(__name__)


@dataclass
class NetworkPolicy:
    """Network access policy for sandboxed agents."""
    allowed_outbound: list[str] = field(default_factory=list)
    blocked_outbound: list[str] = field(default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
    max_connections: int = 100
    allowed_ports: list[int] = field(default_factory=lambda: [80, 443, 53, 8080, 8443])
    dns_allowed: bool = True


@dataclass
class FilePolicy:
    """File access policy for sandboxed agents."""
    read_allowed: list[str] = field(default_factory=lambda: ["/output", "/tmp", "/usr/share/wordlists"])
    write_allowed: list[str] = field(default_factory=lambda: ["/output", "/tmp"])
    blocked: list[str] = field(default_factory=lambda: ["/etc/shadow", "/root/.ssh", "/proc", "/sys"])


@dataclass
class ProcessPolicy:
    """Process execution policy for sandboxed agents."""
    allowed_binaries: list[str] = field(default_factory=lambda: [
        "nmap", "nuclei", "nikto", "testssl", "sslscan", "sslyze",
        "whatweb", "subfinder", "httpx", "gobuster", "dirb", "ffuf",
        "sqlmap", "wpscan", "wapiti", "wafw00f", "dnsrecon", "droopescan",
        "curl", "wget", "dig", "whois", "ping", "traceroute", "openssl",
        "lighthouse", "pa11y", "blc", "axe", "yellowlabtools",
        "k6", "jq", "python3", "node",
        "zap-cli", "zap-baseline.py", "drheader", "shcheck.py",
    ])
    blocked_binaries: list[str] = field(default_factory=lambda: [
        "rm", "mkfs", "dd", "mount", "umount", "chmod", "chown",
        "useradd", "userdel", "passwd", "su", "sudo",
    ])
    max_processes: int = 50
    max_memory_mb: int = 4096
    max_cpu_percent: int = 80


@dataclass
class OpenShellPolicy:
    """Complete OpenShell sandbox policy for security scanning agents."""
    name: str = "security-scanner"
    version: str = "1.0"
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    file: FilePolicy = field(default_factory=FilePolicy)
    process: ProcessPolicy = field(default_factory=ProcessPolicy)
    timeout_seconds: int = 3600
    allow_gpu: bool = False

    def set_target(self, target: str):
        """Configure network policy to only allow outbound to the scan target."""
        self.network.allowed_outbound = [target]

    def to_yaml(self) -> str:
        """Export policy as OpenShell YAML configuration."""
        policy = {
            "apiVersion": "openshell.nvidia.com/v1alpha1",
            "kind": "SandboxPolicy",
            "metadata": {
                "name": self.name,
                "version": self.version,
            },
            "spec": {
                "timeout": f"{self.timeout_seconds}s",
                "gpu": {"enabled": self.allow_gpu},
                "network": {
                    "outbound": {
                        "allow": self.network.allowed_outbound,
                        "block": self.network.blocked_outbound,
                        "ports": self.network.allowed_ports,
                        "maxConnections": self.network.max_connections,
                    },
                    "dns": {"enabled": self.network.dns_allowed},
                },
                "filesystem": {
                    "readOnly": self.file.read_allowed,
                    "readWrite": self.file.write_allowed,
                    "blocked": self.file.blocked,
                },
                "process": {
                    "allowedBinaries": self.process.allowed_binaries,
                    "blockedBinaries": self.process.blocked_binaries,
                    "limits": {
                        "maxProcesses": self.process.max_processes,
                        "maxMemoryMB": self.process.max_memory_mb,
                        "maxCPUPercent": self.process.max_cpu_percent,
                    },
                },
            },
        }
        return yaml.dump(policy, default_flow_style=False, sort_keys=False)

    def save(self, path: str | Path):
        """Save policy to a YAML file."""
        Path(path).write_text(self.to_yaml())
        log.info("OpenShell policy saved to %s", path)

    @classmethod
    def for_scan_type(cls, scan_type: str, target: str) -> "OpenShellPolicy":
        """Create a policy tailored to a specific scan type."""
        policy = cls(name=f"scanner-{scan_type}")
        policy.set_target(target)

        if scan_type == "uptime":
            # Uptime checks need minimal permissions
            policy.process.allowed_binaries = [
                "curl", "dig", "ping", "traceroute", "openssl", "nmap",
            ]
            policy.process.max_processes = 10
            policy.timeout_seconds = 300

        elif scan_type == "performance":
            # Performance tests need more resources
            policy.process.max_memory_mb = 8192
            policy.process.max_cpu_percent = 90
            policy.process.allowed_binaries = [
                "curl", "lighthouse", "k6", "node", "python3", "dig", "whatweb",
            ]

        elif scan_type in ("pentest", "full"):
            # Full pentest needs all tools
            policy.timeout_seconds = 7200
            policy.process.max_memory_mb = 8192

        return policy
