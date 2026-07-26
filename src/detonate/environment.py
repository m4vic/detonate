"""Pre-flight environment checks.

detonate executes UNTRUSTED code, so it must never run without a real sandbox.
That makes Docker a hard requirement: every scan needs a container to detonate
inside. This module answers one question — "is Docker ready?" — before any scan
is allowed to start.

Design choice: we check by shelling out to the `docker` CLI rather than importing
a Docker SDK. A liveness check needs zero dependencies, behaves identically on
every OS, and keeps M0 install-free. The heavier docker-py SDK arrives later,
only when we actually orchestrate containers (M2).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class DockerStatus:
    """Result of the Docker pre-flight check."""

    installed: bool          # is the `docker` binary on PATH?
    running: bool            # is the daemon actually responding?
    detail: str              # human-readable status or the failure reason

    @property
    def ready(self) -> bool:
        """detonate can only sandbox when Docker is both installed AND running."""
        return self.installed and self.running


def check_docker(timeout_s: int = 15) -> DockerStatus:
    """Return whether Docker is installed and its daemon is responding.

    Two separate failure modes, reported distinctly so the user knows what to fix:
      1. binary missing  -> Docker isn't installed at all
      2. daemon down     -> Docker is installed but not started (or no permission)
    """
    # 1. Is the docker binary even on PATH?
    if shutil.which("docker") is None:
        return DockerStatus(installed=False, running=False,
                            detail="docker binary not found on PATH")

    # 2. Is the daemon up? `docker info` returns non-zero if the daemon is down.
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return DockerStatus(installed=True, running=False,
                            detail=f"docker present but not responding: {exc}")

    if proc.returncode != 0:
        # Surface docker's own last line of stderr — usually the clearest reason
        # (e.g. "Cannot connect to the Docker daemon", "permission denied").
        stderr = proc.stderr.strip()
        reason = stderr.splitlines()[-1] if stderr else "docker daemon not running"
        return DockerStatus(installed=True, running=False, detail=reason)

    return DockerStatus(installed=True, running=True, detail="docker ready")
