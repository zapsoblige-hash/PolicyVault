"""Spawn the REAL PolicyVault Node server for the Python integration tests.

There is no mock server anywhere in this suite. ``python/tests/_server_boot.js``
starts ``server/src/server.js`` ``createServer(config)`` from THIS worktree on
an ephemeral loopback port with the JSON backend, seeds one v0.4 vault
manifest, and mints two machine bearer credentials through a real hosted
wallet session. The Python tests then speak real HTTP to that real handler.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
BOOT_SCRIPT = os.path.join(HERE, "_server_boot.js")

# The build path compiles a real covenant via a subprocess; first boot on a
# cold machine is not instant.
BOOT_TIMEOUT_SECONDS = float(os.environ.get("POLICYVAULT_PY_BOOT_TIMEOUT", "180"))


class ServerUnavailable(RuntimeError):
    """The Node server could not be started (missing node, missing kaspa wasm...)."""


class LiveServer:
    """A running PolicyVault server plus the credentials the tests use."""

    def __init__(self, process: subprocess.Popen, handshake: dict, stderr_lines: list) -> None:
        self._process = process
        self._stderr_lines = stderr_lines
        self.info = handshake

    # handshake fields the tests read
    @property
    def base_url(self) -> str:
        return self.info["baseUrl"]

    @property
    def full_token(self) -> str:
        return self.info["fullToken"]

    @property
    def read_token(self) -> str:
        return self.info["readToken"]

    @property
    def vault_id(self) -> str:
        return self.info["vaultId"]

    @property
    def agent_address(self) -> str:
        return self.info["agentAddress"]

    @property
    def owner_address(self) -> str:
        return self.info["ownerAddress"]

    @property
    def agent_pk(self) -> str:
        return self.info["agentPk"]

    @property
    def recipient_pk(self) -> str:
        return self.info["recipientPk"]

    @property
    def network_id(self) -> str:
        return self.info["networkId"]

    @property
    def encoder_available(self) -> bool:
        """Whether the REAL Rust call encoder the v0.4 builder shells out to
        is present. Absent = an ENVIRONMENT gap, never a client defect."""
        return bool(self.info.get("encoderAvailable"))

    @property
    def encoder_remedy(self) -> str:
        return (
            f"the v0.4 builder needs {self.info.get('encoderPath')}. Build it with "
            "`cd tests/vm && cargo build --bin pv_call_encoder` (in a git WORKTREE Cargo "
            "cannot resolve the sibling ../../../silverscript path, so link an existing "
            "build into tests/vm/target/debug/ instead)."
        )

    def stderr(self) -> str:
        return "".join(self._stderr_lines)

    def stop(self) -> None:
        if self._process.poll() is None:
            try:
                if self._process.stdin:
                    self._process.stdin.close()  # EOF -> graceful shutdown
            except OSError:
                pass
            try:
                self._process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._process.terminate()
                try:
                    self._process.wait(timeout=10)
                except subprocess.TimeoutExpired:  # pragma: no cover - last resort
                    self._process.kill()
        for stream in (self._process.stdout, self._process.stderr, self._process.stdin):
            try:
                if stream:
                    stream.close()
            except OSError:
                pass


def _node_binary() -> Optional[str]:
    return shutil.which("node")


def start_server() -> LiveServer:
    """Boot the server, or raise ``ServerUnavailable`` with the reason."""
    node = _node_binary()
    if node is None:
        raise ServerUnavailable("node is not on PATH")
    if not os.path.exists(BOOT_SCRIPT):
        raise ServerUnavailable(f"missing bootstrap script {BOOT_SCRIPT}")

    env = dict(os.environ)
    # The bootstrap passes every config value explicitly; strip anything
    # ambient that could redirect this test at a real deployment.
    for name in (
        "POLICYVAULT_ALLOW_MAINNET",
        "KASPA_NETWORK_ID",
        "KASPA_RPC_URL",
        "POLICYVAULT_PERSISTENCE",
        "POLICYVAULT_API_PORT",
        "POLICYVAULT_API_URL",
        "POLICYVAULT_API_TOKEN",
    ):
        env.pop(name, None)

    process = subprocess.Popen(
        [node, BOOT_SCRIPT],
        cwd=REPO_ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        bufsize=1,
    )

    stderr_lines: list = []

    def drain_stderr() -> None:
        assert process.stderr is not None
        for line in process.stderr:
            stderr_lines.append(line)

    threading.Thread(target=drain_stderr, daemon=True).start()

    handshake: Optional[dict] = None
    deadline = time.monotonic() + BOOT_TIMEOUT_SECONDS
    assert process.stdout is not None
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if line == "":
            break
        if line.startswith("PVBOOT "):
            handshake = json.loads(line[len("PVBOOT ") :])
            break

    if handshake is None:
        process.kill()
        detail = "".join(stderr_lines).strip() or "no output"
        raise ServerUnavailable(f"bootstrap did not hand back a server: {detail}")

    return LiveServer(process, handshake, stderr_lines)


def client_package_on_path() -> None:
    """Make ``policyvault_client`` importable from the source tree."""
    package_parent = os.path.abspath(os.path.join(HERE, ".."))
    if package_parent not in sys.path:
        sys.path.insert(0, package_parent)
