"""
Agent d'exécution SSH (Phase 3 – Semaines 9-10).

Responsable de l'exécution sécurisée des scripts de remédiation sur les assets.
Utilise Paramiko pour se connecter aux machines via SSH.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Optional, Dict, Any

import paramiko

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


@dataclass
class ExecutionResult:
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    rollback_executed: bool = False
    rollback_stdout: Optional[str] = None
    rollback_stderr: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "rollback_executed": self.rollback_executed,
            "rollback_stdout": self.rollback_stdout,
            "rollback_stderr": self.rollback_stderr,
        }


class SSHExecutor:
    """
    Exécute un script sur une machine distante via SSH.

    Pour simplifier, on supporte ici:
    - Authentification par mot de passe
    - Exécution bash inline (bash -s)
    """

    def __init__(
        self,
        hostname: str,
        username: str,
        password: Optional[str] = None,
        port: int = 22,
    ):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port

    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        logger.info("Connexion SSH à %s@%s:%s", self.username, self.hostname, self.port)
        client.connect(
            hostname=self.hostname,
            port=self.port,
            username=self.username,
            password=self.password,
            look_for_keys=False,
            allow_agent=False,
            timeout=30,
        )
        return client

    def _run_script(self, client: paramiko.SSHClient, script: str, requires_sudo: bool) -> ExecutionResult:
        cmd = "bash -s"
        if requires_sudo:
            cmd = f"sudo -S {cmd}"

        logger.info("Exécution script sur %s: %s...", self.hostname, cmd)

        stdin, stdout, stderr = client.exec_command(cmd)

        # Si sudo, on envoie le mot de passe sur stdin (non idéal mais suffisant pour MVP)
        if requires_sudo and self.password:
            stdin.write(self.password + "\n")
            stdin.flush()

        # Envoyer le script sur stdin
        stdin.write(script)
        stdin.close()

        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        exit_code = stdout.channel.recv_exit_status()

        logger.info("Script terminé avec code %s", exit_code)

        return ExecutionResult(
            success=exit_code == 0,
            exit_code=exit_code,
            stdout=out,
            stderr=err,
        )

    def execute(
        self,
        script_content: str,
        rollback_script: Optional[str] = None,
        requires_sudo: bool = True,
    ) -> ExecutionResult:
        """
        Exécute le script principal et, en cas d'échec, tente un rollback.
        """
        client: Optional[paramiko.SSHClient] = None

        try:
            client = self._connect()
            result = self._run_script(client, script_content, requires_sudo=requires_sudo)

            if not result.success and rollback_script:
                logger.warning("Script principal échoué, tentative de rollback...")
                rollback_result = self._run_script(client, rollback_script, requires_sudo=requires_sudo)
                result.rollback_executed = True
                result.rollback_stdout = rollback_result.stdout
                result.rollback_stderr = rollback_result.stderr

            return result

        finally:
            if client:
                client.close()


__all__ = ["SSHExecutor", "ExecutionResult"]

