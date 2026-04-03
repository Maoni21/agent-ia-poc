"""
Gestion des connexions SSH pour l'exécution automatisée de scripts de remédiation.

Utilise Paramiko pour les connexions SSH avec support mot de passe et clé privée.
"""

from __future__ import annotations

import io
import logging
from typing import Optional, Tuple

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class SSHConnectionError(Exception):
    """Erreur de connexion SSH."""
    pass


class SSHCommandError(Exception):
    """Erreur lors de l'exécution d'une commande SSH."""
    pass


class SSHManager:
    """
    Gestionnaire de connexions SSH.

    Supporte:
    - Authentification par mot de passe
    - Authentification par clé privée RSA/DSA/ECDSA/Ed25519
    """

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        timeout: int = 10,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.private_key_str = private_key
        self.timeout = timeout
        self._client: Optional["paramiko.SSHClient"] = None

    def connect(self) -> None:
        """Établit la connexion SSH."""
        if not PARAMIKO_AVAILABLE:
            raise SSHConnectionError(
                "Paramiko n'est pas installé. Exécutez: pip install paramiko"
            )

        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            connect_kwargs = dict(
                hostname=self.host,
                port=self.port,
                username=self.username,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )

            if self.private_key_str:
                # Authentification par clé privée
                pkey = self._load_private_key(self.private_key_str)
                connect_kwargs["pkey"] = pkey
            elif self.password:
                connect_kwargs["password"] = self.password
            else:
                raise SSHConnectionError("Aucun moyen d'authentification fourni (password ou private_key)")

            self._client.connect(**connect_kwargs)
            logger.info("SSH: Connexion établie vers %s@%s:%d", self.username, self.host, self.port)

        except paramiko.AuthenticationException as e:
            raise SSHConnectionError(f"Authentification SSH échouée: {e}")
        except paramiko.SSHException as e:
            raise SSHConnectionError(f"Erreur SSH: {e}")
        except OSError as e:
            raise SSHConnectionError(f"Impossible de joindre {self.host}:{self.port} - {e}")
        except Exception as e:
            raise SSHConnectionError(f"Erreur de connexion inattendue: {e}")

    def _load_private_key(self, key_str: str) -> "paramiko.PKey":
        """Charge une clé privée depuis une chaîne de caractères."""
        key_file = io.StringIO(key_str)
        key_types = [
            paramiko.RSAKey,
            paramiko.DSSKey,
            paramiko.ECDSAKey,
            paramiko.Ed25519Key,
        ]
        for key_type in key_types:
            try:
                key_file.seek(0)
                return key_type.from_private_key(key_file)
            except Exception:
                continue
        raise SSHConnectionError("Format de clé privée non reconnu (RSA, DSA, ECDSA, Ed25519 supportés)")

    def execute_command(
        self,
        command: str,
        timeout: int = 300,
        use_sudo: bool = False,
    ) -> Tuple[str, str, int]:
        """
        Exécute une commande via SSH.

        Args:
            command: Commande shell à exécuter.
            timeout: Délai maximum d'exécution en secondes.
            use_sudo: Ajoute 'sudo' en préfixe si True.

        Returns:
            Tuple (stdout, stderr, exit_code).
        """
        if not self._client:
            raise SSHConnectionError("Non connecté. Appelez connect() d'abord.")

        if use_sudo and not command.startswith("sudo "):
            command = f"sudo {command}"

        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            stdout_text = stdout.read().decode("utf-8", errors="replace")
            stderr_text = stderr.read().decode("utf-8", errors="replace")
            logger.debug(
                "SSH: commande='%s' exit_code=%d stdout_len=%d stderr_len=%d",
                command[:80],
                exit_code,
                len(stdout_text),
                len(stderr_text),
            )
            return stdout_text, stderr_text, exit_code
        except paramiko.SSHException as e:
            raise SSHCommandError(f"Erreur SSH lors de l'exécution: {e}")
        except Exception as e:
            raise SSHCommandError(f"Erreur inattendue lors de l'exécution: {e}")

    def test_connection(self) -> dict:
        """
        Teste la connexion SSH et vérifie les privilèges sudo.

        Returns:
            Dict avec les clés 'connected', 'sudo_available', 'error'.
        """
        result = {
            "connected": False,
            "sudo_available": False,
            "whoami": None,
            "error": None,
        }
        try:
            self.connect()
            result["connected"] = True

            stdout, stderr, exit_code = self.execute_command("whoami")
            if exit_code == 0:
                result["whoami"] = stdout.strip()

            # Test sudo non-interactif (-n : ne pas demander de mot de passe)
            stdout_sudo, _, exit_sudo = self.execute_command("sudo -n true 2>/dev/null", timeout=5)
            result["sudo_available"] = (exit_sudo == 0)

        except SSHConnectionError as e:
            result["error"] = str(e)
        except Exception as e:
            result["error"] = f"Erreur inattendue: {e}"
        finally:
            self.disconnect()

        return result

    def disconnect(self) -> None:
        """Ferme la connexion SSH."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            finally:
                self._client = None
                logger.debug("SSH: Connexion fermée vers %s", self.host)

    def __enter__(self) -> "SSHManager":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()


__all__ = ["SSHManager", "SSHConnectionError", "SSHCommandError"]
