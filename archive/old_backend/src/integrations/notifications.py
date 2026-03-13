"""
Module NotificationManager pour l'Agent IA de Cybersécurité
Gestionnaire de notifications multi-canal (Slack, Email, Teams)
"""

import asyncio
import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum

import aiohttp

from config import get_config
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


# === ÉNUMÉRATIONS ===

class NotificationChannel(str, Enum):
    """Canaux de notification disponibles"""
    SLACK = "slack"
    EMAIL = "email"
    TEAMS = "teams"


class NotificationPriority(str, Enum):
    """Priorités de notification"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


# === CLASSE PRINCIPALE ===

class NotificationManager:
    """Gestionnaire de notifications multi-canal"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config()
        self.is_ready = False
        self.stats = {
            "total_notifications": 0,
            "slack_sent": 0,
            "email_sent": 0,
            "teams_sent": 0,
            "failed_notifications": 0
        }

        # Configuration des canaux
        self.slack_webhook = os.getenv('SLACK_WEBHOOK_URL') or self.config.get('slack_webhook_url')
        self.teams_webhook = os.getenv('TEAMS_WEBHOOK_URL') or self.config.get('teams_webhook_url')
        self.email_config = self._load_email_config()

        # Canaux activés
        self.enabled_channels = self.config.get('notification_channels', ['slack'])
        
        self.is_ready = True
        logger.info(f"NotificationManager initialisé (canaux: {', '.join(self.enabled_channels)})")

    def _load_email_config(self) -> Dict[str, Any]:
        """Charge la configuration email"""
        return {
            "smtp_server": os.getenv('SMTP_SERVER') or self.config.get('smtp_server', 'smtp.gmail.com'),
            "smtp_port": int(os.getenv('SMTP_PORT', '587')),
            "smtp_user": os.getenv('SMTP_USER') or self.config.get('smtp_user'),
            "smtp_password": os.getenv('SMTP_PASSWORD') or self.config.get('smtp_password'),
            "from_email": os.getenv('FROM_EMAIL') or self.config.get('from_email'),
            "to_emails": os.getenv('TO_EMAILS', '').split(',') if os.getenv('TO_EMAILS') else self.config.get('to_emails', [])
        }

    async def notify_critical_vulnerability(self, vuln: Dict[str, Any], scan_id: Optional[str] = None):
        """
        Notifie une vulnérabilité critique
        
        Args:
            vuln: Dictionnaire contenant les détails de la vulnérabilité
            scan_id: ID du scan (optionnel)
        """
        message = self._build_critical_vuln_message(vuln, scan_id)
        
        await self.send_notification(
            title="🚨 Vulnérabilité Critique Détectée",
            message=message,
            priority=NotificationPriority.CRITICAL,
            channels=self.enabled_channels
        )

    async def notify_scan_completed(self, scan_id: str, results: Dict[str, Any]):
        """Notifie la fin d'un scan"""
        vuln_count = results.get('total_vulnerabilities', 0)
        critical_count = results.get('critical_vulnerabilities', 0)
        
        message = f"""
✅ Scan terminé: {scan_id}

📊 Résultats:
• Vulnérabilités détectées: {vuln_count}
• Vulnérabilités critiques: {critical_count}
• Scripts générés: {results.get('scripts_generated', 0)}

Consultez le dashboard pour plus de détails.
"""
        
        await self.send_notification(
            title="Scan Terminé",
            message=message,
            priority=NotificationPriority.NORMAL,
            channels=self.enabled_channels
        )

    async def notify_scan_failed(self, scan_id: str, error: str):
        """Notifie l'échec d'un scan"""
        message = f"""
❌ Scan échoué: {scan_id}

Erreur: {error}

Vérifiez les logs pour plus de détails.
"""
        
        await self.send_notification(
            title="Erreur de Scan",
            message=message,
            priority=NotificationPriority.HIGH,
            channels=self.enabled_channels
        )

    async def notify_system_error(self, error_type: str, error_message: str):
        """Notifie une erreur système"""
        message = f"""
⚠️ Erreur Système

Type: {error_type}
Message: {error_message}

Action requise immédiatement.
"""
        
        await self.send_notification(
            title="Erreur Système",
            message=message,
            priority=NotificationPriority.CRITICAL,
            channels=self.enabled_channels
        )

    async def send_notification(
            self,
            title: str,
            message: str,
            priority: NotificationPriority = NotificationPriority.NORMAL,
            channels: Optional[List[str]] = None
    ):
        """
        Envoie une notification sur les canaux spécifiés
        
        Args:
            title: Titre de la notification
            message: Message de la notification
            priority: Priorité de la notification
            channels: Liste des canaux (None = tous les canaux activés)
        """
        if channels is None:
            channels = self.enabled_channels

        self.stats["total_notifications"] += 1

        # Envoyer sur tous les canaux en parallèle
        tasks = []
        
        if NotificationChannel.SLACK.value in channels:
            tasks.append(self.send_slack(title, message, priority))
        
        if NotificationChannel.EMAIL.value in channels:
            tasks.append(self.send_email(title, message, priority))
        
        if NotificationChannel.TEAMS.value in channels:
            tasks.append(self.send_teams(title, message, priority))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Compter les échecs
            for result in results:
                if isinstance(result, Exception):
                    self.stats["failed_notifications"] += 1
                    logger.error(f"Erreur envoi notification: {result}")

    async def send_slack(self, title: str, message: str, priority: NotificationPriority):
        """Envoie une notification Slack"""
        if not self.slack_webhook:
            logger.warning("Slack webhook non configuré")
            return

        # Couleur selon la priorité
        color_map = {
            NotificationPriority.LOW: "#36a64f",      # Vert
            NotificationPriority.NORMAL: "#439fe0",   # Bleu
            NotificationPriority.HIGH: "#ff9900",     # Orange
            NotificationPriority.CRITICAL: "#ff0000"  # Rouge
        }

        payload = {
            "username": "CyberSec AI",
            "icon_emoji": ":shield:",
            "attachments": [
                {
                    "color": color_map.get(priority, "#439fe0"),
                    "title": title,
                    "text": message,
                    "footer": "Agent IA de Cybersécurité",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.slack_webhook, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        self.stats["slack_sent"] += 1
                        logger.info("✅ Notification Slack envoyée")
                    else:
                        logger.error(f"Erreur Slack: {response.status}")
        except Exception as e:
            logger.error(f"Erreur envoi Slack: {e}")
            raise

    async def send_email(self, title: str, message: str, priority: NotificationPriority):
        """Envoie un email"""
        if not self.email_config.get('smtp_user') or not self.email_config.get('to_emails'):
            logger.warning("Configuration email incomplète")
            return

        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            msg = MIMEMultipart()
            msg['From'] = self.email_config['from_email']
            msg['To'] = ', '.join(self.email_config['to_emails'])
            msg['Subject'] = f"[{priority.value.upper()}] {title}"

            body = f"""
{message}

---
Envoyé par Agent IA de Cybersécurité
"""
            msg.attach(MIMEText(body, 'plain'))

            # Envoyer l'email (synchrone pour simplifier)
            # En production, utiliser un service async comme aiosmtplib
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['smtp_user'], self.email_config['smtp_password'])
            server.send_message(msg)
            server.quit()

            self.stats["email_sent"] += 1
            logger.info("✅ Email envoyé")

        except Exception as e:
            logger.error(f"Erreur envoi email: {e}")
            raise

    async def send_teams(self, title: str, message: str, priority: NotificationPriority):
        """Envoie une notification Microsoft Teams"""
        if not self.teams_webhook:
            logger.warning("Teams webhook non configuré")
            return

        # Couleur selon la priorité
        color_map = {
            NotificationPriority.LOW: "00FF00",      # Vert
            NotificationPriority.NORMAL: "0078D4",   # Bleu
            NotificationPriority.HIGH: "FF8C00",     # Orange
            NotificationPriority.CRITICAL: "FF0000"  # Rouge
        }

        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color_map.get(priority, "0078D4"),
            "summary": title,
            "sections": [
                {
                    "activityTitle": title,
                    "activitySubtitle": "Agent IA de Cybersécurité",
                    "text": message,
                    "markdown": True
                }
            ]
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.teams_webhook,
                    json=card,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        self.stats["teams_sent"] += 1
                        logger.info("✅ Notification Teams envoyée")
                    else:
                        logger.error(f"Erreur Teams: {response.status}")
        except Exception as e:
            logger.error(f"Erreur envoi Teams: {e}")
            raise

    def _build_critical_vuln_message(self, vuln: Dict[str, Any], scan_id: Optional[str] = None) -> str:
        """Construit le message pour une vulnérabilité critique"""
        cve_id = vuln.get('vulnerability_id', 'N/A')
        severity = vuln.get('severity', 'UNKNOWN')
        cvss_score = vuln.get('cvss_score', 0)
        service = vuln.get('affected_service', 'Unknown')
        
        message = f"""
🚨 VULNÉRABILITÉ CRITIQUE DÉTECTÉE

CVE: {cve_id}
Sévérité: {severity}
CVSS: {cvss_score}
Service: {service}

Action requise immédiatement !
"""
        
        if scan_id:
            message += f"\nScan ID: {scan_id}"
        
        return message

    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques"""
        return self.stats.copy()

