"""
Module Collector pour l'Agent IA de Cybersécurité

Ce module gère la collecte des vulnérabilités via différents outils de scan :
- Nmap avec scripts NSE de détection de vulnérabilités
- Parsing de rapports existants (OpenVAS, Tenable, etc.)
- Intégration avec des APIs de vulnérabilités (NVD, CVE)

Fonctionnalités :
- Scan Nmap automatisé avec scripts de vulnérabilités
- Détection de services et versions
- Corrélation avec bases CVE/NVD
- Support de différents formats d'import
- Gestion des timeouts et retry
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, asdict
import re

import nmap
import requests

from config import get_config, get_nmap_config, VULNERABILITY_DB_PATH
from src.utils.logger import setup_logger
from src.utils.validators import validate_ip_address, validate_domain
from src.database.database import Database
from .exceptions import CollectorException, CoreErrorCodes, ERROR_MESSAGES

# Configuration du logging
logger = setup_logger(__name__)


# === MODÈLES DE DONNÉES ===

@dataclass
class ServiceInfo:
    """Informations sur un service détecté"""
    port: int
    protocol: str
    service_name: str
    version: str
    state: str
    banner: Optional[str] = None
    extra_info: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VulnerabilityInfo:
    """Informations sur une vulnérabilité détectée"""
    vulnerability_id: str
    name: str
    severity: str
    cvss_score: Optional[float]
    description: str
    affected_service: str
    affected_port: int
    cve_ids: List[str]
    references: List[str]
    detection_method: str
    confidence: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Résultat complet d'un scan"""
    scan_id: str
    target: str
    scan_type: str
    started_at: datetime
    completed_at: datetime
    duration: float

    # Résultats techniques
    host_status: str
    open_ports: List[int]
    services: List[ServiceInfo]
    vulnerabilities: List[VulnerabilityInfo]

    # Métadonnées du scan
    scan_parameters: Dict[str, Any]
    nmap_version: Optional[str] = None
    scan_stats: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['services'] = [service.to_dict() for service in self.services]
        result['vulnerabilities'] = [vuln.to_dict() for vuln in self.vulnerabilities]
        result['started_at'] = self.started_at.isoformat()
        result['completed_at'] = self.completed_at.isoformat()
        return result


# === CLASSE PRINCIPALE ===

class Collector:
    """
    Collecteur de vulnérabilités

    Cette classe orchestre la collecte de vulnérabilités via différents
    outils et sources, principalement Nmap avec ses scripts NSE.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialise le collecteur

        Args:
            config: Configuration personnalisée (optionnel)
        """
        self.config = config or get_config()
        self.nmap_config = get_nmap_config()

        # État du collecteur
        self.is_ready = False
        self.nm = None

        # Base de données pour historique
        self.db = Database()

        # Cache des vulnérabilités connues
        self.vulnerability_db = self._load_vulnerability_database()

        # Statistiques
        self.stats = {
            "total_scans": 0,
            "successful_scans": 0,
            "failed_scans": 0,
            "total_vulnerabilities_found": 0,
            "average_scan_time": 0.0
        }

        # Initialiser Nmap
        self._initialize_nmap()

    def _initialize_nmap(self):
        """Initialise le scanner Nmap"""
        try:
            # Vérifier que Nmap est installé
            result = subprocess.run(['nmap', '--version'],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise CollectorException(
                    "Nmap non trouvé ou non fonctionnel",
                    CoreErrorCodes.NMAP_NOT_FOUND
                )

            # Extraire la version
            version_match = re.search(r'Nmap version (\d+\.\d+)', result.stdout)
            nmap_version = version_match.group(1) if version_match else "Unknown"

            # Initialiser python-nmap
            self.nm = nmap.PortScanner()

            self.is_ready = True
            logger.info(f"Nmap initialisé - version {nmap_version}")

        except subprocess.TimeoutExpired:
            raise CollectorException(
                "Timeout lors de la vérification de Nmap",
                CoreErrorCodes.NMAP_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Erreur initialisation Nmap: {e}")
            raise CollectorException(
                f"Impossible d'initialiser Nmap: {str(e)}",
                CoreErrorCodes.NMAP_NOT_FOUND
            )

    def _load_vulnerability_database(self) -> Dict[str, Any]:
        """Charge la base de données des vulnérabilités"""
        try:
            if Path(VULNERABILITY_DB_PATH).exists():
                with open(VULNERABILITY_DB_PATH, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                logger.warning(f"Base de vulnérabilités non trouvée: {VULNERABILITY_DB_PATH}")
                return {}
        except Exception as e:
            logger.error(f"Erreur chargement base vulnérabilités: {e}")
            return {}

    async def scan_target(
            self,
            target: str,
            scan_type: str = "full",
            custom_args: Optional[str] = None,
            timeout: int = 300,
            progress_callback: Optional[Callable[[int], None]] = None
    ) -> ScanResult:
        """
        Lance un scan de vulnérabilités sur une cible

        Args:
            target: IP ou hostname cible
            scan_type: Type de scan (quick, full, stealth, aggressive)
            custom_args: Arguments Nmap personnalisés
            timeout: Timeout en secondes
            progress_callback: Fonction de callback pour la progression

        Returns:
            ScanResult: Résultats complets du scan

        Raises:
            CollectorException: Si le scan échoue
        """
        if not self.is_ready:
            raise CollectorException(
                "Collecteur non initialisé",
                CoreErrorCodes.MODULE_NOT_READY
            )

        # Valider la cible
        if not self._validate_target(target):
            raise CollectorException(
                f"Cible invalide: {target}",
                CoreErrorCodes.SCAN_TARGET_INVALID
            )

        scan_id = f"scan_{int(time.time())}"
        start_time = datetime.utcnow()

        try:
            logger.info(f"Début scan {scan_id} - cible: {target}, type: {scan_type}")

            if progress_callback:
                progress_callback(10)

            # Préparer les arguments Nmap
            nmap_args = self._prepare_nmap_args(scan_type, custom_args)

            if progress_callback:
                progress_callback(20)

            # Exécuter le scan principal
            scan_data = await self._execute_nmap_scan(target, nmap_args, timeout, progress_callback)

            if progress_callback:
                progress_callback(70)

            # Parser les résultats
            parsed_results = self._parse_nmap_results(scan_data, target)

            if progress_callback:
                progress_callback(85)

            # Enrichir avec la base de vulnérabilités
            enriched_vulns = self._enrich_vulnerabilities(parsed_results['vulnerabilities'])

            if progress_callback:
                progress_callback(95)

            # Créer le résultat final
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()

            result = ScanResult(
                scan_id=scan_id,
                target=target,
                scan_type=scan_type,
                started_at=start_time,
                completed_at=end_time,
                duration=duration,
                host_status=parsed_results['host_status'],
                open_ports=parsed_results['open_ports'],
                services=parsed_results['services'],
                vulnerabilities=enriched_vulns,
                scan_parameters={
                    'nmap_args': nmap_args,
                    'timeout': timeout,
                    'scan_type': scan_type
                },
                nmap_version=self._get_nmap_version(),
                scan_stats=parsed_results.get('stats')
            )

            # Sauvegarder le résultat
            await self._save_scan_result(result)

            # Mettre à jour les statistiques
            self._update_stats(True, duration, len(enriched_vulns))

            if progress_callback:
                progress_callback(100)

            logger.info(f"Scan terminé: {scan_id} - {len(enriched_vulns)} vulnérabilités trouvées")
            return result

        except asyncio.TimeoutError:
            self._update_stats(False, timeout, 0)
            raise CollectorException(
                f"Timeout du scan après {timeout}s",
                CoreErrorCodes.SCAN_TIMEOUT
            )
        except Exception as e:
            self._update_stats(False, (datetime.utcnow() - start_time).total_seconds(), 0)
            logger.error(f"Erreur scan {scan_id}: {e}")

            if isinstance(e, CollectorException):
                raise
            else:
                raise CollectorException(
                    f"Erreur lors du scan: {str(e)}",
                    CoreErrorCodes.SCAN_FAILED if "scan" in str(e).lower() else CoreErrorCodes.CORE_INIT_ERROR
                )

    def _validate_target(self, target: str) -> bool:
        """Valide la cible du scan"""
        try:
            # Essayer validation IP
            if validate_ip_address(target):
                return True

            # Essayer validation domaine
            if validate_domain(target):
                return True

            return False

        except Exception:
            return False

    def _prepare_nmap_args(self, scan_type: str, custom_args: Optional[str]) -> str:
        """Prépare les arguments Nmap selon le type de scan"""

        if custom_args:
            return custom_args

        # Configuration par type de scan
        scan_configs = {
            "quick": "-sV -T4 --top-ports 1000 --script vuln",
            "full": "-sV -sC -T4 --script vuln,safe",
            "stealth": "-sS -sV -T2 --script vuln",
            "aggressive": "-sV -sC -A -T4 --script vuln,exploit",
            "custom": self.nmap_config.get("args", "-sV -sC --script vuln")
        }

        base_args = scan_configs.get(scan_type, scan_configs["full"])

        # Ajouter les arguments de timing et timeout
        timing = self.nmap_config.get("timing", "T4")
        if timing not in base_args:
            base_args += f" -{timing}"

        # Ajouter les timeouts
        host_timeout = self.nmap_config.get("host_timeout", "5m")
        script_timeout = self.nmap_config.get("script_timeout", "2m")

        base_args += f" --host-timeout {host_timeout} --script-timeout {script_timeout}"

        return base_args

    async def _execute_nmap_scan(
            self,
            target: str,
            nmap_args: str,
            timeout: int,
            progress_callback: Optional[Callable[[int], None]] = None
    ) -> Dict[str, Any]:
        """Exécute le scan Nmap de manière asynchrone"""

        def run_scan():
            """Fonction synchrone pour le scan"""
            try:
                logger.debug(f"Commande Nmap: nmap {nmap_args} {target}")

                # Callback de progression pour Nmap
                def nmap_progress(host, state):
                    if progress_callback and state.get('progress'):
                        # Mapper la progression Nmap (20-70%)
                        nmap_progress_pct = float(state['progress'])
                        overall_progress = 20 + (nmap_progress_pct * 0.5)
                        progress_callback(int(overall_progress))

                # Exécuter le scan
                self.nm.scan(
                    hosts=target,
                    arguments=nmap_args
                )

                return self.nm.all_hosts()

            except Exception as e:
                logger.error(f"Erreur exécution Nmap: {e}")
                raise

        # Exécuter de manière asynchrone avec timeout
        try:
            loop = asyncio.get_event_loop()
            hosts = await asyncio.wait_for(
                loop.run_in_executor(None, run_scan),
                timeout=timeout
            )

            return {
                'hosts': hosts,
                'scan_info': self.nm.scaninfo(),
                'command_line': self.nm.command_line()
            }

        except asyncio.TimeoutError:
            logger.error(f"Timeout Nmap après {timeout}s")
            raise

    def _parse_nmap_results(self, scan_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Parse les résultats du scan Nmap"""

        hosts = scan_data.get('hosts', [])
        if not hosts or target not in hosts:
            return {
                'host_status': 'down',
                'open_ports': [],
                'services': [],
                'vulnerabilities': [],
                'stats': scan_data.get('scan_info', {})
            }

        # Informations sur l'hôte
        host_info = self.nm[target]
        host_status = host_info.state()

        # Services et ports ouverts
        services = []
        open_ports = []

        for protocol in host_info.all_protocols():
            ports = host_info[protocol].keys()

            for port in ports:
                port_info = host_info[protocol][port]

                if port_info['state'] == 'open':
                    open_ports.append(port)

                    service = ServiceInfo(
                        port=port,
                        protocol=protocol,
                        service_name=port_info.get('name', 'unknown'),
                        version=port_info.get('version', ''),
                        state=port_info['state'],
                        banner=port_info.get('product', ''),
                        extra_info=port_info.get('extrainfo', '')
                    )
                    services.append(service)

        # Vulnérabilités détectées par les scripts NSE
        vulnerabilities = self._extract_vulnerabilities_from_scripts(host_info)

        return {
            'host_status': host_status,
            'open_ports': sorted(open_ports),
            'services': services,
            'vulnerabilities': vulnerabilities,
            'stats': scan_data.get('scan_info', {})
        }

    def _extract_vulnerabilities_from_scripts(self, host_info) -> List[VulnerabilityInfo]:
        """Extrait les vulnérabilités des scripts NSE"""
        vulnerabilities = []

        # Parcourir tous les ports et leurs scripts
        for protocol in host_info.all_protocols():
            ports = host_info[protocol].keys()

            for port in ports:
                port_info = host_info[protocol][port]

                # Scripts exécutés sur ce port
                if 'script' in port_info:
                    for script_name, script_output in port_info['script'].items():
                        # Détecter les vulnérabilités selon le script
                        vulns = self._parse_script_vulnerabilities(
                            script_name,
                            script_output,
                            port,
                            port_info.get('name', 'unknown')
                        )
                        vulnerabilities.extend(vulns)

        # Scripts au niveau de l'hôte
        if hasattr(host_info, 'hostscript'):
            for script in host_info.hostscript():
                script_name = script['id']
                script_output = script['output']

                vulns = self._parse_script_vulnerabilities(
                    script_name, script_output, 0, 'host'
                )
                vulnerabilities.extend(vulns)

        return vulnerabilities

    def _parse_script_vulnerabilities(
            self,
            script_name: str,
            script_output: str,
            port: int,
            service: str
    ) -> List[VulnerabilityInfo]:
        """Parse les vulnérabilités d'un script NSE spécifique"""
        vulnerabilities = []

        # Patterns de détection par script
        script_patterns = {
            'ssl-heartbleed': {
                'pattern': r'VULNERABLE.*Heartbleed',
                'vuln_id': 'CVE-2014-0160',
                'name': 'OpenSSL Heartbleed',
                'severity': 'HIGH'
            },
            'ssl-poodle': {
                'pattern': r'VULNERABLE.*POODLE',
                'vuln_id': 'CVE-2014-3566',
                'name': 'SSL POODLE',
                'severity': 'MEDIUM'
            },
            'smb-vuln-ms17-010': {
                'pattern': r'VULNERABLE.*MS17-010',
                'vuln_id': 'CVE-2017-0144',
                'name': 'EternalBlue SMB',
                'severity': 'CRITICAL'
            },
            'http-vuln-cve2017-5638': {
                'pattern': r'VULNERABLE.*CVE-2017-5638',
                'vuln_id': 'CVE-2017-5638',
                'name': 'Apache Struts2 RCE',
                'severity': 'CRITICAL'
            },
            'ftp-anon': {
                'pattern': r'Anonymous FTP login allowed',
                'vuln_id': 'FTP-ANON',
                'name': 'Anonymous FTP Access',
                'severity': 'MEDIUM'
            }
        }

        # Recherche générique de CVE dans l'output
        cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', script_output, re.IGNORECASE)

        # Vérifier les patterns connus
        if script_name in script_patterns:
            pattern_info = script_patterns[script_name]

            if re.search(pattern_info['pattern'], script_output, re.IGNORECASE):
                vuln = VulnerabilityInfo(
                    vulnerability_id=pattern_info['vuln_id'],
                    name=pattern_info['name'],
                    severity=pattern_info['severity'],
                    cvss_score=self._get_cvss_score(pattern_info['vuln_id']),
                    description=self._extract_description(script_output),
                    affected_service=service,
                    affected_port=port,
                    cve_ids=[pattern_info['vuln_id']] if pattern_info['vuln_id'].startswith('CVE') else [],
                    references=self._extract_references(script_output),
                    detection_method=f"nmap-script:{script_name}",
                    confidence="HIGH"
                )
                vulnerabilities.append(vuln)

        # Traiter les CVE trouvés génériquement
        for cve_id in cve_matches:
            if not any(v.vulnerability_id == cve_id for v in vulnerabilities):
                vuln = VulnerabilityInfo(
                    vulnerability_id=cve_id,
                    name=f"Vulnerability {cve_id}",
                    severity=self._estimate_severity(script_output),
                    cvss_score=self._get_cvss_score(cve_id),
                    description=self._extract_description(script_output),
                    affected_service=service,
                    affected_port=port,
                    cve_ids=[cve_id],
                    references=self._extract_references(script_output),
                    detection_method=f"nmap-script:{script_name}",
                    confidence="MEDIUM"
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _get_cvss_score(self, vuln_id: str) -> Optional[float]:
        """Récupère le score CVSS depuis la base de vulnérabilités"""
        if not self.vulnerability_db:
            return None

        # Chercher dans les vulnérabilités connues
        known_vulns = self.vulnerability_db.get('known_vulnerabilities', [])
        for vuln in known_vulns:
            if vuln.get('id') == vuln_id or vuln_id in vuln.get('cve_ids', []):
                return vuln.get('cvss_score')

        return None

    def _extract_description(self, script_output: str) -> str:
        """Extrait une description de la vulnérabilité"""
        # Prendre les premières lignes significatives
        lines = script_output.split('\n')
        description_lines = []

        for line in lines:
            line = line.strip()
            if line and not line.startswith('|') and len(line) > 20:
                description_lines.append(line)
                if len(description_lines) >= 2:  # Limiter à 2 lignes
                    break

        return ' '.join(description_lines) if description_lines else "Vulnérabilité détectée par scan"

    def _extract_references(self, script_output: str) -> List[str]:
        """Extrait les références URL du script output"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, script_output)
        return list(set(urls))  # Éliminer les doublons

    def _estimate_severity(self, script_output: str) -> str:
        """Estime la gravité basée sur les mots-clés"""
        output_lower = script_output.lower()

        if any(keyword in output_lower for keyword in ['critical', 'remote code execution', 'rce', 'buffer overflow']):
            return 'CRITICAL'
        elif any(keyword in output_lower for keyword in ['high', 'privilege escalation', 'authentication bypass']):
            return 'HIGH'
        elif any(keyword in output_lower for keyword in ['medium', 'information disclosure', 'denial of service']):
            return 'MEDIUM'
        else:
            return 'LOW'

    def _enrich_vulnerabilities(self, vulnerabilities: List[VulnerabilityInfo]) -> List[VulnerabilityInfo]:
        """Enrichit les vulnérabilités avec des données supplémentaires"""

        for vuln in vulnerabilities:
            # Enrichir depuis la base de vulnérabilités
            if self.vulnerability_db:
                known_vulns = self.vulnerability_db.get('known_vulnerabilities', [])

                for known_vuln in known_vulns:
                    if (vuln.vulnerability_id == known_vuln.get('id') or
                            vuln.vulnerability_id in known_vuln.get('cve_ids', [])):

                        # Mettre à jour avec les infos connues
                        if not vuln.cvss_score:
                            vuln.cvss_score = known_vuln.get('cvss_score')

                        if vuln.name.startswith('Vulnerability '):
                            vuln.name = known_vuln.get('name', vuln.name)

                        if not vuln.references:
                            vuln.references = known_vuln.get('references', [])

                        break

        return vulnerabilities

    def _get_nmap_version(self) -> Optional[str]:
        """Récupère la version de Nmap"""
        try:
            result = subprocess.run(['nmap', '--version'],
                                    capture_output=True, text=True, timeout=5)
            version_match = re.search(r'Nmap version (\d+\.\d+)', result.stdout)
            return version_match.group(1) if version_match else None
        except Exception:
            return None

    async def _save_scan_result(self, result: ScanResult):
        """Sauvegarde le résultat du scan dans la base de données"""
        try:
            # TODO: Implémenter la sauvegarde complète en base
            logger.debug(f"Sauvegarde scan: {result.scan_id}")
        except Exception as e:
            logger.warning(f"Erreur sauvegarde scan: {e}")

    def _update_stats(self, success: bool, duration: float, vuln_count: int):
        """Met à jour les statistiques du collecteur"""
        self.stats["total_scans"] += 1

        if success:
            self.stats["successful_scans"] += 1
            self.stats["total_vulnerabilities_found"] += vuln_count
        else:
            self.stats["failed_scans"] += 1

        # Moyenne mobile simple
        current_avg = self.stats["average_scan_time"]
        total = self.stats["total_scans"]
        self.stats["average_scan_time"] = (current_avg * (total - 1) + duration) / total

    async def import_scan_results(
            self,
            file_path: str,
            file_format: str = "auto"
    ) -> ScanResult:
        """
        Importe des résultats de scan depuis un fichier

        Args:
            file_path: Chemin vers le fichier
            file_format: Format (nmap_xml, openvas_xml, json, auto)

        Returns:
            ScanResult: Résultats parsés
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise CollectorException(
                    f"Fichier non trouvé: {file_path}",
                    CoreErrorCodes.SCAN_TARGET_INVALID
                )

            # Détection automatique du format
            if file_format == "auto":
                file_format = self._detect_file_format(file_path)

            # Parser selon le format
            if file_format == "nmap_xml":
                return await self._parse_nmap_xml(file_path)
            elif file_format == "json":
                return await self._parse_json_report(file_path)
            else:
                raise CollectorException(
                    f"Format non supporté: {file_format}",
                    CoreErrorCodes.INVALID_CONFIGURATION
                )

        except Exception as e:
            logger.error(f"Erreur import scan: {e}")
            if isinstance(e, CollectorException):
                raise
            else:
                raise CollectorException(
                    f"Erreur lors de l'import: {str(e)}",
                    CoreErrorCodes.SCAN_FAILED
                )

    def _detect_file_format(self, file_path: Path) -> str:
        """Détecte automatiquement le format du fichier"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read(1024)  # Lire les premiers 1024 caractères

            if content.strip().startswith('<?xml') and 'nmaprun' in content:
                return "nmap_xml"
            elif content.strip().startswith('{'):
                return "json"
            else:
                return "unknown"

        except Exception:
            return "unknown"

    async def _parse_nmap_xml(self, file_path: Path) -> ScanResult:
        """Parse un fichier XML Nmap"""
        # TODO: Implémenter le parsing XML Nmap complet
        raise CollectorException(
            "Import XML Nmap pas encore implémenté",
            CoreErrorCodes.INVALID_CONFIGURATION
        )

    async def _parse_json_report(self, file_path: Path) -> ScanResult:
        """Parse un rapport JSON générique"""
        # TODO: Implémenter le parsing JSON générique
        raise CollectorException(
            "Import JSON pas encore implémenté",
            CoreErrorCodes.INVALID_CONFIGURATION
        )

    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du collecteur"""
        return self.stats.copy()

    def is_healthy(self) -> bool:
        """Vérifie si le collecteur est en bonne santé"""
        if not self.is_ready:
            return False

        try:
            # Test rapide de Nmap
            result = subprocess.run(['nmap', '--version'],
                                    capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False


# === FONCTIONS UTILITAIRES ===

async def quick_scan(target: str, scan_type: str = "quick") -> Dict[str, Any]:
    """
    Scan rapide d'une cible (fonction utilitaire)

    Args:
        target: Cible à scanner
        scan_type: Type de scan (quick par défaut)

    Returns:
        Dict contenant les résultats simplifiés
    """
    collector = Collector()

    try:
        result = await collector.scan_target(target, scan_type)
        return result.to_dict()
    except Exception as e:
        logger.error(f"Erreur scan rapide: {e}")
        return {
            "error": str(e),
            "target": target,
            "vulnerabilities": []
        }


def create_collector(config: Optional[Dict[str, Any]] = None) -> Collector:
    """
    Factory pour créer un collecteur avec configuration spécifique

    Args:
        config: Configuration personnalisée

    Returns:
        Collector: Instance configurée
    """
    return Collector(config)


def validate_nmap_installation() -> Dict[str, Any]:
    """
    Valide l'installation et configuration de Nmap

    Returns:
        Dict avec le statut de validation
    """
    try:
        # Vérifier version
        result = subprocess.run(['nmap', '--version'],
                                capture_output=True, text=True, timeout=10)

        if result.returncode != 0:
            return {
                "valid": False,
                "error": "Nmap non fonctionnel",
                "version": None
            }

        # Extraire version
        version_match = re.search(r'Nmap version (\d+\.\d+)', result.stdout)
        version = version_match.group(1) if version_match else "Unknown"

        # Vérifier scripts NSE
        nse_check = subprocess.run(['nmap', '--script-help', 'vuln'],
                                   capture_output=True, text=True, timeout=10)

        has_vuln_scripts = nse_check.returncode == 0 and 'vuln' in nse_check.stdout

        # Vérifier permissions (test sur localhost)
        perm_check = subprocess.run(['nmap', '-sn', '127.0.0.1'],
                                    capture_output=True, text=True, timeout=10)

        has_permissions = perm_check.returncode == 0

        return {
            "valid": True,
            "version": version,
            "has_vuln_scripts": has_vuln_scripts,
            "has_permissions": has_permissions,
            "warnings": [] if has_vuln_scripts and has_permissions else [
                "Scripts de vulnérabilités manquants" if not has_vuln_scripts else "",
                "Permissions insuffisantes" if not has_permissions else ""
            ]
        }

    except subprocess.TimeoutExpired:
        return {
            "valid": False,
            "error": "Timeout lors de la vérification",
            "version": None
        }
    except Exception as e:
        return {
            "valid": False,
            "error": str(e),
            "version": None
        }


def get_supported_scan_types() -> Dict[str, Dict[str, Any]]:
    """
    Retourne les types de scan supportés avec leurs descriptions

    Returns:
        Dict des types de scan avec métadonnées
    """
    return {
        "quick": {
            "name": "Scan Rapide",
            "description": "Scan des 1000 ports les plus courants avec détection de vulnérabilités",
            "estimated_time": "1-3 minutes",
            "nmap_args": "-sV -T4 --top-ports 1000 --script vuln",
            "use_cases": ["Découverte rapide", "Tests de routine", "Scan préliminaire"]
        },
        "full": {
            "name": "Scan Complet",
            "description": "Scan complet avec détection de services et vulnérabilités",
            "estimated_time": "5-15 minutes",
            "nmap_args": "-sV -sC -T4 --script vuln,safe",
            "use_cases": ["Audit de sécurité", "Évaluation complète", "Scan de production"]
        },
        "stealth": {
            "name": "Scan Furtif",
            "description": "Scan discret pour éviter la détection",
            "estimated_time": "10-30 minutes",
            "nmap_args": "-sS -sV -T2 --script vuln",
            "use_cases": ["Test d'intrusion", "Évitement IDS/IPS", "Reconnaissance discrète"]
        },
        "aggressive": {
            "name": "Scan Agressif",
            "description": "Scan intensif avec tous les scripts de détection",
            "estimated_time": "15-45 minutes",
            "nmap_args": "-sV -sC -A -T4 --script vuln,exploit",
            "use_cases": ["Pentest approfondi", "Recherche exhaustive", "Environnement de test"]
        }
    }


async def bulk_scan(
        targets: List[str],
        scan_type: str = "quick",
        max_concurrent: int = 3,
        progress_callback: Optional[Callable[[str, int], None]] = None
) -> Dict[str, ScanResult]:
    """
    Lance des scans sur plusieurs cibles en parallèle

    Args:
        targets: Liste des cibles à scanner
        scan_type: Type de scan pour toutes les cibles
        max_concurrent: Nombre maximum de scans simultanés
        progress_callback: Callback pour progression (target, progress)

    Returns:
        Dict avec les résultats par cible
    """
    results = {}
    collector = Collector()

    # Semaphore pour limiter la concurrence
    semaphore = asyncio.Semaphore(max_concurrent)

    async def scan_single_target(target: str):
        """Scan d'une cible unique avec semaphore"""
        async with semaphore:
            try:
                logger.info(f"Début scan bulk: {target}")

                def target_progress(progress: int):
                    if progress_callback:
                        progress_callback(target, progress)

                result = await collector.scan_target(
                    target=target,
                    scan_type=scan_type,
                    progress_callback=target_progress
                )

                results[target] = result
                logger.info(f"Scan bulk terminé: {target}")

            except Exception as e:
                logger.error(f"Erreur scan bulk {target}: {e}")
                results[target] = {
                    "error": str(e),
                    "target": target
                }

    # Lancer tous les scans
    tasks = [scan_single_target(target) for target in targets]
    await asyncio.gather(*tasks, return_exceptions=True)

    return results


class ScanScheduler:
    """
    Planificateur de scans automatiques

    Permet de programmer des scans récurrents sur des cibles définies
    """

    def __init__(self, collector: Collector):
        self.collector = collector
        self.scheduled_scans = {}
        self.running = False

    def add_scheduled_scan(
            self,
            schedule_id: str,
            target: str,
            scan_type: str,
            interval_hours: int,
            callback: Optional[Callable[[ScanResult], None]] = None
    ):
        """
        Ajoute un scan programmé

        Args:
            schedule_id: Identifiant unique du planning
            target: Cible à scanner
            scan_type: Type de scan
            interval_hours: Intervalle en heures
            callback: Fonction appelée avec les résultats
        """
        self.scheduled_scans[schedule_id] = {
            "target": target,
            "scan_type": scan_type,
            "interval_hours": interval_hours,
            "callback": callback,
            "last_run": None,
            "next_run": None
        }

        logger.info(f"Scan programmé ajouté: {schedule_id} ({target} toutes les {interval_hours}h)")

    def remove_scheduled_scan(self, schedule_id: str):
        """Supprime un scan programmé"""
        if schedule_id in self.scheduled_scans:
            del self.scheduled_scans[schedule_id]
            logger.info(f"Scan programmé supprimé: {schedule_id}")

    async def start_scheduler(self):
        """Démarre le planificateur"""
        self.running = True
        logger.info("Planificateur de scans démarré")

        while self.running:
            await self._check_and_run_scheduled_scans()
            await asyncio.sleep(300)  # Vérifier toutes les 5 minutes

    def stop_scheduler(self):
        """Arrête le planificateur"""
        self.running = False
        logger.info("Planificateur de scans arrêté")

    async def _check_and_run_scheduled_scans(self):
        """Vérifie et exécute les scans programmés"""
        current_time = datetime.utcnow()

        for schedule_id, scan_config in self.scheduled_scans.items():
            last_run = scan_config.get("last_run")
            interval_hours = scan_config["interval_hours"]

            # Vérifier s'il faut exécuter le scan
            should_run = (
                    last_run is None or
                    (current_time - last_run).total_seconds() >= interval_hours * 3600
            )

            if should_run:
                await self._execute_scheduled_scan(schedule_id, scan_config)

    async def _execute_scheduled_scan(self, schedule_id: str, scan_config: Dict[str, Any]):
        """Exécute un scan programmé"""
        try:
            logger.info(f"Exécution scan programmé: {schedule_id}")

            result = await self.collector.scan_target(
                target=scan_config["target"],
                scan_type=scan_config["scan_type"]
            )

            # Mettre à jour la dernière exécution
            scan_config["last_run"] = datetime.utcnow()

            # Appeler le callback si défini
            if scan_config.get("callback"):
                try:
                    scan_config["callback"](result)
                except Exception as e:
                    logger.error(f"Erreur callback scan programmé {schedule_id}: {e}")

            logger.info(f"Scan programmé terminé: {schedule_id}")

        except Exception as e:
            logger.error(f"Erreur scan programmé {schedule_id}: {e}")


def estimate_scan_duration(target: str, scan_type: str, port_count: Optional[int] = None) -> int:
    """
    Estime la durée d'un scan en secondes

    Args:
        target: Cible à scanner
        scan_type: Type de scan
        port_count: Nombre de ports (optionnel)

    Returns:
        int: Durée estimée en secondes
    """
    base_durations = {
        "quick": 120,  # 2 minutes
        "full": 600,  # 10 minutes
        "stealth": 1800,  # 30 minutes
        "aggressive": 2700  # 45 minutes
    }

    base_duration = base_durations.get(scan_type, 600)

    # Ajuster selon le nombre de ports si fourni
    if port_count:
        if port_count > 10000:
            base_duration *= 1.5
        elif port_count > 1000:
            base_duration *= 1.2

    # Ajuster selon le type de cible (IP vs domaine)
    if not validate_ip_address(target):
        base_duration += 30  # Temps de résolution DNS

    return int(base_duration)


def get_nmap_script_categories() -> Dict[str, List[str]]:
    """
    Retourne les catégories de scripts NSE et leurs scripts

    Returns:
        Dict des catégories avec liste des scripts
    """
    return {
        "vuln": [
            "ssl-heartbleed", "ssl-poodle", "ssl-dh-params",
            "smb-vuln-ms17-010", "smb-vuln-ms08-067", "smb-vuln-cve2009-3103",
            "http-vuln-cve2017-5638", "http-vuln-cve2014-6271", "http-vuln-cve2015-1635",
            "ftp-anon", "mysql-empty-password", "telnet-encryption"
        ],
        "safe": [
            "http-title", "http-server-header", "ssh-hostkey",
            "ssl-cert", "banner", "fingerprint-strings"
        ],
        "intrusive": [
            "http-sql-injection", "http-xss", "http-csrf",
            "smb-brute", "ssh-brute", "ftp-brute"
        ],
        "malware": [
            "http-malware-host", "smtp-strangeport", "unusual-port"
        ]
    }


# === CONFIGURATION ET HELPERS ===

def optimize_nmap_performance() -> Dict[str, str]:
    """
    Retourne des optimisations Nmap pour différents contextes

    Returns:
        Dict avec les optimisations par contexte
    """
    return {
        "fast_network": "-T5 --min-rate 1000 --max-retries 1",
        "slow_network": "-T2 --scan-delay 1s --max-retries 3",
        "stealth_mode": "-T1 -f --scan-delay 10s --max-retries 1",
        "local_network": "-T4 --min-rate 500 --max-retries 2",
        "internet_scan": "-T3 --max-retries 2 --host-timeout 10m"
    }


def get_common_ports_by_service() -> Dict[str, List[int]]:
    """
    Retourne les ports communs par type de service

    Returns:
        Dict des services avec leurs ports
    """
    return {
        "web": [80, 443, 8080, 8443, 8000, 8888, 9000],
        "ssh": [22, 2222],
        "ftp": [21, 2121],
        "mail": [25, 110, 143, 465, 587, 993, 995],
        "dns": [53],
        "database": [1433, 1521, 3306, 5432, 27017, 6379],
        "remote_access": [3389, 5900, 5901, 1723],
        "file_sharing": [139, 445, 2049, 548],
        "monitoring": [161, 162, 514, 10050, 10051]
    }


# === CLASSE D'EXPORT DE RÉSULTATS ===

class ScanResultExporter:
    """
    Exporteur de résultats de scan vers différents formats
    """

    @staticmethod
    def to_json(scan_result: ScanResult, indent: int = 2) -> str:
        """Exporte en JSON"""
        return json.dumps(scan_result.to_dict(), indent=indent, ensure_ascii=False)

    @staticmethod
    def to_csv(scan_result: ScanResult) -> str:
        """Exporte les vulnérabilités en CSV"""
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        # En-têtes
        writer.writerow([
            'Target', 'Vulnerability ID', 'Name', 'Severity', 'CVSS Score',
            'Affected Service', 'Port', 'CVE IDs', 'Detection Method'
        ])

        # Données
        for vuln in scan_result.vulnerabilities:
            writer.writerow([
                scan_result.target,
                vuln.vulnerability_id,
                vuln.name,
                vuln.severity,
                vuln.cvss_score or '',
                vuln.affected_service,
                vuln.affected_port,
                ','.join(vuln.cve_ids),
                vuln.detection_method
            ])

        return output.getvalue()

    @staticmethod
    def to_html(scan_result: ScanResult) -> str:
        """Exporte en rapport HTML"""
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rapport de Scan - {scan_result.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f8ff; padding: 15px; border-radius: 5px; }}
                .summary {{ margin: 20px 0; }}
                .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 3px; }}
                .critical {{ border-left: 5px solid #dc3545; }}
                .high {{ border-left: 5px solid #fd7e14; }}
                .medium {{ border-left: 5px solid #ffc107; }}
                .low {{ border-left: 5px solid #28a745; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Rapport de Scan de Vulnérabilités</h1>
                <p><strong>Cible:</strong> {scan_result.target}</p>
                <p><strong>Date:</strong> {scan_result.completed_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Durée:</strong> {scan_result.duration:.1f} secondes</p>
            </div>

            <div class="summary">
                <h2>Résumé</h2>
                <p><strong>Statut hôte:</strong> {scan_result.host_status}</p>
                <p><strong>Ports ouverts:</strong> {len(scan_result.open_ports)}</p>
                <p><strong>Services détectés:</strong> {len(scan_result.services)}</p>
                <p><strong>Vulnérabilités trouvées:</strong> {len(scan_result.vulnerabilities)}</p>
            </div>

            <h2>Vulnérabilités Détectées</h2>
        """

        for vuln in scan_result.vulnerabilities:
            severity_class = vuln.severity.lower()
            html_template += f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln.name}</h3>
                <p><strong>ID:</strong> {vuln.vulnerability_id}</p>
                <p><strong>Gravité:</strong> {vuln.severity}</p>
                {f"<p><strong>Score CVSS:</strong> {vuln.cvss_score}</p>" if vuln.cvss_score else ""}
                <p><strong>Service affecté:</strong> {vuln.affected_service} (port {vuln.affected_port})</p>
                <p><strong>Description:</strong> {vuln.description}</p>
                {f"<p><strong>CVE:</strong> {', '.join(vuln.cve_ids)}</p>" if vuln.cve_ids else ""}
            </div>
            """

        html_template += """
        </body>
        </html>
        """

        return html_template


if __name__ == "__main__":
    # Tests et exemples d'utilisation
    async def test_collector():
        print("Test du collecteur de vulnérabilités")

        # Valider Nmap
        nmap_status = validate_nmap_installation()
        print(f"Nmap valide: {nmap_status['valid']}")
        if nmap_status['valid']:
            print(f"Version: {nmap_status['version']}")

        # Test scan rapide sur localhost
        try:
            result = await quick_scan("127.0.0.1", "quick")
            print(f"Scan terminé: {len(result.get('vulnerabilities', []))} vulnérabilités")
        except Exception as e:
            print(f"Erreur test scan: {e}")


    # Lancer le test
    asyncio.run(test_collector())