"""
Module Parsers pour l'Agent IA de Cybersécurité

Ce module fournit des fonctions de parsing pour différents formats de données :
- Résultats Nmap (XML, JSON)
- Rapports OpenVAS (XML)
- Données Tenable (JSON)
- Fichiers de configuration système
- Logs de sécurité

Fonctionnalités :
- Parsing robuste avec gestion d'erreurs
- Normalisation des données
- Extraction d'informations de vulnérabilités
- Validation des formats
- Support de multiples sources de données
"""

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple
import csv
import yaml
from dataclasses import dataclass
import logging

from .validators import validate_ip_address, validate_port
from .logger import setup_logger

# Configuration du logging
logger = setup_logger(__name__)


# === STRUCTURES DE DONNÉES ===

@dataclass
class ParsedVulnerability:
    """Structure pour une vulnérabilité parsée"""
    id: str
    name: str
    severity: str
    cvss_score: Optional[float]
    description: str
    affected_service: str
    affected_port: int
    cve_ids: List[str]
    references: List[str]
    solution: Optional[str] = None
    risk_factor: Optional[str] = None
    plugin_output: Optional[str] = None


@dataclass
class ParsedHost:
    """Structure pour un hôte parsé"""
    ip: str
    hostname: Optional[str]
    mac_address: Optional[str]
    os_info: Optional[str]
    status: str
    open_ports: List[int]
    services: List[Dict[str, Any]]
    vulnerabilities: List[ParsedVulnerability]


@dataclass
class ParseResult:
    """Résultat général de parsing"""
    source_type: str
    source_file: str
    parsed_at: datetime
    hosts: List[ParsedHost]
    scan_info: Dict[str, Any]
    total_hosts: int
    total_vulnerabilities: int


# === PARSERS NMAP ===

class NmapParser:
    """Parser pour les résultats Nmap"""

    @staticmethod
    def parse_xml(xml_content: Union[str, Path]) -> ParseResult:
        """
        Parse un fichier XML Nmap

        Args:
            xml_content: Contenu XML ou chemin vers le fichier

        Returns:
            ParseResult: Résultats parsés

        Raises:
            ValueError: Si le XML est invalide
            FileNotFoundError: Si le fichier n'existe pas
        """
        try:
            # Lire le fichier si c'est un chemin
            if isinstance(xml_content, Path) or isinstance(xml_content, str):
                if Path(xml_content).exists():
                    with open(xml_content, 'r', encoding='utf-8') as f:
                        xml_content = f.read()
                        source_file = str(xml_content)
                else:
                    source_file = "string_input"
            else:
                source_file = "string_input"

            # Parser le XML
            root = ET.fromstring(xml_content)

            # Extraire les informations du scan
            scan_info = NmapParser._extract_scan_info(root)

            # Parser chaque hôte
            hosts = []
            for host_elem in root.findall('host'):
                host = NmapParser._parse_host(host_elem)
                if host:
                    hosts.append(host)

            # Créer le résultat
            result = ParseResult(
                source_type="nmap_xml",
                source_file=source_file,
                parsed_at=datetime.utcnow(),
                hosts=hosts,
                scan_info=scan_info,
                total_hosts=len(hosts),
                total_vulnerabilities=sum(len(h.vulnerabilities) for h in hosts)
            )

            logger.info(f"Nmap XML parsé: {len(hosts)} hôtes, {result.total_vulnerabilities} vulnérabilités")
            return result

        except ET.ParseError as e:
            logger.error(f"Erreur parsing XML Nmap: {e}")
            raise ValueError(f"XML Nmap invalide: {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue parsing Nmap: {e}")
            raise

    @staticmethod
    def _extract_scan_info(root: ET.Element) -> Dict[str, Any]:
        """Extrait les informations générales du scan"""
        scan_info = {}

        # Informations de base
        scan_info['scanner'] = root.get('scanner', 'nmap')
        scan_info['version'] = root.get('version', 'unknown')
        scan_info['start_time'] = root.get('start')

        # Arguments utilisés
        args_elem = root.find('scaninfo')
        if args_elem is not None:
            scan_info['arguments'] = args_elem.get('services', '')
            scan_info['scan_type'] = args_elem.get('type', '')
            scan_info['protocol'] = args_elem.get('protocol', '')

        # Statistiques
        runstats = root.find('runstats')
        if runstats is not None:
            finished = runstats.find('finished')
            if finished is not None:
                scan_info['end_time'] = finished.get('time')
                scan_info['elapsed'] = finished.get('elapsed')
                scan_info['summary'] = finished.get('summary', '')

        return scan_info

    @staticmethod
    def _parse_host(host_elem: ET.Element) -> Optional[ParsedHost]:
        """Parse un élément host XML"""
        try:
            # Status de l'hôte
            status_elem = host_elem.find('status')
            if status_elem is None or status_elem.get('state') != 'up':
                return None

            # Adresse IP
            address_elem = host_elem.find('address[@addrtype="ipv4"]')
            if address_elem is None:
                return None

            ip = address_elem.get('addr')
            if not validate_ip_address(ip):
                return None

            # Hostname
            hostname = None
            hostnames_elem = host_elem.find('hostnames')
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find('hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')

            # MAC Address
            mac_address = None
            mac_elem = host_elem.find('address[@addrtype="mac"]')
            if mac_elem is not None:
                mac_address = mac_elem.get('addr')

            # OS Information
            os_info = None
            os_elem = host_elem.find('os')
            if os_elem is not None:
                osmatch = os_elem.find('osmatch')
                if osmatch is not None:
                    os_info = osmatch.get('name')

            # Services et ports
            services = []
            open_ports = []
            ports_elem = host_elem.find('ports')

            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_info = NmapParser._parse_port(port_elem)
                    if port_info:
                        services.append(port_info)
                        if port_info['state'] == 'open':
                            open_ports.append(port_info['port'])

            # Vulnérabilités (depuis les scripts)
            vulnerabilities = []
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_vulns = NmapParser._extract_vulnerabilities_from_port(port_elem)
                    vulnerabilities.extend(port_vulns)

            # Scripts au niveau de l'hôte
            host_scripts = host_elem.find('hostscript')
            if host_scripts is not None:
                host_vulns = NmapParser._extract_vulnerabilities_from_scripts(host_scripts)
                vulnerabilities.extend(host_vulns)

            return ParsedHost(
                ip=ip,
                hostname=hostname,
                mac_address=mac_address,
                os_info=os_info,
                status='up',
                open_ports=open_ports,
                services=services,
                vulnerabilities=vulnerabilities
            )

        except Exception as e:
            logger.warning(f"Erreur parsing hôte: {e}")
            return None

    @staticmethod
    def _parse_port(port_elem: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse un élément port"""
        try:
            port_id = int(port_elem.get('portid'))
            protocol = port_elem.get('protocol', 'tcp')

            state_elem = port_elem.find('state')
            state = state_elem.get('state') if state_elem is not None else 'unknown'

            service_elem = port_elem.find('service')
            service_info = {
                'port': port_id,
                'protocol': protocol,
                'state': state,
                'service': 'unknown',
                'version': '',
                'product': '',
                'extra_info': ''
            }

            if service_elem is not None:
                service_info.update({
                    'service': service_elem.get('name', 'unknown'),
                    'version': service_elem.get('version', ''),
                    'product': service_elem.get('product', ''),
                    'extra_info': service_elem.get('extrainfo', '')
                })

            return service_info

        except (ValueError, TypeError) as e:
            logger.warning(f"Erreur parsing port: {e}")
            return None

    @staticmethod
    def _extract_vulnerabilities_from_port(port_elem: ET.Element) -> List[ParsedVulnerability]:
        """Extrait les vulnérabilités des scripts de port"""
        vulnerabilities = []

        port_id = int(port_elem.get('portid', 0))
        service_elem = port_elem.find('service')
        service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'

        # Chercher les scripts de vulnérabilité
        for script_elem in port_elem.findall('.//script'):
            script_id = script_elem.get('id', '')
            script_output = script_elem.get('output', '')

            if 'vuln' in script_id or 'cve' in script_id.lower():
                vulns = NmapParser._parse_vulnerability_script(
                    script_id, script_output, service_name, port_id
                )
                vulnerabilities.extend(vulns)

        return vulnerabilities

    @staticmethod
    def _extract_vulnerabilities_from_scripts(hostscript_elem: ET.Element) -> List[ParsedVulnerability]:
        """Extrait les vulnérabilités des scripts d'hôte"""
        vulnerabilities = []

        for script_elem in hostscript_elem.findall('script'):
            script_id = script_elem.get('id', '')
            script_output = script_elem.get('output', '')

            if 'vuln' in script_id or 'cve' in script_id.lower():
                vulns = NmapParser._parse_vulnerability_script(
                    script_id, script_output, 'host', 0
                )
                vulnerabilities.extend(vulns)

        return vulnerabilities

    @staticmethod
    def _parse_vulnerability_script(
            script_id: str,
            output: str,
            service: str,
            port: int
    ) -> List[ParsedVulnerability]:
        """Parse un script de vulnérabilité spécifique"""
        vulnerabilities = []

        # Patterns de détection
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cvss_pattern = r'CVSS[:\s]+(\d+\.?\d*)'

        # Extraire les CVE
        cves = re.findall(cve_pattern, output)

        # Extraire le score CVSS
        cvss_match = re.search(cvss_pattern, output)
        cvss_score = float(cvss_match.group(1)) if cvss_match else None

        # Déterminer la sévérité
        severity = NmapParser._determine_severity(output, cvss_score)

        # Créer la vulnérabilité
        if cves or 'VULNERABLE' in output.upper():
            vuln_id = cves[0] if cves else f"nmap_{script_id}_{port}"

            vuln = ParsedVulnerability(
                id=vuln_id,
                name=NmapParser._extract_vuln_name(script_id, output),
                severity=severity,
                cvss_score=cvss_score,
                description=NmapParser._clean_description(output),
                affected_service=service,
                affected_port=port,
                cve_ids=cves,
                references=NmapParser._extract_references(output),
                plugin_output=output[:500]  # Limiter la taille
            )

            vulnerabilities.append(vuln)

        return vulnerabilities

    @staticmethod
    def _determine_severity(output: str, cvss_score: Optional[float]) -> str:
        """Détermine la sévérité basée sur l'output et le CVSS"""
        output_lower = output.lower()

        # Basé sur le score CVSS
        if cvss_score:
            if cvss_score >= 9.0:
                return 'CRITICAL'
            elif cvss_score >= 7.0:
                return 'HIGH'
            elif cvss_score >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'

        # Basé sur les mots-clés
        if any(word in output_lower for word in ['critical', 'remote code execution', 'rce']):
            return 'CRITICAL'
        elif any(word in output_lower for word in ['high', 'dangerous', 'exploit']):
            return 'HIGH'
        elif any(word in output_lower for word in ['medium', 'moderate']):
            return 'MEDIUM'
        else:
            return 'LOW'

    @staticmethod
    def _extract_vuln_name(script_id: str, output: str) -> str:
        """Extrait le nom de la vulnérabilité"""
        # Mapping des scripts connus
        script_names = {
            'ssl-heartbleed': 'SSL Heartbleed Vulnerability',
            'ssl-poodle': 'SSL POODLE Vulnerability',
            'smb-vuln-ms17-010': 'MS17-010 EternalBlue SMB Vulnerability',
            'http-vuln-cve2017-5638': 'Apache Struts2 RCE (CVE-2017-5638)',
        }

        if script_id in script_names:
            return script_names[script_id]

        # Essayer d'extraire depuis l'output
        lines = output.split('\n')
        for line in lines[:3]:  # Premières lignes
            line = line.strip()
            if line and not line.startswith('|') and len(line) > 10:
                return line[:100]

        return f"Vulnerability detected by {script_id}"

    @staticmethod
    def _clean_description(output: str) -> str:
        """Nettoie la description de la vulnérabilité"""
        lines = output.split('\n')
        clean_lines = []

        for line in lines:
            line = line.strip()
            if line and not line.startswith('|_') and not line.startswith('|'):
                clean_lines.append(line)
            if len(clean_lines) >= 3:  # Limiter à 3 lignes
                break

        return ' '.join(clean_lines)[:500]

    @staticmethod
    def _extract_references(output: str) -> List[str]:
        """Extrait les références URL de l'output"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, output)
        return list(set(urls))  # Éliminer les doublons


# === PARSERS OPENVAS ===

# class OpenVASParser:
#     """Parser pour les rapports OpenVAS XML"""
# 
#     @staticmethod
#     def parse_xml(xml_content: Union[str, Path]) -> ParseResult:
#         """
#         Parse un rapport OpenVAS XML
# 
#         Args:
#             xml_content: Contenu XML ou chemin vers le fichier
# 
#         Returns:
#             ParseResult: Résultats parsés
#         """
#         try:
#             # Lire le fichier si nécessaire
#             if isinstance(xml_content, (str, Path)) and Path(xml_content).exists():
#                 with open(xml_content, 'r', encoding='utf-8') as f:
#                     xml_content = f.read()
#                     source_file = str(xml_content)
#             else:
#                 source_file = "string_input"
# 
#             root = ET.fromstring(xml_content)
# 
#             # Extraire les informations du rapport
#             scan_info = OpenVASParser._extract_scan_info(root)
# 
#             # Grouper les résultats par hôte
#             hosts_data = {}
# 
#             for result in root.findall('.//result'):
#                 host_ip = OpenVASParser._get_host_ip(result)
#                 if not host_ip:
#                     continue
# 
#                 if host_ip not in hosts_data:
#                     hosts_data[host_ip] = {
#                         'vulnerabilities': [],
#                         'services': set(),
#                         'ports': set()
#                     }
# 
#                 vuln = OpenVASParser._parse_result(result)
#                 if vuln:
#                     hosts_data[host_ip]['vulnerabilities'].append(vuln)
#                     hosts_data[host_ip]['ports'].add(vuln.affected_port)
#                     hosts_data[host_ip]['services'].add(vuln.affected_service)
# 
#             # Créer les objets ParsedHost
#             hosts = []
#             for host_ip, data in hosts_data.items():
#                 host = ParsedHost(
#                     ip=host_ip,
#                     hostname=None,  # OpenVAS ne fournit pas toujours le hostname
#                     mac_address=None,
#                     os_info=None,
#                     status='up',
#                     open_ports=list(data['ports']),
#                     services=[{'service': s, 'port': 0} for s in data['services']],
#                     vulnerabilities=data['vulnerabilities']
#                 )
#                 hosts.append(host)
# 
#             result = ParseResult(
#                 source_type="openvas_xml",
#                 source_file=source_file,
#                 parsed_at=datetime.utcnow(),
#                 hosts=hosts,
#                 scan_info=scan_info,
#                 total_hosts=len(hosts),
#                 total_vulnerabilities=sum(len(h.vulnerabilities) for h in hosts)
#             )
# 
#             logger.info(f"OpenVAS XML parsé: {len(hosts)} hôtes, {result.total_vulnerabilities} vulnérabilités")
#             return result
# 
#         except ET.ParseError as e:
#             logger.error(f"Erreur parsing XML OpenVAS: {e}")
#             raise ValueError(f"XML OpenVAS invalide: {e}")
#         except Exception as e:
#             logger.error(f"Erreur inattendue parsing OpenVAS: {e}")
#             raise
# 
#     @staticmethod
#     def _extract_scan_info(root: ET.Element) -> Dict[str, Any]:
#         """Extrait les informations générales du scan OpenVAS"""
#         scan_info = {'scanner': 'openvas'}
# 
#         # Informations du rapport
#         report = root.find('.//report')
#         if report is not None:
#             scan_info['report_id'] = report.get('id', '')
#             scan_info['format_id'] = report.get('format_id', '')
# 
#         # Date de création
#         creation_time = root.find('.//creation_time')
#         if creation_time is not None:
#             scan_info['creation_time'] = creation_time.text
# 
#         # Tâche associée
#         task = root.find('.//task')
#         if task is not None:
#             scan_info['task_name'] = task.find('name').text if task.find('name') is not None else ''
# 
#         return scan_info
# 
#     @staticmethod
#     def _get_host_ip(result: ET.Element) -> Optional[str]:
#         """Extrait l'IP de l'hôte depuis un résultat"""
#         host = result.find('host')
#         if host is not None:
#             ip = host.text
#             if validate_ip_address(ip):
#                 return ip
#         return None
# 
#     @staticmethod
#     def _parse_result(result: ET.Element) -> Optional[ParsedVulnerability]:
#         """Parse un élément result OpenVAS"""
#         try:
#             # ID du NVT
#             nvt = result.find('nvt')
#             if nvt is None:
#                 return None
# 
#             nvt_id = nvt.get('oid', '')
# 
#             # Nom de la vulnérabilité
#             name_elem = nvt.find('name')
#             name = name_elem.text if name_elem is not None else 'Unknown Vulnerability'
# 
#             # Sévérité et CVSS
#             threat_elem = result.find('threat')
#             threat = threat_elem.text if threat_elem is not None else 'Log'
# 
#             severity_elem = result.find('severity')
#             cvss_score = None
#             if severity_elem is not None:
#                 try:
#                     cvss_score = float(severity_elem.text)
#                 except (ValueError, TypeError):
#                     pass
# 
#             # Description
#             description_elem = result.find('description')
#             description = description_elem.text if description_elem is not None else ''
# 
#             # Port
#             port_elem = result.find('port')
#             port_str = port_elem.text if port_elem is not None else '0'
# 
#             # Extraire le numéro de port
#             port_match = re.search(r'(\d+)/', port_str)
#             port = int(port_match.group(1)) if port_match else 0
# 
#             # Service
#             service = 'unknown'
#             if '/' in port_str:
#                 service = port_str.split('/')[1]
# 
#             # CVEs
#             cves = []
#             refs_elem = nvt.find('refs')
#             if refs_elem is not None:
#                 for ref in refs_elem.findall('ref'):
#                     if ref.get('type') == 'cve':
#                         cves.append(ref.get('id', ''))
# 
#             # Solution
#             solution_elem = nvt.find('solution')
#             solution = solution_elem.text if solution_elem is not None else None
# 
#             # Mapping de sévérité OpenVAS -> Standard
#             severity_map = {
#                 'High': 'HIGH',
#                 'Medium': 'MEDIUM',
#                 'Low': 'LOW',
#                 'Log': 'INFO',
#                 'Debug': 'INFO'
#             }
# 
#             severity = severity_map.get(threat, 'LOW')
#             if cvss_score and cvss_score >= 9.0:
#                 severity = 'CRITICAL'
# 
#             return ParsedVulnerability(
#                 id=nvt_id,
#                 name=name,
#                 severity=severity,
#                 cvss_score=cvss_score,
#                 description=description[:500],  # Limiter la taille
#                 affected_service=service,
#                 affected_port=port,
#                 cve_ids=cves,
#                 references=[],
#                 solution=solution,
#                 risk_factor=threat
#             )
# 
#         except Exception as e:
#             logger.warning(f"Erreur parsing résultat OpenVAS: {e}")
#             return None
# 
# 
# # === PARSERS TENABLE ===
# 
# class TenableParser:
    """Parser pour les exports Tenable/Nessus JSON"""

    @staticmethod
    def parse_json(json_content: Union[str, Path, dict]) -> ParseResult:
        """
        Parse un export Tenable JSON

        Args:
            json_content: Contenu JSON, chemin vers fichier, ou dict

        Returns:
            ParseResult: Résultats parsés
        """
        try:
            # Charger les données JSON
            if isinstance(json_content, dict):
                data = json_content
                source_file = "dict_input"
            elif isinstance(json_content, (str, Path)) and Path(json_content).exists():
                with open(json_content, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    source_file = str(json_content)
            else:
                data = json.loads(json_content)
                source_file = "string_input"

            # Extraire les informations générales
            scan_info = TenableParser._extract_scan_info(data)

            # Grouper par hôte
            hosts_data = {}

            # Parser les vulnérabilités
            vulnerabilities = data.get('vulnerabilities', [])

            for vuln_data in vulnerabilities:
                assets = vuln_data.get('asset', {}).get('ipv4', [])

                for asset_ip in assets:
                    if not validate_ip_address(asset_ip):
                        continue

                    if asset_ip not in hosts_data:
                        hosts_data[asset_ip] = {
                            'vulnerabilities': [],
                            'services': set(),
                            'ports': set()
                        }

                    vuln = TenableParser._parse_vulnerability(vuln_data, asset_ip)
                    if vuln:
                        hosts_data[asset_ip]['vulnerabilities'].append(vuln)
                        hosts_data[asset_ip]['ports'].add(vuln.affected_port)
                        hosts_data[asset_ip]['services'].add(vuln.affected_service)

            # Créer les objets ParsedHost
            hosts = []
            for host_ip, host_data in hosts_data.items():
                host = ParsedHost(
                    ip=host_ip,
                    hostname=None,
                    mac_address=None,
                    os_info=None,
                    status='up',
                    open_ports=list(host_data['ports']),
                    services=[{'service': s, 'port': 0} for s in host_data['services']],
                    vulnerabilities=host_data['vulnerabilities']
                )
                hosts.append(host)

            result = ParseResult(
                source_type="tenable_json",
                source_file=source_file,
                parsed_at=datetime.utcnow(),
                hosts=hosts,
                scan_info=scan_info,
                total_hosts=len(hosts),
                total_vulnerabilities=sum(len(h.vulnerabilities) for h in hosts)
            )

            logger.info(f"Tenable JSON parsé: {len(hosts)} hôtes, {result.total_vulnerabilities} vulnérabilités")
            return result

        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Erreur parsing JSON Tenable: {e}")
            raise ValueError(f"JSON Tenable invalide: {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue parsing Tenable: {e}")
            raise

    @staticmethod
    def _extract_scan_info(data: dict) -> Dict[str, Any]:
        """Extrait les informations générales du scan"""
        return {
            'scanner': 'tenable',
            'export_uuid': data.get('export_uuid', ''),
            'num_assets': data.get('num_assets', 0),
            'num_findings': data.get('num_findings', 0)
        }

    @staticmethod
    def _parse_vulnerability(vuln_data: dict, asset_ip: str) -> Optional[ParsedVulnerability]:
        """Parse une vulnérabilité Tenable"""
        try:
            plugin = vuln_data.get('plugin', {})

            # Informations de base
            plugin_id = str(plugin.get('id', ''))
            name = plugin.get('name', 'Unknown Vulnerability')
            description = plugin.get('description', '')
            solution = plugin.get('solution', '')

            # Sévérité
            severity_id = plugin.get('risk_factor', 'None')
            severity_map = {
                'Critical': 'CRITICAL',
                'High': 'HIGH',
                'Medium': 'MEDIUM',
                'Low': 'LOW',
                'None': 'INFO'
            }
            severity = severity_map.get(severity_id, 'LOW')

            # CVSS
            cvss_score = None
            cvss_base_score = plugin.get('cvss_base_score')
            if cvss_base_score:
                try:
                    cvss_score = float(cvss_base_score)
                except (ValueError, TypeError):
                    pass

            # CVEs
            cves = []
            cve_list = plugin.get('cve', [])
            if isinstance(cve_list, list):
                cves = cve_list
            elif isinstance(cve_list, str):
                cves = [cve_list]

            # Port et service
            port = vuln_data.get('port', 0)
            service = vuln_data.get('service', 'unknown')

            # Références
            references = []
            if 'see_also' in plugin:
                see_also = plugin['see_also']
                if isinstance(see_also, list):
                    references = see_also
                elif isinstance(see_also, str):
                    references = [see_also]

            return ParsedVulnerability(
                id=f"tenable_{plugin_id}",
                name=name,
                severity=severity,
                cvss_score=cvss_score,
                description=description[:500],
                affected_service=service,
                affected_port=port,
                cve_ids=cves,
                references=references,
                solution=solution,
                risk_factor=severity_id,
                plugin_output=vuln_data.get('output', '')[:500]
            )

        except Exception as e:
            logger.warning(f"Erreur parsing vulnérabilité Tenable: {e}")
            return None


# === PARSERS CSV ===

class CSVParser:
    """Parser pour les fichiers CSV de vulnérabilités"""

    @staticmethod
    def parse_csv(csv_content: Union[str, Path], delimiter: str = ',') -> ParseResult:
        """
        Parse un fichier CSV de vulnérabilités

        Args:
            csv_content: Contenu CSV ou chemin vers le fichier
            delimiter: Délimiteur CSV

        Returns:
            ParseResult: Résultats parsés
        """
        try:
            # Lire le fichier si nécessaire
            if isinstance(csv_content, (str, Path)) and Path(csv_content).exists():
                with open(csv_content, 'r', encoding='utf-8') as f:
                    content = f.read()
                    source_file = str(csv_content)
            else:
                content = csv_content
                source_file = "string_input"

            # Parser le CSV
            import io
            csv_reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)

            # Grouper par hôte
            hosts_data = {}

            for row in csv_reader:
                # Normaliser les noms de colonnes
                row = {k.lower().strip(): v for k, v in row.items()}

                # Extraire l'IP
                ip = CSVParser._extract_ip(row)
                if not ip:
                    continue

                if ip not in hosts_data:
                    hosts_data[ip] = {
                        'vulnerabilities': [],
                        'services': set(),
                        'ports': set()
                    }

                vuln = CSVParser._parse_csv_row(row)
                if vuln:
                    hosts_data[ip]['vulnerabilities'].append(vuln)
                    hosts_data[ip]['ports'].add(vuln.affected_port)
                    hosts_data[ip]['services'].add(vuln.affected_service)

            # Créer les objets ParsedHost
            hosts = []
            for host_ip, host_data in hosts_data.items():
                host = ParsedHost(
                    ip=host_ip,
                    hostname=None,
                    mac_address=None,
                    os_info=None,
                    status='up',
                    open_ports=list(host_data['ports']),
                    services=[{'service': s, 'port': 0} for s in host_data['services']],
                    vulnerabilities=host_data['vulnerabilities']
                )
                hosts.append(host)

            result = ParseResult(
                source_type="csv",
                source_file=source_file,
                parsed_at=datetime.utcnow(),
                hosts=hosts,
                scan_info={'scanner': 'csv_import'},
                total_hosts=len(hosts),
                total_vulnerabilities=sum(len(h.vulnerabilities) for h in hosts)
            )

            logger.info(f"CSV parsé: {len(hosts)} hôtes, {result.total_vulnerabilities} vulnérabilités")
            return result

        except Exception as e:
            logger.error(f"Erreur parsing CSV: {e}")
            raise ValueError(f"CSV invalide: {e}")

    @staticmethod
    def _extract_ip(row: dict) -> Optional[str]:
        """Extrait l'adresse IP d'une ligne CSV"""
        # Essayer différents noms de colonnes
        ip_columns = ['ip', 'host', 'target', 'address', 'ip_address']

        for col in ip_columns:
            if col in row and row[col]:
                ip = row[col].strip()
                if validate_ip_address(ip):
                    return ip

        return None

    @staticmethod
    def _parse_csv_row(row: dict) -> Optional[ParsedVulnerability]:
        """Parse une ligne CSV en vulnérabilité"""
        try:
            # Mapping des colonnes communes
            vuln_id = row.get('id', row.get('plugin_id', row.get('cve_id', 'unknown')))
            name = row.get('name', row.get('title', row.get('vulnerability', 'Unknown')))

            # Sévérité
            severity_raw = row.get('severity', row.get('risk', row.get('criticality', 'low')))
            severity = CSVParser._normalize_severity(severity_raw)

            # CVSS
            cvss_score = None
            cvss_raw = row.get('cvss', row.get('cvss_score', row.get('score', '')))
            if cvss_raw:
                try:
                    cvss_score = float(cvss_raw)
                except (ValueError, TypeError):
                    pass

            # Description
            description = row.get('description', row.get('summary', ''))

            # Service et port
            service = row.get('service', row.get('protocol', 'unknown'))
            port_raw = row.get('port', row.get('port_number', '0'))

            try:
                port = int(port_raw)
            except (ValueError, TypeError):
                port = 0

            # CVEs
            cve_raw = row.get('cve', row.get('cves', ''))
            cves = []
            if cve_raw:
                # Séparer par virgule ou espace
                cves = re.findall(r'CVE-\d{4}-\d{4,}', cve_raw)

            # Solution
            solution = row.get('solution', row.get('fix', row.get('remediation', '')))

            return ParsedVulnerability(
                id=str(vuln_id),
                name=name,
                severity=severity,
                cvss_score=cvss_score,
                description=description[:500],
                affected_service=service,
                affected_port=port,
                cve_ids=cves,
                references=[],
                solution=solution
            )

        except Exception as e:
            logger.warning(f"Erreur parsing ligne CSV: {e}")
            return None

    @staticmethod
    def _normalize_severity(severity_raw: str) -> str:
        """Normalise la sévérité depuis différents formats"""
        if not severity_raw:
            return 'LOW'

        severity_lower = severity_raw.lower().strip()

        # Mapping des différents formats
        if severity_lower in ['critical', '4', 'very high']:
            return 'CRITICAL'
        elif severity_lower in ['high', '3', 'severe']:
            return 'HIGH'
        elif severity_lower in ['medium', '2', 'moderate']:
            return 'MEDIUM'
        elif severity_lower in ['low', '1', 'minor']:
            return 'LOW'
        else:
            return 'LOW'


# === PARSERS DE CONFIGURATION ===

class ConfigParser:
    """Parser pour les fichiers de configuration système"""

    @staticmethod
    def parse_apache_config(config_path: Union[str, Path]) -> Dict[str, Any]:
        """Parse une configuration Apache"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()

            config = {
                'server_root': None,
                'listen_ports': [],
                'modules': [],
                'virtual_hosts': [],
                'ssl_enabled': False,
                'security_headers': {},
                'potential_issues': []
            }

            lines = content.split('\n')
            in_vhost = False
            current_vhost = {}

            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # ServerRoot
                if line.startswith('ServerRoot'):
                    config['server_root'] = line.split()[1].strip('"')

                # Listen
                elif line.startswith('Listen'):
                    port_match = re.search(r':?(\d+)', line)
                    if port_match:
                        config['listen_ports'].append(int(port_match.group(1)))

                # LoadModule
                elif line.startswith('LoadModule'):
                    module = line.split()[1]
                    config['modules'].append(module)
                    if 'ssl' in module.lower():
                        config['ssl_enabled'] = True

                # VirtualHost
                elif line.startswith('<VirtualHost'):
                    in_vhost = True
                    current_vhost = {'directives': []}
                elif line.startswith('</VirtualHost>'):
                    in_vhost = False
                    config['virtual_hosts'].append(current_vhost)
                    current_vhost = {}
                elif in_vhost:
                    current_vhost['directives'].append(line)

                # En-têtes de sécurité
                elif 'Header' in line and any(header in line for header in
                                              ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']):
                    header_match = re.search(r'Header.*"([^"]+)"', line)
                    if header_match:
                        config['security_headers'][header_match.group(1)] = True

            # Identifier les problèmes potentiels
            ConfigParser._identify_apache_issues(config)

            logger.info(f"Configuration Apache parsée: {len(config['virtual_hosts'])} vhosts")
            return config

        except Exception as e:
            logger.error(f"Erreur parsing config Apache: {e}")
            return {'error': str(e)}

    @staticmethod
    def _identify_apache_issues(config: Dict[str, Any]):
        """Identifie les problèmes de sécurité dans la configuration Apache"""
        issues = []

        # Vérifier SSL
        if not config['ssl_enabled']:
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'SSL module not loaded',
                'recommendation': 'Enable SSL module for HTTPS support'
            })

        # Vérifier les en-têtes de sécurité
        security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']
        for header in security_headers:
            if header not in config['security_headers']:
                issues.append({
                    'severity': 'LOW',
                    'issue': f'Missing security header: {header}',
                    'recommendation': f'Add {header} header for security'
                })

        # Vérifier les modules dangereux
        dangerous_modules = ['mod_userdir', 'mod_info', 'mod_status']
        for module in config['modules']:
            if any(dangerous in module for dangerous in dangerous_modules):
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': f'Potentially dangerous module enabled: {module}',
                    'recommendation': f'Review necessity of {module} module'
                })

        config['potential_issues'] = issues


# === PARSERS DE LOGS ===

class LogParser:
    """Parser pour les logs de sécurité"""

    @staticmethod
    def parse_auth_log(log_path: Union[str, Path],
                       lines_limit: int = 1000) -> Dict[str, Any]:
        """Parse les logs d'authentification Linux"""
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Limiter le nombre de lignes pour les performances
            if len(lines) > lines_limit:
                lines = lines[-lines_limit:]

            analysis = {
                'total_entries': len(lines),
                'failed_logins': [],
                'successful_logins': [],
                'suspicious_activity': [],
                'brute_force_attempts': {},
                'summary': {}
            }

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Parse des tentatives de connexion
                LogParser._parse_auth_line(line, analysis)

            # Analyser les tentatives de brute force
            LogParser._analyze_brute_force(analysis)

            # Générer le résumé
            analysis['summary'] = {
                'failed_login_count': len(analysis['failed_logins']),
                'successful_login_count': len(analysis['successful_logins']),
                'suspicious_activity_count': len(analysis['suspicious_activity']),
                'brute_force_sources': len(analysis['brute_force_attempts'])
            }

            logger.info(f"Auth log parsé: {analysis['summary']}")
            return analysis

        except Exception as e:
            logger.error(f"Erreur parsing auth log: {e}")
            return {'error': str(e)}

    @staticmethod
    def _parse_auth_line(line: str, analysis: Dict[str, Any]):
        """Parse une ligne de log d'authentification"""
        timestamp_match = re.match(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', line)
        timestamp = timestamp_match.group(1) if timestamp_match else 'unknown'

        # Tentatives de connexion échouées
        if 'Failed password' in line or 'authentication failure' in line:
            user_match = re.search(r'user (\w+)', line)
            ip_match = re.search(r'from ([\d.]+)', line)

            failure = {
                'timestamp': timestamp,
                'user': user_match.group(1) if user_match else 'unknown',
                'ip': ip_match.group(1) if ip_match else 'unknown',
                'line': line
            }
            analysis['failed_logins'].append(failure)

            # Compter pour brute force
            ip = failure['ip']
            if ip != 'unknown':
                if ip not in analysis['brute_force_attempts']:
                    analysis['brute_force_attempts'][ip] = []
                analysis['brute_force_attempts'][ip].append(failure)

        # Connexions réussies
        elif 'Accepted password' in line or 'session opened' in line:
            user_match = re.search(r'user (\w+)', line)
            ip_match = re.search(r'from ([\d.]+)', line)

            success = {
                'timestamp': timestamp,
                'user': user_match.group(1) if user_match else 'unknown',
                'ip': ip_match.group(1) if ip_match else 'unknown'
            }
            analysis['successful_logins'].append(success)

        # Activité suspecte
        elif any(suspicious in line.lower() for suspicious in
                 ['invalid user', 'illegal user', 'break-in attempt']):
            analysis['suspicious_activity'].append({
                'timestamp': timestamp,
                'activity': line,
                'type': 'suspicious_user'
            })

    @staticmethod
    def _analyze_brute_force(analysis: Dict[str, Any]):
        """Analyse les tentatives de brute force"""
        # Seuil pour considérer comme brute force
        threshold = 10

        brute_force_ips = []
        for ip, attempts in analysis['brute_force_attempts'].items():
            if len(attempts) >= threshold:
                brute_force_ips.append({
                    'ip': ip,
                    'attempt_count': len(attempts),
                    'users_targeted': list(set(a['user'] for a in attempts)),
                    'first_attempt': attempts[0]['timestamp'],
                    'last_attempt': attempts[-1]['timestamp']
                })

        analysis['brute_force_sources'] = brute_force_ips


# === PARSER UNIFIÉ ===

class UnifiedParser:
    """Parser unifié qui détecte automatiquement le format"""

    PARSERS = {
        'nmap_xml': NmapParser.parse_xml,
        'openvas_xml': OpenVASParser.parse_xml,
        'tenable_json': TenableParser.parse_json,
        'csv': CSVParser.parse_csv,
    }

    @staticmethod
    def parse_file(file_path: Union[str, Path]) -> ParseResult:
        """
        Parse automatiquement un fichier selon son format

        Args:
            file_path: Chemin vers le fichier

        Returns:
            ParseResult: Résultats parsés

        Raises:
            ValueError: Si le format n'est pas reconnu
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Fichier non trouvé: {file_path}")

        # Détecter le format
        file_type = UnifiedParser._detect_format(file_path)

        if file_type not in UnifiedParser.PARSERS:
            raise ValueError(f"Format non supporté: {file_type}")

        # Parser avec le bon parser
        parser_func = UnifiedParser.PARSERS[file_type]

        try:
            result = parser_func(file_path)
            logger.info(f"Fichier parsé avec succès: {file_path} ({file_type})")
            return result
        except Exception as e:
            logger.error(f"Erreur parsing {file_path}: {e}")
            raise

    @staticmethod
    def _detect_format(file_path: Path) -> str:
        """Détecte automatiquement le format d'un fichier"""

        # Détecter par extension
        extension = file_path.suffix.lower()
        if extension == '.csv':
            return 'csv'
        elif extension == '.json':
            return 'tenable_json'

        # Détecter par contenu pour XML
        if extension == '.xml':
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read(1000)  # Lire les premiers 1000 caractères

                if '<nmaprun' in content:
                    return 'nmap_xml'
                elif '<report' in content and 'openvas' in content.lower():
                    return 'openvas_xml'
                else:
                    return 'nmap_xml'  # Par défaut pour XML

            except Exception:
                return 'nmap_xml'  # Par défaut

        # Détecter par contenu général
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read(1000)

            if content.strip().startswith('{'):
                return 'tenable_json'
            elif content.strip().startswith('<'):
                if '<nmaprun' in content:
                    return 'nmap_xml'
                else:
                    return 'openvas_xml'
            else:
                # Essayer de détecter CSV
                lines = content.split('\n')[:5]
                if any(',' in line for line in lines):
                    return 'csv'

        except Exception:
            pass

        # Par défaut, essayer XML Nmap
        return 'nmap_xml'

    @staticmethod
    def get_supported_formats() -> List[str]:
        """Retourne la liste des formats supportés"""
        return list(UnifiedParser.PARSERS.keys())

    @staticmethod
    def validate_file_format(file_path: Union[str, Path], expected_format: str) -> bool:
        """
        Valide qu'un fichier correspond au format attendu

        Args:
            file_path: Chemin vers le fichier
            expected_format: Format attendu

        Returns:
            bool: True si le format correspond
        """
        try:
            detected_format = UnifiedParser._detect_format(Path(file_path))
            return detected_format == expected_format
        except Exception:
            return False


# === FONCTIONS UTILITAIRES ===

def parse_vulnerability_file(file_path: Union[str, Path]) -> ParseResult:
    """
    Fonction principale pour parser un fichier de vulnérabilités

    Args:
        file_path: Chemin vers le fichier

    Returns:
        ParseResult: Résultats parsés
    """
    return UnifiedParser.parse_file(file_path)


def convert_to_json(parse_result: ParseResult, indent: int = 2) -> str:
    """
    Convertit un ParseResult en JSON

    Args:
        parse_result: Résultat de parsing
        indent: Indentation JSON

    Returns:
        str: JSON formaté
    """

    def serialize_obj(obj):
        """Sérialise les objets personnalisés"""
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        elif isinstance(obj, datetime):
            return obj.isoformat()
        return str(obj)

    result_dict = {
        'source_type': parse_result.source_type,
        'source_file': parse_result.source_file,
        'parsed_at': parse_result.parsed_at.isoformat(),
        'total_hosts': parse_result.total_hosts,
        'total_vulnerabilities': parse_result.total_vulnerabilities,
        'scan_info': parse_result.scan_info,
        'hosts': []
    }

    for host in parse_result.hosts:
        host_dict = {
            'ip': host.ip,
            'hostname': host.hostname,
            'mac_address': host.mac_address,
            'os_info': host.os_info,
            'status': host.status,
            'open_ports': host.open_ports,
            'services': host.services,
            'vulnerabilities': []
        }

        for vuln in host.vulnerabilities:
            vuln_dict = {
                'id': vuln.id,
                'name': vuln.name,
                'severity': vuln.severity,
                'cvss_score': vuln.cvss_score,
                'description': vuln.description,
                'affected_service': vuln.affected_service,
                'affected_port': vuln.affected_port,
                'cve_ids': vuln.cve_ids,
                'references': vuln.references,
                'solution': vuln.solution,
                'risk_factor': vuln.risk_factor
            }
            host_dict['vulnerabilities'].append(vuln_dict)

        result_dict['hosts'].append(host_dict)

    return json.dumps(result_dict, indent=indent, ensure_ascii=False)


def filter_vulnerabilities_by_severity(
        parse_result: ParseResult,
        min_severity: str = 'MEDIUM'
) -> ParseResult:
    """
    Filtre les vulnérabilités par niveau de sévérité minimum

    Args:
        parse_result: Résultat de parsing
        min_severity: Sévérité minimum (LOW, MEDIUM, HIGH, CRITICAL)

    Returns:
        ParseResult: Résultats filtrés
    """
    severity_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    min_level = severity_levels.get(min_severity, 2)

    filtered_hosts = []

    for host in parse_result.hosts:
        filtered_vulns = []
        for vuln in host.vulnerabilities:
            vuln_level = severity_levels.get(vuln.severity, 1)
            if vuln_level >= min_level:
                filtered_vulns.append(vuln)

        if filtered_vulns:  # Garder seulement les hôtes avec vulnérabilités
            filtered_host = ParsedHost(
                ip=host.ip,
                hostname=host.hostname,
                mac_address=host.mac_address,
                os_info=host.os_info,
                status=host.status,
                open_ports=host.open_ports,
                services=host.services,
                vulnerabilities=filtered_vulns
            )
            filtered_hosts.append(filtered_host)

    return ParseResult(
        source_type=parse_result.source_type,
        source_file=parse_result.source_file,
        parsed_at=parse_result.parsed_at,
        hosts=filtered_hosts,
        scan_info=parse_result.scan_info,
        total_hosts=len(filtered_hosts),
        total_vulnerabilities=sum(len(h.vulnerabilities) for h in filtered_hosts)
    )


def generate_summary_report(parse_result: ParseResult) -> Dict[str, Any]:
    """
    Génère un rapport de résumé des vulnérabilités

    Args:
        parse_result: Résultat de parsing

    Returns:
        Dict: Rapport de résumé
    """
    summary = {
        'scan_info': {
            'source_type': parse_result.source_type,
            'source_file': parse_result.source_file,
            'parsed_at': parse_result.parsed_at.isoformat(),
            'total_hosts': parse_result.total_hosts,
            'total_vulnerabilities': parse_result.total_vulnerabilities
        },
        'severity_breakdown': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0},
        'top_vulnerabilities': [],
        'affected_services': {},
        'host_summary': []
    }

    all_vulnerabilities = []

    for host in parse_result.hosts:
        host_vulns = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

        for vuln in host.vulnerabilities:
            # Compter par sévérité
            severity = vuln.severity if vuln.severity in summary['severity_breakdown'] else 'LOW'
            summary['severity_breakdown'][severity] += 1
            host_vulns[severity] += 1

            # Compter par service
            service = vuln.affected_service
            if service not in summary['affected_services']:
                summary['affected_services'][service] = 0
            summary['affected_services'][service] += 1

            all_vulnerabilities.append(vuln)

        # Résumé par hôte
        summary['host_summary'].append({
            'ip': host.ip,
            'hostname': host.hostname,
            'total_vulnerabilities': len(host.vulnerabilities),
            'severity_breakdown': host_vulns,
            'open_ports': len(host.open_ports),
            'services_count': len(host.services)
        })

    # Top vulnérabilités (par occurrence)
    vuln_counts = {}
    for vuln in all_vulnerabilities:
        key = f"{vuln.name}_{vuln.severity}"
        if key not in vuln_counts:
            vuln_counts[key] = {'vuln': vuln, 'count': 0, 'hosts': set()}
        vuln_counts[key]['count'] += 1
        vuln_counts[key]['hosts'].add(vuln.affected_service)  # Approximation

    # Trier par occurrence et sévérité
    severity_weight = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
    sorted_vulns = sorted(
        vuln_counts.items(),
        key=lambda x: (severity_weight.get(x[1]['vuln'].severity, 0), x[1]['count']),
        reverse=True
    )

    summary['top_vulnerabilities'] = [
        {
            'name': data['vuln'].name,
            'severity': data['vuln'].severity,
            'cvss_score': data['vuln'].cvss_score,
            'occurrence_count': data['count'],
            'affected_hosts': len(data['hosts']),
            'cve_ids': data['vuln'].cve_ids[:3]  # Limiter à 3 CVE
        }
        for _, data in sorted_vulns[:10]  # Top 10
    ]

    return summary


if __name__ == "__main__":
    # Tests des parsers
    def test_parsers():
        print("Test des parsers de vulnérabilités")

        # Test des formats supportés
        print(f"Formats supportés: {UnifiedParser.get_supported_formats()}")

        # Exemple de parsing d'un fichier
        # result = parse_vulnerability_file("example_scan.xml")
        # print(f"Résultat: {result.total_vulnerabilities} vulnérabilités trouvées")

        print("Tests terminés")


    test_parsers()