"""
Module pour récupérer les solutions textuelles depuis l'API Vulners
et formater en phrases simples pour détection de patterns par l'IA.
"""

import re
import asyncio
import httpx
from typing import Dict, Optional, List, Any


class VulnersFetcher:
    """
    Récupère les solutions textuelles depuis l'API Vulners
    et les formate en phrases simples pour l'IA.
    
    L'objectif est de fournir un texte avec toutes les solutions
    pour que Claude puisse détecter les patterns répétés et identifier
    les mises à jour qui corrigent le maximum de vulnérabilités.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://vulners.com/api/v3/search/id/"
        self.api_key = api_key
        self.cache = {}  # Cache pour éviter les appels répétés
    
    async def fetch_solution_text(self, cve_id: str) -> Optional[str]:
        """
        Récupère la solution textuelle pour une CVE depuis Vulners
        et retourne une phrase simple du style :
        "CVE-2023-XXXX se règle en mettant à jour Apache vers 2.4.62"
        
        Args:
            cve_id: ID de la CVE (ex: "CVE-2023-1234")
        
        Returns:
            Phrase simple décrivant la solution, ou None si non trouvée
        """
        # Vérifier le cache
        if cve_id in self.cache:
            return self.cache[cve_id]
        
        try:
            # Timeout court pour éviter de bloquer
            async with httpx.AsyncClient(timeout=5.0) as client:
                params = {"id": cve_id}
                if self.api_key:
                    params["apiKey"] = self.api_key
                
                response = await client.get(
                    self.base_url,
                    params=params,
                    headers={"User-Agent": "SecurityAgent/1.0"}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    solution_phrase = self._extract_solution_phrase(cve_id, data)
                    if solution_phrase:
                        self.cache[cve_id] = solution_phrase
                        return solution_phrase
                elif response.status_code == 404:
                    # CVE non trouvée dans Vulners - pas de log pour éviter le spam
                    return None
                    
        except (httpx.TimeoutException, asyncio.TimeoutError):
            # Timeout silencieux pour ne pas spammer les logs
            return None
        except Exception as e:
            # Log seulement les erreurs critiques
            if "timeout" not in str(e).lower():
                print(f"⚠️ Erreur API Vulners pour {cve_id}: {e}")
        
        return None
    
    def _extract_solution_phrase(self, cve_id: str, vulners_data: Dict) -> Optional[str]:
        """
        Extrait une phrase de solution depuis la réponse Vulners.
        
        Format Vulners typique :
        {
          "data": {
            "documents": {
              "CVE-2023-XXXX": {
                "description": "...",
                "remediation": "...",
                "cvelist": ["CVE-2023-XXXX"],
                "cvss": {"score": 9.8},
                "affectedSoftware": [...],
                "type": "cve"
              }
            }
          }
        }
        
        Args:
            cve_id: ID de la CVE
            vulners_data: Données JSON de l'API Vulners
        
        Returns:
            Phrase simple décrivant la solution, ou None
        """
        documents = vulners_data.get("data", {}).get("documents", {})
        if not documents:
            return None
        
        # Prendre le premier document (généralement la CVE elle-même)
        doc = list(documents.values())[0] if documents else {}
        
        # Chercher dans remediation en premier
        remediation = doc.get("remediation", "") or doc.get("description", "")
        
        if remediation:
            # Chercher des patterns de version dans la remediation
            version_match = re.search(
                r'(?:upgrade|update|version|fixed|patch|install)\s+(?:to\s+)?(\d+\.\d+\.\d+)',
                remediation,
                re.IGNORECASE
            )
            if version_match:
                version = version_match.group(1)
                # Essayer d'extraire le nom du composant
                component_match = re.search(
                    r'(apache|nginx|openssl|php|mysql|postgres|kernel|libssl|httpd|python|node)',
                    remediation,
                    re.IGNORECASE
                )
                if component_match:
                    component = self._normalize_package_name(component_match.group(1))
                    return f"{cve_id} se règle en mettant à jour {component} vers {version}"
                else:
                    return f"{cve_id} se règle en mettant à jour vers la version {version}"
        
        # Chercher dans affectedSoftware
        affected_software = doc.get("affectedSoftware", [])
        if affected_software:
            for item in affected_software:
                software_name = item.get("name", "")
                fixed_version = item.get("versionEndExcluding") or item.get("versionEndIncluding")
                
                if software_name and fixed_version:
                    component = self._normalize_package_name(software_name)
                    return f"{cve_id} se règle en mettant à jour {component} vers {fixed_version}"
        
        # Si on a juste le remediation textuel, retourner une phrase générique
        if remediation and len(remediation) > 50:
            # Prendre les 100 premiers caractères et nettoyer
            cleaned = re.sub(r'\s+', ' ', remediation[:100]).strip()
            return f"{cve_id} se règle : {cleaned}"
        
        return None
    
    async def fetch_cvss_info(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Récupère les informations CVSS depuis Vulners pour une CVE.
        
        Returns:
            Dict avec cvss_score et severity, ou None
        """
        # Vérifier le cache
        cache_key = f"{cve_id}_cvss"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            # Timeout court pour éviter de bloquer
            async with httpx.AsyncClient(timeout=5.0) as client:
                params = {"id": cve_id}
                if self.api_key:
                    params["apiKey"] = self.api_key
                
                response = await client.get(
                    self.base_url,
                    params=params,
                    headers={"User-Agent": "SecurityAgent/1.0"}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    documents = data.get("data", {}).get("documents", {})
                    if documents:
                        doc = list(documents.values())[0]
                        cvss_data = doc.get("cvss", {})
                        cvss_score = None
                        severity = "UNKNOWN"
                        
                        if isinstance(cvss_data, dict):
                            cvss_score = cvss_data.get("score") or cvss_data.get("baseScore")
                        elif isinstance(cvss_data, (int, float)):
                            cvss_score = float(cvss_data)
                        
                        # Calculer la sévérité
                        if cvss_score:
                            cvss_float = float(cvss_score)
                            if cvss_float >= 9.0:
                                severity = "CRITICAL"
                            elif cvss_float >= 7.0:
                                severity = "HIGH"
                            elif cvss_float >= 4.0:
                                severity = "MEDIUM"
                            else:
                                severity = "LOW"
                            
                            result = {
                                "cvss_score": cvss_float,
                                "severity": severity
                            }
                            self.cache[cache_key] = result
                            return result
                            
        except (httpx.TimeoutException, asyncio.TimeoutError):
            # Timeout silencieux
            return None
        except Exception as e:
            # Log seulement les erreurs critiques
            if "timeout" not in str(e).lower():
                print(f"⚠️ Erreur CVSS Vulners pour {cve_id}: {e}")
        
        return None
    
    def _normalize_package_name(self, package_name: str) -> str:
        """
        Normalise le nom du package pour un affichage cohérent.
        
        Args:
            package_name: Nom brut du package
        
        Returns:
            Nom normalisé pour l'affichage
        """
        package_lower = package_name.lower()
        
        if "apache" in package_lower or "httpd" in package_lower:
            return "Apache"
        elif "nginx" in package_lower:
            return "Nginx"
        elif "openssl" in package_lower or "libssl" in package_lower:
            return "OpenSSL"
        elif "php" in package_lower:
            return "PHP"
        elif "mysql" in package_lower:
            return "MySQL"
        elif "postgres" in package_lower or "postgresql" in package_lower:
            return "PostgreSQL"
        elif "kernel" in package_lower:
            return "Linux Kernel"
        elif "python" in package_lower:
            return "Python"
        elif "node" in package_lower or "npm" in package_lower:
            return "Node.js"
        else:
            # Capitaliser la première lettre
            return package_name.capitalize()
    
    async def fetch_all_solutions_as_text(
        self, 
        vulnerabilities: List[Dict[str, Any]],
        max_vulns: int = 100
    ) -> str:
        """
        Récupère toutes les solutions pour une liste de vulnérabilités
        et retourne un texte avec une phrase par CVE.
        
        Format retourné :
        ```
        CVE-2023-XXXX se règle en mettant à jour Apache vers 2.4.62
        CVE-2023-YYYY se règle en mettant à jour OpenSSL vers 1.1.1w
        ...
        ```
        
        C'est ce texte qui sera envoyé à Claude pour détecter les patterns répétés.
        
        Args:
            vulnerabilities: Liste des vulnérabilités du scan
            max_vulns: Nombre maximum de vulnérabilités à traiter (par défaut 100)
        
        Returns:
            Texte avec une phrase de solution par CVE, séparées par des sauts de ligne
        """
        # Trier par CVSS décroissant (les plus critiques en premier)
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: x.get("cvss_score", 0) or 0,
            reverse=True,
        )
        
        limited_vulns = sorted_vulns[:max_vulns]
        
        # Récupérer toutes les solutions en parallèle (batch de 20 pour optimiser)
        solutions = []
        cve_ids = []
        
        for vuln in limited_vulns:
            cve_id = vuln.get("vulnerability_id", "")
            if cve_id.startswith("CVE-"):
                cve_ids.append(cve_id)
        
        if not cve_ids:
            return ""
        
        print(f"📡 Récupération des solutions depuis Vulners API pour {len(cve_ids)} CVE...")
        
        # Traiter par batch de 20 pour optimiser les performances
        batch_size = 20
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            tasks = [self.fetch_solution_text(cve_id) for cve_id in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for j, result in enumerate(batch_results):
                if isinstance(result, str):
                    solutions.append(result)
                elif isinstance(result, Exception):
                    print(f"⚠️ Erreur récupération solution pour {batch[j]}: {result}")
        
        print(f"✅ {len(solutions)} solutions récupérées sur {len(cve_ids)} CVE")
        
        return "\n".join(solutions)

