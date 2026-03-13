"""
Module pour récupérer les solutions textuelles depuis l'API OSV.dev
et formater en phrases simples pour détection de patterns par l'IA.
"""

import re
import asyncio
import httpx
from typing import Dict, Optional, List, Any


class SolutionFetcher:
    """
    Récupère les solutions textuelles depuis l'API OSV.dev
    et les formate en phrases simples pour l'IA.
    
    L'objectif est de fournir un texte avec toutes les solutions
    pour que Claude puisse détecter les patterns répétés et identifier
    les mises à jour qui corrigent le maximum de vulnérabilités.
    """
    
    def __init__(self):
        self.base_url = "https://api.osv.dev/v1/vulns"
        self.cache = {}  # Cache pour éviter les appels répétés
    
    async def fetch_solution_text(self, cve_id: str) -> Optional[str]:
        """
        Récupère la solution textuelle pour une CVE depuis OSV.dev
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
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self.base_url}/{cve_id}",
                    headers={"User-Agent": "SecurityAgent/1.0"}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    solution_phrase = self._extract_solution_phrase(cve_id, data)
                    if solution_phrase:
                        self.cache[cve_id] = solution_phrase
                        return solution_phrase
                elif response.status_code == 404:
                    # CVE non trouvée dans OSV
                    print(f"⚠️ CVE {cve_id} non trouvée dans OSV.dev")
                    return None
                    
        except httpx.TimeoutException:
            print(f"⚠️ Timeout API OSV pour {cve_id}")
        except Exception as e:
            print(f"⚠️ Erreur API OSV pour {cve_id}: {e}")
        
        return None
    
    def _extract_solution_phrase(self, cve_id: str, osv_data: Dict) -> Optional[str]:
        """
        Extrait une phrase de solution depuis la réponse OSV.dev.
        
        Format OSV typique :
        {
          "id": "CVE-2023-XXXX",
          "affected": [{
            "package": {"name": "apache", "ecosystem": "..."},
            "ranges": [{
              "type": "ECOSYSTEM",
              "events": [
                {"introduced": "0"},
                {"fixed": "2.4.62"}
              ]
            }]
          }]
        }
        
        Args:
            cve_id: ID de la CVE
            osv_data: Données JSON de l'API OSV.dev
        
        Returns:
            Phrase simple décrivant la solution, ou None
        """
        affected = osv_data.get("affected", [])
        if not affected:
            return None
        
        # Extraire les informations de solution
        package_name = None
        fixed_version = None
        
        for item in affected:
            package = item.get("package", {})
            package_name = package.get("name", "")
            
            ranges = item.get("ranges", [])
            for range_item in ranges:
                events = range_item.get("events", [])
                for event in events:
                    if "fixed" in event:
                        fixed_version = event["fixed"]
                        break
                if fixed_version:
                    break
            if fixed_version:
                break
        
        # Si on a trouvé package et version, formater la phrase
        if package_name and fixed_version:
            # Normaliser le nom du package
            package_display = self._normalize_package_name(package_name)
            
            return f"{cve_id} se règle en mettant à jour {package_display} vers {fixed_version}"
        
        # Fallback : chercher dans details ou database_specific
        details = osv_data.get("details", "") or osv_data.get("summary", "")
        if details:
            # Chercher des patterns de version dans les détails
            version_match = re.search(
                r'(?:upgrade|update|version|fixed|patch)\s+(?:to\s+)?(\d+\.\d+\.\d+)',
                details,
                re.IGNORECASE
            )
            if version_match:
                version = version_match.group(1)
                # Essayer d'extraire aussi le nom du composant
                component_match = re.search(
                    r'(apache|nginx|openssl|php|mysql|postgres|kernel|libssl)',
                    details,
                    re.IGNORECASE
                )
                if component_match:
                    component = self._normalize_package_name(component_match.group(1))
                    return f"{cve_id} se règle en mettant à jour {component} vers {version}"
                else:
                    return f"{cve_id} se règle en mettant à jour vers la version {version}"
        
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
        
        # Récupérer toutes les solutions en parallèle
        tasks = []
        cve_ids = []
        
        for vuln in limited_vulns:
            cve_id = vuln.get("vulnerability_id", "")
            if cve_id.startswith("CVE-"):
                tasks.append(self.fetch_solution_text(cve_id))
                cve_ids.append(cve_id)
        
        if not tasks:
            return ""
        
        print(f"📡 Récupération des solutions depuis OSV.dev pour {len(tasks)} CVE...")
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filtrer les None et exceptions
        solutions = []
        for i, result in enumerate(results):
            if isinstance(result, str):
                solutions.append(result)
            elif isinstance(result, Exception):
                print(f"⚠️ Erreur récupération solution pour {cve_ids[i]}: {result}")
        
        print(f"✅ {len(solutions)} solutions récupérées sur {len(tasks)} CVE")
        
        return "\n".join(solutions)

