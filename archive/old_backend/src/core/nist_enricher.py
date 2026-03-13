"""
Module d'enrichissement NIST
Récupère les scores CVSS officiels et les liens de solutions
"""

import requests
import time
from typing import Dict, Optional, List

class NISTEnricher:
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        self.cache = {}  # Cache simple en mémoire
        self.last_request_time = 0

    async def enrich_cve(self, cve_id: str) -> Optional[Dict]:
        """Enrichit un CVE avec les données NIST officielles"""
        # Vérifier le cache
        if cve_id in self.cache:
            return self.cache[cve_id]

        # Rate limiting (5 req/30s sans API key)
        time_since_last = time.time() - self.last_request_time
        if time_since_last < 6:
            time.sleep(6 - time_since_last)
        self.last_request_time = time.time()

        # Appeler NIST
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            response = requests.get(
                f"{self.base_url}?cveId={cve_id}",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                enriched_data = self._parse_nist_response(data)
                if enriched_data:
                    self.cache[cve_id] = enriched_data
                return enriched_data

        except Exception as e:
            print(f"Erreur NIST pour {cve_id}: {e}")

        return None

    def _parse_nist_response(self, data: Dict) -> Optional[Dict]:
        """Parse la réponse NIST et extrait les infos utiles"""
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        cve = vulns[0].get("cve", {})

        return {
            "cvss_score": self._extract_cvss_score(cve),
            "severity": self._extract_severity(cve),
            "description": self._extract_description(cve),
            "solution_links": self._extract_solution_links(cve),
            "references": self._extract_references(cve)
        }

    def _extract_cvss_score(self, cve_data: Dict) -> Optional[float]:
        metrics = cve_data.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            return metrics['cvssMetricV31'][0]['cvssData']['baseScore']
        elif 'cvssMetricV30' in metrics:
            return metrics['cvssMetricV30'][0]['cvssData']['baseScore']
        elif 'cvssMetricV2' in metrics:
            return metrics['cvssMetricV2'][0]['cvssData']['baseScore']
        return None

    def _extract_severity(self, cve_data: Dict) -> str:
        metrics = cve_data.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            return metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
        elif 'cvssMetricV30' in metrics:
            return metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
        return "UNKNOWN"

    def _extract_description(self, cve_data: Dict) -> str:
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        return ""

    def _extract_solution_links(self, cve_data: Dict) -> List[str]:
        solutions = []
        for ref in cve_data.get('references', []):
            tags = ref.get('tags', [])
            url = ref.get('url', '')
            if 'Patch' in tags or 'Vendor Advisory' in tags:
                solutions.append(url)
        return solutions

    def _extract_references(self, cve_data: Dict) -> List[str]:
        return [ref.get('url', '') for ref in cve_data.get('references', [])]
