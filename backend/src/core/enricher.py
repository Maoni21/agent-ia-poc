"""
Enrichissement externe des vulnérabilités.

Sources :
  - NVD (NIST) : CVSS v3.1 vector complet, description officielle, CWE, références, dates
  - EPSS (FIRST.org) : probabilité d'exploitation dans les 30 prochains jours
  - CISA KEV : liste des CVE activement exploitées en production (catalog officiel US-CERT)

Usage depuis le scan_worker :
    from src.core.enricher import enrich_cve_batch
    results = await enrich_cve_batch(["CVE-2021-44228", "CVE-2017-0144"])
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

import httpx
import requests

logger = logging.getLogger(__name__)


# ── CISA KEV – cache process-level (valide 24h) ──────────────────────────────

_kev_cache: Optional[frozenset] = None
_kev_cache_ts: float = 0.0
_KEV_TTL = 86_400          # 24h en secondes
_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def _get_kev_set() -> frozenset:
    """Retourne l'ensemble des CVE CISA KEV, avec cache 24h."""
    global _kev_cache, _kev_cache_ts

    now = time.monotonic()
    if _kev_cache is not None and (now - _kev_cache_ts) < _KEV_TTL:
        return _kev_cache

    try:
        resp = requests.get(_KEV_URL, timeout=20, headers={"User-Agent": "CyberSecAI/1.0"})
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        kev = frozenset(v["cveID"].upper() for v in vulns if "cveID" in v)
        _kev_cache = kev
        _kev_cache_ts = now
        logger.info("CISA KEV chargé : %d CVE activement exploitées", len(kev))
        return kev
    except Exception as exc:
        logger.warning("Impossible de charger CISA KEV : %s", exc)
        return _kev_cache if _kev_cache is not None else frozenset()


# ── NVD (NIST) ────────────────────────────────────────────────────────────────

def _parse_nvd(data: dict) -> Optional[dict]:
    """Extrait les champs utiles depuis la réponse NVD API v2."""
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})

    # Description anglaise officielle
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )

    # CVSS : v3.1 > v3.0 > v2
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_version: Optional[str] = None
    severity: Optional[str] = None
    metrics = cve.get("metrics", {})
    for key, ver in [("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")]:
        if key in metrics:
            d = metrics[key][0].get("cvssData", {})
            cvss_score = d.get("baseScore")
            cvss_vector = d.get("vectorString")
            severity = d.get("baseSeverity")
            cvss_version = ver
            break

    # CWE
    cwe_ids = list({
        desc["value"]
        for w in cve.get("weaknesses", [])
        for desc in w.get("description", [])
        if desc.get("value", "").startswith("CWE-")
    })

    # Références avec tags
    refs = cve.get("references", [])
    references = [{"url": r.get("url", ""), "tags": r.get("tags", [])} for r in refs]
    patch_refs = [
        r["url"] for r in references
        if any(t in r["tags"] for t in ("Patch", "Vendor Advisory", "Mitigation"))
    ]

    # Dates
    published = cve.get("published")
    last_modified = cve.get("lastModified")

    # CPE (produits affectés – limité à 10)
    affected: List[dict] = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if cpe.get("vulnerable"):
                    affected.append({
                        "cpe": cpe.get("criteria", ""),
                        "version_start": cpe.get("versionStartIncluding"),
                        "version_end": cpe.get("versionEndExcluding"),
                    })
                    if len(affected) >= 10:
                        break

    return {
        "source": "NVD",
        "cvss_score": float(cvss_score) if cvss_score is not None else None,
        "cvss_vector": cvss_vector,
        "cvss_version": cvss_version,
        "severity": severity,
        "description": description,
        "cwe_ids": cwe_ids,
        "references": references[:20],
        "patch_references": patch_refs,
        "published_date": published,
        "last_modified": last_modified,
        "affected_products": affected,
    }


async def _fetch_nvd(client: httpx.AsyncClient, cve_id: str, api_key: Optional[str] = None) -> Optional[dict]:
    """Appel NVD API v2 pour un CVE donné."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": api_key} if api_key else {}
    try:
        resp = await client.get(url, params={"cveId": cve_id}, headers=headers, timeout=15)
        if resp.status_code == 200:
            return _parse_nvd(resp.json())
        if resp.status_code == 404:
            return None
        logger.warning("NVD %s : HTTP %s", cve_id, resp.status_code)
        return None
    except Exception as exc:
        logger.warning("NVD erreur %s : %s", cve_id, exc)
        return None


# ── EPSS (FIRST.org) – batch ──────────────────────────────────────────────────

async def _fetch_epss_batch(client: httpx.AsyncClient, cve_ids: List[str]) -> Dict[str, dict]:
    """
    Récupère les scores EPSS pour plusieurs CVE en un seul appel.
    https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B,...
    """
    if not cve_ids:
        return {}

    results: Dict[str, dict] = {}
    # L'API accepte jusqu'à ~100 CVE par requête
    chunk_size = 80
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i : i + chunk_size]
        try:
            resp = await client.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": ",".join(chunk)},
                timeout=15,
            )
            if resp.status_code == 200:
                for item in resp.json().get("data", []):
                    cve = item.get("cve", "").upper()
                    results[cve] = {
                        "epss_score": float(item.get("epss", 0)),
                        "epss_percentile": float(item.get("percentile", 0)),
                        "epss_date": item.get("date"),
                    }
        except Exception as exc:
            logger.warning("EPSS erreur batch : %s", exc)

    return results


# ── API publique ──────────────────────────────────────────────────────────────

async def enrich_cve_batch(
    cve_ids: List[str],
    nvd_api_key: Optional[str] = None,
) -> Dict[str, dict]:
    """
    Enrichit une liste de CVE depuis NVD + EPSS + CISA KEV.

    Retourne un dict { cve_id.upper() -> enrichment_dict }.

    Le dict d'enrichissement contient :
      - cisa_kev        (bool)
      - epss_score      (float 0-1)
      - epss_percentile (float 0-1)
      - cvss_vector     (str CVSS:3.1/…)
      - cvss_version    (str "3.1"/"3.0"/"2.0")
      - cwe_ids         (list[str])
      - description     (str description officielle NVD)
      - patch_references (list[str] URLs)
      - published_date  (str ISO)
      - affected_products (list[dict])
      - enriched_at     (str ISO)
    """
    if not cve_ids:
        return {}

    # Dédupliquer et normaliser
    unique = list({c.upper() for c in cve_ids if c and c.upper().startswith("CVE-")})
    if not unique:
        return {}

    logger.info("Enrichissement de %d CVE (NVD + EPSS + CISA KEV)…", len(unique))
    now_iso = datetime.utcnow().isoformat()

    # Charger CISA KEV (synchrone, mise en cache)
    try:
        kev_set = await asyncio.get_event_loop().run_in_executor(None, _get_kev_set)
    except Exception:
        kev_set = frozenset()

    results: Dict[str, dict] = {}

    async with httpx.AsyncClient(
        headers={"User-Agent": "CyberSecAI/1.0"},
        follow_redirects=True,
    ) as client:

        # ── EPSS batch (un seul appel pour tous les CVE) ──────────────────
        epss_map = await _fetch_epss_batch(client, unique)

        # ── NVD séquentiel avec rate-limiting ─────────────────────────────
        # Sans clé API : 5 req/30s → attendre ~6s entre chaque appel
        # Avec clé API : 50 req/30s → attendre ~0.6s
        delay = 0.7 if nvd_api_key else 6.1

        for idx, cve_id in enumerate(unique):
            if idx > 0:
                await asyncio.sleep(delay)

            nvd = await _fetch_nvd(client, cve_id, nvd_api_key)
            epss = epss_map.get(cve_id, {})
            in_kev = cve_id in kev_set

            entry: dict = {
                "enriched_at": now_iso,
                "cisa_kev": in_kev,
                "epss_score": epss.get("epss_score"),
                "epss_percentile": epss.get("epss_percentile"),
            }

            if nvd:
                entry.update({
                    "cvss_vector": nvd.get("cvss_vector"),
                    "cvss_version": nvd.get("cvss_version"),
                    "cwe_ids": nvd.get("cwe_ids", []),
                    "description": nvd.get("description", ""),
                    "patch_references": nvd.get("patch_references", []),
                    "published_date": nvd.get("published_date"),
                    "last_modified": nvd.get("last_modified"),
                    "affected_products": nvd.get("affected_products", []),
                    "nvd_cvss_score": nvd.get("cvss_score"),
                    "nvd_severity": nvd.get("severity"),
                })

            results[cve_id] = entry

    logger.info("Enrichissement terminé : %d/%d CVE enrichis", len(results), len(unique))
    return results
