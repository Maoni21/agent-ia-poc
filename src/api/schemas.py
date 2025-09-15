"""
Schémas Pydantic pour l'API REST de l'Agent IA de Cybersécurité

Ce module définit tous les modèles de données utilisés pour la validation
des requêtes et réponses de l'API REST.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, validator, root_validator
import re


# === ÉNUMÉRATIONS ===

class ScanStatus(str, Enum):
    """Statuts possibles d'un scan"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, Enum):
    """Types de scan disponibles"""
    QUICK = "quick"
    FULL = "full"
    STEALTH = "stealth"
    AGGRESSIVE = "aggressive"
    CUSTOM = "custom"


class VulnerabilitySeverity(str, Enum):
    """Niveaux de gravité des vulnérabilités"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ScriptRiskLevel(str, Enum):
    """Niveaux de risque des scripts"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ReportType(str, Enum):
    """Types de rapport disponibles"""
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    REMEDIATION = "remediation"


class ReportFormat(str, Enum):
    """Formats de rapport disponibles"""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"


# === MODÈLES DE BASE ===

class BaseResponse(BaseModel):
    """Modèle de réponse de base"""
    success: bool = True
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    message: Optional[str] = None


class ErrorDetail(BaseModel):
    """Détail d'une erreur"""
    code: int
    message: str
    type: str
    details: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseResponse):
    """Réponse d'erreur standardisée"""
    success: bool = False
    error: ErrorDetail


# === MODÈLES DE SCAN ===

class ScanRequest(BaseModel):
    """Requête de démarrage de scan"""
    target: str = Field(..., description="Adresse IP ou nom de domaine cible")
    scan_type: ScanType = Field(ScanType.FULL, description="Type de scan à effectuer")
    nmap_args: Optional[str] = Field(None, description="Arguments Nmap personnalisés")
    timeout: Optional[int] = Field(300, description="Timeout en secondes", ge=30, le=3600)
    ports: Optional[str] = Field(None, description="Ports spécifiques à scanner")
    scripts: Optional[List[str]] = Field(None, description="Scripts NSE à utiliser")
    exclude_hosts: Optional[List[str]] = Field(None, description="Hôtes à exclure")

    @validator('target')
    def validate_target(cls, v):
        """Valider le format de la cible"""
        # Validation IP
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        # Validation domaine
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'

        if not (re.match(ip_pattern, v) or re.match(domain_pattern, v)):
            raise ValueError('Format de cible invalide (IP ou domaine requis)')
        return v

    @validator('ports')
    def validate_ports(cls, v):
        """Valider le format des ports"""
        if v is None:
            return v

        # Format acceptés: "80", "80,443", "1-1000", "80,443,1000-2000"
        port_pattern = r'^(?:\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*)$'
        if not re.match(port_pattern, v):
            raise ValueError('Format de ports invalide')

        # Vérifier les plages
        for part in v.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                if start > end or start < 1 or end > 65535:
                    raise ValueError('Plage de ports invalide')
            else:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError('Numéro de port invalide')

        return v

    class Config:
        schema_extra = {
            "example": {
                "target": "192.168.1.100",
                "scan_type": "full",
                "nmap_args": "-sV -sC --script vuln",
                "timeout": 600,
                "ports": "22,80,443,1000-2000"
            }
        }


class ScanResponse(BaseResponse):
    """Réponse de démarrage de scan"""
    scan_id: str = Field(..., description="Identifiant unique du scan")
    target: str = Field(..., description="Cible du scan")
    status: ScanStatus = Field(..., description="Statut du scan")
    started_at: datetime = Field(..., description="Date/heure de démarrage")
    estimated_duration: Optional[str] = Field(None, description="Durée estimée")


class ScanResultModel(BaseModel):
    """Résultats détaillés d'un scan"""
    scan_id: str
    target: str
    started_at: datetime
    completed_at: datetime
    duration: int = Field(..., description="Durée en secondes")

    # Résumé
    summary: Dict[str, Any] = Field(..., description="Résumé des résultats")

    # Services et ports
    open_ports: List[int] = Field(..., description="Ports ouverts détectés")
    services: List[Dict[str, Any]] = Field(..., description="Services détectés")

    # Vulnérabilités
    vulnerabilities: List[Dict[str, Any]] = Field(..., description="Vulnérabilités trouvées")

    # Métadonnées
    scan_parameters: Dict[str, Any] = Field(..., description="Paramètres utilisés")
    nmap_version: Optional[str] = Field(None, description="Version Nmap utilisée")

    class Config:
        schema_extra = {
            "example": {
                "scan_id": "550e8400-e29b-41d4-a716-446655440000",
                "target": "192.168.1.100",
                "started_at": "2025-01-15T10:30:00Z",
                "completed_at": "2025-01-15T10:35:00Z",
                "duration": 300,
                "summary": {
                    "total_ports_scanned": 1000,
                    "open_ports_found": 5,
                    "services_identified": 4,
                    "vulnerabilities_found": 12,
                    "risk_score": 7.8
                },
                "open_ports": [22, 80, 443, 3306, 8080],
                "vulnerabilities": []
            }
        }


# === MODÈLES DE VULNÉRABILITÉ ===

class VulnerabilityModel(BaseModel):
    """Modèle d'une vulnérabilité"""
    id: str = Field(..., description="Identifiant unique")
    name: str = Field(..., description="Nom de la vulnérabilité")
    cve_id: Optional[str] = Field(None, description="Identifiant CVE")
    severity: VulnerabilitySeverity = Field(..., description="Niveau de gravité")
    cvss_score: Optional[float] = Field(None, description="Score CVSS", ge=0.0, le=10.0)

    # Description et impact
    description: str = Field(..., description="Description détaillée")
    impact: str = Field(..., description="Impact potentiel")
    exploitability: str = Field(..., description="Facilité d'exploitation")

    # Informations techniques
    affected_service: str = Field(..., description="Service affecté")
    affected_versions: Optional[List[str]] = Field(None, description="Versions affectées")
    ports: List[int] = Field(..., description="Ports concernés")

    # Remédiation
    remediation: Optional[str] = Field(None, description="Solution de correction")
    workaround: Optional[str] = Field(None, description="Contournement temporaire")
    references: List[str] = Field(default_factory=list, description="Références externes")

    # Métadonnées
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    priority_score: Optional[int] = Field(None, description="Score de priorité", ge=1, le=10)

    class Config:
        schema_extra = {
            "example": {
                "id": "vuln_001",
                "name": "Apache HTTP Server Remote Code Execution",
                "cve_id": "CVE-2024-12345",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "description": "Vulnérabilité permettant l'exécution de code à distance",
                "impact": "Compromission totale du serveur",
                "exploitability": "EASY",
                "affected_service": "Apache HTTP Server",
                "affected_versions": ["2.4.0-2.4.58"],
                "ports": [80, 443],
                "remediation": "Mettre à jour vers la version 2.4.59",
                "priority_score": 10
            }
        }


class VulnerabilityResponse(BaseResponse):
    """Réponse avec détails d'une vulnérabilité"""
    vulnerability: VulnerabilityModel


# === MODÈLES D'ANALYSE ===

class AnalysisRequest(BaseModel):
    """Requête d'analyse IA"""
    vulnerabilities_data: List[Dict[str, Any]] = Field(..., description="Données des vulnérabilités à analyser")
    target_system: Optional[str] = Field(None, description="Système cible pour le contexte")
    business_context: Optional[Dict[str, Any]] = Field(None, description="Contexte business")
    analysis_depth: Optional[str] = Field("standard", description="Profondeur d'analyse")

    @validator('vulnerabilities_data')
    def validate_vulnerabilities_data(cls, v):
        """Valider que les données de vulnérabilités ne sont pas vides"""
        if not v:
            raise ValueError('Aucune donnée de vulnérabilité fournie')
        if len(v) > 100:  # Limite raisonnable
            raise ValueError('Trop de vulnérabilités (max 100)')
        return v

    class Config:
        schema_extra = {
            "example": {
                "vulnerabilities_data": [
                    {
                        "name": "Apache RCE",
                        "severity": "CRITICAL",
                        "cvss_score": 9.8,
                        "service": "Apache HTTP Server"
                    }
                ],
                "target_system": "Production Web Server",
                "analysis_depth": "detailed"
            }
        }


class AnalysisResponse(BaseResponse):
    """Réponse d'analyse IA"""
    analysis_id: str = Field(..., description="Identifiant de l'analyse")

    # Résumé de l'analyse
    summary: Dict[str, Any] = Field(..., description="Résumé de l'analyse")

    # Vulnérabilités analysées
    vulnerabilities: List[Dict[str, Any]] = Field(..., description="Vulnérabilités avec analyse IA")

    # Plan de remédiation
    remediation_plan: Dict[str, Any] = Field(..., description="Plan de remédiation priorisé")

    # Métadonnées
    analyzed_at: datetime = Field(..., description="Date/heure de l'analyse")
    ai_model_used: Optional[str] = Field(None, description="Modèle IA utilisé")
    confidence_score: Optional[float] = Field(None, description="Score de confiance", ge=0.0, le=1.0)


# === MODÈLES DE SCRIPT ===

class ScriptGenerationRequest(BaseModel):
    """Requête de génération de script"""
    vulnerability_id: str = Field(..., description="ID de la vulnérabilité à corriger")
    target_system: str = Field(..., description="Système cible (Linux/Windows)")
    execution_context: Optional[str] = Field("production", description="Contexte d'exécution")
    risk_tolerance: Optional[str] = Field("low", description="Tolérance au risque")

    @validator('target_system')
    def validate_target_system(cls, v):
        """Valider le système cible"""
        allowed_systems = ["linux", "ubuntu", "debian", "centos", "rhel", "windows"]
        if v.lower() not in allowed_systems:
            raise ValueError(f'Système non supporté. Supportés: {", ".join(allowed_systems)}')
        return v.lower()

    class Config:
        schema_extra = {
            "example": {
                "vulnerability_id": "vuln_001",
                "target_system": "ubuntu",
                "execution_context": "production",
                "risk_tolerance": "low"
            }
        }


class ScriptModel(BaseModel):
    """Modèle d'un script de correction"""
    script_id: str
    vulnerability_id: str
    script_content: str = Field(..., description="Contenu du script principal")
    rollback_script: Optional[str] = Field(None, description="Script de rollback")

    # Métadonnées
    target_system: str = Field(..., description="Système cible")
    risk_level: ScriptRiskLevel = Field(..., description="Niveau de risque")
    estimated_duration: Optional[str] = Field(None, description="Durée estimée d'exécution")
    requires_reboot: bool = Field(False, description="Redémarrage requis")

    # Validation et sécurité
    validation_status: str = Field("pending", description="Statut de validation")
    safety_checks: List[str] = Field(default_factory=list, description="Vérifications de sécurité")
    warnings: List[str] = Field(default_factory=list, description="Avertissements")

    # Timestamps
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    validated_at: Optional[datetime] = Field(None)

    class Config:
        schema_extra = {
            "example": {
                "script_id": "script_001",
                "vulnerability_id": "vuln_001",
                "script_content": "#!/bin/bash\napt update && apt upgrade apache2",
                "rollback_script": "#!/bin/bash\napt install apache2=2.4.58",
                "target_system": "ubuntu",
                "risk_level": "MEDIUM",
                "estimated_duration": "5 minutes",
                "requires_reboot": False,
                "validation_status": "approved",
                "warnings": ["Assurez-vous d'avoir une sauvegarde"]
            }
        }


class ScriptResponse(BaseResponse):
    """Réponse de génération de script"""
    script_id: str = Field(..., description="Identifiant du script généré")
    vulnerability_id: str = Field(..., description="ID de la vulnérabilité")
    script_content: str = Field(..., description="Contenu du script")
    rollback_script: Optional[str] = Field(None, description="Script de rollback")
    validation_status: str = Field(..., description="Statut de validation")
    risk_level: ScriptRiskLevel = Field(..., description="Niveau de risque")
    generated_at: datetime = Field(..., description="Date/heure de génération")


# === MODÈLES DE RAPPORT ===

class ReportRequest(BaseModel):
    """Requête de génération de rapport"""
    report_type: ReportType = Field(..., description="Type de rapport à générer")
    format: ReportFormat = Field(ReportFormat.PDF, description="Format de sortie")
    scan_id: Optional[str] = Field(None, description="ID du scan pour le rapport")
    analysis_id: Optional[str] = Field(None, description="ID de l'analyse pour le rapport")

    # Paramètres du rapport
    include_raw_data: bool = Field(False, description="Inclure les données brutes")
    include_charts: bool = Field(True, description="Inclure les graphiques")
    include_recommendations: bool = Field(True, description="Inclure les recommandations")

    # Contexte business (pour rapport exécutif)
    company_name: Optional[str] = Field(None, description="Nom de l'entreprise")
    industry: Optional[str] = Field(None, description="Secteur d'activité")

    @root_validator
    def validate_report_requirements(cls, values):
        """Valider que les données nécessaires sont fournies"""
        report_type = values.get('report_type')
        scan_id = values.get('scan_id')
        analysis_id = values.get('analysis_id')

        if report_type in [ReportType.TECHNICAL, ReportType.REMEDIATION]:
            if not scan_id and not analysis_id:
                raise ValueError('scan_id ou analysis_id requis pour ce type de rapport')

        return values

    class Config:
        schema_extra = {
            "example": {
                "report_type": "technical",
                "format": "pdf",
                "scan_id": "550e8400-e29b-41d4-a716-446655440000",
                "include_charts": True,
                "include_recommendations": True,
                "company_name": "ACME Corp"
            }
        }


class ReportResponse(BaseResponse):
    """Réponse de génération de rapport"""
    report_id: str = Field(..., description="Identifiant du rapport")
    report_type: ReportType = Field(..., description="Type de rapport")
    format: ReportFormat = Field(..., description="Format du rapport")
    status: str = Field(..., description="Statut de génération")
    download_url: Optional[str] = Field(None, description="URL de téléchargement")
    generated_at: datetime = Field(..., description="Date/heure de génération")
    expires_at: Optional[datetime] = Field(None, description="Date d'expiration du lien")


# === MODÈLES DE SANTÉ ===

class HealthResponse(BaseModel):
    """Réponse de vérification de santé"""
    status: str = Field(..., description="Statut global (healthy/unhealthy)")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str = Field(..., description="Version de l'application")
    services: Dict[str, str] = Field(..., description="Statut des services")
    uptime: Optional[float] = Field(None, description="Temps de fonctionnement en secondes")


class MetricsResponse(BaseModel):
    """Réponse des métriques de monitoring"""
    metrics: Dict[str, Any] = Field(..., description="Métriques de l'application")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# === MODÈLES DE PAGINATION ===

class PaginationParams(BaseModel):
    """Paramètres de pagination"""
    limit: int = Field(10, description="Nombre d'éléments par page", ge=1, le=100)
    offset: int = Field(0, description="Décalage", ge=0)
    sort_by: Optional[str] = Field(None, description="Champ de tri")
    sort_order: Optional[str] = Field("asc", description="Ordre de tri (asc/desc)")

    @validator('sort_order')
    def validate_sort_order(cls, v):
        if v not in ["asc", "desc"]:
            raise ValueError('sort_order doit être "asc" ou "desc"')
        return v


class PaginatedResponse(BaseModel):
    """Réponse paginée générique"""
    items: List[Any] = Field(..., description="Éléments de la page")
    total: int = Field(..., description="Nombre total d'éléments")
    limit: int = Field(..., description="Limite par page")
    offset: int = Field(..., description="Décalage actuel")
    has_next: bool = Field(..., description="Page suivante disponible")
    has_previous: bool = Field(..., description="Page précédente disponible")