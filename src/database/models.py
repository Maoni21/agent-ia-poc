"""
Modèles de données pour l'Agent IA de Cybersécurité

Ce module définit tous les modèles de données utilisés par l'application
pour interagir avec la base SQLite. Il fournit une interface ORM simple
et des méthodes de validation pour toutes les entités métier.

Modèles principaux :
- ScanModel : Scans de vulnérabilités
- VulnerabilityModel : Vulnérabilités détectées
- AnalysisModel : Analyses IA
- ScriptModel : Scripts de correction
- WorkflowModel : Workflows d'exécution
"""

import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path

from src.utils.logger import setup_logger
from . import DatabaseError, ValidationError, IntegrityError

# Configuration du logging
logger = setup_logger(__name__)


# === ÉNUMÉRATIONS ===

class ScanStatus(str, Enum):
    """États possibles d'un scan"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnerabilitySeverity(str, Enum):
    """Niveaux de gravité des vulnérabilités"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScriptStatus(str, Enum):
    """États de validation des scripts"""
    PENDING = "pending"
    VALIDATED = "validated"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"


class WorkflowStatus(str, Enum):
    """États des workflows"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


# === CLASSE DE BASE ===

@dataclass
class BaseModel:
    """
    Classe de base pour tous les modèles

    Fournit les fonctionnalités communes :
    - Serialisation JSON
    - Validation des données
    - Timestamps automatiques
    - Génération d'IDs uniques
    """

    id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def __post_init__(self):
        """Initialisation automatique après création"""
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = self.created_at

    def to_dict(self) -> Dict[str, Any]:
        """
        Convertit le modèle en dictionnaire

        Returns:
            Dict: Représentation dictionnaire du modèle
        """
        data = asdict(self)

        # Convertir les dates en ISO format
        if self.created_at:
            data['created_at'] = self.created_at.isoformat()
        if self.updated_at:
            data['updated_at'] = self.updated_at.isoformat()

        return data

    def to_json(self, indent: int = 2) -> str:
        """
        Convertit le modèle en JSON

        Args:
            indent: Indentation du JSON

        Returns:
            str: Représentation JSON du modèle
        """
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """
        Crée une instance depuis un dictionnaire

        Args:
            data: Données sous forme de dictionnaire

        Returns:
            Instance du modèle
        """
        # Convertir les dates ISO en objets datetime
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if 'updated_at' in data and isinstance(data['updated_at'], str):
            data['updated_at'] = datetime.fromisoformat(data['updated_at'])

        return cls(**data)

    def validate(self) -> bool:
        """
        Valide les données du modèle

        Returns:
            bool: True si valide

        Raises:
            ValidationError: Si les données sont invalides
        """
        # Validation de base - à surcharger dans les classes dérivées
        if self.created_at and self.updated_at:
            if self.created_at > self.updated_at:
                raise ValidationError("created_at ne peut pas être postérieur à updated_at")

        return True

    def update_timestamp(self):
        """Met à jour le timestamp updated_at"""
        self.updated_at = datetime.utcnow()


# === MODÈLES PRINCIPAUX ===

@dataclass
class ScanModel(BaseModel):
    """
    Modèle pour les scans de vulnérabilités

    Représente un scan effectué sur une cible avec Nmap ou autre outil.
    """

    scan_id: str = field(default_factory=lambda: f"scan_{uuid.uuid4().hex[:8]}")
    target: str = ""
    scan_type: str = "full"
    status: ScanStatus = ScanStatus.PENDING

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration: Optional[float] = None

    # Résultats
    host_status: str = "unknown"
    open_ports: List[int] = field(default_factory=list)
    services_count: int = 0
    vulnerabilities_count: int = 0

    # Métadonnées techniques
    nmap_version: Optional[str] = None
    scan_parameters: Dict[str, Any] = field(default_factory=dict)
    command_line: Optional[str] = None

    # Statistiques
    total_ports_scanned: int = 0
    scan_progress: int = 0

    def validate(self) -> bool:
        """Validation spécifique aux scans"""
        super().validate()

        if not self.scan_id:
            raise ValidationError("scan_id est obligatoire")

        if not self.target:
            raise ValidationError("target est obligatoire")

        if self.scan_type not in ['quick', 'full', 'stealth', 'aggressive', 'custom']:
            raise ValidationError(f"scan_type invalide: {self.scan_type}")

        if self.started_at and self.completed_at:
            if self.started_at > self.completed_at:
                raise ValidationError("started_at ne peut pas être postérieur à completed_at")

        if self.duration is not None and self.duration < 0:
            raise ValidationError("duration ne peut pas être négative")

        return True

    def calculate_duration(self):
        """Calcule la durée du scan si les timestamps sont disponibles"""
        if self.started_at and self.completed_at:
            self.duration = (self.completed_at - self.started_at).total_seconds()

    def is_completed(self) -> bool:
        """Vérifie si le scan est terminé"""
        return self.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]

    def get_summary(self) -> Dict[str, Any]:
        """Retourne un résumé du scan"""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "status": self.status.value,
            "vulnerabilities_found": self.vulnerabilities_count,
            "duration": self.duration,
            "open_ports": len(self.open_ports)
        }


@dataclass
class VulnerabilityModel(BaseModel):
    """
    Modèle pour les vulnérabilités détectées

    Représente une vulnérabilité spécifique trouvée lors d'un scan.
    """

    vulnerability_id: str = field(default_factory=lambda: f"vuln_{uuid.uuid4().hex[:8]}")
    name: str = ""
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM

    # Scoring et classification
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)

    # Description et impact
    description: str = ""
    impact: str = ""
    solution: str = ""

    # Informations techniques
    affected_service: str = ""
    affected_port: Optional[int] = None
    affected_protocol: str = "tcp"
    affected_versions: List[str] = field(default_factory=list)

    # Détection
    detection_method: str = ""
    confidence: str = "medium"
    false_positive_risk: str = "low"

    # Références
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    patch_available: bool = False

    # Classification métier
    category: str = ""
    tags: List[str] = field(default_factory=list)

    def validate(self) -> bool:
        """Validation spécifique aux vulnérabilités"""
        super().validate()

        if not self.vulnerability_id:
            raise ValidationError("vulnerability_id est obligatoire")

        if not self.name:
            raise ValidationError("name est obligatoire")

        if self.cvss_score is not None:
            if not (0.0 <= self.cvss_score <= 10.0):
                raise ValidationError("cvss_score doit être entre 0.0 et 10.0")

        if self.affected_port is not None:
            if not (1 <= self.affected_port <= 65535):
                raise ValidationError("affected_port doit être entre 1 et 65535")

        # Validation des CVE IDs
        for cve_id in self.cve_ids:
            if not cve_id.startswith('CVE-'):
                raise ValidationError(f"Format CVE invalide: {cve_id}")

        return True

    def get_risk_score(self) -> float:
        """
        Calcule un score de risque composite

        Returns:
            float: Score de risque entre 0 et 10
        """
        base_score = 0.0

        # Score CVSS
        if self.cvss_score:
            base_score = self.cvss_score
        else:
            # Score basé sur la gravité si pas de CVSS
            severity_scores = {
                VulnerabilitySeverity.CRITICAL: 9.0,
                VulnerabilitySeverity.HIGH: 7.0,
                VulnerabilitySeverity.MEDIUM: 5.0,
                VulnerabilitySeverity.LOW: 3.0,
                VulnerabilitySeverity.INFO: 1.0
            }
            base_score = severity_scores.get(self.severity, 5.0)

        # Ajustements selon le contexte
        if self.exploit_available:
            base_score += 1.0

        if self.confidence == "high":
            base_score += 0.5
        elif self.confidence == "low":
            base_score -= 0.5

        return min(10.0, max(0.0, base_score))

    def is_critical(self) -> bool:
        """Vérifie si la vulnérabilité est critique"""
        return (self.severity == VulnerabilitySeverity.CRITICAL or
                (self.cvss_score and self.cvss_score >= 9.0))


@dataclass
class AnalysisModel(BaseModel):
    """
    Modèle pour les analyses IA des vulnérabilités

    Représente le résultat d'une analyse par intelligence artificielle.
    """

    analysis_id: str = field(default_factory=lambda: f"analysis_{uuid.uuid4().hex[:8]}")
    target_system: str = ""

    # Paramètres d'analyse
    ai_model_used: str = ""
    analysis_type: str = "vulnerability_assessment"
    confidence_score: float = 0.0
    processing_time: float = 0.0

    # Résultats
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    overall_risk_score: float = 0.0

    # Analyse détaillée
    analysis_summary: Dict[str, Any] = field(default_factory=dict)
    vulnerability_analyses: List[Dict[str, Any]] = field(default_factory=list)
    remediation_plan: Dict[str, Any] = field(default_factory=dict)

    # Recommandations
    immediate_actions: List[str] = field(default_factory=list)
    short_term_actions: List[str] = field(default_factory=list)
    long_term_actions: List[str] = field(default_factory=list)

    # Contexte business
    business_impact: str = ""
    compliance_notes: List[str] = field(default_factory=list)

    def validate(self) -> bool:
        """Validation spécifique aux analyses"""
        super().validate()

        if not self.analysis_id:
            raise ValidationError("analysis_id est obligatoire")

        if not (0.0 <= self.confidence_score <= 1.0):
            raise ValidationError("confidence_score doit être entre 0.0 et 1.0")

        if not (0.0 <= self.overall_risk_score <= 10.0):
            raise ValidationError("overall_risk_score doit être entre 0.0 et 10.0")

        if self.processing_time < 0:
            raise ValidationError("processing_time ne peut pas être négatif")

        # Vérifier la cohérence des compteurs
        total_counted = (self.critical_count + self.high_count +
                         self.medium_count + self.low_count)
        if self.total_vulnerabilities != total_counted:
            raise ValidationError("Incohérence dans les compteurs de vulnérabilités")

        return True

    def calculate_priority_score(self) -> float:
        """
        Calcule un score de priorité pour cette analyse

        Returns:
            float: Score de priorité entre 0 et 10
        """
        priority = 0.0

        # Poids selon la gravité
        priority += self.critical_count * 10
        priority += self.high_count * 7
        priority += self.medium_count * 4
        priority += self.low_count * 1

        # Normaliser selon le nombre total
        if self.total_vulnerabilities > 0:
            priority = priority / self.total_vulnerabilities

        return min(10.0, priority)


@dataclass
class ScriptModel(BaseModel):
    """
    Modèle pour les scripts de correction générés

    Représente un script de correction automatisé pour une vulnérabilité.
    """

    script_id: str = field(default_factory=lambda: f"script_{uuid.uuid4().hex[:8]}")
    vulnerability_id: str = ""
    target_system: str = "ubuntu"
    script_type: str = "remediation"

    # Contenu du script
    script_content: str = ""
    rollback_script: Optional[str] = None
    validation_script: Optional[str] = None

    # Métadonnées de génération
    generated_by: str = "ai"
    ai_model_used: str = ""
    generation_prompt: str = ""

    # Validation et sécurité
    validation_status: ScriptStatus = ScriptStatus.PENDING
    risk_level: str = "medium"
    safety_checks: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # Exécution
    estimated_duration: str = "unknown"
    requires_reboot: bool = False
    requires_sudo: bool = True
    requires_network: bool = False

    # Dépendances
    dependencies: List[str] = field(default_factory=list)
    pre_conditions: List[str] = field(default_factory=list)
    post_conditions: List[str] = field(default_factory=list)

    # Hash et versioning
    script_hash: Optional[str] = None
    version: str = "1.0"

    # Historique d'exécution
    execution_count: int = 0
    last_executed: Optional[datetime] = None
    execution_history: List[Dict[str, Any]] = field(default_factory=list)

    def validate(self) -> bool:
        """Validation spécifique aux scripts"""
        super().validate()

        if not self.script_id:
            raise ValidationError("script_id est obligatoire")

        if not self.vulnerability_id:
            raise ValidationError("vulnerability_id est obligatoire")

        if not self.script_content:
            raise ValidationError("script_content est obligatoire")

        if self.script_type not in ['remediation', 'validation', 'rollback', 'diagnostic']:
            raise ValidationError(f"script_type invalide: {self.script_type}")

        if self.risk_level not in ['low', 'medium', 'high', 'critical']:
            raise ValidationError(f"risk_level invalide: {self.risk_level}")

        return True

    def calculate_hash(self):
        """Calcule et met à jour le hash du script"""
        import hashlib
        content_hash = hashlib.sha256(self.script_content.encode()).hexdigest()
        self.script_hash = content_hash[:16]

    def is_approved(self) -> bool:
        """Vérifie si le script est approuvé pour exécution"""
        return self.validation_status == ScriptStatus.APPROVED

    def add_execution_record(self, success: bool, output: str = "", error: str = ""):
        """
        Ajoute un enregistrement d'exécution

        Args:
            success: Succès de l'exécution
            output: Sortie du script
            error: Erreur éventuelle
        """
        execution_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "success": success,
            "output": output,
            "error": error,
            "duration": 0  # À calculer si nécessaire
        }

        self.execution_history.append(execution_record)
        self.execution_count += 1
        self.last_executed = datetime.utcnow()
        self.update_timestamp()


@dataclass
class WorkflowModel(BaseModel):
    """
    Modèle pour les workflows d'exécution

    Représente un workflow complet de détection/analyse/correction.
    """

    workflow_id: str = field(default_factory=lambda: f"workflow_{uuid.uuid4().hex[:8]}")
    workflow_type: str = "full_assessment"
    target: str = ""
    status: WorkflowStatus = WorkflowStatus.PENDING

    # Paramètres
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: str = "normal"
    created_by: str = "system"

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    estimated_duration: Optional[int] = None
    actual_duration: Optional[float] = None

    # État d'avancement
    current_step: str = ""
    total_steps: int = 0
    completed_steps: int = 0
    progress_percentage: int = 0

    # Résultats
    scan_id: Optional[str] = None
    analysis_id: Optional[str] = None
    script_ids: List[str] = field(default_factory=list)

    # Métriques
    vulnerabilities_found: int = 0
    scripts_generated: int = 0
    critical_issues: int = 0

    # Logs et événements
    workflow_logs: List[Dict[str, Any]] = field(default_factory=list)
    error_logs: List[Dict[str, Any]] = field(default_factory=list)

    def validate(self) -> bool:
        """Validation spécifique aux workflows"""
        super().validate()

        if not self.workflow_id:
            raise ValidationError("workflow_id est obligatoire")

        if not self.target:
            raise ValidationError("target est obligatoire")

        if self.workflow_type not in ['scan_only', 'scan_and_analyze', 'full_assessment', 'custom']:
            raise ValidationError(f"workflow_type invalide: {self.workflow_type}")

        if not (0 <= self.progress_percentage <= 100):
            raise ValidationError("progress_percentage doit être entre 0 et 100")

        if self.completed_steps > self.total_steps:
            raise ValidationError("completed_steps ne peut pas dépasser total_steps")

        return True

    def calculate_duration(self):
        """Calcule la durée réelle du workflow"""
        if self.started_at and self.completed_at:
            self.actual_duration = (self.completed_at - self.started_at).total_seconds()

    def update_progress(self, step: str, completed_steps: int = None):
        """
        Met à jour la progression du workflow

        Args:
            step: Étape actuelle
            completed_steps: Nombre d'étapes complétées
        """
        self.current_step = step

        if completed_steps is not None:
            self.completed_steps = completed_steps

        if self.total_steps > 0:
            self.progress_percentage = int((self.completed_steps / self.total_steps) * 100)

        self.update_timestamp()

    def add_log(self, level: str, message: str, details: Dict[str, Any] = None):
        """
        Ajoute un log au workflow

        Args:
            level: Niveau de log (info, warning, error)
            message: Message de log
            details: Détails supplémentaires
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
            "details": details or {},
            "step": self.current_step
        }

        if level == "error":
            self.error_logs.append(log_entry)
        else:
            self.workflow_logs.append(log_entry)

        self.update_timestamp()

    def is_completed(self) -> bool:
        """Vérifie si le workflow est terminé"""
        return self.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED,
                               WorkflowStatus.CANCELLED]

    def get_summary(self) -> Dict[str, Any]:
        """Retourne un résumé du workflow"""
        return {
            "workflow_id": self.workflow_id,
            "type": self.workflow_type,
            "target": self.target,
            "status": self.status.value,
            "progress": self.progress_percentage,
            "vulnerabilities_found": self.vulnerabilities_found,
            "scripts_generated": self.scripts_generated,
            "duration": self.actual_duration
        }


# === MODÈLES DE LIAISON ===

@dataclass
class ScanVulnerabilityModel(BaseModel):
    """
    Modèle de liaison entre scans et vulnérabilités

    Représente la relation many-to-many entre scans et vulnérabilités.
    """

    scan_id: str = ""
    vulnerability_id: str = ""
    detected_at: Optional[datetime] = None
    confidence: str = "medium"
    false_positive: bool = False
    verified: bool = False
    notes: str = ""

    def validate(self) -> bool:
        """Validation de la liaison"""
        super().validate()

        if not self.scan_id:
            raise ValidationError("scan_id est obligatoire")

        if not self.vulnerability_id:
            raise ValidationError("vulnerability_id est obligatoire")

        return True


@dataclass
class AnalysisVulnerabilityModel(BaseModel):
    """
    Modèle de liaison entre analyses et vulnérabilités

    Représente les vulnérabilités analysées par l'IA avec leurs métadonnées.
    """

    analysis_id: str = ""
    vulnerability_id: str = ""
    ai_severity_assessment: str = ""
    ai_priority_score: int = 5
    ai_recommended_actions: List[str] = field(default_factory=list)
    ai_business_impact: str = ""
    ai_confidence: float = 0.0

    def validate(self) -> bool:
        """Validation de la liaison analyse-vulnérabilité"""
        super().validate()

        if not self.analysis_id:
            raise ValidationError("analysis_id est obligatoire")

        if not self.vulnerability_id:
            raise ValidationError("vulnerability_id est obligatoire")

        if not (1 <= self.ai_priority_score <= 10):
            raise ValidationError("ai_priority_score doit être entre 1 et 10")

        if not (0.0 <= self.ai_confidence <= 1.0):
            raise ValidationError("ai_confidence doit être entre 0.0 et 1.0")

        return True


# === SCHÉMA DE BASE DE DONNÉES ===

class DatabaseSchema:
    """
    Définition du schéma de base de données

    Contient les définitions SQL pour créer toutes les tables
    et les index nécessaires au fonctionnement de l'application.
    """

    @staticmethod
    def get_creation_sql() -> str:
        """
        Retourne le SQL de création de toutes les tables

        Returns:
            str: Script SQL complet
        """
        return """
        -- ================================================================
        -- SCHÉMA DE BASE DE DONNÉES - AGENT IA CYBERSÉCURITÉ
        -- Version: 1.0.0
        -- ================================================================

        -- Active les clés étrangères
        PRAGMA foreign_keys = ON;

        -- Table des scans
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL DEFAULT 'full',
            status TEXT NOT NULL DEFAULT 'pending',

            -- Timing
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            duration REAL,

            -- Résultats
            host_status TEXT DEFAULT 'unknown',
            open_ports TEXT, -- JSON array
            services_count INTEGER DEFAULT 0,
            vulnerabilities_count INTEGER DEFAULT 0,

            -- Métadonnées techniques
            nmap_version TEXT,
            scan_parameters TEXT, -- JSON
            command_line TEXT,

            -- Statistiques
            total_ports_scanned INTEGER DEFAULT 0,
            scan_progress INTEGER DEFAULT 0,

            -- Timestamps système
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table des vulnérabilités
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vulnerability_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'MEDIUM',

            -- Scoring et classification
            cvss_score REAL,
            cvss_vector TEXT,
            cwe_id TEXT,
            cve_ids TEXT, -- JSON array

            -- Description et impact
            description TEXT,
            impact TEXT,
            solution TEXT,

            -- Informations techniques
            affected_service TEXT,
            affected_port INTEGER,
            affected_protocol TEXT DEFAULT 'tcp',
            affected_versions TEXT, -- JSON array

            -- Détection
            detection_method TEXT,
            confidence TEXT DEFAULT 'medium',
            false_positive_risk TEXT DEFAULT 'low',

            -- Références
            references TEXT, -- JSON array
            exploit_available BOOLEAN DEFAULT FALSE,
            patch_available BOOLEAN DEFAULT FALSE,

            -- Classification métier
            category TEXT,
            tags TEXT, -- JSON array

            -- Timestamps
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table des analyses IA
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT UNIQUE NOT NULL,
            target_system TEXT NOT NULL,

            -- Paramètres d'analyse
            ai_model_used TEXT,
            analysis_type TEXT DEFAULT 'vulnerability_assessment',
            confidence_score REAL DEFAULT 0.0,
            processing_time REAL DEFAULT 0.0,

            -- Résultats
            total_vulnerabilities INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            overall_risk_score REAL DEFAULT 0.0,

            -- Analyse détaillée (JSON)
            analysis_summary TEXT,
            vulnerability_analyses TEXT,
            remediation_plan TEXT,

            -- Recommandations (JSON arrays)
            immediate_actions TEXT,
            short_term_actions TEXT,
            long_term_actions TEXT,

            -- Contexte business
            business_impact TEXT,
            compliance_notes TEXT, -- JSON array

            -- Timestamps
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table des scripts
        CREATE TABLE IF NOT EXISTS scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            script_id TEXT UNIQUE NOT NULL,
            vulnerability_id TEXT NOT NULL,
            target_system TEXT NOT NULL DEFAULT 'ubuntu',
            script_type TEXT NOT NULL DEFAULT 'remediation',

            -- Contenu du script
            script_content TEXT NOT NULL,
            rollback_script TEXT,
            validation_script TEXT,

            -- Métadonnées de génération
            generated_by TEXT DEFAULT 'ai',
            ai_model_used TEXT,
            generation_prompt TEXT,

            -- Validation et sécurité
            validation_status TEXT DEFAULT 'pending',
            risk_level TEXT DEFAULT 'medium',
            safety_checks TEXT, -- JSON array
            warnings TEXT, -- JSON array

            -- Exécution
            estimated_duration TEXT DEFAULT 'unknown',
            requires_reboot BOOLEAN DEFAULT FALSE,
            requires_sudo BOOLEAN DEFAULT TRUE,
            requires_network BOOLEAN DEFAULT FALSE,

            -- Dépendances (JSON arrays)
            dependencies TEXT,
            pre_conditions TEXT,
            post_conditions TEXT,

            -- Hash et versioning
            script_hash TEXT,
            version TEXT DEFAULT '1.0',

            -- Historique d'exécution
            execution_count INTEGER DEFAULT 0,
            last_executed TIMESTAMP,
            execution_history TEXT, -- JSON array

            -- Timestamps
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            -- Clé étrangère
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id)
        );

        -- Table des workflows
        CREATE TABLE IF NOT EXISTS workflows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workflow_id TEXT UNIQUE NOT NULL,
            workflow_type TEXT NOT NULL DEFAULT 'full_assessment',
            target TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',

            -- Paramètres
            parameters TEXT, -- JSON
            priority TEXT DEFAULT 'normal',
            created_by TEXT DEFAULT 'system',

            -- Timing
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            estimated_duration INTEGER,
            actual_duration REAL,

            -- État d'avancement
            current_step TEXT,
            total_steps INTEGER DEFAULT 0,
            completed_steps INTEGER DEFAULT 0,
            progress_percentage INTEGER DEFAULT 0,

            -- Résultats
            scan_id TEXT,
            analysis_id TEXT,
            script_ids TEXT, -- JSON array

            -- Métriques
            vulnerabilities_found INTEGER DEFAULT 0,
            scripts_generated INTEGER DEFAULT 0,
            critical_issues INTEGER DEFAULT 0,

            -- Logs (JSON arrays)
            workflow_logs TEXT,
            error_logs TEXT,

            -- Timestamps
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            -- Clés étrangères
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
            FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id)
        );

        -- Table de liaison scan-vulnérabilités
        CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            vulnerability_id TEXT NOT NULL,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            confidence TEXT DEFAULT 'medium',
            false_positive BOOLEAN DEFAULT FALSE,
            verified BOOLEAN DEFAULT FALSE,
            notes TEXT,

            -- Timestamps
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            -- Clés étrangères et contrainte d'unicité
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id),
            UNIQUE(scan_id, vulnerability_id)
        );

        -- Table de liaison analyse-vulnérabilités
        CREATE TABLE IF NOT EXISTS analysis_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            vulnerability_id TEXT NOT NULL,
            ai_severity_assessment TEXT,
            ai_priority_score INTEGER DEFAULT 5,
            ai_recommended_actions TEXT, -- JSON array
            ai_business_impact TEXT,
            ai_confidence REAL DEFAULT 0.0,

            -- Timestamps
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            -- Clés étrangères et contrainte d'unicité
            FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id),
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id),
            UNIQUE(analysis_id, vulnerability_id)
        );

        -- Table de métadonnées système
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT,
            description TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table des paramètres de configuration
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT,
            data_type TEXT DEFAULT 'string',
            description TEXT,
            is_sensitive BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(category, key)
        );

        -- Table des logs système
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT NOT NULL,
            logger_name TEXT,
            message TEXT NOT NULL,
            module TEXT,
            function_name TEXT,
            line_number INTEGER,
            exception_info TEXT,
            extra_data TEXT, -- JSON
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- ================================================================
        -- INDEX POUR LES PERFORMANCES
        -- ================================================================

        -- Index sur les scans
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
        CREATE INDEX IF NOT EXISTS idx_scans_scan_type ON scans(scan_type);

        -- Index sur les vulnérabilités
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_service ON vulnerabilities(affected_service);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_port ON vulnerabilities(affected_port);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss ON vulnerabilities(cvss_score);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_category ON vulnerabilities(category);

        -- Index sur les analyses
        CREATE INDEX IF NOT EXISTS idx_analyses_target ON analyses(target_system);
        CREATE INDEX IF NOT EXISTS idx_analyses_risk_score ON analyses(overall_risk_score);
        CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at);

        -- Index sur les scripts
        CREATE INDEX IF NOT EXISTS idx_scripts_vulnerability ON scripts(vulnerability_id);
        CREATE INDEX IF NOT EXISTS idx_scripts_system ON scripts(target_system);
        CREATE INDEX IF NOT EXISTS idx_scripts_status ON scripts(validation_status);
        CREATE INDEX IF NOT EXISTS idx_scripts_risk ON scripts(risk_level);

        -- Index sur les workflows
        CREATE INDEX IF NOT EXISTS idx_workflows_target ON workflows(target);
        CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflows(status);
        CREATE INDEX IF NOT EXISTS idx_workflows_type ON workflows(workflow_type);
        CREATE INDEX IF NOT EXISTS idx_workflows_created_by ON workflows(created_by);
        CREATE INDEX IF NOT EXISTS idx_workflows_created_at ON workflows(created_at);

        -- Index sur les liaisons
        CREATE INDEX IF NOT EXISTS idx_scan_vulns_scan ON scan_vulnerabilities(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scan_vulns_vuln ON scan_vulnerabilities(vulnerability_id);
        CREATE INDEX IF NOT EXISTS idx_analysis_vulns_analysis ON analysis_vulnerabilities(analysis_id);
        CREATE INDEX IF NOT EXISTS idx_analysis_vulns_vuln ON analysis_vulnerabilities(vulnerability_id);

        -- Index sur les logs
        CREATE INDEX IF NOT EXISTS idx_system_logs_level ON system_logs(level);
        CREATE INDEX IF NOT EXISTS idx_system_logs_timestamp ON system_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_system_logs_module ON system_logs(module);

        -- ================================================================
        -- TRIGGERS POUR LA MAINTENANCE AUTOMATIQUE
        -- ================================================================

        -- Trigger pour mettre à jour updated_at automatiquement
        CREATE TRIGGER IF NOT EXISTS trigger_scans_updated_at
            AFTER UPDATE ON scans
        BEGIN
            UPDATE scans SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
        END;

        CREATE TRIGGER IF NOT EXISTS trigger_vulnerabilities_updated_at
            AFTER UPDATE ON vulnerabilities
        BEGIN
            UPDATE vulnerabilities SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
        END;

        CREATE TRIGGER IF NOT EXISTS trigger_analyses_updated_at
            AFTER UPDATE ON analyses
        BEGIN
            UPDATE analyses SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
        END;

        CREATE TRIGGER IF NOT EXISTS trigger_scripts_updated_at
            AFTER UPDATE ON scripts
        BEGIN
            UPDATE scripts SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
        END;

        CREATE TRIGGER IF NOT EXISTS trigger_workflows_updated_at
            AFTER UPDATE ON workflows
        BEGIN
            UPDATE workflows SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
        END;

        -- ================================================================
        -- VUES POUR LES REQUÊTES COMPLEXES
        -- ================================================================

        -- Vue des scans avec leurs statistiques
        CREATE VIEW IF NOT EXISTS view_scan_summary AS
        SELECT 
            s.scan_id,
            s.target,
            s.scan_type,
            s.status,
            s.started_at,
            s.completed_at,
            s.duration,
            s.vulnerabilities_count,
            s.services_count,
            COUNT(DISTINCT sv.vulnerability_id) as linked_vulnerabilities,
            COUNT(DISTINCT CASE WHEN v.severity = 'CRITICAL' THEN v.id END) as critical_vulns,
            COUNT(DISTINCT CASE WHEN v.severity = 'HIGH' THEN v.id END) as high_vulns,
            COUNT(DISTINCT CASE WHEN v.severity = 'MEDIUM' THEN v.id END) as medium_vulns,
            COUNT(DISTINCT CASE WHEN v.severity = 'LOW' THEN v.id END) as low_vulns
        FROM scans s
        LEFT JOIN scan_vulnerabilities sv ON s.scan_id = sv.scan_id
        LEFT JOIN vulnerabilities v ON sv.vulnerability_id = v.vulnerability_id
        GROUP BY s.scan_id;

        -- Vue des vulnérabilités avec leurs occurrences
        CREATE VIEW IF NOT EXISTS view_vulnerability_stats AS
        SELECT 
            v.vulnerability_id,
            v.name,
            v.severity,
            v.cvss_score,
            v.affected_service,
            v.affected_port,
            COUNT(DISTINCT sv.scan_id) as detection_count,
            MAX(sv.detected_at) as last_detected,
            COUNT(DISTINCT s.script_id) as script_count,
            v.created_at
        FROM vulnerabilities v
        LEFT JOIN scan_vulnerabilities sv ON v.vulnerability_id = sv.vulnerability_id
        LEFT JOIN scripts s ON v.vulnerability_id = s.vulnerability_id
        GROUP BY v.vulnerability_id;

        -- Vue des workflows en cours
        CREATE VIEW IF NOT EXISTS view_active_workflows AS
        SELECT 
            w.workflow_id,
            w.workflow_type,
            w.target,
            w.status,
            w.progress_percentage,
            w.current_step,
            w.started_at,
            w.created_by,
            CASE 
                WHEN w.started_at IS NOT NULL 
                THEN (julianday('now') - julianday(w.started_at)) * 24 * 60 * 60
                ELSE NULL 
            END as elapsed_seconds
        FROM workflows w
        WHERE w.status IN ('pending', 'running', 'paused');

        -- ================================================================
        -- DONNÉES INITIALES
        -- ================================================================

        -- Insérer la version du schéma
        INSERT OR REPLACE INTO metadata (key, value, description) 
        VALUES ('schema_version', '1.0.0', 'Version du schéma de base de données');

        INSERT OR REPLACE INTO metadata (key, value, description) 
        VALUES ('created_at', datetime('now'), 'Date de création de la base');

        INSERT OR REPLACE INTO metadata (key, value, description) 
        VALUES ('last_migration', datetime('now'), 'Date de dernière migration');

        -- Configuration par défaut
        INSERT OR IGNORE INTO settings (category, key, value, description) VALUES
        ('scan', 'default_timeout', '300', 'Timeout par défaut pour les scans en secondes'),
        ('scan', 'max_concurrent', '3', 'Nombre maximum de scans simultanés'),
        ('scan', 'default_type', 'full', 'Type de scan par défaut'),
        ('ai', 'default_model', 'gpt-4', 'Modèle IA par défaut'),
        ('ai', 'max_tokens', '2000', 'Nombre maximum de tokens pour l\'IA'),
        ('ai', 'temperature', '0.3', 'Température pour la génération IA'),
        ('system', 'log_level', 'INFO', 'Niveau de log par défaut'),
        ('system', 'auto_backup', 'true', 'Sauvegarde automatique activée'),
        ('system', 'backup_retention_days', '30', 'Rétention des sauvegardes en jours');

        -- ================================================================
        -- PROCÉDURES STOCKÉES (Fonctions SQLite)
        -- ================================================================

        -- Note: SQLite ne supporte pas les procédures stockées classiques,
        -- mais nous pouvons définir des requêtes complexes réutilisables

        -- Fin du script de création du schéma
        """

    @staticmethod
    def get_sample_data() -> str:
        """
        Retourne des données d'exemple pour les tests

        Returns:
            str: Script SQL avec données d'exemple
        """
        return """
        -- ================================================================
        -- DONNÉES D'EXEMPLE POUR TESTS
        -- ================================================================

        -- Scan d'exemple
        INSERT OR IGNORE INTO scans (
            scan_id, target, scan_type, status, started_at, completed_at, 
            duration, host_status, vulnerabilities_count, services_count
        ) VALUES (
            'scan_example_001', '192.168.1.100', 'full', 'completed',
            datetime('now', '-1 hour'), datetime('now', '-30 minutes'),
            1800.0, 'up', 5, 8
        );

        -- Vulnérabilités d'exemple
        INSERT OR IGNORE INTO vulnerabilities (
            vulnerability_id, name, severity, cvss_score, description,
            affected_service, affected_port, detection_method
        ) VALUES 
        ('vuln_ssh_001', 'OpenSSH Weak Configuration', 'MEDIUM', 5.3,
         'Configuration SSH permettant des attaques par force brute',
         'OpenSSH', 22, 'nmap-script:ssh-auth-methods'),

        ('vuln_apache_001', 'Apache Server Information Disclosure', 'LOW', 2.6,
         'Le serveur Apache révèle des informations sur sa version',
         'Apache HTTP Server', 80, 'nmap-script:http-server-header'),

        ('vuln_ssl_001', 'SSL/TLS Weak Cipher Suites', 'HIGH', 7.4,
         'Le serveur accepte des suites de chiffrement faibles',
         'SSL/TLS', 443, 'nmap-script:ssl-enum-ciphers');

        -- Liens scan-vulnérabilités
        INSERT OR IGNORE INTO scan_vulnerabilities (scan_id, vulnerability_id, confidence)
        VALUES 
        ('scan_example_001', 'vuln_ssh_001', 'high'),
        ('scan_example_001', 'vuln_apache_001', 'medium'),
        ('scan_example_001', 'vuln_ssl_001', 'high');

        -- Analyse d'exemple
        INSERT OR IGNORE INTO analyses (
            analysis_id, target_system, ai_model_used, total_vulnerabilities,
            critical_count, high_count, medium_count, low_count, overall_risk_score
        ) VALUES (
            'analysis_example_001', '192.168.1.100', 'gpt-4', 3,
            0, 1, 1, 1, 6.2
        );

        -- Script d'exemple
        INSERT OR IGNORE INTO scripts (
            script_id, vulnerability_id, target_system, script_content,
            validation_status, risk_level
        ) VALUES (
            'script_example_001', 'vuln_ssh_001', 'ubuntu',
            '#!/bin/bash\n# Configuration SSH sécurisée\nsudo sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config\nsudo systemctl restart ssh',
            'approved', 'low'
        );

        -- Workflow d'exemple
        INSERT OR IGNORE INTO workflows (
            workflow_id, workflow_type, target, status, progress_percentage,
            scan_id, analysis_id, vulnerabilities_found, scripts_generated
        ) VALUES (
            'workflow_example_001', 'full_assessment', '192.168.1.100', 'completed', 100,
            'scan_example_001', 'analysis_example_001', 3, 1
        );
        """


# === FONCTIONS UTILITAIRES POUR LES MODÈLES ===

def create_model_from_dict(model_class, data: Dict[str, Any]):
    """
    Crée une instance de modèle depuis un dictionnaire

    Args:
        model_class: Classe du modèle à créer
        data: Données sous forme de dictionnaire

    Returns:
        Instance du modèle
    """
    try:
        return model_class.from_dict(data)
    except Exception as e:
        logger.error(f"Erreur création modèle {model_class.__name__}: {e}")
        raise ValidationError(f"Impossible de créer le modèle: {str(e)}")


def validate_json_field(value: Any, field_name: str) -> str:
    """
    Valide et convertit une valeur en JSON pour stockage

    Args:
        value: Valeur à convertir
        field_name: Nom du champ (pour les messages d'erreur)

    Returns:
        str: JSON valide

    Raises:
        ValidationError: Si la conversion échoue
    """
    try:
        if isinstance(value, str):
            # Vérifier que c'est du JSON valide
            json.loads(value)
            return value
        else:
            # Convertir en JSON
            return json.dumps(value, ensure_ascii=False)
    except (json.JSONDecodeError, TypeError) as e:
        raise ValidationError(f"Valeur JSON invalide pour {field_name}: {str(e)}")


def parse_json_field(value: Optional[str], default=None):
    """
    Parse un champ JSON depuis la base de données

    Args:
        value: Valeur JSON string ou None
        default: Valeur par défaut si parsing échoue

    Returns:
        Objet Python parsé ou valeur par défaut
    """
    if not value:
        return default

    try:
        return json.loads(value)
    except json.JSONDecodeError:
        logger.warning(f"Impossible de parser le JSON: {value}")
        return default


def get_model_schema() -> Dict[str, Any]:
    """
    Retourne le schéma complet des modèles

    Returns:
        Dict: Schéma avec toutes les tables et leurs champs
    """
    return {
        "version": "1.0.0",
        "tables": {
            "scans": {
                "model": ScanModel,
                "description": "Scans de vulnérabilités effectués",
                "primary_key": "scan_id"
            },
            "vulnerabilities": {
                "model": VulnerabilityModel,
                "description": "Vulnérabilités détectées",
                "primary_key": "vulnerability_id"
            },
            "analyses": {
                "model": AnalysisModel,
                "description": "Analyses IA des vulnérabilités",
                "primary_key": "analysis_id"
            },
            "scripts": {
                "model": ScriptModel,
                "description": "Scripts de correction générés",
                "primary_key": "script_id"
            },
            "workflows": {
                "model": WorkflowModel,
                "description": "Workflows d'exécution complets",
                "primary_key": "workflow_id"
            },
            "scan_vulnerabilities": {
                "model": ScanVulnerabilityModel,
                "description": "Liaison entre scans et vulnérabilités",
                "primary_key": "id"
            },
            "analysis_vulnerabilities": {
                "model": AnalysisVulnerabilityModel,
                "description": "Liaison entre analyses et vulnérabilités",
                "primary_key": "id"
            }
        }
    }


# === EXPORT DES MODÈLES ===

__all__ = [
    # Énumérations
    "ScanStatus",
    "VulnerabilitySeverity",
    "ScriptStatus",
    "WorkflowStatus",

    # Classe de base
    "BaseModel",

    # Modèles principaux
    "ScanModel",
    "VulnerabilityModel",
    "AnalysisModel",
    "ScriptModel",
    "WorkflowModel",

    # Modèles de liaison
    "ScanVulnerabilityModel",
    "AnalysisVulnerabilityModel",

    # Schéma et utilitaires
    "DatabaseSchema",
    "create_model_from_dict",
    "validate_json_field",
    "parse_json_field",
    "get_model_schema"
]

if __name__ == "__main__":
    # Tests et exemples d'utilisation
    def test_models():
        print("=== Test des modèles de données ===")

        # Test ScanModel
        scan = ScanModel(
            target="192.168.1.100",
            scan_type="full"
        )
        scan.validate()
        print(f"✅ ScanModel: {scan.scan_id}")

        # Test VulnerabilityModel
        vuln = VulnerabilityModel(
            name="Test Vulnerability",
            severity=VulnerabilitySeverity.HIGH,
            cvss_score=7.5
        )
        vuln.validate()
        print(f"✅ VulnerabilityModel: {vuln.vulnerability_id}")

        # Test sérialisation JSON
        scan_json = scan.to_json()
        scan_restored = ScanModel.from_dict(json.loads(scan_json))
        print(f"✅ Sérialisation JSON: {scan_restored.scan_id == scan.scan_id}")

        # Test du schéma
        schema = get_model_schema()
        print(f"✅ Schéma: {len(schema['tables'])} tables définies")

        print("=== Tests terminés avec succès ===")


    test_models()