#!/usr/bin/env python3
"""
Script de migration des fichiers JSON de workflow vers la base de données

Ce script parcourt tous les fichiers JSON dans data/workflow_results/ et les
synchronise vers la base de données SQLite pour en faire la source de vérité.

Usage:
    python scripts/migrate_json_to_db.py
    python scripts/migrate_json_to_db.py --dry-run  # Simulation sans écriture
    python scripts/migrate_json_to_db.py --workflow-id <id>  # Migrer un seul workflow
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

# Ajouter le répertoire backend au path pour utiliser le backend unifié
repo_root = Path(__file__).parent.parent
backend_dir = repo_root / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from src.database.database import Database
from src.core.supervisor import WorkflowResult, WorkflowType, WorkflowStatus
from src.core.collector import ScanResult, VulnerabilityInfo, ServiceInfo
from src.core.analyzer import AnalysisResult, VulnerabilityAnalysis
from src.core.generator import ScriptResult
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


def parse_workflow_json(json_data: Dict[str, Any]) -> WorkflowResult:
    """
    Parse un dictionnaire JSON et reconstruit un objet WorkflowResult
    
    Args:
        json_data: Données JSON du workflow
        
    Returns:
        WorkflowResult: Objet WorkflowResult reconstruit
    """
    from datetime import datetime
    
    # Parser le scan_result si présent
    scan_result = None
    if json_data.get('scan_result'):
        sr = json_data['scan_result']
        scan_result = ScanResult(
            scan_id=sr.get('scan_id', ''),
            target=sr.get('target', ''),
            scan_type=sr.get('scan_type', 'full'),
            started_at=datetime.fromisoformat(sr['started_at']) if sr.get('started_at') else datetime.utcnow(),
            completed_at=datetime.fromisoformat(sr['completed_at']) if sr.get('completed_at') else datetime.utcnow(),
            duration=sr.get('duration', 0.0),
            host_status=sr.get('host_status', 'unknown'),
            open_ports=sr.get('open_ports', []),
            services=[ServiceInfo(**s) if isinstance(s, dict) else s for s in sr.get('services', [])],
            vulnerabilities=[VulnerabilityInfo(**v) if isinstance(v, dict) else v for v in sr.get('vulnerabilities', [])],
            scan_parameters=sr.get('scan_parameters', {}),
            nmap_version=sr.get('nmap_version')
        )
    
    # Parser l'analysis_result si présent
    analysis_result = None
    if json_data.get('analysis_result'):
        ar = json_data['analysis_result']
        analysis_result = AnalysisResult(
            analysis_id=ar.get('analysis_id', ''),
            target_system=ar.get('target_system', ''),
            analyzed_at=datetime.fromisoformat(ar['analyzed_at']) if ar.get('analyzed_at') else datetime.utcnow(),
            analysis_summary=ar.get('analysis_summary', {}),
            vulnerabilities=[VulnerabilityAnalysis(**v) if isinstance(v, dict) else v for v in ar.get('vulnerabilities', [])],
            remediation_plan=ar.get('remediation_plan', {}),
            ai_model_used=ar.get('ai_model_used', ''),
            confidence_score=ar.get('confidence_score', 0.0),
            processing_time=ar.get('processing_time', 0.0),
            business_context=ar.get('business_context')
        )
    
    # Parser les script_results si présents
    script_results = []
    if json_data.get('script_results'):
        for sr_data in json_data['script_results']:
            if isinstance(sr_data, dict):
                script_results.append(ScriptResult(**sr_data))
            else:
                script_results.append(sr_data)
    
    # Construire le WorkflowResult
    workflow_result = WorkflowResult(
        workflow_id=json_data.get('workflow_id', ''),
        workflow_type=WorkflowType(json_data.get('workflow_type', 'full_workflow')),
        target=json_data.get('target', ''),
        status=WorkflowStatus(json_data.get('status', 'completed')),
        started_at=datetime.fromisoformat(json_data['started_at']) if json_data.get('started_at') else datetime.utcnow(),
        completed_at=datetime.fromisoformat(json_data['completed_at']) if json_data.get('completed_at') else None,
        duration=json_data.get('duration'),
        scan_result=scan_result,
        analysis_result=analysis_result,
        script_results=script_results if script_results else None,
        total_vulnerabilities=json_data.get('total_vulnerabilities', 0),
        critical_vulnerabilities=json_data.get('critical_vulnerabilities', 0),
        scripts_generated=json_data.get('scripts_generated', 0)
    )
    
    return workflow_result


def migrate_workflow_file(workflow_file: Path, db: Database, dry_run: bool = False) -> bool:
    """
    Migre un fichier JSON de workflow vers la base de données
    
    Args:
        workflow_file: Chemin vers le fichier JSON
        db: Instance de Database
        dry_run: Si True, simule sans écrire
        
    Returns:
        bool: True si succès, False sinon
    """
    try:
        logger.info(f"Traitement de {workflow_file.name}...")
        
        # Lire le JSON
        with open(workflow_file, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        
        # Parser en WorkflowResult
        workflow_result = parse_workflow_json(json_data)
        
        if dry_run:
            logger.info(f"  [DRY-RUN] Workflow {workflow_result.workflow_id} serait sauvegardé")
            logger.info(f"  - Scan: {'Oui' if workflow_result.scan_result else 'Non'}")
            logger.info(f"  - Analyse: {'Oui' if workflow_result.analysis_result else 'Non'}")
            logger.info(f"  - Scripts: {len(workflow_result.script_results) if workflow_result.script_results else 0}")
            return True
        
        # Sauvegarder dans la DB
        db.save_workflow_result(workflow_result)
        logger.info(f"  ✅ Workflow {workflow_result.workflow_id} migré avec succès")
        return True
        
    except Exception as e:
        logger.error(f"  ❌ Erreur migration {workflow_file.name}: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    parser = argparse.ArgumentParser(description='Migrer les workflows JSON vers la base de données')
    parser.add_argument('--dry-run', action='store_true', help='Simulation sans écriture en DB')
    parser.add_argument('--workflow-id', type=str, help='Migrer un seul workflow par son ID')
    parser.add_argument('--workflow-dir', type=str, default='data/workflow_results', 
                       help='Répertoire contenant les fichiers JSON (défaut: data/workflow_results)')
    
    args = parser.parse_args()
    
    # Initialiser la base de données
    logger.info("Initialisation de la base de données...")
    db = Database()
    db.create_tables()
    logger.info("✅ Base de données initialisée")
    
    # Trouver les fichiers JSON
    workflow_dir = Path(args.workflow_dir)
    if not workflow_dir.exists():
        logger.error(f"Répertoire non trouvé: {workflow_dir}")
        return 1
    
    if args.workflow_id:
        # Migrer un seul workflow
        workflow_file = workflow_dir / f"{args.workflow_id}.json"
        if not workflow_file.exists():
            logger.error(f"Fichier non trouvé: {workflow_file}")
            return 1
        
        success = migrate_workflow_file(workflow_file, db, args.dry_run)
        return 0 if success else 1
    else:
        # Migrer tous les workflows
        workflow_files = list(workflow_dir.glob("*.json"))
        
        if not workflow_files:
            logger.warning(f"Aucun fichier JSON trouvé dans {workflow_dir}")
            return 0
        
        logger.info(f"Trouvé {len(workflow_files)} fichier(s) à migrer")
        
        if args.dry_run:
            logger.info("Mode DRY-RUN activé - aucune écriture en DB")
        
        # Migrer chaque fichier
        success_count = 0
        error_count = 0
        
        for workflow_file in sorted(workflow_files):
            if migrate_workflow_file(workflow_file, db, args.dry_run):
                success_count += 1
            else:
                error_count += 1
        
        # Rapport final
        logger.info("")
        logger.info("=" * 60)
        logger.info("Rapport de migration")
        logger.info("=" * 60)
        logger.info(f"Total: {len(workflow_files)}")
        logger.info(f"✅ Succès: {success_count}")
        logger.info(f"❌ Erreurs: {error_count}")
        
        if args.dry_run:
            logger.info("")
            logger.info("Mode DRY-RUN - aucune donnée n'a été écrite")
            logger.info("Relancez sans --dry-run pour effectuer la migration")
        
        return 0 if error_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
