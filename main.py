# !/usr/bin/env python3
"""
Agent IA de Cybersécurité - Interface CLI Principale

Ce module fournit l'interface en ligne de commande pour l'agent IA de cybersécurité.
Il permet de scanner des systèmes, analyser les vulnérabilités et générer des scripts de correction.

Usage:
    python main.py --scan <target> [options]
    python main.py --analyze --analyze-file <file> [options]
    python main.py --full-workflow <target> [options]
"""

import argparse
import asyncio
import json
import logging
import signal
import sys
from pathlib import Path
from typing import Optional, Dict, Any

# Imports locaux
from config import get_config, validate_config
from config.settings import SCAN_TYPES
from src.utils.logger import setup_logger
from src.core.supervisor import Supervisor, WorkflowType

# Configuration du logging
logger = setup_logger(__name__)

# Instance globale du superviseur (pour le signal handling)
supervisor_instance: Optional[Supervisor] = None


# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

def print_application_banner():
    """Affiche la bannière de l'application"""
    banner = """
============================================================
🛡️  AGENT IA DE CYBERSÉCURITÉ
============================================================
    """
    print(banner)


def configure_logging(args):
    """
    Configure le système de logging

    Args:
        args: Arguments parsés
    """
    log_level = logging.DEBUG if args.verbose else logging.INFO
    if args.quiet:
        log_level = logging.WARNING

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger.info(f"Logging configuré: niveau {logging.getLevelName(log_level)}")


def create_agent(config: Optional[Dict[str, Any]] = None) -> Supervisor:
    """
    Crée et initialise un agent (superviseur)

    Args:
        config: Configuration optionnelle

    Returns:
        Supervisor: Instance configurée
    """
    if config is None:
        config = get_config()

    # Valider la configuration
    validation_result = validate_config(config)

    # validate_config retourne un dict avec 'valid', 'issues', 'warnings'
    if isinstance(validation_result, dict):
        if not validation_result.get('valid', False):
            issues = validation_result.get('issues', [])
            logger.error(f"Erreurs de configuration: {issues}")
            raise ValueError(f"Configuration invalide: {', '.join(issues)}")

        # Afficher les warnings s'il y en a
        warnings = validation_result.get('warnings', [])
        if warnings:
            for warning in warnings:
                logger.warning(f"Configuration: {warning}")

    return Supervisor(config)


def setup_signal_handlers():
    """Configure les gestionnaires de signaux pour l'arrêt propre"""

    def signal_handler(signum, frame):
        """Gestionnaire de signal pour arrêt propre"""
        print("\n🛑 Interruption reçue, arrêt en cours...")
        logger.info(f"Signal {signum} reçu, arrêt du superviseur...")

        global supervisor_instance
        if supervisor_instance:
            try:
                # Utiliser asyncio.run uniquement si pas déjà dans une boucle
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(supervisor_instance.shutdown())
                except RuntimeError:
                    asyncio.run(supervisor_instance.shutdown())
            except Exception as e:
                logger.error(f"Erreur lors de l'arrêt: {e}")

        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


# ============================================================================
# PARSEUR D'ARGUMENTS
# ============================================================================

def create_argument_parser() -> argparse.ArgumentParser:
    """
    Crée et configure le parseur d'arguments CLI

    Returns:
        ArgumentParser: Parseur configuré
    """
    parser = argparse.ArgumentParser(
        description="Agent IA de Cybersécurité - Scan et correction automatisée",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  # Scan rapide d'une cible
  python main.py --scan 192.168.1.1 --scan-type quick

  # Analyse avec IA d'un fichier de vulnérabilités
  python main.py --analyze --analyze-file vulnerabilities.json

  # Workflow complet (scan + analyse + génération)
  python main.py --full-workflow 192.168.1.1

  # Mode API REST
  python main.py --api --port 8000
        """
    )

    # === COMMANDES PRINCIPALES ===
    commands = parser.add_mutually_exclusive_group()

    commands.add_argument(
        '--scan',
        action='store_true',
        help='Scanner une cible pour détecter des vulnérabilités'
    )

    commands.add_argument(
        '--analyze',
        action='store_true',
        help='Analyser des vulnérabilités avec l\'IA'
    )

    commands.add_argument(
        '--generate',
        action='store_true',
        help='Générer des scripts de correction'
    )

    commands.add_argument(
        '--full-workflow',
        action='store_true',
        help='Workflow complet: scan + analyse + génération'
    )

    commands.add_argument(
        '--api',
        action='store_true',
        help='Lancer le serveur API REST'
    )

    commands.add_argument(
        '--interactive',
        action='store_true',
        help='Mode interactif'
    )

    # === PARAMÈTRES GÉNÉRAUX ===
    parser.add_argument(
        '--target',
        type=str,
        help='Cible à scanner (IP ou nom de domaine)'
    )

    parser.add_argument(
        '--scan-type',
        type=str,
        choices=['ultra-quick', 'quick', 'full', 'stealth', 'aggressive'],
        default='full',
        help='Type de scan à effectuer (défaut: full)'
    )

    parser.add_argument(
        '--analyze-file',
        type=str,
        help='Fichier JSON contenant les vulnérabilités à analyser'
    )

    parser.add_argument(
        '--output',
        type=str,
        help='Fichier de sortie pour les résultats'
    )

    parser.add_argument(
        '--format',
        type=str,
        choices=['json', 'txt', 'html', 'markdown'],
        default='json',
        help='Format de sortie (défaut: json)'
    )

    # === CONFIGURATION IA ===
    ai_group = parser.add_argument_group('Configuration IA')

    ai_group.add_argument(
        '--ai-model',
        type=str,
        default='gpt-4',
        help='Modèle IA à utiliser (défaut: gpt-4)'
    )

    ai_group.add_argument(
        '--ai-temperature',
        type=float,
        default=0.3,
        help='Température pour la génération IA (défaut: 0.3)'
    )

    # === OPTIONS API ===
    api_group = parser.add_argument_group('Options API')

    api_group.add_argument(
        '--port',
        type=int,
        default=8000,
        help='Port pour le serveur API (défaut: 8000)'
    )

    api_group.add_argument(
        '--host',
        type=str,
        default='127.0.0.1',
        help='Hôte pour le serveur API (défaut: 127.0.0.1)'
    )

    # === OPTIONS DE DÉBOGAGE ===
    debug_group = parser.add_argument_group('Débogage')

    debug_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Mode verbeux (plus de logs)'
    )

    debug_group.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Mode silencieux (moins de logs)'
    )

    debug_group.add_argument(
        '--version',
        action='store_true',
        help='Afficher la version'
    )

    debug_group.add_argument(
        '--status',
        action='store_true',
        help='Afficher le statut de l\'agent'
    )

    debug_group.add_argument(
        '--check-deps',
        action='store_true',
        help='Vérifier les dépendances'
    )

    debug_group.add_argument(
        '--test',
        action='store_true',
        help='Lancer les tests de base'
    )

    return parser


def validate_arguments(args):
    """
    Valide les arguments fournis

    Args:
        args: Arguments parsés

    Raises:
        ValueError: Si les arguments sont invalides
    """
    errors = []

    # Vérifier qu'une action a été spécifiée
    if not any([
        args.scan,
        args.analyze,
        args.generate,
        args.full_workflow,
        args.api,
        args.interactive,
        args.version,
        args.status,
        args.check_deps,
        args.test
    ]):
        errors.append("Aucune action spécifiée. Utilisez --help pour voir les options.")

    # Valider les paramètres de scan
    if args.scan or args.full_workflow:
        if not args.target:
            errors.append("--target est requis pour --scan et --full-workflow")

    # Valider les paramètres d'analyse
    if args.analyze and not args.analyze_file and not args.target:
        errors.append("--analyze nécessite soit --analyze-file soit --target")

    # Valider le fichier d'analyse
    if args.analyze_file:
        if not Path(args.analyze_file).exists():
            errors.append(f"Fichier d'analyse non trouvé: {args.analyze_file}")

    if errors:
        print("❌ Erreurs de validation des arguments:")
        for error in errors:
            print(f"   {error}")
        sys.exit(1)


# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

def display_application_status():
    """Affiche le statut de l'application"""
    print("\n📊 STATUT DE L'AGENT IA\n")

    # Configuration
    try:
        config = get_config()
        print("✅ Configuration: OK")
        print(f"   - Modèle IA: {config.get('openai_model', 'N/A')}")
    except Exception as e:
        print(f"❌ Configuration: {e}")

    # Dépendances
    print("\n📦 Dépendances:")
    try:
        import nmap
        print("   ✅ python-nmap")
    except ImportError:
        print("   ❌ python-nmap (requis)")

    try:
        import openai
        print("   ✅ openai")
    except ImportError:
        print("   ❌ openai (requis)")

    print()


def check_dependencies() -> bool:
    """
    Vérifie que toutes les dépendances sont installées

    Returns:
        bool: True si toutes les dépendances sont présentes
    """
    print("🔍 Vérification des dépendances...\n")

    all_ok = True

    # Dépendances Python
    required_modules = [
        ('nmap', 'python-nmap'),
        ('openai', 'openai'),
        ('fastapi', 'fastapi'),
        ('uvicorn', 'uvicorn'),
        ('pydantic', 'pydantic')
    ]

    for module_name, package_name in required_modules:
        try:
            __import__(module_name)
            print(f"✅ {package_name}")
        except ImportError:
            print(f"❌ {package_name} (pip install {package_name})")
            all_ok = False

    # Outils système
    print("\n🔧 Outils système:")
    import shutil

    if shutil.which('nmap'):
        print("✅ nmap")
    else:
        print("❌ nmap (apt install nmap / brew install nmap)")
        all_ok = False

    print()
    return all_ok


async def run_basic_tests() -> int:
    """
    Lance des tests de base

    Returns:
        int: Code de retour
    """
    print("🧪 Tests de base...\n")

    try:
        # Test 1: Configuration
        print("Test 1: Configuration...", end=" ")
        config = get_config()
        assert config is not None
        print("✅")

        # Test 2: Création superviseur
        print("Test 2: Création superviseur...", end=" ")
        supervisor = create_agent(config)
        assert supervisor is not None
        print("✅")

        # Test 3: Fermeture
        print("Test 3: Fermeture propre...", end=" ")
        await supervisor.shutdown()
        print("✅")

        print("\n✅ Tous les tests passent")
        return 0

    except Exception as e:
        print(f" ❌")
        print(f"❌ Erreur lors des tests: {e}")
        logger.error(f"Erreur tests de base: {e}")
        return 1


# ============================================================================
# GESTIONNAIRES DE COMMANDES
# ============================================================================

async def handle_scan_command(args) -> int:
    """
    Traite la commande de scan

    Args:
        args: Arguments parsés

    Returns:
        int: Code de retour
    """
    try:
        logger.info(f"🔍 Début du scan de {args.target}")
        print(f"🔍 Scan de: {args.target}")
        print(f"   Type: {args.scan_type}\n")

        # Créer le superviseur
        global supervisor_instance
        config = get_config()
        supervisor_instance = create_agent(config)

        # Lancer le scan
        scan_result = await supervisor_instance.run_scan(
            target=args.target,
            scan_type=args.scan_type
        )

        # Vérifier que le résultat existe
        if not scan_result:
            print("❌ Erreur: Aucun résultat de scan")
            return 1

        # Afficher les résultats
        print(f"\n✅ Scan terminé:")
        print(f"   • Ports ouverts: {len(scan_result.open_ports) if hasattr(scan_result, 'open_ports') else 0}")
        print(f"   • Services détectés: {len(scan_result.services) if hasattr(scan_result, 'services') else 0}")
        print(
            f"   • Vulnérabilités trouvées: {len(scan_result.vulnerabilities) if hasattr(scan_result, 'vulnerabilities') else 0}")
        print(f"   • Durée: {scan_result.duration:.1f}s" if hasattr(scan_result, 'duration') else "")

        # Afficher les vulnérabilités critiques
        if hasattr(scan_result, 'vulnerabilities') and scan_result.vulnerabilities:
            critical_vulns = [v for v in scan_result.vulnerabilities if
                              hasattr(v, 'severity') and v.severity == 'CRITICAL']
            if critical_vulns:
                print(f"\n🔴 Vulnérabilités critiques ({len(critical_vulns)}):")
                for vuln in critical_vulns[:5]:  # Limiter à 5
                    cve_id = vuln.cve_ids[0] if hasattr(vuln, 'cve_ids') and vuln.cve_ids else 'N/A'
                    vuln_name = vuln.name if hasattr(vuln, 'name') else 'Vulnérabilité inconnue'
                    print(f"   - {vuln_name} (CVE: {cve_id})")

        # Sauvegarder si demandé
        if args.output:
            result_dict = scan_result.to_dict() if hasattr(scan_result, 'to_dict') else scan_result
            await save_results(result_dict, args.output, args.format)

        return 0

    except Exception as e:
        logger.error(f"Erreur lors du scan: {e}")
        print(f"❌ Erreur: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    finally:
        if supervisor_instance:
            await supervisor_instance.shutdown()


async def handle_analyze_command(args) -> int:
    """
    Traite la commande d'analyse IA

    Args:
        args: Arguments parsés

    Returns:
        int: Code de retour
    """
    try:
        logger.info("🧠 Début de l'analyse IA")

        # Créer le superviseur
        global supervisor_instance
        config = get_config()
        supervisor_instance = create_agent(config)

        # Charger les données de vulnérabilités
        if args.analyze_file:
            print(f"📂 Chargement du fichier: {args.analyze_file}")

            with open(args.analyze_file, 'r', encoding='utf-8') as f:
                vulnerabilities_data = json.load(f)

            # S'assurer que c'est une liste
            if isinstance(vulnerabilities_data, dict):
                if 'vulnerabilities' in vulnerabilities_data:
                    vulnerabilities_data = vulnerabilities_data['vulnerabilities']
                else:
                    vulnerabilities_data = [vulnerabilities_data]

        else:
            print(f"🔍 Scan et analyse de: {args.target}")
            scan_result = await supervisor_instance.run_scan(args.target, args.scan_type)
            vulnerabilities_data = [vuln.to_dict() for vuln in scan_result.vulnerabilities]

        if not vulnerabilities_data:
            print("⚠️ Aucune vulnérabilité à analyser")
            return 0

        # ============================================================
        # FILTRAGE À 10 VULNÉRABILITÉS MAX (ÉCONOMIE DE TOKENS)
        # ============================================================

        original_count = len(vulnerabilities_data)

        if original_count > 10:
            print(f"⚡ Filtrage: {original_count} vulnérabilités → Top 10 les plus critiques")

            # Fonction de tri par priorité
            def get_vulnerability_priority(vuln):
                """Calcule la priorité d'une vulnérabilité"""
                severity_map = {
                    "CRITICAL": 4,
                    "HIGH": 3,
                    "MEDIUM": 2,
                    "LOW": 1,
                    "UNKNOWN": 0
                }

                severity = vuln.get('severity', 'UNKNOWN')
                if isinstance(severity, str):
                    severity = severity.upper()

                cvss = vuln.get('cvss_score', 0)
                if cvss is None:
                    cvss = 0

                # Priorité = (niveau de sévérité * 10) + score CVSS
                severity_priority = severity_map.get(severity, 0)
                return (severity_priority * 10 + float(cvss))

            # Trier et limiter à 10
            try:
                vulnerabilities_data = sorted(
                    vulnerabilities_data,
                    key=get_vulnerability_priority,
                    reverse=True
                )[:10]

                print(f"✅ Top 10 sélectionnées (économie: {original_count - 10} vulnérabilités)")

                # Afficher le résumé des vulnérabilités sélectionnées
                critical = sum(1 for v in vulnerabilities_data if v.get('severity', '').upper() == 'CRITICAL')
                high = sum(1 for v in vulnerabilities_data if v.get('severity', '').upper() == 'HIGH')
                medium = sum(1 for v in vulnerabilities_data if v.get('severity', '').upper() == 'MEDIUM')

                print(f"   📊 Répartition: {critical} critiques, {high} élevées, {medium} moyennes")

            except Exception as e:
                logger.warning(f"Erreur lors du filtrage: {e}, analyse de toutes les vulnérabilités")
                # En cas d'erreur, on garde toutes les vulnérabilités
                pass

        print(f"🧠 Analyse de {len(vulnerabilities_data)} vulnérabilités...")

        # Lancer l'analyse
        analysis_result = await supervisor_instance.analyze_vulnerabilities(
            vulnerabilities_data=vulnerabilities_data,
            target_system=args.target or "Système inconnu"
        )

        # ============================================================
        # FIX BUG #4 : VÉRIFICATIONS ROBUSTES
        # ============================================================

        # Vérifier que le résultat existe
        if not analysis_result:
            print("❌ Erreur: L'analyse n'a pas retourné de résultats")
            logger.error("analysis_result est None")
            return 1

        # Vérifier que les attributs existent
        if not hasattr(analysis_result, 'vulnerabilities'):
            print("❌ Erreur: Format de résultat invalide (pas d'attribut vulnerabilities)")
            logger.error(f"analysis_result type: {type(analysis_result)}, attributs: {dir(analysis_result)}")
            return 1

        # Vérifier que vulnerabilities n'est pas None
        if analysis_result.vulnerabilities is None:
            print("❌ Erreur: Liste de vulnérabilités est None")
            return 1

        # ============================================================
        # AFFICHAGE SÉCURISÉ
        # ============================================================

        print(f"\n✅ Analyse terminée:")
        print(f"   • Vulnérabilités analysées: {len(analysis_result.vulnerabilities)}")

        # Vérifier que analysis_summary existe
        if hasattr(analysis_result, 'analysis_summary') and analysis_result.analysis_summary:
            summary = analysis_result.analysis_summary
            overall_risk = summary.get('overall_risk_score', 0)
            print(f"   • Score de risque global: {overall_risk:.1f}/10")
        else:
            print("   • Score de risque global: N/A")

        # Vérifier que ai_model_used existe
        if hasattr(analysis_result, 'ai_model_used'):
            print(f"   • Modèle IA utilisé: {analysis_result.ai_model_used}")

        # Afficher le résumé par gravité
        if hasattr(analysis_result, 'analysis_summary') and analysis_result.analysis_summary:
            summary = analysis_result.analysis_summary
            print(f"\n📊 Répartition par gravité:")
            print(f"   🔴 Critiques: {summary.get('critical_count', 0)}")
            print(f"   🟠 Élevées: {summary.get('high_count', 0)}")
            print(f"   🟡 Moyennes: {summary.get('medium_count', 0)}")
            print(f"   🟢 Faibles: {summary.get('low_count', 0)}")

        # Afficher les actions prioritaires
        if hasattr(analysis_result, 'analysis_summary') and analysis_result.analysis_summary:
            summary = analysis_result.analysis_summary
            if 'immediate_actions_required' in summary:
                immediate = summary['immediate_actions_required']
                if immediate > 0:
                    print(f"\n⚠️ Actions immédiates requises: {immediate}")

                    # Afficher les vulnérabilités prioritaires
                    priority_vulns = sorted(
                        analysis_result.vulnerabilities,
                        key=lambda v: v.priority_score if hasattr(v, 'priority_score') else 0,
                        reverse=True
                    )[:3]

                    for vuln in priority_vulns:
                        if hasattr(vuln, 'priority_score') and vuln.priority_score >= 8:
                            severity_icon = {
                                "CRITICAL": "🔴",
                                "HIGH": "🟠",
                                "MEDIUM": "🟡",
                                "LOW": "🟢"
                            }.get(vuln.severity if hasattr(vuln, 'severity') else 'UNKNOWN', "⚪")
                            name = vuln.name if hasattr(vuln, 'name') else 'Vulnérabilité inconnue'
                            print(f"   {severity_icon} {name} (Priorité: {vuln.priority_score}/10)")

        # Sauvegarder si demandé
        if args.output:
            await save_results(analysis_result.to_dict(), args.output, args.format)

        return 0

    except Exception as e:
        logger.error(f"Erreur lors de l'analyse: {e}")
        print(f"❌ Erreur: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    finally:
        if supervisor_instance:
            await supervisor_instance.shutdown()


async def handle_generate_command(args) -> int:
    """
    Traite la commande de génération de scripts

    Args:
        args: Arguments parsés

    Returns:
        int: Code de retour
    """
    try:
        logger.info("🔧 Début de la génération de scripts")

        # Créer le superviseur
        global supervisor_instance
        config = get_config()
        supervisor_instance = create_agent(config)

        # Déterminer les vulnérabilités à traiter
        if args.analyze_file:
            print(f"📂 Chargement des vulnérabilités: {args.analyze_file}")

            with open(args.analyze_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Extraire les vulnérabilités selon le format
            if isinstance(data, list):
                vulnerabilities = data
            elif isinstance(data, dict):
                if 'vulnerabilities' in data:
                    vulnerabilities = data['vulnerabilities']
                else:
                    vulnerabilities = [data]
            else:
                raise ValueError("Format de données invalide")

        else:
            # Analyser d'abord
            print(f"🔍 Scan et analyse de: {args.target}")
            analysis_result = await supervisor_instance.run_complete_workflow(
                target=args.target,
                scan_type=args.scan_type
            )
            vulnerabilities = analysis_result.vulnerabilities

        if not vulnerabilities:
            print("⚠️ Aucune vulnérabilité à traiter")
            return 0

        print(f"🔧 Génération de scripts pour {len(vulnerabilities)} vulnérabilités...")

        # Limiter à 5 scripts max pour économiser les tokens
        vulnerabilities_to_process = vulnerabilities[:5]

        scripts_generated = []
        for i, vuln in enumerate(vulnerabilities_to_process, 1):
            try:
                # Extraire l'ID de la vulnérabilité
                vuln_id = vuln.get('vulnerability_id') or vuln.get('cve_id', f'VULN-{i}')

                print(f"   {i}/{len(vulnerabilities_to_process)} - {vuln_id}...", end=" ")

                script_result = await supervisor_instance.generate_fix_script(
                    vulnerability_id=vuln_id,
                    target_system='ubuntu'
                )

                scripts_generated.append(script_result)
                print("✅")

            except Exception as e:
                logger.error(f"Erreur génération script pour {vuln_id}: {e}")
                print(f"❌ ({e})")

        print(f"\n✅ Scripts générés: {len(scripts_generated)}/{len(vulnerabilities_to_process)}")

        # Sauvegarder si demandé
        if args.output:
            scripts_data = [script.to_dict() for script in scripts_generated]
            await save_results(scripts_data, args.output, args.format)

        return 0

    except Exception as e:
        logger.error(f"Erreur lors de la génération: {e}")
        print(f"❌ Erreur: {e}", file=sys.stderr)
        return 1
    finally:
        if supervisor_instance:
            await supervisor_instance.shutdown()


async def handle_full_workflow_command(args) -> int:
    """
    Traite la commande de workflow complet

    Args:
        args: Arguments parsés

    Returns:
        int: Code de retour
    """
    try:
        logger.info(f"🚀 Début du workflow complet pour {args.target}")

        print(f"🚀 Workflow complet: {args.target}\n")
        print("Étapes:")
        print("   1. 🔍 Scan de vulnérabilités")
        print("   2. 🧠 Analyse IA")
        print("   3. 🔧 Génération de scripts\n")

        # Créer le superviseur
        global supervisor_instance
        config = get_config()
        supervisor_instance = create_agent(config)

        # Charger les vulnérabilités si fichier fourni
        if args.analyze_file:
            print(f"📂 Chargement des vulnérabilités: {args.analyze_file}")
            with open(args.analyze_file, 'r', encoding='utf-8') as f:
                loaded_data = json.load(f)

            # S'assurer que c'est une liste
            if isinstance(loaded_data, dict):
                if 'vulnerabilities' in loaded_data:
                    vulnerabilities_data = loaded_data['vulnerabilities']
                else:
                    vulnerabilities_data = [loaded_data]
            else:
                vulnerabilities_data = loaded_data

            print(f"✅ {len(vulnerabilities_data)} vulnérabilités chargées\n")

            # Lancer l'analyse directement
            print("🧠 Étape 2/3: Analyse IA...")
            analysis_result = await supervisor_instance.analyze_vulnerabilities(
                vulnerabilities_data=vulnerabilities_data,
                target_system=args.target or "Système inconnu"
            )

            # Afficher les résultats d'analyse
            if analysis_result and hasattr(analysis_result, 'vulnerabilities'):
                print(f"✅ Analyse terminée: {len(analysis_result.vulnerabilities)} vulnérabilités analysées")

                # Limiter aux 5 plus critiques pour la génération de scripts
                vulnerabilities_for_scripts = sorted(
                    analysis_result.vulnerabilities,
                    key=lambda v: v.priority_score if hasattr(v, 'priority_score') else 0,
                    reverse=True
                )[:5]

                # Générer les scripts
                print(f"\n🔧 Étape 3/3: Génération de scripts (limité à 5)...")
                scripts_generated = []

                for i, vuln in enumerate(vulnerabilities_for_scripts, 1):
                    try:
                        vuln_id = vuln.vulnerability_id if hasattr(vuln, 'vulnerability_id') else f'VULN-{i}'
                        print(f"   {i}/5 - {vuln_id}...", end=" ")

                        # Convertir en dict pour passer au générateur
                        vuln_dict = vuln.to_dict() if hasattr(vuln, 'to_dict') else vuln

                        script_result = await supervisor_instance.generate_fix_script(
                            vulnerability_id=vuln_id,
                            target_system='ubuntu'
                        )

                        scripts_generated.append(script_result)
                        print("✅")

                    except Exception as e:
                        logger.error(f"Erreur génération script: {e}")
                        print(f"❌")

                print(f"\n✅ Scripts générés: {len(scripts_generated)}/5")

        else:
            # Workflow complet avec scan
            print("🔍 Étape 1/3: Scan...")
            result = await supervisor_instance.run_complete_workflow(
                target=args.target,
                scan_type=args.scan_type
            )

            # Afficher les résultats
            print(f"\n✅ Workflow complet terminé:")
            print(f"   • Vulnérabilités détectées: {result.total_vulnerabilities}")
            print(f"   • Vulnérabilités critiques: {result.critical_vulnerabilities}")
            print(f"   • Scripts générés: {result.scripts_generated}")
            print(f"   • Durée totale: {result.duration:.1f}s")

            # Sauvegarder si demandé
            if args.output:
                await save_results(result.to_dict(), args.output, args.format)

        return 0

    except Exception as e:
        logger.error(f"Erreur lors du workflow: {e}")
        print(f"❌ Erreur: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    finally:
        if supervisor_instance:
            await supervisor_instance.shutdown()


def handle_interactive_mode() -> int:
    """
    Lance le mode interactif

    Returns:
        int: Code de retour
    """
    print("🎮 Mode interactif - Non implémenté")
    print("Cette fonctionnalité sera disponible dans une future version.")
    return 0


def handle_api_command(args) -> int:
    """
    Lance le serveur API

    Args:
        args: Arguments parsés

    Returns:
        int: Code de retour
    """
    try:
        print(f"🚀 Démarrage du serveur API")
        print(f"   Host: {args.host}")
        print(f"   Port: {args.port}\n")

        import uvicorn
        # L'application FastAPI est définie dans src/api/main.py (routes.py n'expose qu'un router)
        from src.api.main import app

        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="info" if args.verbose else "warning"
        )

        return 0

    except Exception as e:
        logger.error(f"Erreur lors du démarrage de l'API: {e}")
        print(f"❌ Erreur: {e}", file=sys.stderr)
        return 1


async def save_results(data: Dict[str, Any], output_file: str, format_type: str):
    """
    Sauvegarde les résultats dans un fichier

    Args:
        data: Données à sauvegarder
        output_file: Chemin du fichier de sortie
        format_type: Format de sortie (json, txt, html, markdown)
    """
    try:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format_type == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        elif format_type == 'txt':
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(str(data))

        elif format_type == 'html':
            # Génération HTML basique
            html_content = generate_html_report(data)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

        elif format_type == 'markdown':
            # Génération Markdown basique
            md_content = generate_markdown_report(data)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(md_content)

        print(f"💾 Résultats sauvegardés: {output_path}")
        logger.info(f"Résultats sauvegardés dans {output_path}")

    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde: {e}")
        print(f"⚠️ Impossible de sauvegarder: {e}")


def generate_html_report(data: Dict[str, Any]) -> str:
    """Génère un rapport HTML basique"""
    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Rapport d'Analyse</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .vulnerability {{ border: 1px solid #ddd; padding: 10px; margin: 10px 0; }}
        .critical {{ border-left: 5px solid red; }}
        .high {{ border-left: 5px solid orange; }}
        .medium {{ border-left: 5px solid yellow; }}
        .low {{ border-left: 5px solid green; }}
    </style>
</head>
<body>
    <h1>Rapport d'Analyse de Sécurité</h1>
    <pre>{json.dumps(data, indent=2, ensure_ascii=False)}</pre>
</body>
</html>
    """


def generate_markdown_report(data: Dict[str, Any]) -> str:
    """Génère un rapport Markdown basique"""
    return f"""# Rapport d'Analyse de Sécurité

## Résultats

```json
{json.dumps(data, indent=2, ensure_ascii=False)}
```
"""


# ============================================================================
# MAIN
# ============================================================================

async def main() -> int:
    """
    Fonction principale

    Returns:
        int: Code de retour du programme
    """
    # Parser les arguments
    parser = create_argument_parser()
    args = parser.parse_args()

    # Configuration du logging
    configure_logging(args)

    # Afficher la bannière (sauf en mode silencieux)
    if not args.quiet and not args.api:
        print_application_banner()

    # Traiter les commandes utilitaires d'abord
    if args.version:
        print(f"Agent IA de Cybersécurité v1.0.0")
        return 0

    if args.status:
        display_application_status()
        return 0

    if args.check_deps:
        return 0 if check_dependencies() else 1

    if args.test:
        return await run_basic_tests()

    # Valider les arguments
    validate_arguments(args)

    # Configurer les gestionnaires de signaux
    setup_signal_handlers()

    # Traiter les commandes principales
    try:
        if args.interactive:
            return handle_interactive_mode()

        elif args.api:
            return handle_api_command(args)

        elif args.scan:
            return await handle_scan_command(args)

        elif args.analyze:
            return await handle_analyze_command(args)

        elif args.generate:
            return await handle_generate_command(args)

        elif args.full_workflow:
            return await handle_full_workflow_command(args)

        else:
            # Aucune action spécifiée, afficher l'aide
            parser.print_help()
            return 1

    except KeyboardInterrupt:
        print("\n🛑 Interruption par l'utilisateur")
        return 130  # Code standard pour SIGINT
    except Exception as e:
        logger.error(f"Erreur inattendue: {e}", exc_info=True)
        print(f"❌ Erreur inattendue: {e}", file=sys.stderr)
        return 1
    finally:
        # Nettoyage final
        if supervisor_instance:
            try:
                await supervisor_instance.shutdown()
            except Exception as e:
                logger.error(f"Erreur lors du shutdown: {e}")


if __name__ == "__main__":
    # Afficher les informations de configuration au démarrage
    try:
        config = get_config()
        print("✅ Configuration OpenAI chargée:")
        print(f"   - Modèle: {config.get('openai_model', 'N/A')}")
        print(f"   - Timeout: {config.get('openai_timeout', 'N/A')}s")
        print(f"   - Max tokens: {config.get('openai_max_tokens', 'N/A')}")

        print("💰 Limites pour économiser les tokens:")
        print(f"   - Vulnérabilités analysées max: 10")
        print(f"   - Scripts générés max: 5")

        print("⚡ Types de scans disponibles:")
        for scan_type, info in SCAN_TYPES.items():
            print(f"   - {scan_type}: {info['description']}")
    except Exception as e:
        print(f"⚠️ Avertissement configuration: {e}")

    # Lancer l'application
    exit_code = asyncio.run(main())
    sys.exit(exit_code)