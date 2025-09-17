#!/usr/bin/env python3
"""
Point d'entrée principal pour l'Agent IA de Cybersécurité

Ce script fournit une interface en ligne de commande pour lancer
l'agent de cybersécurité avec différents modes d'exécution :
- Scan de vulnérabilités
- Analyse IA
- Génération de scripts
- Interface API REST
- Workflows complets

Usage:
    python main.py --help
    python main.py --target 192.168.1.100 --scan
    python main.py --api --port 8000
    python main.py --target example.com --full-workflow
"""

import asyncio
import argparse
import logging
import sys
import signal
import os
from pathlib import Path
from typing import Optional, Dict, Any
import uvicorn

# Ajouter le répertoire src au PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent / "src"))

from config import get_config, validate_config
from src import (
    print_application_banner,
    print_quick_start,
    get_application_status,
    create_agent,
    ApplicationStatus
)
from src.core.supervisor import Supervisor, WorkflowType
from src.api.main import create_app
from src.utils.logger import setup_logger

# Configuration du logging principal
logger = setup_logger(__name__)

# Variables globales pour la gestion des signaux
supervisor_instance: Optional[Supervisor] = None
api_server_process: Optional[Any] = None
shutdown_event = asyncio.Event()


def setup_signal_handlers():
    """Configure les gestionnaires de signaux pour un arrêt propre"""

    def signal_handler(signum, frame):
        """Gestionnaire de signal pour arrêt propre"""
        logger.info(f"Signal {signum} reçu, arrêt en cours...")
        shutdown_event.set()

        # Arrêter le superviseur si actif
        if supervisor_instance:
            asyncio.create_task(supervisor_instance.shutdown())

    # Configurer les signaux
    signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Kill


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Crée le parser d'arguments en ligne de commande

    Returns:
        argparse.ArgumentParser: Parser configuré
    """
    parser = argparse.ArgumentParser(
        description="Agent IA de Cybersécurité - Détection et correction automatisée de vulnérabilités",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:

  # Scan simple
  %(prog)s --target 192.168.1.100 --scan

  # Scan avec analyse IA
  %(prog)s --target example.com --scan --analyze

  # Workflow complet (scan + analyse + génération scripts)
  %(prog)s --target 192.168.1.1 --full-workflow

  # Lancer l'API REST
  %(prog)s --api --port 8000

  # Scan avec paramètres personnalisés
  %(prog)s --target 192.168.1.0/24 --scan-type aggressive --timeout 600

  # Analyser un fichier de vulnérabilités existant
  %(prog)s --analyze-file vulnerabilities.json

  # Interface interactive
  %(prog)s --interactive

Pour plus d'informations: https://github.com/votre-repo/agent-ia-poc
        """
    )

    # === ARGUMENTS PRINCIPAUX ===

    # Mode d'exécution
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--scan',
        action='store_true',
        help="Lancer un scan de vulnérabilités"
    )
    mode_group.add_argument(
        '--analyze',
        action='store_true',
        help="Analyser des vulnérabilités avec l'IA"
    )
    mode_group.add_argument(
        '--generate',
        action='store_true',
        help="Générer des scripts de correction"
    )
    mode_group.add_argument(
        '--full-workflow',
        action='store_true',
        help="Workflow complet (scan + analyse + génération)"
    )
    mode_group.add_argument(
        '--api',
        action='store_true',
        help="Lancer l'interface API REST"
    )
    mode_group.add_argument(
        '--interactive',
        action='store_true',
        help="Mode interactif"
    )

    # === PARAMÈTRES DE CIBLE ===

    target_group = parser.add_argument_group('Paramètres de cible')
    target_group.add_argument(
        '--target',
        type=str,
        help="Cible à scanner (IP, hostname, ou plage CIDR)"
    )
    target_group.add_argument(
        '--target-file',
        type=str,
        help="Fichier contenant la liste des cibles"
    )

    # === PARAMÈTRES DE SCAN ===

    scan_group = parser.add_argument_group('Paramètres de scan')
    scan_group.add_argument(
        '--scan-type',
        choices=['quick', 'full', 'stealth', 'aggressive'],
        default='full',
        help="Type de scan à effectuer (défaut: full)"
    )
    scan_group.add_argument(
        '--nmap-args',
        type=str,
        help="Arguments Nmap personnalisés"
    )
    scan_group.add_argument(
        '--timeout',
        type=int,
        default=300,
        help="Timeout du scan en secondes (défaut: 300)"
    )
    scan_group.add_argument(
        '--ports',
        type=str,
        help="Ports à scanner (ex: 22,80,443 ou 1-1000)"
    )

    # === PARAMÈTRES D'ANALYSE ===

    analyze_group = parser.add_argument_group('Paramètres d\'analyse IA')
    analyze_group.add_argument(
        '--analyze-file',
        type=str,
        help="Fichier JSON de vulnérabilités à analyser"
    )
    analyze_group.add_argument(
        '--ai-model',
        choices=['gpt-4', 'gpt-3.5-turbo', 'ollama'],
        default='gpt-4',
        help="Modèle IA à utiliser (défaut: gpt-4)"
    )
    analyze_group.add_argument(
        '--business-context',
        type=str,
        help="Contexte business pour l'analyse (ex: production, test)"
    )

    # === PARAMÈTRES DE GÉNÉRATION ===

    generate_group = parser.add_argument_group('Paramètres de génération de scripts')
    generate_group.add_argument(
        '--target-system',
        choices=['ubuntu', 'debian', 'centos', 'rhel', 'windows'],
        default='ubuntu',
        help="Système d'exploitation cible (défaut: ubuntu)"
    )
    generate_group.add_argument(
        '--risk-tolerance',
        choices=['low', 'medium', 'high'],
        default='low',
        help="Tolérance au risque pour les scripts (défaut: low)"
    )
    generate_group.add_argument(
        '--max-scripts',
        type=int,
        default=10,
        help="Nombre maximum de scripts à générer (défaut: 10)"
    )

    # === PARAMÈTRES API ===

    api_group = parser.add_argument_group('Paramètres API REST')
    api_group.add_argument(
        '--host',
        type=str,
        default='0.0.0.0',
        help="Adresse d'écoute de l'API (défaut: 0.0.0.0)"
    )
    api_group.add_argument(
        '--port',
        type=int,
        default=8000,
        help="Port d'écoute de l'API (défaut: 8000)"
    )
    api_group.add_argument(
        '--dev',
        action='store_true',
        help="Mode développement (reload automatique)"
    )
    api_group.add_argument(
        '--reload',
        action='store_true',
        help="Activer le reload automatique"
    )

    # === PARAMÈTRES GÉNÉRAUX ===

    general_group = parser.add_argument_group('Paramètres généraux')
    general_group.add_argument(
        '--config',
        type=str,
        help="Fichier de configuration personnalisé"
    )
    general_group.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help="Niveau de logging (défaut: INFO)"
    )
    general_group.add_argument(
        '--output',
        type=str,
        help="Fichier de sortie pour les résultats"
    )
    general_group.add_argument(
        '--format',
        choices=['json', 'txt', 'html', 'csv'],
        default='json',
        help="Format de sortie (défaut: json)"
    )
    general_group.add_argument(
        '--quiet',
        action='store_true',
        help="Mode silencieux (moins de logs)"
    )
    general_group.add_argument(
        '--verbose', '-v',
        action='store_true',
        help="Mode verbeux (plus de logs)"
    )

    # === ACTIONS UTILITAIRES ===

    utils_group = parser.add_argument_group('Actions utilitaires')
    utils_group.add_argument(
        '--version',
        action='store_true',
        help="Afficher la version et quitter"
    )
    utils_group.add_argument(
        '--status',
        action='store_true',
        help="Afficher le statut de l'application"
    )
    utils_group.add_argument(
        '--check-deps',
        action='store_true',
        help="Vérifier les dépendances"
    )
    utils_group.add_argument(
        '--test',
        action='store_true',
        help="Lancer les tests de base"
    )

    return parser


def configure_logging(args) -> None:
    """
    Configure le système de logging selon les arguments

    Args:
        args: Arguments parsés
    """
    # Déterminer le niveau de log
    log_level = args.log_level

    if args.quiet:
        log_level = 'WARNING'
    elif args.verbose:
        log_level = 'DEBUG'

    # Configurer le logging
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('logs/app.log') if Path('logs').exists() else logging.NullHandler()
        ]
    )

    logger.info(f"Logging configuré: niveau {log_level}")


def validate_arguments(args) -> None:
    """
    Valide la cohérence des arguments

    Args:
        args: Arguments parsés

    Raises:
        SystemExit: Si les arguments sont invalides
    """
    errors = []

    # Vérifier qu'une action est spécifiée
    actions = [args.scan, args.analyze, args.generate, args.full_workflow, args.api, args.interactive]
    if not any(actions) and not any([args.version, args.status, args.check_deps, args.test]):
        errors.append("Aucune action spécifiée. Utilisez --help pour voir les options.")

    # Vérifier les prérequis par action
    if args.scan or args.full_workflow:
        if not args.target and not args.target_file:
            errors.append("--target ou --target-file requis pour le scan")

    if args.analyze and not args.analyze_file and not args.target:
        errors.append("--analyze-file ou --target requis pour l'analyse")

    # Vérifier les fichiers d'entrée
    if args.target_file and not Path(args.target_file).exists():
        errors.append(f"Fichier de cibles non trouvé: {args.target_file}")

    if args.analyze_file and not Path(args.analyze_file).exists():
        errors.append(f"Fichier d'analyse non trouvé: {args.analyze_file}")

    if args.config and not Path(args.config).exists():
        errors.append(f"Fichier de configuration non trouvé: {args.config}")

    # Vérifier les paramètres numériques
    if args.timeout <= 0:
        errors.append("Le timeout doit être positif")

    if args.port < 1 or args.port > 65535:
        errors.append("Le port doit être entre 1 et 65535")

    if args.max_scripts < 1:
        errors.append("Le nombre maximum de scripts doit être positif")

    # Afficher les erreurs et quitter si nécessaire
    if errors:
        print("❌ Erreurs de validation des arguments:", file=sys.stderr)
        for error in errors:
            print(f"   {error}", file=sys.stderr)
        sys.exit(1)


async def handle_scan_command(args) -> int:
    """
    Traite la commande de scan

    Args:
        args: Arguments parsés

    Returns:
        int: Code de retour (0 = succès)
    """
    try:
        logger.info(f"🔍 Début du scan: {args.target}")

        # Créer le superviseur
        global supervisor_instance
        supervisor_instance = create_agent()

        # Préparer les paramètres de scan
        scan_params = {
            'scan_type': args.scan_type,
            'timeout': args.timeout,
        }

        if args.nmap_args:
            scan_params['nmap_args'] = args.nmap_args

        if args.ports:
            scan_params['ports'] = args.ports

        # Lancer le scan
        def progress_callback(progress: int):
            if not args.quiet:
                print(f"\r🔄 Progression du scan: {progress}%", end="", flush=True)

        result = await supervisor_instance.run_scan(
            target=args.target,
            scan_type=args.scan_type,
            progress_callback=progress_callback if not args.quiet else None
        )

        if not args.quiet:
            print()  # Nouvelle ligne après la progression

        # Afficher les résultats
        vulns_found = len(result.vulnerabilities)
        print(f"\n✅ Scan terminé:")
        print(f"   • Cible: {result.target}")
        print(f"   • Durée: {result.duration:.1f}s")
        print(f"   • Ports ouverts: {len(result.open_ports)}")
        print(f"   • Services: {len(result.services)}")
        print(f"   • Vulnérabilités: {vulns_found}")

        if vulns_found > 0:
            print(f"\n🚨 Vulnérabilités détectées:")
            for vuln in result.vulnerabilities[:5]:  # Limiter à 5 pour l'affichage
                severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(vuln.severity, "⚪")
                print(f"   {severity_icon} {vuln.name} ({vuln.severity})")

            if vulns_found > 5:
                print(f"   ... et {vulns_found - 5} autres vulnérabilités")

        # Sauvegarder les résultats si demandé
        if args.output:
            await save_results(result.to_dict(), args.output, args.format)

        return 0

    except Exception as e:
        logger.error(f"Erreur lors du scan: {e}")
        print(f"❌ Erreur: {e}", file=sys.stderr)
        return 1
    finally:
        if supervisor_instance:
            await supervisor_instance.shutdown()


async def handle_full_workflow_command(args) -> int:
    """
    Traite le workflow complet (scan + analyse + génération)

    Args:
        args: Arguments parsés

    Returns:
        int: Code de retour
    """
    try:
        logger.info(f"🚀 Début du workflow complet: {args.target}")

        # Créer le superviseur
        global supervisor_instance
        supervisor_instance = create_agent()

        # Callback de progression
        def progress_callback(task: str, progress: int):
            if not args.quiet:
                task_icons = {
                    "scan": "🔍",
                    "analyze": "🧠",
                    "generate_scripts": "🔧"
                }
                icon = task_icons.get(task, "⚙️")
                print(f"\r{icon} {task.title()}: {progress}%", end="", flush=True)

        # Lancer le workflow complet
        result = await supervisor_instance.run_complete_workflow(
            target=args.target,
            scan_type=args.scan_type,
            progress_callback=progress_callback if not args.quiet else None
        )

        if not args.quiet:
            print()  # Nouvelle ligne après la progression

        # Afficher le résumé
        print(f"\n✅ Workflow terminé:")
        print(f"   • Cible: {result.target}")
        print(f"   • Durée totale: {result.duration:.1f}s")
        print(f"   • Vulnérabilités trouvées: {result.total_vulnerabilities}")
        print(f"   • Vulnérabilités critiques: {result.critical_vulnerabilities}")
        print(f"   • Scripts générés: {result.scripts_generated}")

        # Détails sur les résultats
        if result.scan_result:
            print(f"\n📊 Résultats du scan:")
            print(f"   • Ports ouverts: {len(result.scan_result.open_ports)}")
            print(f"   • Services détectés: {len(result.scan_result.services)}")

        if result.analysis_result:
            print(f"\n🧠 Résultats de l'analyse IA:")
            print(f"   • Modèle utilisé: {result.analysis_result.ai_model_used}")
            print(f"   • Confiance: {result.analysis_result.confidence_score:.1%}")

        if result.script_results:
            print(f"\n🔧 Scripts générés:")
            for script in result.script_results[:3]:  # Limiter l'affichage
                risk_icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(script.metadata.risk_level,
                                                                                          "⚪")
                print(f"   {risk_icon} {script.script_id} (Risque: {script.metadata.risk_level})")

            if len(result.script_results) > 3:
                print(f"   ... et {len(result.script_results) - 3} autres scripts")

        # Sauvegarder les résultats
        if args.output:
            await save_results(result.to_dict(), args.output, args.format)

        return 0

    except Exception as e:
        logger.error(f"Erreur lors du workflow: {e}")
        print(f"❌ Erreur: {e}", file=sys.stderr)
        return 1
    finally:
        if supervisor_instance:
            await supervisor_instance.shutdown()


def handle_api_command(args) -> int:
    """
    Lance l'interface API REST

    Args:
        args: Arguments parsés

    Returns:
        int: Code de retour
    """
    try:
        print(f"🚀 Lancement de l'API REST sur {args.host}:{args.port}")

        # Créer l'application FastAPI
        app = create_app()

        # Configuration uvicorn
        uvicorn_config = {
            "app": app,
            "host": args.host,
            "port": args.port,
            "log_level": args.log_level.lower(),
            "access_log": not args.quiet,
        }

        # Mode développement
        if args.dev or args.reload:
            uvicorn_config.update({
                "reload": True,
                "reload_dirs": ["src", "config"],
                "log_level": "debug"
            })

        print(f"📚 Documentation API: http://{args.host}:{args.port}/docs")
        print(f"🔄 Alternative ReDoc: http://{args.host}:{args.port}/redoc")
        print(f"🏥 Health Check: http://{args.host}:{args.port}/health")

        if not args.quiet:
            print(f"🛑 Arrêt: Ctrl+C")

        # Lancer le serveur
        uvicorn.run(**uvicorn_config)

        return 0

    except KeyboardInterrupt:
        print("\n🛑 Arrêt de l'API demandé par l'utilisateur")
        return 0
    except Exception as e:
        logger.error(f"Erreur lors du lancement de l'API: {e}")
        print(f"❌ Erreur API: {e}", file=sys.stderr)
        return 1


def handle_interactive_mode() -> int:
    """
    Mode interactif

    Returns:
        int: Code de retour
    """
    try:
        print("🎮 Mode interactif - Agent IA de Cybersécurité")
        print("Tapez 'help' pour voir les commandes disponibles, 'quit' pour quitter.")

        while True:
            try:
                command = input("\n> ").strip()

                if command in ['quit', 'exit', 'q']:
                    print("👋 Au revoir !")
                    break

                elif command == 'help':
                    print("""
Commandes disponibles:
  scan <target>           - Scanner une cible
  analyze <file>          - Analyser un fichier de vulnérabilités  
  status                  - Afficher le statut de l'application
  check                   - Vérifier les dépendances
  api                     - Lancer l'API REST
  help                    - Afficher cette aide
  quit/exit/q             - Quitter
                    """)

                elif command == 'status':
                    display_application_status()

                elif command == 'check':
                    check_dependencies()

                elif command.startswith('scan '):
                    target = command.split(' ', 1)[1]
                    print(f"🔍 Scan de {target} (fonctionnalité à implémenter en mode async)")

                elif command == 'api':
                    print("🚀 Lancement de l'API sur http://localhost:8000")
                    print("(Utilisez --api en ligne de commande pour un contrôle complet)")

                else:
                    print(f"❓ Commande inconnue: {command}")
                    print("Tapez 'help' pour voir les commandes disponibles.")

            except KeyboardInterrupt:
                print("\n(Utilisez 'quit' pour quitter)")
                continue

        return 0

    except Exception as e:
        logger.error(f"Erreur mode interactif: {e}")
        print(f"❌ Erreur: {e}", file=sys.stderr)
        return 1


async def save_results(results: dict, output_file: str, format: str) -> None:
    """
    Sauvegarde les résultats dans un fichier

    Args:
        results: Résultats à sauvegarder
        output_file: Fichier de sortie
        format: Format de sortie
    """
    import json

    try:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

        elif format == 'txt':
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(str(results))

        # TODO: Implémenter les autres formats (HTML, CSV)

        print(f"💾 Résultats sauvegardés: {output_path}")

    except Exception as e:
        logger.error(f"Erreur sauvegarde: {e}")
        print(f"⚠️ Erreur sauvegarde: {e}", file=sys.stderr)


def display_application_status() -> None:
    """Affiche le statut de l'application"""
    print("\n📊 Statut de l'application:")

    try:
        status = get_application_status()

        # Statut global
        status_icon = "✅" if status["status"] == ApplicationStatus.READY else "❌"
        print(f"   {status_icon} Statut: {status['status']}")
        print(f"   📌 Version: {status['version']}")
        print(f"   💬 Message: {status['message']}")

        # Composants
        print(f"\n🧩 Composants:")
        for component, available in status["components_available"].items():
            icon = "✅" if available else "❌"
            print(f"   {icon} {component}")

        # Dépendances
        print(f"\n📦 Dépendances:")
        deps = status["dependencies"]

        for package, pkg_status in deps["python_packages"].items():
            icon = "✅" if pkg_status == "available" else "❌"
            print(f"   {icon} {package}")

        for tool, tool_status in deps["external_tools"].items():
            icon = "✅" if tool_status == "available" else "❌"
            print(f"   {icon} {tool}")

        # Recommandations
        if status["missing_critical"]:
            print(f"\n⚠️ Dépendances critiques manquantes:")
            for dep in status["missing_critical"]:
                print(f"   • {dep}")
            print(f"   💡 Exécutez: ./scripts/install.sh")
        else:
            print(f"\n✅ Toutes les dépendances critiques sont disponibles !")

    except Exception as e:
        print(f"❌ Erreur lors de la vérification du statut: {e}")


def check_dependencies() -> None:
    """Vérifie les dépendances et affiche le résultat"""
    print("🔍 Vérification des dépendances...")

    try:
        status = get_application_status()
        deps = status["dependencies"]

        print(f"\n📦 Packages Python:")
        for package, pkg_status in deps["python_packages"].items():
            icon = "✅" if pkg_status == "available" else "❌"
            print(f"   {icon} {package}")

        print(f"\n🔧 Outils externes:")
        for tool, tool_status in deps["external_tools"].items():
            icon = "✅" if tool_status == "available" else "❌"
            print(f"   {icon} {tool}")

        missing = status["missing_critical"]
        if missing:
            print(f"\n❌ {len(missing)} dépendances critiques manquantes")
            return False
        else:
            print(f"\n✅ Toutes les dépendances sont disponibles !")
            return True

    except Exception as e:
        print(f"❌ Erreur vérification dépendances: {e}")
        return False


def run_basic_tests() -> int:
    """Lance des tests de base"""
    print("🧪 Lancement des tests de base...")

    try:
        # Test 1: Configuration
        print("📋 Test de configuration...", end="")
        config = get_config()
        print(" ✅")

        # Test 2: Modules core
        print("🧩 Test des modules core...", end="")
        from src.core import Collector, Analyzer, Generator
        print(" ✅")

        # Test 3: Base de données
        print("🗄️ Test de base de données...", end="")
        from src.database import Database
        db = Database()
        print(" ✅")

        # Test 4: API
        print("🌐 Test de l'API...", end="")
        from src.api import create_app
        app = create_app()
        print(" ✅")

        print("\n✅ Tous les tests de base sont passés !")
        return 0

    except Exception as e:
        print(f" ❌")
        print(f"❌ Erreur lors des tests: {e}")
        logger.error(f"Erreur tests de base: {e}")
        return 1


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
        from src import get_version
        print(f"Agent IA de Cybersécurité v{get_version()}")
        return 0

    if args.status:
        display_application_status()
        return 0

    if args.check_deps:
        return 0 if check_dependencies() else 1

    if args.test:
        return run_basic_tests()

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
            except:
                pass


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
        supervisor_instance = create_agent()

        # Charger les données de vulnérabilités
        if args.analyze_file:
            print(f"📂 Chargement du fichier: {args.analyze_file}")

            import json
            with open(args.analyze_file, 'r', encoding='utf-8') as f:
                vulnerabilities_data = json.load(f)

            # S'assurer que c'est une liste
            if isinstance(vulnerabilities_data, dict):
                if 'vulnerabilities' in vulnerabilities_data:
                    vulnerabilities_data = vulnerabilities_data['vulnerabilities']
                else:
                    vulnerabilities_data = [vulnerabilities_data]

        else:
            # Analyser à partir d'un scan
            print(f"🔍 Scan et analyse de: {args.target}")
            scan_result = await supervisor_instance.run_scan(args.target, args.scan_type)
            vulnerabilities_data = [vuln.to_dict() for vuln in scan_result.vulnerabilities]

        if not vulnerabilities_data:
            print("⚠️ Aucune vulnérabilité à analyser")
            return 0

        print(f"🧠 Analyse de {len(vulnerabilities_data)} vulnérabilités...")

        # Lancer l'analyse
        analysis_result = await supervisor_instance.analyze_vulnerabilities(
            vulnerabilities_data=vulnerabilities_data,
            target_system=args.target or "Système inconnu"
        )

        # Afficher les résultats
        print(f"\n✅ Analyse terminée:")
        print(f"   • Vulnérabilités analysées: {len(analysis_result.vulnerabilities)}")
        print(f"   • Score de risque global: {analysis_result.analysis_summary.get('overall_risk_score', 0):.1f}/10")
        print(f"   • Modèle IA utilisé: {analysis_result.ai_model_used}")
        print(f"   • Confiance: {analysis_result.confidence_score:.1%}")

        # Afficher le résumé par gravité
        summary = analysis_result.analysis_summary
        if 'critical_count' in summary:
            print(f"\n📊 Répartition par gravité:")
            print(f"   🔴 Critiques: {summary.get('critical_count', 0)}")
            print(f"   🟠 Élevées: {summary.get('high_count', 0)}")
            print(f"   🟡 Moyennes: {summary.get('medium_count', 0)}")
            print(f"   🟢 Faibles: {summary.get('low_count', 0)}")

        # Afficher les actions prioritaires
        if 'immediate_actions_required' in summary:
            immediate = summary['immediate_actions_required']
            if immediate > 0:
                print(f"\n⚠️ Actions immédiates requises: {immediate}")

                # Afficher les vulnérabilités prioritaires
                priority_vulns = sorted(
                    analysis_result.vulnerabilities,
                    key=lambda v: v.priority_score,
                    reverse=True
                )[:3]

                for vuln in priority_vulns:
                    if vuln.priority_score >= 8:
                        severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(vuln.severity,
                                                                                                      "⚪")
                        print(f"   {severity_icon} {vuln.name} (Priorité: {vuln.priority_score}/10)")

        # Sauvegarder si demandé
        if args.output:
            await save_results(analysis_result.to_dict(), args.output, args.format)

        return 0

    except Exception as e:
        logger.error(f"Erreur lors de l'analyse: {e}")
        print(f"❌ Erreur: {e}", file=sys.stderr)
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
        supervisor_instance = create_agent()

        # Déterminer les vulnérabilités à traiter
        if args.analyze_file:
            print(f"📂 Chargement des vulnérabilités: {args.analyze_file}")

            import json
            with open(args.analyze_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Extraire les vulnérabilités selon le format
            if isinstance(data, list):
                vulnerabilities_data = data
            elif 'vulnerabilities' in data:
                vulnerabilities_data = data['vulnerabilities']
            elif 'analysis_result' in data and 'vulnerabilities' in data['analysis_result']:
                vulnerabilities_data = data['analysis_result']['vulnerabilities']
            else:
                vulnerabilities_data = [data]

        elif args.target:
            # Scanner d'abord, puis générer
            print(f"🔍 Scan de {args.target} pour détecter les vulnérabilités...")
            scan_result = await supervisor_instance.run_scan(args.target, args.scan_type)
            vulnerabilities_data = [vuln.to_dict() for vuln in scan_result.vulnerabilities]
        else:
            print("❌ Aucune source de vulnérabilités spécifiée")
            return 1

        if not vulnerabilities_data:
            print("⚠️ Aucune vulnérabilité trouvée pour la génération de scripts")
            return 0

        # Limiter le nombre selon les arguments
        max_scripts = min(len(vulnerabilities_data), args.max_scripts)
        vulnerabilities_to_process = vulnerabilities_data[:max_scripts]

        print(f"🔧 Génération de scripts pour {len(vulnerabilities_to_process)} vulnérabilités...")

        # Workflow de génération
        workflow_params = {
            'vulnerabilities_data': vulnerabilities_to_process,
            'target_system': args.target_system,
            'risk_tolerance': args.risk_tolerance,
            'max_scripts': args.max_scripts
        }

        workflow_id = await supervisor_instance.start_workflow(
            workflow_type=WorkflowType.GENERATE_SCRIPTS,
            target=args.target_system,
            parameters=workflow_params
        )

        # Attendre les résultats
        def progress_callback(task: str, progress: int):
            if not args.quiet:
                print(f"\r🔧 Génération: {progress}%", end="", flush=True)

        supervisor_instance.set_progress_callback(workflow_id, progress_callback)
        result = await supervisor_instance.wait_for_workflow(workflow_id)

        if not args.quiet:
            print()  # Nouvelle ligne après la progression

        # Afficher les résultats
        scripts_generated = len(result.script_results) if result.script_results else 0
        print(f"\n✅ Génération terminée:")
        print(f"   • Scripts générés: {scripts_generated}")
        print(f"   • Système cible: {args.target_system}")
        print(f"   • Tolérance au risque: {args.risk_tolerance}")

        if result.script_results:
            print(f"\n📝 Scripts générés:")

            # Compter par niveau de risque
            risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

            for script in result.script_results:
                risk_level = script.metadata.risk_level
                risk_counts[risk_level] += 1

                # Afficher les détails des premiers scripts
                if len([s for s in result.script_results if s == script]) <= 5:
                    risk_icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(risk_level, "⚪")
                    reboot_icon = " 🔄" if script.metadata.requires_reboot else ""
                    sudo_icon = " 🔑" if script.metadata.requires_sudo else ""

                    print(f"   {risk_icon} {script.script_id}")
                    print(f"      Vulnérabilité: {script.vulnerability_id}")
                    print(f"      Risque: {risk_level}{reboot_icon}{sudo_icon}")
                    print(f"      Durée estimée: {script.metadata.estimated_duration}")

                    # Afficher les warnings importants
                    if script.warnings:
                        critical_warnings = [w for w in script.warnings if "🚨" in w or "DANGER" in w.upper()]
                        for warning in critical_warnings[:2]:
                            print(f"      ⚠️ {warning}")

            if scripts_generated > 5:
                print(f"   ... et {scripts_generated - 5} autres scripts")

            # Résumé par risque
            print(f"\n📊 Répartition par niveau de risque:")
            for risk, count in risk_counts.items():
                if count > 0:
                    risk_icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(risk, "⚪")
                    print(f"   {risk_icon} {risk}: {count} scripts")

            # Recommandations de sécurité
            high_risk_count = risk_counts["HIGH"] + risk_counts["CRITICAL"]
            if high_risk_count > 0:
                print(f"\n⚠️ Attention: {high_risk_count} scripts à haut risque détectés")
                print(f"   Recommandation: Révision manuelle obligatoire avant exécution")
                print(f"   Testez d'abord dans un environnement de développement")

        # Sauvegarder les résultats
        if args.output:
            await save_results(result.to_dict(), args.output, args.format)

        return 0

    except Exception as e:
        logger.error(f"Erreur lors de la génération: {e}")
        print(f"❌ Erreur: {e}", file=sys.stderr)
        return 1
    finally:
        if supervisor_instance:
            await supervisor_instance.shutdown()


def load_targets_from_file(target_file: str) -> list:
    """
    Charge les cibles depuis un fichier

    Args:
        target_file: Chemin vers le fichier de cibles

    Returns:
        list: Liste des cibles
    """
    targets = []

    try:
        with open(target_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Ignorer les commentaires et lignes vides
                if line and not line.startswith('#'):
                    targets.append(line)

        return targets

    except Exception as e:
        logger.error(f"Erreur lecture fichier cibles: {e}")
        raise


def setup_directories():
    """Crée les répertoires nécessaires s'ils n'existent pas"""
    directories = [
        "data/scans",
        "data/reports",
        "data/scripts",
        "data/database",
        "logs"
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)


def check_prerequisites() -> bool:
    """
    Vérifie les prérequis avant le lancement

    Returns:
        bool: True si tous les prérequis sont OK
    """
    issues = []

    # Vérifier Python
    if sys.version_info < (3, 10):
        issues.append(f"Python 3.10+ requis (version actuelle: {sys.version})")

    # Vérifier les répertoires
    try:
        setup_directories()
    except Exception as e:
        issues.append(f"Impossible de créer les répertoires: {e}")

    # Vérifier la configuration
    try:
        config = get_config()
        validate_config(config)
    except Exception as e:
        issues.append(f"Configuration invalide: {e}")

    # Vérifier les dépendances critiques
    status = get_application_status()
    if status["missing_critical"]:
        issues.append(f"Dépendances manquantes: {', '.join(status['missing_critical'])}")

    if issues:
        print("❌ Prérequis non satisfaits:", file=sys.stderr)
        for issue in issues:
            print(f"   • {issue}", file=sys.stderr)
        print("\n💡 Exécutez ./scripts/install.sh pour installer les dépendances", file=sys.stderr)
        return False

    return True


def main_sync():
    """Point d'entrée synchrone pour les cas non-async"""
    return asyncio.run(main())


if __name__ == "__main__":
    try:
        # Vérifier les prérequis de base
        if not check_prerequisites():
            sys.exit(1)

        # Lancer le programme principal
        exit_code = main_sync()
        sys.exit(exit_code)

    except KeyboardInterrupt:
        print("\n🛑 Interruption par l'utilisateur")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Erreur fatale: {e}", file=sys.stderr)
        sys.exit(1)