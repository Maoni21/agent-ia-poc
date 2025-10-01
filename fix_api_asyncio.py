#!/usr/bin/env python3
"""
Script pour corriger le lancement de l'API dans main.py
"""

from pathlib import Path
import re


def fix_main_api_launch():
    """Corrige la fonction run_api_server dans main.py"""

    main_file = Path("main.py")

    if not main_file.exists():
        print(f"❌ {main_file} n'existe pas")
        return False

    print(f"🔧 Correction de {main_file}...")

    with open(main_file, 'r') as f:
        content = f.read()

    # Sauvegarder
    backup = main_file.with_suffix('.py.backup')
    with open(backup, 'w') as f:
        f.write(content)
    print(f"✅ Sauvegarde: {backup}")

    # Trouver et remplacer la fonction run_api_server
    old_pattern = r'def run_api_server\(.*?\):.*?(?=\ndef |\Z)'

    new_function = '''def run_api_server(host: str = "0.0.0.0", port: int = 8000) -> int:
    """Lance le serveur API REST"""
    try:
        print(f"🚀 Lancement de l'API REST sur {host}:{port}")
        print(f"📚 Documentation API: http://{host}:{port}/docs")
        print(f"🔄 Alternative ReDoc: http://{host}:{port}/redoc")
        print(f"🏥 Health Check: http://{host}:{port}/health")
        print("🛑 Arrêt: Ctrl+C")

        # Importer uvicorn
        import uvicorn

        # Créer l'app
        from src.api.main import create_app
        app = create_app()

        # Lancer uvicorn directement (pas avec asyncio.run)
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level="info",
            access_log=True
        )

        return 0

    except KeyboardInterrupt:
        print("\\n🛑 API arrêtée par l'utilisateur")
        return 0
    except Exception as e:
        logger.error(f"Erreur lors du lancement de l'API: {e}")
        print(f"❌ Erreur API: {e}")
        return 1

'''

    # Remplacer
    content = re.sub(old_pattern, new_function, content, flags=re.DOTALL)

    # Écrire
    with open(main_file, 'w') as f:
        f.write(content)

    print(f"✅ {main_file} corrigé")
    return True


def main():
    print("=" * 70)
    print("CORRECTION DU LANCEMENT API")
    print("=" * 70)
    print()

    if fix_main_api_launch():
        print()
        print("✅ MAIN.PY CORRIGÉ")
        print()
        print("Testez maintenant:")
        print("   python main.py --api")
        print()
        print("L'API devrait démarrer sur http://localhost:8000")
        print("Documentation: http://localhost:8000/docs")
        return 0

    return 1


if __name__ == "__main__":
    exit(main())