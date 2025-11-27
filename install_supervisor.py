#!/usr/bin/env python3
"""
Script pour installer le supervisor.py corrigé
Lit les fichiers depuis la racine du projet
"""

from pathlib import Path
import shutil


def install_supervisor():
    """Installe le supervisor corrigé"""

    print("🔧 Installation du supervisor.py corrigé\n")

    # Tout dans la racine du projet
    project_root = Path.cwd()

    part1_source = project_root / "supervisor_fixed_part1.py"
    part2_source = project_root / "supervisor_fixed_part2.py"
    output_file = project_root / "src" / "core" / "supervisor.py"
    backup_file = project_root / "src" / "core" / "supervisor.py.fixed-backup"

    # 1. Vérifier que les parties existent
    if not part1_source.exists():
        print(f"❌ Partie 1 non trouvée: {part1_source}")
        return False

    if not part2_source.exists():
        print(f"❌ Partie 2 non trouvée: {part2_source}")
        return False

    print(f"✅ Parties trouvées")

    # 2. Backup
    if output_file.exists():
        print(f"💾 Sauvegarde: {backup_file.name}")
        shutil.copy(output_file, backup_file)

    # 3. Lire les parties
    print("📖 Lecture des parties...")
    with open(part1_source, 'r', encoding='utf-8') as f:
        part1_content = f.read()

    with open(part2_source, 'r', encoding='utf-8') as f:
        part2_content = f.read()

    # 4. Fusionner
    print("🔗 Fusion...")
    full_content = part1_content + "\n" + part2_content

    # 5. Écrire
    print(f"💾 Installation...")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(full_content)

    lines = len(full_content.split('\n'))
    print(f"\n✅ Supervisor installé!")
    print(f"   • Lignes: {lines}")
    print(f"   • Fichier: src/core/supervisor.py")
    print(f"\n🧪 Testez:")
    print(f"   PYTHONPATH=. python main.py --analyze --analyze-file scan_dvwa.json")

    return True


if __name__ == "__main__":
    success = install_supervisor()
    exit(0 if success else 1)