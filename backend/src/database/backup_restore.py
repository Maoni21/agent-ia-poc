"""
Fonctions de sauvegarde, restauration et statistiques pour SQLite.
"""
import gzip
import os
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


def backup_database(
    database_path: str,
    backup_path: Optional[str] = None,
    compress: bool = False,
) -> str:
    """
    Sauvegarde une base SQLite.

    Args:
        database_path: Chemin de la base source
        backup_path: Chemin de destination (optionnel)
        compress: Compresser avec gzip

    Returns:
        Chemin du fichier de sauvegarde créé
    """
    path = Path(database_path)
    if not path.exists():
        raise FileNotFoundError(f"Base non trouvée: {database_path}")

    if backup_path is None:
        if compress:
            # Sauvegarde compressée -> même nom + suffixe .gz
            backup_path = str(path.with_suffix(path.suffix + ".gz"))
        else:
            # Sauvegarde non compressée -> nouveau fichier se terminant par .db
            # Exemple: backup_test.db -> backup_test_backup.db
            backup_path = str(path.with_name(f"{path.stem}_backup.db"))

    if compress:
        with open(database_path, "rb") as f_in:
            with gzip.open(backup_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
    else:
        shutil.copy2(database_path, backup_path)

    return backup_path


def restore_database(
    backup_path: str,
    target_path: str,
    verify_integrity: bool = True,
) -> bool:
    """
    Restaure une base SQLite depuis une sauvegarde.

    Args:
        backup_path: Chemin du fichier de sauvegarde (.db ou .db.gz)
        target_path: Chemin de la base à créer/écraser
        verify_integrity: Vérifier l'intégrité après restauration

    Returns:
        True si la restauration a réussi
    """
    path = Path(backup_path)
    if not path.exists():
        return False

    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    if path.suffix == ".gz":
        with gzip.open(backup_path, "rb") as f_in:
            with open(target_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
    else:
        shutil.copy2(backup_path, target_path)

    if verify_integrity:
        try:
            conn = sqlite3.connect(target_path)
            conn.execute("PRAGMA integrity_check")
            conn.close()
        except Exception:
            return False

    return True


def get_database_stats(database_path: str) -> Dict[str, Any]:
    """
    Retourne des statistiques sur une base SQLite.

    Args:
        database_path: Chemin du fichier .db

    Returns:
        Dict avec file_size_bytes, file_size_human, tables_count, tables (nom -> nb lignes),
        ou {"error": "..."} si fichier absent
    """
    path = Path(database_path)
    if not path.exists():
        return {"error": "Base de données non trouvée"}

    size = path.stat().st_size
    if size < 1024:
        size_human = f"{size} B"
    elif size < 1024 * 1024:
        size_human = f"{size / 1024:.1f} KB"
    else:
        size_human = f"{size / (1024 * 1024):.1f} MB"

    try:
        conn = sqlite3.connect(database_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        tables = [row[0] for row in cursor.fetchall()]
        tables_count = {}
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
            tables_count[table] = cursor.fetchone()[0]
        conn.close()
    except Exception as e:
        return {"error": str(e)}

    tables_count_value = len(tables)

    # Pour compatibilité avec les tests: exposer à la fois tables_count et table_counts
    return {
        "file_size_bytes": size,
        "file_size_human": size_human,
        "tables_count": tables_count_value,
        "table_counts": tables_count_value,
        "tables": tables_count,
    }
