"""
Script pour ajouter les tables personnalisées (groupes de vulnérabilités, historique analyses)
"""

import sqlite3
from pathlib import Path
import sys

def add_custom_tables(db_path: Path):
    """Ajoute les tables personnalisées à la base de données"""
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Table des groupes de vulnérabilités personnalisés
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                vulnerability_ids TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT DEFAULT 'user'
            )
        """)
        
        # Table pour l'historique des analyses IA
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT UNIQUE NOT NULL,
                workflow_id TEXT,
                target_system TEXT NOT NULL,
                vulnerability_ids TEXT NOT NULL,
                ai_model_used TEXT,
                analysis_summary TEXT,
                remediation_plan TEXT,
                confidence_score REAL,
                processing_time REAL,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT DEFAULT 'user'
            )
        """)
        
        # Index
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_groups_name ON vulnerability_groups(name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_history_target ON analysis_history(target_system)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_history_analyzed_at ON analysis_history(analyzed_at)")
        
        conn.commit()
        conn.close()
        
        print(f"✅ Tables personnalisées ajoutées avec succès: {db_path}")
        return True
        
    except Exception as e:
        print(f"❌ Erreur lors de l'ajout des tables: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    BASE_DIR = Path(__file__).parent  # src/web
    ROOT_DIR = BASE_DIR.parent.parent  # Racine du projet
    DATA_DIR = ROOT_DIR / "data"
    DB_PATH = DATA_DIR / "database" / "vulnerability_agent.db"
    
    print(f"🔧 Ajout des tables personnalisées...")
    print(f"📁 Chemin: {DB_PATH}")
    
    if add_custom_tables(DB_PATH):
        print("✅ Tables ajoutées avec succès!")
    else:
        print("❌ Échec de l'ajout des tables")
        sys.exit(1)

