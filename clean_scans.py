#!/usr/bin/env python3
"""
Script pour nettoyer les scans dans la base de données et les fichiers JSON
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import List, Dict

# Chemins
WORKFLOWS_DIR = Path("src/web/data/workflow_results")
ALT_WORKFLOWS_DIR = Path("data/workflow_results")
DB_PATH = Path("data/database/vulnerability_agent.db")


def load_all_scans() -> List[Dict]:
    """Charge tous les scans depuis les fichiers JSON"""
    scans = []
    
    for workflows_dir in [WORKFLOWS_DIR, ALT_WORKFLOWS_DIR]:
        if not workflows_dir.exists():
            continue
            
        for json_file in workflows_dir.glob("*.json"):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                status = data.get('status', 'unknown')
                workflow_id = data.get('workflow_id', json_file.stem)
                target = data.get('target', 'N/A')
                workflow_type = data.get('workflow_type', 'N/A')
                started_at = data.get('started_at', 'N/A')
                total_vulns = data.get('total_vulnerabilities', 0)
                
                # Compter les vulnérabilités réelles si total_vulnerabilities est 0
                if total_vulns == 0:
                    scan_result = data.get('scan_result', {})
                    analysis_result = data.get('analysis_result', {})
                    if scan_result:
                        total_vulns = len(scan_result.get('vulnerabilities', []))
                    elif analysis_result:
                        total_vulns = len(analysis_result.get('vulnerabilities', []))
                
                scans.append({
                    'file': json_file,
                    'workflow_id': workflow_id,
                    'status': status,
                    'target': target,
                    'type': workflow_type,
                    'started_at': started_at,
                    'vulns': total_vulns
                })
            except Exception as e:
                print(f"⚠️ Erreur lecture {json_file.name}: {e}")
    
    # Trier par date (plus récent en premier)
    scans.sort(key=lambda x: x['started_at'], reverse=True)
    return scans


def display_scans(scans: List[Dict]):
    """Affiche la liste des scans"""
    print("\n" + "=" * 110)
    print(f"{'#':<4} {'Status':<12} {'Workflow ID':<40} {'Cible':<20} {'Type':<20} {'Vulns':<8} {'Date'}")
    print("=" * 110)
    
    for i, scan in enumerate(scans, 1):
        status_icon = "✅" if scan['status'] == 'completed' else "❌" if scan['status'] == 'failed' else "⏳"
        status_display = f"{status_icon} {scan['status']}"
        workflow_short = scan['workflow_id'][:36] + "..." if len(scan['workflow_id']) > 36 else scan['workflow_id']
        date_short = scan['started_at'][:19] if len(scan['started_at']) > 19 else scan['started_at']
        
        print(f"{i:<4} {status_display:<12} {workflow_short:<40} {scan['target']:<20} {scan['type']:<20} {scan['vulns']:<8} {date_short}")
    
    print("=" * 110)
    
    completed = [s for s in scans if s['status'] == 'completed']
    failed = [s for s in scans if s['status'] == 'failed']
    other = [s for s in scans if s['status'] not in ('completed', 'failed')]
    zero_vulns = [s for s in scans if s['vulns'] == 0]
    
    print(f"\n📊 Résumé:")
    print(f"   ✅ Complétés: {len(completed)}")
    print(f"   ❌ Échoués: {len(failed)}")
    print(f"   ⏳ Autres: {len(other)}")
    print(f"   🔴 Sans vulnérabilités: {len(zero_vulns)}")


def delete_scans(scans_to_delete: List[Dict], dry_run: bool = False):
    """Supprime les scans sélectionnés"""
    deleted_count = 0
    
    for scan in scans_to_delete:
        json_file = scan['file']
        if json_file.exists():
            if dry_run:
                print(f"🔍 [DRY RUN] Suppression de: {json_file.name}")
            else:
                try:
                    json_file.unlink()
                    print(f"🗑️  Supprimé: {json_file.name}")
                    deleted_count += 1
                except Exception as e:
                    print(f"❌ Erreur suppression {json_file.name}: {e}")
        else:
            print(f"⚠️  Fichier non trouvé: {json_file}")
    
    if not dry_run:
        print(f"\n✅ {deleted_count} scan(s) supprimé(s)")
    
    return deleted_count


def clean_database():
    """Nettoie la base de données SQLite"""
    if not DB_PATH.exists():
        print("ℹ️  Base de données non trouvée, rien à nettoyer")
        return
    
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        # Lister les tables
        tables = cursor.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        
        print("\n🧹 Nettoyage de la base de données...")
        for table in tables:
            table_name = table[0]
            count_before = cursor.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
            if count_before > 0:
                cursor.execute(f"DELETE FROM {table_name}")
                print(f"   ✅ Table '{table_name}': {count_before} ligne(s) supprimée(s)")
        
        conn.commit()
        conn.close()
        print("✅ Base de données nettoyée")
    except Exception as e:
        print(f"❌ Erreur nettoyage DB: {e}")


def main():
    print("🧹 Script de nettoyage des scans\n")
    
    # Charger tous les scans
    scans = load_all_scans()
    
    if not scans:
        print("ℹ️  Aucun scan trouvé")
        return
    
    print(f"📊 {len(scans)} scan(s) trouvé(s)")
    
    # Afficher la liste
    display_scans(scans)
    
    # Options de nettoyage
    print("\n🔧 Options de nettoyage:")
    print("   1. Supprimer les scans avec 0 vulnérabilités")
    print("   2. Supprimer les scans échoués")
    print("   3. Supprimer tous les scans sauf les 3 plus récents")
    print("   4. Supprimer tous les scans")
    print("   5. Nettoyer uniquement la base de données")
    print("   6. Annuler")
    
    choice = input("\n👉 Votre choix (1-6): ").strip()
    
    scans_to_delete = []
    
    if choice == "1":
        scans_to_delete = [s for s in scans if s['vulns'] == 0]
        print(f"\n🔴 {len(scans_to_delete)} scan(s) avec 0 vulnérabilité(s) seront supprimés")
        
    elif choice == "2":
        scans_to_delete = [s for s in scans if s['status'] == 'failed']
        print(f"\n❌ {len(scans_to_delete)} scan(s) échoué(s) seront supprimés")
        
    elif choice == "3":
        if len(scans) > 3:
            scans_to_delete = scans[3:]  # Garder les 3 plus récents
            print(f"\n🗑️  {len(scans_to_delete)} scan(s) ancien(s) seront supprimés (les 3 plus récents seront conservés)")
        else:
            print("\nℹ️  Moins de 3 scans, rien à supprimer")
            return
        
    elif choice == "4":
        scans_to_delete = scans
        print(f"\n⚠️  TOUS les {len(scans_to_delete)} scan(s) seront supprimés")
        
    elif choice == "5":
        clean_database()
        return
        
    elif choice == "6":
        print("\n❌ Annulé")
        return
        
    else:
        print("\n❌ Choix invalide")
        return
    
    if scans_to_delete:
        print("\n📋 Scans à supprimer:")
        for scan in scans_to_delete:
            print(f"   - {scan['workflow_id'][:8]}... ({scan['target']}, {scan['vulns']} vulns)")
        
        confirm = input("\n⚠️  Confirmer la suppression? (oui/non): ").strip().lower()
        
        if confirm in ('oui', 'o', 'yes', 'y'):
            deleted = delete_scans(scans_to_delete, dry_run=False)
            
            # Nettoyer aussi la DB
            clean_database()
            
            print(f"\n✅ Nettoyage terminé: {deleted} scan(s) supprimé(s)")
        else:
            print("\n❌ Suppression annulée")
    else:
        print("\nℹ️  Aucun scan à supprimer")


if __name__ == "__main__":
    main()

