#!/usr/bin/env python3
"""
Script pour afficher les résultats des scans sauvegardés

Usage:
    python view_results.py                    # Dernier scan
    python view_results.py <workflow_id>      # Scan spécifique
    python view_results.py --list             # Lister tous les scans
"""

import json
import sys
from pathlib import Path
from datetime import datetime

def format_duration(seconds):
    """Formate la durée en format lisible"""
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs}s"

def list_workflows():
    """Liste tous les workflows disponibles"""
    results_dir = Path("data/workflow_results")
    
    if not results_dir.exists():
        print("❌ Aucun résultat trouvé")
        return
    
    workflows = sorted(results_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    
    if not workflows:
        print("❌ Aucun workflow trouvé")
        return
    
    print(f"\n📋 Workflows disponibles ({len(workflows)}):\n")
    
    for i, workflow_file in enumerate(workflows[:10], 1):
        try:
            with open(workflow_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            workflow_id = data.get('workflow_id', 'unknown')[:12]
            target = data.get('target', 'unknown')
            status = data.get('status', 'unknown')
            duration = data.get('duration', 0)
            vulns = data.get('total_vulnerabilities', 0)
            
            # Icône de statut
            status_icon = "✅" if status == "completed" else "❌"
            
            # Date
            started = data.get('started_at', '')
            if started:
                dt = datetime.fromisoformat(started)
                date_str = dt.strftime('%Y-%m-%d %H:%M')
            else:
                date_str = "unknown"
            
            print(f"{i}. {status_icon} {workflow_id}... | {target} | {vulns} vulns | {format_duration(duration)} | {date_str}")
            
        except Exception as e:
            print(f"{i}. ❌ Erreur lecture: {workflow_file.name}")
    
    if len(workflows) > 10:
        print(f"\n... et {len(workflows) - 10} autres workflows")

def show_workflow_details(workflow_id=None):
    """Affiche les détails d'un workflow"""
    results_dir = Path("data/workflow_results")
    
    if not results_dir.exists():
        print("❌ Aucun résultat trouvé")
        return
    
    # Si pas d'ID, prendre le plus récent
    if not workflow_id:
        workflows = sorted(results_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
        if not workflows:
            print("❌ Aucun workflow trouvé")
            return
        workflow_file = workflows[0]
    else:
        # Chercher par ID (complet ou partiel)
        matching = list(results_dir.glob(f"{workflow_id}*.json"))
        if not matching:
            print(f"❌ Workflow non trouvé: {workflow_id}")
            return
        workflow_file = matching[0]
    
    # Charger et afficher
    try:
        with open(workflow_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print("\n" + "=" * 60)
        print("🛡️  RÉSULTATS DU SCAN")
        print("=" * 60 + "\n")
        
        # Informations générales
        print(f"📋 Workflow ID: {data.get('workflow_id', 'unknown')}")
        print(f"🎯 Cible: {data.get('target', 'unknown')}")
        print(f"📊 Statut: {data.get('status', 'unknown')}")
        print(f"⏱️  Durée: {format_duration(data.get('duration', 0))}")
        
        started = data.get('started_at', '')
        if started:
            dt = datetime.fromisoformat(started)
            print(f"🕐 Date: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Résultats du scan
        scan_result = data.get('scan_result', {})
        if scan_result:
            print(f"\n{'─' * 60}")
            print("🔍 RÉSULTATS DU SCAN")
            print(f"{'─' * 60}\n")
            
            print(f"📡 Ports ouverts: {len(scan_result.get('open_ports', []))}")
            if scan_result.get('open_ports'):
                ports = ', '.join(str(p) for p in scan_result['open_ports'][:10])
                print(f"   {ports}")
            
            print(f"\n🔧 Services: {len(scan_result.get('services', []))}")
            for service in scan_result.get('services', [])[:5]:
                port = service.get('port', '?')
                name = service.get('name', '?')
                version = service.get('version', '')
                print(f"   • Port {port}: {name} {version}")
            
            vulns = scan_result.get('vulnerabilities', [])
            print(f"\n🚨 Vulnérabilités: {len(vulns)}")
            
            # Compter par sévérité
            severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
            for vuln in vulns:
                severity = vuln.get('severity', 'UNKNOWN')
                severity_count[severity] = severity_count.get(severity, 0) + 1
            
            print(f"\n   📊 Par sévérité:")
            if severity_count['CRITICAL'] > 0:
                print(f"      🔴 Critiques: {severity_count['CRITICAL']}")
            if severity_count['HIGH'] > 0:
                print(f"      🟠 Élevées: {severity_count['HIGH']}")
            if severity_count['MEDIUM'] > 0:
                print(f"      🟡 Moyennes: {severity_count['MEDIUM']}")
            if severity_count['LOW'] > 0:
                print(f"      🟢 Faibles: {severity_count['LOW']}")
            
            # Top 10 vulnérabilités
            print(f"\n   🔝 Top 10 vulnérabilités:\n")
            
            # Trier par sévérité
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
            sorted_vulns = sorted(
                vulns,
                key=lambda v: (
                    severity_order.get(v.get('severity', 'UNKNOWN'), 4),
                    -(v.get('cvss_score') or 0.0)
                )
            )
            
            for i, vuln in enumerate(sorted_vulns[:10], 1):
                severity = vuln.get('severity', 'UNKNOWN')
                severity_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
                
                name = vuln.get('name', 'Unknown')
                vuln_id = vuln.get('vulnerability_id', '')
                cvss = vuln.get('cvss_score', 0.0)
                
                print(f"   {i}. {severity_icon} {name}")
                print(f"      ID: {vuln_id} | CVSS: {cvss}")
                
                description = vuln.get('description', '')
                if description:
                    desc_short = description[:80] + '...' if len(description) > 80 else description
                    print(f"      {desc_short}")
                print()
        
        # Résultats de l'analyse
        analysis_result = data.get('analysis_result')
        if analysis_result:
            print(f"{'─' * 60}")
            print("🧠 ANALYSE IA")
            print(f"{'─' * 60}\n")
            
            print(f"🤖 Modèle: {analysis_result.get('ai_model_used', 'unknown')}")
            print(f"📊 Confiance: {analysis_result.get('confidence_score', 0) * 100:.1f}%")
            
            summary = analysis_result.get('analysis_summary', {})
            if summary:
                risk_score = summary.get('overall_risk_score', 0)
                print(f"⚠️  Risque global: {risk_score:.1f}/10")
        
        # Scripts générés
        scripts = data.get('script_results', [])
        if scripts:
            print(f"\n{'─' * 60}")
            print(f"🔧 SCRIPTS GÉNÉRÉS: {len(scripts)}")
            print(f"{'─' * 60}\n")
            
            for script in scripts[:5]:
                risk = script.get('metadata', {}).get('risk_level', 'UNKNOWN')
                risk_icon = {'LOW': '🟢', 'MEDIUM': '🟡', 'HIGH': '🟠', 'CRITICAL': '🔴'}.get(risk, '⚪')
                script_id = script.get('script_id', 'unknown')
                vuln_id = script.get('vulnerability_id', 'unknown')
                
                print(f"   {risk_icon} {script_id}")
                print(f"      Vulnérabilité: {vuln_id}")
                print(f"      Risque: {risk}")
                print()
        
        print("=" * 60 + "\n")
        print(f"📄 Fichier: {workflow_file}")
        
    except Exception as e:
        print(f"❌ Erreur lecture workflow: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Fonction principale"""
    
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        
        if arg in ['--list', '-l']:
            list_workflows()
        elif arg in ['--help', '-h']:
            print(__doc__)
        else:
            # Afficher un workflow spécifique
            show_workflow_details(arg)
    else:
        # Afficher le dernier workflow
        show_workflow_details()

if __name__ == "__main__":
    main()
