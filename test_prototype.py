#!/usr/bin/env python3
"""
🧪 TEST VALIDATEUR - Agent IA POC
===================================

Script pour tester que toutes les optimisations fonctionnent correctement.

Usage:
    python test_prototype.py
"""

import json
import time
from pathlib import Path
from datetime import datetime

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_test(name: str):
    print(f"\n{Colors.BLUE}🧪 TEST: {name}{Colors.END}")

def print_pass(msg: str):
    print(f"  {Colors.GREEN}✅ {msg}{Colors.END}")

def print_fail(msg: str):
    print(f"  {Colors.RED}❌ {msg}{Colors.END}")

def print_warn(msg: str):
    print(f"  {Colors.YELLOW}⚠️  {msg}{Colors.END}")

def test_nist_filter():
    """Tester le filtrage des liens NIST"""
    print_test("Filtrage Liens NIST")
    
    results_dir = Path("data/workflow_results")
    if not results_dir.exists():
        print_warn("Aucun workflow trouvé - lancer un scan d'abord")
        return False
    
    # Prendre le dernier workflow
    workflows = sorted(results_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    if not workflows:
        print_warn("Aucun résultat de scan")
        return False
    
    latest = workflows[0]
    
    try:
        with open(latest, 'r') as f:
            data = json.load(f)
        
        scan_result = data.get('scan_result', {})
        vulnerabilities = scan_result.get('vulnerabilities', [])
        
        if not vulnerabilities:
            print_warn("Aucune vulnérabilité dans le scan")
            return False
        
        # Vérifier qu'il y a des données NIST
        nist_count = 0
        total_refs = 0
        solution_urls = 0
        
        for vuln in vulnerabilities:
            nist_data = vuln.get('nist_data', {})
            if nist_data:
                nist_count += 1
                
                # Vérifier solution_url
                if 'solution_url' in nist_data:
                    solution_urls += 1
                
                # Compter les références (devrait être vide ou minimal)
                refs = nist_data.get('references', [])
                total_refs += len(refs)
        
        print(f"  • Vulnérabilités: {len(vulnerabilities)}")
        print(f"  • Avec données NIST: {nist_count}")
        print(f"  • Avec solution_url: {solution_urls}")
        print(f"  • Total références: {total_refs}")
        
        # Critères de succès
        if solution_urls > 0:
            print_pass("Filtrage NIST activé (solution_url présent)")
            success = True
        else:
            print_warn("Pas de solution_url - filtre peut-être pas appliqué")
            success = False
        
        if total_refs > len(vulnerabilities) * 2:
            print_warn(f"Trop de références ({total_refs}) - filtrage incomplet")
            success = False
        else:
            print_pass(f"Références filtrées correctement ({total_refs} refs)")
        
        # Estimer la taille du JSON
        json_size = Path(latest).stat().st_size
        print(f"  • Taille JSON: {json_size:,} bytes ({json_size/1024:.1f} KB)")
        
        if json_size < 500_000:  # < 500 KB
            print_pass("Taille JSON optimisée")
        else:
            print_warn(f"Taille JSON élevée ({json_size/1024:.0f} KB)")
        
        return success
        
    except Exception as e:
        print_fail(f"Erreur: {e}")
        return False

def test_humanized_text():
    """Tester l'humanisation du texte"""
    print_test("Humanisation Texte ChatGPT")
    
    results_dir = Path("data/workflow_results")
    if not results_dir.exists():
        print_warn("Aucun workflow avec analyse - lancer un workflow complet")
        return False
    
    workflows = sorted(results_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    
    for workflow_file in workflows[:5]:  # Vérifier les 5 derniers
        try:
            with open(workflow_file, 'r') as f:
                data = json.load(f)
            
            analysis = data.get('analysis_result')
            if not analysis:
                continue
            
            # Vérifier les analyses
            analyses = analysis.get('analyses', [])
            if not analyses:
                continue
            
            print(f"  • Workflow: {workflow_file.name[:20]}...")
            print(f"  • Analyses trouvées: {len(analyses)}")
            
            # Vérifier le contenu
            first_analysis = analyses[0]
            
            has_explication = 'explication_simple' in first_analysis
            has_impact = 'impact_reel' in first_analysis
            has_solution = 'solution_prioritaire' in first_analysis
            has_urgence = 'urgence' in first_analysis
            
            if has_explication:
                print_pass("Champ 'explication_simple' présent")
            else:
                print_warn("Champ 'explication_simple' manquant")
            
            if has_impact:
                print_pass("Champ 'impact_reel' présent")
            
            if has_solution:
                print_pass("Champ 'solution_prioritaire' présent")
            
            if has_urgence:
                print_pass("Champ 'urgence' présent")
            
            # Vérifier le français
            explication = first_analysis.get('explication_simple', '')
            if explication:
                # Mots clés français vs anglais
                french_words = ['est', 'sont', 'peut', 'permet', 'comme', 'cette']
                english_words = ['is', 'are', 'can', 'allows', 'this', 'that']
                
                french_count = sum(1 for w in french_words if w in explication.lower())
                english_count = sum(1 for w in english_words if w in explication.lower())
                
                if french_count > english_count:
                    print_pass("Texte en français détecté")
                else:
                    print_warn("Texte possiblement en anglais")
            
            return True
            
        except Exception as e:
            continue
    
    print_warn("Aucune analyse avec texte humanisé trouvée")
    return False

def test_scan_duration():
    """Tester la durée des scans"""
    print_test("Durée des Scans")
    
    results_dir = Path("data/workflow_results")
    if not results_dir.exists():
        print_warn("Aucun workflow")
        return False
    
    workflows = sorted(results_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    
    scan_durations = []
    
    for workflow_file in workflows[:5]:
        try:
            with open(workflow_file, 'r') as f:
                data = json.load(f)
            
            workflow_type = data.get('workflow_type', '')
            if 'scan' not in workflow_type.lower():
                continue
            
            duration = data.get('duration', 0)
            target = data.get('target', 'unknown')
            
            scan_durations.append((workflow_file.name[:20], target, duration))
            
        except:
            continue
    
    if not scan_durations:
        print_warn("Aucun scan trouvé")
        return False
    
    print(f"  • {len(scan_durations)} scans récents:")
    
    avg_duration = sum(d[2] for d in scan_durations) / len(scan_durations)
    
    for name, target, duration in scan_durations:
        minutes = int(duration // 60)
        if duration < 300:  # < 5 minutes
            status = "✅"
        elif duration < 600:  # < 10 minutes
            status = "⚠️ "
        else:
            status = "❌"
        
        print(f"    {status} {name}... : {minutes}m {int(duration%60)}s")
    
    print(f"\n  • Durée moyenne: {int(avg_duration//60)}m {int(avg_duration%60)}s")
    
    if avg_duration < 300:
        print_pass("Scans optimisés (< 5 minutes)")
        return True
    elif avg_duration < 600:
        print_warn("Scans modérés (5-10 minutes)")
        return True
    else:
        print_fail("Scans lents (> 10 minutes)")
        return False

def test_scripts_generation():
    """Tester la génération de scripts"""
    print_test("Génération de Scripts")
    
    results_dir = Path("data/workflow_results")
    if not results_dir.exists():
        print_warn("Aucun workflow")
        return False
    
    workflows = sorted(results_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    
    for workflow_file in workflows[:5]:
        try:
            with open(workflow_file, 'r') as f:
                data = json.load(f)
            
            scripts = data.get('script_results', [])
            if not scripts:
                continue
            
            print(f"  • Workflow: {workflow_file.name[:20]}...")
            print(f"  • Scripts générés: {len(scripts)}")
            
            # Vérifier le contenu
            valid_scripts = 0
            for script in scripts:
                if 'script_bash' in script or 'script_content' in script:
                    valid_scripts += 1
            
            if valid_scripts > 0:
                print_pass(f"{valid_scripts} scripts valides générés")
                return True
            else:
                print_warn("Scripts générés mais contenu manquant")
                return False
            
        except:
            continue
    
    print_warn("Aucun script généré - lancer un workflow complet")
    return False

def test_file_sizes():
    """Vérifier les tailles de fichiers"""
    print_test("Taille des Fichiers")
    
    results_dir = Path("data/workflow_results")
    if not results_dir.exists():
        print_warn("Aucun résultat")
        return False
    
    workflows = sorted(results_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    
    if not workflows:
        print_warn("Aucun workflow")
        return False
    
    sizes = []
    for wf in workflows[:10]:
        size = wf.stat().st_size
        sizes.append((wf.name[:20], size))
    
    avg_size = sum(s[1] for s in sizes) / len(sizes)
    
    print(f"  • {len(sizes)} fichiers récents:")
    
    for name, size in sizes[:5]:
        size_kb = size / 1024
        if size < 100_000:  # < 100 KB
            status = "✅"
        elif size < 500_000:  # < 500 KB
            status = "⚠️ "
        else:
            status = "❌"
        
        print(f"    {status} {name}... : {size_kb:.1f} KB")
    
    print(f"\n  • Taille moyenne: {avg_size/1024:.1f} KB")
    
    if avg_size < 100_000:
        print_pass("Fichiers optimisés (< 100 KB)")
        return True
    elif avg_size < 500_000:
        print_warn("Fichiers modérés (100-500 KB)")
        return True
    else:
        print_fail("Fichiers volumineux (> 500 KB)")
        return False

def main():
    """Fonction principale"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'🧪 VALIDATION DU PROTOTYPE'.center(60)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.END}")
    
    tests = [
        ("Filtrage NIST", test_nist_filter),
        ("Humanisation Texte", test_humanized_text),
        ("Durée Scans", test_scan_duration),
        ("Génération Scripts", test_scripts_generation),
        ("Taille Fichiers", test_file_sizes),
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            success = test_func()
            results.append((name, success))
        except Exception as e:
            print_fail(f"Erreur test: {e}")
            results.append((name, False))
    
    # Rapport final
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'📊 RAPPORT FINAL'.center(60)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.END}\n")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for name, success in results:
        if success:
            print(f"  ✅ {name}")
        else:
            print(f"  ❌ {name}")
    
    print(f"\n{Colors.BOLD}Score: {passed}/{total} tests réussis{Colors.END}")
    
    if passed == total:
        print(f"\n{Colors.GREEN}🎉 PROTOTYPE VALIDÉ ! Tous les tests passent.{Colors.END}")
        print(f"\n{Colors.BOLD}Prochaines étapes :{Colors.END}")
        print("  1. Tester un workflow complet")
        print("  2. Générer un rapport pour Yassine")
        print("  3. Déployer en production")
    elif passed >= total * 0.7:
        print(f"\n{Colors.YELLOW}⚠️  PROTOTYPE FONCTIONNEL mais améliorations nécessaires{Colors.END}")
        print(f"\nTests échoués : vérifier les warnings ci-dessus")
    else:
        print(f"\n{Colors.RED}❌ PROTOTYPE INCOMPLET - Des corrections sont nécessaires{Colors.END}")
        print(f"\nRelancer les patches ou vérifier la configuration")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠️  Test interrompu{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Erreur: {e}{Colors.END}")
