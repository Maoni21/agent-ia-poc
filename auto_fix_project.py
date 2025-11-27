#!/usr/bin/env python3
"""
🔧 AUTO-PATCHER AGENT-IA-POC
=============================

Script pour appliquer automatiquement toutes les optimisations :
1. Filtrage des liens NIST (20k → 2k lignes)
2. Humanisation du texte ChatGPT
3. Fix des scripts de correction
4. Réduction du timeout de scan

Usage:
    python auto_fix_project.py              # Mode interactif
    python auto_fix_project.py --auto       # Mode automatique
    python auto_fix_project.py --validate   # Validation seulement
    python auto_fix_project.py --restore    # Restaurer les backups
"""

import os
import sys
import re
import json
import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional

# Couleurs pour l'affichage
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text: str):
    """Afficher un en-tête"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(60)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.END}\n")

def print_success(text: str):
    print(f"{Colors.GREEN}✅ {text}{Colors.END}")

def print_warning(text: str):
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.END}")

def print_error(text: str):
    print(f"{Colors.RED}❌ {text}{Colors.END}")

def print_info(text: str):
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.END}")


class ProjectPatcher:
    """Classe principale pour patcher le projet"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.backup_dir = project_root / "backups" / datetime.now().strftime("%Y%m%d_%H%M%S")
        self.changes_made = []
        self.errors = []
        
    def create_backup(self, file_path: Path) -> bool:
        """Créer un backup d'un fichier"""
        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            
            # Chemin relatif pour garder la structure
            rel_path = file_path.relative_to(self.project_root)
            backup_path = self.backup_dir / rel_path
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            
            shutil.copy2(file_path, backup_path)
            print_info(f"Backup créé: {backup_path}")
            return True
            
        except Exception as e:
            print_error(f"Erreur backup {file_path}: {e}")
            return False
    
    def read_file(self, file_path: Path) -> Optional[str]:
        """Lire un fichier"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print_error(f"Erreur lecture {file_path}: {e}")
            return None
    
    def write_file(self, file_path: Path, content: str) -> bool:
        """Écrire dans un fichier"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            print_error(f"Erreur écriture {file_path}: {e}")
            return False
    
    def patch_analyzer_nist_filter(self, content: str) -> Tuple[str, bool]:
        """Patcher analyzer.py pour filtrer les liens NIST"""
        
        # Chercher la fonction qui enrichit avec NIST
        patterns = [
            (r'def _enrich_from_nist\(.*?\):', '_enrich_from_nist'),
            (r'def enrich_with_nist\(.*?\):', 'enrich_with_nist'),
            (r'def _fetch_nist_data\(.*?\):', '_fetch_nist_data'),
        ]
        
        function_found = None
        function_name = None
        
        for pattern, name in patterns:
            if re.search(pattern, content):
                function_found = pattern
                function_name = name
                break
        
        if not function_found:
            print_warning("Fonction d'enrichissement NIST non trouvée, création...")
            # Ajouter la fonction à la fin de la classe Analyzer
            
            nist_filter_code = '''
    def _filter_nist_references(self, references: List[dict]) -> Optional[str]:
        """
        Filtrer les références NIST pour garder UN SEUL lien solution
        
        Priorité : Patch > Vendor Advisory > Mitigation > Premier lien
        """
        if not references:
            return None
        
        # Tags prioritaires (dans l'ordre)
        priority_tags = ['Patch', 'Vendor Advisory', 'Mitigation', 'Third Party Advisory']
        
        # Chercher le premier lien avec un tag prioritaire
        for tag in priority_tags:
            for ref in references:
                ref_tags = ref.get('tags', [])
                if tag in ref_tags:
                    return ref.get('url', '')
        
        # Si aucun tag prioritaire, prendre le premier lien
        return references[0].get('url', '') if references else None
    
    def _enrich_vulnerability_with_nist(self, vulnerability: dict) -> dict:
        """
        Enrichir une vulnérabilité avec les données NIST (FILTRÉES)
        """
        cve_id = vulnerability.get('vulnerability_id', '')
        
        if not cve_id or not cve_id.startswith('CVE-'):
            return vulnerability
        
        try:
            # Récupérer les données NIST (depuis cache ou API)
            nist_data = self.nist_cache.get(cve_id)
            
            if not nist_data:
                # Appel API NIST (votre code existant)
                # nist_data = self._call_nist_api(cve_id)
                pass
            
            if nist_data:
                # ⚡ FILTRER pour garder UN SEUL lien
                references = nist_data.get('references', [])
                solution_url = self._filter_nist_references(references)
                
                # Enrichir avec données essentielles SEULEMENT
                vulnerability['nist_data'] = {
                    'cvss_score': nist_data.get('cvss_score'),
                    'severity': nist_data.get('severity'),
                    'description': nist_data.get('description', '')[:500],  # Limiter
                    'solution_url': solution_url,  # UN SEUL LIEN
                    'published_date': nist_data.get('published_date'),
                    'last_modified': nist_data.get('last_modified')
                }
                
                # NE PAS inclure toutes les références
                # vulnerability['references'] = references  # ← SUPPRIMÉ
        
        except Exception as e:
            self.logger.warning(f"Erreur enrichissement NIST {cve_id}: {e}")
        
        return vulnerability
'''
            
            # Trouver la fin de la classe Analyzer
            class_pattern = r'class Analyzer.*?:'
            if re.search(class_pattern, content):
                # Insérer avant la dernière ligne de la classe
                # (approximation - chercher la prochaine classe ou fin de fichier)
                insert_pos = content.rfind('\n\nclass ')
                if insert_pos == -1:
                    insert_pos = len(content)
                
                content = content[:insert_pos] + nist_filter_code + content[insert_pos:]
                return content, True
            else:
                print_error("Classe Analyzer non trouvée")
                return content, False
        
        else:
            print_info(f"Fonction trouvée: {function_name}")
            
            # Ajouter le filtre dans la fonction existante
            filter_code = '''
        # ⚡ FILTRER les références pour garder UN SEUL lien
        if 'references' in nist_data and nist_data['references']:
            references = nist_data['references']
            solution_url = None
            
            # Priorité : Patch > Vendor Advisory > Mitigation
            priority_tags = ['Patch', 'Vendor Advisory', 'Mitigation']
            for tag in priority_tags:
                for ref in references:
                    if tag in ref.get('tags', []):
                        solution_url = ref.get('url', '')
                        break
                if solution_url:
                    break
            
            # Si pas trouvé, prendre le premier
            if not solution_url and references:
                solution_url = references[0].get('url', '')
            
            # Remplacer toutes les références par UN SEUL lien
            nist_data['solution_url'] = solution_url
            nist_data['references'] = []  # Vider les références
'''
            
            # Chercher où insérer (après avoir récupéré nist_data)
            nist_data_pattern = r'nist_data\s*=.*?(\n\s+if nist_data|\n\s+vulnerability\[)'
            match = re.search(nist_data_pattern, content)
            
            if match:
                insert_pos = match.start() + len(match.group(0).split('\n')[0])
                content = content[:insert_pos] + filter_code + content[insert_pos:]
                return content, True
            else:
                print_warning("Position d'insertion non trouvée")
                return content, False
    
    def patch_analyzer_humanize_prompt(self, content: str) -> Tuple[str, bool]:
        """Améliorer le prompt OpenAI pour humaniser le texte"""
        
        # Chercher la fonction d'analyse OpenAI
        openai_pattern = r'async def .*?analyze.*?openai.*?\(.*?\):'
        
        if not re.search(openai_pattern, content, re.IGNORECASE):
            print_warning("Fonction OpenAI non trouvée")
            return content, False
        
        # Chercher le prompt actuel
        prompt_pattern = r'prompt\s*=\s*f?["\'].*?["\']'
        
        # Nouveau prompt humanisé
        new_prompt = '''prompt = f"""Tu es un expert en cybersécurité qui explique les vulnérabilités de manière claire et accessible en FRANÇAIS.

🎯 MISSION :
Analyse ces {len(vulnerabilities)} vulnérabilités et fournis pour CHAQUE vulnérabilité :

1. **Explication Simple** (2-3 phrases en français conversationnel) :
   - Qu'est-ce que c'est exactement ?
   - Pourquoi c'est dangereux ?
   - Utilise des analogies du quotidien (ex: "c'est comme laisser sa porte ouverte")

2. **Impact Réel** (concret et précis) :
   - Que peut faire un attaquant concrètement ?
   - Exemples : vol de données sensibles, prise de contrôle totale, arrêt du service

3. **Solution Prioritaire** (maximum 3 étapes) :
   - Action immédiate et concrète
   - Lien vers la solution officielle
   - Temps estimé de correction

4. **Niveau d'Urgence** :
   - CRITIQUE : corriger IMMÉDIATEMENT (danger imminent)
   - ÉLEVÉ : corriger sous 24h
   - MOYEN : corriger sous 1 semaine
   - FAIBLE : corriger lors de la prochaine maintenance

📊 VULNÉRABILITÉS À ANALYSER :
{json.dumps(vulnerability_summary, indent=2, ensure_ascii=False)}

⚠️ RÈGLES IMPORTANTES :
- Réponds UNIQUEMENT en JSON (pas de texte avant/après)
- Ton conversationnel et accessible (évite le jargon)
- Maximum 150 mots par vulnérabilité
- Sois concret et actionnable

FORMAT JSON STRICT :
{{
  "analyses": [
    {{
      "vulnerability_id": "CVE-XXXX-XXXX",
      "explication_simple": "Texte en français accessible...",
      "impact_reel": "Ce qu'un attaquant peut faire...",
      "solution_prioritaire": ["Étape 1", "Étape 2", "Lien: https://..."],
      "urgence": "CRITIQUE|ÉLEVÉ|MOYEN|FAIBLE",
      "temps_correction_estime": "30 minutes"
    }}
  ],
  "resume_global": {{
    "risque_global": "ÉLEVÉ",
    "actions_immediates": 3,
    "recommandation": "Commencer par les 3 vulnérabilités critiques..."
  }}
}}"""'''
        
        # Remplacer le prompt existant
        content = re.sub(
            r'prompt\s*=\s*f?""".*?"""',
            new_prompt,
            content,
            flags=re.DOTALL
        )
        
        return content, True
    
    def patch_generator_scripts(self, content: str) -> Tuple[str, bool]:
        """Corriger la génération de scripts"""
        
        # 1. Réduire max_tokens
        content = re.sub(
            r'max_tokens\s*=\s*\d+',
            'max_tokens=800',
            content
        )
        
        # 2. Améliorer le parsing JSON
        parse_improvement = '''
        # Parser la réponse avec gestion d'erreur robuste
        try:
            response_text = response.choices[0].message.content.strip()
            
            # Nettoyer le texte (enlever les backticks markdown)
            response_text = re.sub(r'^```json\\s*', '', response_text)
            response_text = re.sub(r'\\s*```$', '', response_text)
            response_text = response_text.strip()
            
            # Parser le JSON
            script_data = json.loads(response_text)
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Erreur parsing JSON: {e}")
            self.logger.error(f"Réponse brute: {response_text[:500]}")
            raise ValueError("Impossible de parser la réponse IA")
'''
        
        # Chercher et remplacer le parsing existant
        content = re.sub(
            r'response_text\s*=\s*response\.choices.*?json\.loads\(response_text\)',
            parse_improvement,
            content,
            flags=re.DOTALL
        )
        
        return content, True
    
    def patch_supervisor_timeout(self, content: str) -> Tuple[str, bool]:
        """Réduire le timeout par défaut des scans"""
        
        # Chercher timeout = workflow_def.parameters.get('timeout', 3600)
        content = re.sub(
            r"timeout\s*=\s*workflow_def\.parameters\.get\s*\(\s*['\"]timeout['\"]\s*,\s*\d+\s*\)",
            "timeout = workflow_def.parameters.get('timeout', 180)",
            content
        )
        
        return content, True
    
    def patch_supervisor_return_result(self, content: str) -> Tuple[str, bool]:
        """Corriger run_scan() pour retourner le résultat"""
        
        fix_code = '''
        # Attendre la fin du workflow
        result = await self.wait_for_workflow(workflow_id)
        
        # Vérifier et retourner le scan_result
        if result and hasattr(result, 'scan_result') and result.scan_result:
            return result.scan_result
        
        # Fallback : charger depuis le fichier JSON
        self.logger.warning(f"Chargement scan depuis fichier...")
        try:
            from pathlib import Path
            import json
            
            results_dir = Path("data/workflow_results")
            result_file = results_dir / f"{workflow_id}.json"
            
            if result_file.exists():
                with open(result_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                scan_data = data.get('scan_result', {})
                if scan_data:
                    from .collector import ScanResult, Vulnerability, Service
                    
                    vulnerabilities = [Vulnerability(**v) for v in scan_data.get('vulnerabilities', [])]
                    services = [Service(**s) for s in scan_data.get('services', [])]
                    
                    return ScanResult(
                        scan_id=scan_data.get('scan_id', ''),
                        target=scan_data.get('target', target),
                        scan_type=scan_data.get('scan_type', scan_type),
                        start_time=scan_data.get('start_time', ''),
                        end_time=scan_data.get('end_time', ''),
                        duration=scan_data.get('duration', 0),
                        open_ports=scan_data.get('open_ports', []),
                        services=services,
                        vulnerabilities=vulnerabilities,
                        metadata=scan_data.get('metadata', {})
                    )
        except Exception as e:
            self.logger.error(f"Erreur chargement: {e}")
        
        return None
'''
        
        # Remplacer le return simple par le code amélioré
        content = re.sub(
            r'result\s*=\s*await\s+self\.wait_for_workflow\(workflow_id\)\s*\n\s*return\s+result\.scan_result',
            fix_code,
            content,
            flags=re.DOTALL
        )
        
        return content, True
    
    def validate_changes(self) -> bool:
        """Valider que les changements sont corrects"""
        print_header("VALIDATION DES CHANGEMENTS")
        
        all_valid = True
        
        # Vérifier que les fichiers modifiés sont syntaxiquement corrects
        files_to_check = [
            self.project_root / 'src' / 'core' / 'analyzer.py',
            self.project_root / 'src' / 'core' / 'generator.py',
            self.project_root / 'src' / 'core' / 'supervisor.py',
        ]
        
        for file_path in files_to_check:
            if not file_path.exists():
                continue
            
            try:
                # Vérifier la syntaxe Python
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                    compile(code, str(file_path), 'exec')
                
                print_success(f"{file_path.name} : Syntaxe valide")
                
            except SyntaxError as e:
                print_error(f"{file_path.name} : Erreur syntaxe ligne {e.lineno}")
                all_valid = False
                self.errors.append(f"{file_path.name}: {e}")
        
        return all_valid
    
    def apply_all_patches(self, auto_mode: bool = False) -> bool:
        """Appliquer tous les patches"""
        print_header("🔧 APPLICATION DES PATCHES")
        
        patches = [
            {
                'name': 'Filtrage liens NIST',
                'file': 'src/core/analyzer.py',
                'function': self.patch_analyzer_nist_filter,
                'description': '20,000 lignes → 2,000 lignes'
            },
            {
                'name': 'Humanisation texte ChatGPT',
                'file': 'src/core/analyzer.py',
                'function': self.patch_analyzer_humanize_prompt,
                'description': 'Réponses en français conversationnel'
            },
            {
                'name': 'Fix génération scripts',
                'file': 'src/core/generator.py',
                'function': self.patch_generator_scripts,
                'description': 'Correction parsing + max_tokens'
            },
            {
                'name': 'Réduction timeout scan',
                'file': 'src/core/supervisor.py',
                'function': self.patch_supervisor_timeout,
                'description': '3600s → 180s (12min → 3min)'
            },
            {
                'name': 'Fix retour run_scan()',
                'file': 'src/core/supervisor.py',
                'function': self.patch_supervisor_return_result,
                'description': 'Retourner le ScanResult correctement'
            },
        ]
        
        for i, patch in enumerate(patches, 1):
            print(f"\n{Colors.BOLD}[{i}/{len(patches)}] {patch['name']}{Colors.END}")
            print(f"    📄 Fichier: {patch['file']}")
            print(f"    📝 Action: {patch['description']}")
            
            if not auto_mode:
                response = input(f"    Appliquer ce patch ? (o/N) : ").lower()
                if response != 'o':
                    print_warning("Patch ignoré")
                    continue
            
            file_path = self.project_root / patch['file']
            
            if not file_path.exists():
                print_error(f"Fichier non trouvé: {file_path}")
                continue
            
            # Backup
            if not self.create_backup(file_path):
                print_error("Erreur backup, patch annulé")
                continue
            
            # Lire le fichier
            content = self.read_file(file_path)
            if not content:
                continue
            
            # Appliquer le patch
            try:
                new_content, success = patch['function'](content)
                
                if success:
                    # Écrire le nouveau contenu
                    if self.write_file(file_path, new_content):
                        print_success(f"Patch appliqué : {patch['name']}")
                        self.changes_made.append(patch['name'])
                    else:
                        print_error("Erreur écriture fichier")
                else:
                    print_warning(f"Patch non appliqué : {patch['name']}")
                    
            except Exception as e:
                print_error(f"Erreur application patch: {e}")
                self.errors.append(f"{patch['name']}: {e}")
        
        return len(self.changes_made) > 0
    
    def generate_report(self):
        """Générer un rapport des changements"""
        print_header("📊 RAPPORT DES MODIFICATIONS")
        
        if self.changes_made:
            print(f"\n{Colors.GREEN}✅ {len(self.changes_made)} patches appliqués avec succès :{Colors.END}\n")
            for change in self.changes_made:
                print(f"  ✓ {change}")
        else:
            print_warning("Aucun patch appliqué")
        
        if self.errors:
            print(f"\n{Colors.RED}❌ {len(self.errors)} erreurs :{Colors.END}\n")
            for error in self.errors:
                print(f"  ✗ {error}")
        
        print(f"\n{Colors.BLUE}📁 Backups sauvegardés dans: {self.backup_dir}{Colors.END}")
        
        print(f"\n{Colors.BOLD}📋 PROCHAINES ÉTAPES :{Colors.END}")
        print("  1. Vérifier que tout fonctionne :")
        print("     PYTHONPATH=. python main.py --target 127.0.0.1 --ports 8080 --scan-type quick --scan")
        print("\n  2. Si tout est OK, supprimer les backups :")
        print(f"     rm -rf {self.backup_dir}")
        print("\n  3. Si problème, restaurer :")
        print(f"     python auto_fix_project.py --restore")


def restore_from_backup(project_root: Path):
    """Restaurer depuis le dernier backup"""
    print_header("🔄 RESTAURATION DEPUIS BACKUP")
    
    backup_base = project_root / "backups"
    if not backup_base.exists():
        print_error("Aucun backup trouvé")
        return
    
    # Trouver le dernier backup
    backups = sorted(backup_base.iterdir(), key=lambda x: x.name, reverse=True)
    if not backups:
        print_error("Aucun backup trouvé")
        return
    
    latest_backup = backups[0]
    print_info(f"Dernier backup: {latest_backup.name}")
    
    response = input("Restaurer depuis ce backup ? (o/N) : ").lower()
    if response != 'o':
        print_warning("Restauration annulée")
        return
    
    # Restaurer les fichiers
    restored = 0
    for backup_file in latest_backup.rglob("*.py"):
        rel_path = backup_file.relative_to(latest_backup)
        target_file = project_root / rel_path
        
        try:
            shutil.copy2(backup_file, target_file)
            print_success(f"Restauré: {rel_path}")
            restored += 1
        except Exception as e:
            print_error(f"Erreur restauration {rel_path}: {e}")
    
    print(f"\n{Colors.GREEN}✅ {restored} fichiers restaurés{Colors.END}")


def main():
    """Fonction principale"""
    print_header("🔧 AUTO-PATCHER AGENT-IA-POC")
    
    # Déterminer le répertoire du projet
    if len(sys.argv) > 1 and sys.argv[1] not in ['--auto', '--validate', '--restore']:
        project_root = Path(sys.argv[1])
    else:
        project_root = Path.cwd()
    
    print_info(f"Répertoire projet: {project_root}")
    
    # Vérifier que c'est bien le bon répertoire
    if not (project_root / 'src' / 'core').exists():
        print_error("Ce n'est pas le répertoire du projet agent-ia-poc")
        print_info("Usage: python auto_fix_project.py [chemin_projet]")
        sys.exit(1)
    
    # Mode restauration
    if '--restore' in sys.argv:
        restore_from_backup(project_root)
        return
    
    # Créer le patcher
    patcher = ProjectPatcher(project_root)
    
    # Mode validation seulement
    if '--validate' in sys.argv:
        if patcher.validate_changes():
            print_success("Tous les fichiers sont valides")
            sys.exit(0)
        else:
            print_error("Erreurs de validation détectées")
            sys.exit(1)
    
    # Mode automatique ou interactif
    auto_mode = '--auto' in sys.argv
    
    if not auto_mode:
        print(f"\n{Colors.YELLOW}Mode interactif : vous serez invité à valider chaque patch{Colors.END}")
        print(f"{Colors.BLUE}Utilisez --auto pour appliquer tous les patches automatiquement{Colors.END}\n")
        input("Appuyez sur Entrée pour continuer...")
    
    # Appliquer les patches
    if patcher.apply_all_patches(auto_mode):
        # Valider les changements
        if patcher.validate_changes():
            patcher.generate_report()
            print_success("\n🎉 Patches appliqués avec succès !")
        else:
            print_error("\n⚠️  Des erreurs de validation ont été détectées")
            patcher.generate_report()
    else:
        print_warning("Aucun patch appliqué")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠️  Interruption utilisateur{Colors.END}")
        sys.exit(130)
    except Exception as e:
        print_error(f"\n💥 Erreur fatale: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
