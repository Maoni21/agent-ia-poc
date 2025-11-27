#!/usr/bin/env python3
"""
Script pour fixer le rechargement d'analysis_result - VERSION CORRIGÉE

Usage:
    python fix_workflow_result_v2.py
"""

import re
from pathlib import Path
import shutil

SUPERVISOR_PATH = Path("src/core/supervisor.py")
BACKUP_PATH = Path("src/core/supervisor.py.pre-fix-backup")


def apply_fix():
    """Applique le fix pour recharger analysis_result"""

    print("🔧 Application du fix workflow_result dans supervisor.py\n")

    # 1. Vérifier que le fichier existe
    if not SUPERVISOR_PATH.exists():
        print(f"❌ Fichier non trouvé: {SUPERVISOR_PATH}")
        return False

    # 2. Backup
    print(f"💾 Sauvegarde: {BACKUP_PATH}")
    shutil.copy(SUPERVISOR_PATH, BACKUP_PATH)

    # 3. Lire le fichier
    with open(SUPERVISOR_PATH, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # 4. Vérifier si déjà appliqué
    content = ''.join(lines)
    if 'FIX : RECHARGER analysis_result' in content:
        print("✅ Fix déjà appliqué!")
        return True

    # 5. Trouver la ligne de la fonction _load_workflow_result
    start_line = None
    for i, line in enumerate(lines):
        if 'async def _load_workflow_result(self, workflow_id: str) -> WorkflowResult:' in line:
            start_line = i
            break

    if start_line is None:
        print("❌ Fonction _load_workflow_result non trouvée")
        return False

    print(f"✅ Fonction trouvée à la ligne {start_line + 1}")

    # 6. Trouver la fin de la fonction (prochaine fonction ou fin de classe)
    end_line = None
    indent_level = len(lines[start_line]) - len(lines[start_line].lstrip())

    for i in range(start_line + 1, len(lines)):
        line = lines[i]
        current_indent = len(line) - len(line.lstrip())

        # Si on trouve une ligne avec même indentation ou moins et qui commence une nouvelle fonction/classe
        if current_indent <= indent_level and line.strip():
            if line.strip().startswith(('async def ', 'def ', 'class ', '@')):
                end_line = i
                break

    if end_line is None:
        end_line = len(lines)

    print(f"✅ Fin de fonction à la ligne {end_line}")

    # 7. Trouver où insérer le code (après la création de result, avant le return)
    insert_line = None
    for i in range(start_line, end_line):
        line = lines[i]
        # Chercher "scripts_generated=data.get('scripts_generated', 0)"
        if "scripts_generated=data.get('scripts_generated', 0)" in line:
            # Chercher la ligne suivante avec ")"
            for j in range(i, end_line):
                if ')' in lines[j] and 'scripts_generated' not in lines[j]:
                    insert_line = j + 1
                    break
            break

    if insert_line is None:
        print("❌ Point d'insertion non trouvé")
        return False

    print(f"✅ Point d'insertion trouvé à la ligne {insert_line + 1}")

    # 8. Construire le code à insérer avec la bonne indentation
    base_indent = ' ' * 16  # 4 niveaux d'indentation

    fix_code = [
        '\n',
        f'{base_indent}# ============================================================\n',
        f'{base_indent}# FIX : RECHARGER analysis_result depuis le JSON\n',
        f'{base_indent}# ============================================================\n',
        f'{base_indent}if "analysis_result" in data and data["analysis_result"]:\n',
        f'{base_indent}    analysis_data = data["analysis_result"]\n',
        f'{base_indent}    \n',
        f'{base_indent}    # Reconstruire les VulnerabilityAnalysis\n',
        f'{base_indent}    from src.core.analyzer import VulnerabilityAnalysis, AnalysisResult\n',
        f'{base_indent}    \n',
        f'{base_indent}    vulnerabilities = []\n',
        f'{base_indent}    for vuln_dict in analysis_data.get("vulnerabilities", []):\n',
        f'{base_indent}        vuln = VulnerabilityAnalysis(\n',
        f'{base_indent}            vulnerability_id=vuln_dict["vulnerability_id"],\n',
        f'{base_indent}            name=vuln_dict["name"],\n',
        f'{base_indent}            severity=vuln_dict["severity"],\n',
        f'{base_indent}            cvss_score=vuln_dict["cvss_score"],\n',
        f'{base_indent}            impact_analysis=vuln_dict["impact_analysis"],\n',
        f'{base_indent}            exploitability=vuln_dict["exploitability"],\n',
        f'{base_indent}            priority_score=vuln_dict["priority_score"],\n',
        f'{base_indent}            affected_service=vuln_dict["affected_service"],\n',
        f'{base_indent}            recommended_actions=vuln_dict.get("recommended_actions", []),\n',
        f'{base_indent}            dependencies=vuln_dict.get("dependencies", []),\n',
        f'{base_indent}            references=vuln_dict.get("references", []),\n',
        f'{base_indent}            cvss_vector=vuln_dict.get("cvss_vector"),\n',
        f'{base_indent}            nist_verified=vuln_dict.get("nist_verified", False),\n',
        f'{base_indent}            nist_url=vuln_dict.get("nist_url"),\n',
        f'{base_indent}            solution_links=vuln_dict.get("solution_links", []),\n',
        f'{base_indent}            ai_explanation=vuln_dict.get("ai_explanation"),\n',
        f'{base_indent}            correction_script=vuln_dict.get("correction_script"),\n',
        f'{base_indent}            rollback_script=vuln_dict.get("rollback_script"),\n',
        f'{base_indent}            business_impact=vuln_dict.get("business_impact")\n',
        f'{base_indent}        )\n',
        f'{base_indent}        vulnerabilities.append(vuln)\n',
        f'{base_indent}    \n',
        f'{base_indent}    # Reconstruire AnalysisResult\n',
        f'{base_indent}    result.analysis_result = AnalysisResult(\n',
        f'{base_indent}        analysis_id=analysis_data["analysis_id"],\n',
        f'{base_indent}        target_system=analysis_data["target_system"],\n',
        f'{base_indent}        analyzed_at=datetime.fromisoformat(analysis_data["analyzed_at"]),\n',
        f'{base_indent}        analysis_summary=analysis_data["analysis_summary"],\n',
        f'{base_indent}        vulnerabilities=vulnerabilities,\n',
        f'{base_indent}        remediation_plan=analysis_data["remediation_plan"],\n',
        f'{base_indent}        ai_model_used=analysis_data["ai_model_used"],\n',
        f'{base_indent}        confidence_score=analysis_data["confidence_score"],\n',
        f'{base_indent}        processing_time=analysis_data["processing_time"],\n',
        f'{base_indent}        business_context=analysis_data.get("business_context"),\n',
        f'{base_indent}        nist_enriched=analysis_data.get("nist_enriched", False),\n',
        f'{base_indent}        nist_call_count=analysis_data.get("nist_call_count", 0),\n',
        f'{base_indent}        nist_cache_hits=analysis_data.get("nist_cache_hits", 0)\n',
        f'{base_indent}    )\n',
        f'{base_indent}    \n',
        f'{base_indent}    logger.info(f"✅ analysis_result rechargé: {{len(vulnerabilities)}} vulnérabilités")\n',
        '\n',
    ]

    # 9. Insérer le code
    new_lines = lines[:insert_line] + fix_code + lines[insert_line:]

    # 10. Sauvegarder
    with open(SUPERVISOR_PATH, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)

    print(f"\n✅ Fix appliqué avec succès!")
    print(f"   • Backup: {BACKUP_PATH}")
    print(f"   • Modifié: {SUPERVISOR_PATH}")
    print(f"   • Lignes ajoutées: {len(fix_code)}")
    print(f"\n🧪 Testez maintenant avec:")
    print(f"   PYTHONPATH=. python main.py --analyze --analyze-file scan_dvwa.json")
    print(f"\nVous devriez voir:")
    print(f"   ✅ analysis_result rechargé: X vulnérabilités")
    print(f"   ✅ Analyse terminée: X vulnérabilités analysées")

    return True


if __name__ == "__main__":
    success = apply_fix()
    exit(0 if success else 1)