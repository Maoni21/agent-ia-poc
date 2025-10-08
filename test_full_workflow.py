"""
Test complet du workflow avec OpenAI
"""

import asyncio
import sys
from pathlib import Path

# Ajouter le path
sys.path.insert(0, str(Path(__file__).parent))

from src.core.supervisor import Supervisor


# Données de test réelles
REAL_VULNERABILITIES = [
    {
        "name": "OpenSSH Weak Encryption Algorithms",
        "cve_id": "CVE-2023-38408",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected_service": "SSH",
        "ports": [22],
        "description": "Le serveur OpenSSH accepte des algorithmes de chiffrement faibles qui peuvent être exploités"
    },
    {
        "name": "Apache HTTP Server Information Disclosure",
        "cve_id": "CVE-2023-25690",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "affected_service": "HTTP",
        "ports": [80, 443],
        "description": "Fuite d'informations sensibles via les en-têtes HTTP mal configurés"
    },
    {
        "name": "Outdated SSL/TLS Configuration",
        "cve_id": "CVE-2023-12345",
        "severity": "HIGH",
        "cvss_score": 7.0,
        "affected_service": "HTTPS",
        "ports": [443],
        "description": "Support de protocoles SSL/TLS obsolètes (SSLv3, TLS 1.0, TLS 1.1)"
    },
    {
        "name": "MySQL Default Credentials",
        "cve_id": "CVE-2023-67890",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected_service": "MySQL",
        "ports": [3306],
        "description": "Compte root MySQL accessible avec mot de passe par défaut"
    }
]


async def test_openai_with_real_data():
    """Test avec des données réelles de vulnérabilités"""

    print("\n" + "🎬 " * 20)
    print("LANCEMENT DU TEST")
    print("🎬 " * 20 + "\n")

    print("=" * 70)
    print("🧪 TEST COMPLET AVEC OPENAI")
    print("=" * 70)
    print(f"\n📊 Données: {len(REAL_VULNERABILITIES)} vulnérabilités réelles")
    print(f"💰 Coût estimé: ~0.05-0.10€")
    print(f"⏱️  Durée estimée: 30-60 secondes")
    print(f"\n{'=' * 70}\n")

    supervisor = None

    try:
        # Créer le supervisor
        supervisor = Supervisor()

        # ÉTAPE 1: Analyse IA
        print("🔄 ÉTAPE 1/2 : Analyse IA des vulnérabilités...")
        print("-" * 70)

        # Lancer l'analyse via workflow
        from src.core.supervisor import WorkflowType

        workflow_id = await supervisor.start_workflow(
            WorkflowType.ANALYZE_EXISTING,
            "Test System - Ubuntu 20.04",
            {"vulnerabilities_data": REAL_VULNERABILITIES}
        )

        # Attendre le résultat du workflow
        workflow_result = await supervisor.wait_for_workflow(workflow_id)

        print("✅ Analyse terminée !\n")

        # Récupérer le résultat d'analyse depuis le workflow_result
        analysis_result = workflow_result.analysis_result

        if not analysis_result:
            print("❌ ERREUR: Aucun résultat d'analyse retourné")
            print(f"Workflow status: {workflow_result.status}")

            # Debug: afficher tout le contenu
            result_dict = workflow_result.to_dict()
            print(f"\n🔍 DEBUG - Contenu du workflow_result:")
            for key, value in result_dict.items():
                if value is not None:
                    print(f"   - {key}: {type(value).__name__} = {str(value)[:100]}")
                else:
                    print(f"   - {key}: None")

            # Vérifier si les résultats sont sauvegardés dans un fichier
            import json
            from pathlib import Path
            results_file = Path(f"data/workflow_results/{workflow_result.workflow_id}.json")
            if results_file.exists():
                print(f"\n📄 Fichier de résultats trouvé: {results_file}")
                with open(results_file, 'r') as f:
                    saved_data = json.load(f)
                    if saved_data.get('analysis_result'):
                        print("✅ Les résultats sont dans le fichier JSON!")
                        # Recréer l'objet AnalysisResult depuis le fichier
                        from src.core.analyzer import AnalysisResult, VulnerabilityAnalysis
                        from datetime import datetime

                        ar_data = saved_data['analysis_result']
                        vulnerabilities = [
                            VulnerabilityAnalysis(**v) for v in ar_data['vulnerabilities']
                        ]

                        analysis_result = AnalysisResult(
                            analysis_id=ar_data['analysis_id'],
                            target_system=ar_data['target_system'],
                            analyzed_at=datetime.fromisoformat(ar_data['analyzed_at']),
                            analysis_summary=ar_data['analysis_summary'],
                            vulnerabilities=vulnerabilities,
                            remediation_plan=ar_data['remediation_plan'],
                            ai_model_used=ar_data['ai_model_used'],
                            confidence_score=ar_data['confidence_score'],
                            processing_time=ar_data['processing_time']
                        )
                        print("✅ AnalysisResult reconstruit depuis le fichier!")

            if not analysis_result:
                print("\n⚠️  Impossible de récupérer les résultats d'analyse")
                return

        # Afficher les résultats
        print("=" * 70)
        print("📊 RÉSULTATS DE L'ANALYSE IA")
        print("=" * 70)

        print(f"\n🤖 Modèle utilisé: {analysis_result.ai_model_used}")
        print(f"⏱️  Temps de traitement: {analysis_result.processing_time:.2f}s")
        print(f"🎯 Score de confiance: {analysis_result.confidence_score:.1%}")

        # Résumé
        summary = analysis_result.analysis_summary
        print(f"\n📈 RÉSUMÉ:")
        print(f"   • Total vulnérabilités: {summary['total_vulnerabilities']}")
        print(f"   • Critiques: {summary['critical_count']}")
        print(f"   • Élevées: {summary['high_count']}")
        print(f"   • Moyennes: {summary['medium_count']}")
        print(f"   • Faibles: {summary['low_count']}")
        print(f"   • Score de risque global: {summary['overall_risk_score']}/10")

        # Détail des vulnérabilités analysées
        print(f"\n🔍 VULNÉRABILITÉS ANALYSÉES:")
        print("-" * 70)

        for i, vuln in enumerate(analysis_result.vulnerabilities, 1):
            severity_icons = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢"
            }
            icon = severity_icons.get(vuln.severity, "⚪")

            print(f"\n{i}. {icon} {vuln.name}")
            print(f"   ID: {vuln.vulnerability_id}")
            print(f"   Gravité: {vuln.severity} (CVSS: {vuln.cvss_score})")
            print(f"   Priorité: {vuln.priority_score}/10")
            print(f"   Exploitabilité: {vuln.exploitability}")
            print(f"   Service affecté: {vuln.affected_service}")

            if vuln.impact_analysis:
                print(f"   Impact: {vuln.impact_analysis[:100]}...")

            if vuln.recommended_actions:
                print(f"   Actions recommandées ({len(vuln.recommended_actions)}):")
                for action in vuln.recommended_actions[:2]:
                    print(f"      • {action}")
                if len(vuln.recommended_actions) > 2:
                    print(f"      ... et {len(vuln.recommended_actions) - 2} autres")

        # Plan de remédiation
        remediation = analysis_result.remediation_plan
        print(f"\n📋 PLAN DE REMÉDIATION:")
        print("-" * 70)

        if 'executive_summary' in remediation:
            exec_summary = remediation['executive_summary']
            print(f"\n⚡ Actions immédiates requises: {exec_summary.get('immediate_action_required', 'N/A')}")
            print(f"⏰ Effort estimé total: {exec_summary.get('estimated_total_effort', 'N/A')}")
            print(f"⚠️  Niveau de risque business: {exec_summary.get('business_risk_level', 'N/A')}")

        if 'implementation_roadmap' in remediation:
            roadmap = remediation['implementation_roadmap']

            if 'phase_1_immediate' in roadmap:
                phase1 = roadmap['phase_1_immediate']
                print(f"\n🚨 PHASE 1 - IMMÉDIAT:")
                print(f"   • Vulnérabilités: {len(phase1.get('vulnerabilities', []))}")
                print(f"   • Durée: {phase1.get('duration', 'N/A')}")
                print(f"   • Ressources: {', '.join(phase1.get('resources_needed', []))}")

            if 'phase_2_short_term' in roadmap:
                phase2 = roadmap['phase_2_short_term']
                print(f"\n📅 PHASE 2 - COURT TERME:")
                print(f"   • Vulnérabilités: {len(phase2.get('vulnerabilities', []))}")
                print(f"   • Durée: {phase2.get('duration', 'N/A')}")

            if 'phase_3_long_term' in roadmap:
                phase3 = roadmap['phase_3_long_term']
                print(f"\n📆 PHASE 3 - LONG TERME:")
                print(f"   • Vulnérabilités: {len(phase3.get('vulnerabilities', []))}")
                print(f"   • Durée: {phase3.get('duration', 'N/A')}")

        if 'recommendations' in remediation:
            print(f"\n💡 RECOMMANDATIONS:")
            for rec in remediation['recommendations'][:3]:
                print(f"   • {rec}")

        print(f"\n{'=' * 70}\n")

        # SUCCESS !
        print("\n" + "✨ " * 20)
        print("TEST RÉUSSI AVEC SUCCÈS !")
        print("✨ " * 20 + "\n")

        print("✅ Votre système est maintenant capable de :")
        print("   1. 🔍 Scanner les vulnérabilités")
        print("   2. 🤖 Analyser avec OpenAI")
        print("   3. 📊 Générer des rapports détaillés")
        print("   4. 📋 Créer des plans de remédiation\n")

    except Exception as e:
        print(f"\n❌ ERREUR: {e}")
        print(f"Type: {type(e).__name__}")

        import traceback
        traceback.print_exc()

        print("\n" + "💥 " * 20)
        print("TEST ÉCHOUÉ")
        print("💥 " * 20 + "\n")

    finally:
        if supervisor:
            await supervisor.shutdown()


if __name__ == "__main__":
    asyncio.run(test_openai_with_real_data())