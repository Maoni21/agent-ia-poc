"""
Test minimal pour identifier le problème OpenAI
"""

import asyncio
import os
import sys
from pathlib import Path

# Ajouter le path
sys.path.insert(0, str(Path(__file__).parent))


async def test_1_openai_import():
    """Test 1: Import OpenAI"""
    print("\n" + "=" * 70)
    print("TEST 1: Import OpenAI")
    print("=" * 70)

    try:
        from openai import AsyncOpenAI
        print("✅ Import AsyncOpenAI réussi")
        return True
    except Exception as e:
        print(f"❌ Erreur import: {e}")
        return False


async def test_2_openai_connection():
    """Test 2: Connexion OpenAI"""
    print("\n" + "=" * 70)
    print("TEST 2: Connexion OpenAI")
    print("=" * 70)

    try:
        from openai import AsyncOpenAI
        from config import get_config

        config = get_config()
        api_key = config.openai_api_key

        if not api_key:
            print("❌ Pas de clé API OpenAI dans la config")
            return False

        print(f"✅ Clé API trouvée: {api_key[:10]}...{api_key[-4:]}")

        # Créer le client
        client = AsyncOpenAI(api_key=api_key)
        print("✅ Client OpenAI créé")

        return True

    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_3_simple_openai_call():
    """Test 3: Appel simple OpenAI"""
    print("\n" + "=" * 70)
    print("TEST 3: Appel simple OpenAI")
    print("=" * 70)

    try:
        from openai import AsyncOpenAI
        from config import get_config

        config = get_config()
        api_key = config.openai_api_key

        if not api_key:
            print("❌ Pas de clé API")
            return False

        client = AsyncOpenAI(api_key=api_key)

        print("📞 Appel de l'API OpenAI...")

        response = await client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Tu es un assistant."},
                {"role": "user", "content": "Dis juste 'OK' si tu me reçois"}
            ],
            max_tokens=10,
            temperature=0.3
        )

        result = response.choices[0].message.content
        print(f"✅ Réponse reçue: {result}")

        return True

    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_4_prompt_formatting():
    """Test 4: Formatage du prompt de vulnérabilité"""
    print("\n" + "=" * 70)
    print("TEST 4: Formatage du prompt")
    print("=" * 70)

    try:
        from config.prompts import format_vulnerability_prompt

        test_data = """
Vulnérabilité: Test Vulnerability
CVE: CVE-2023-00000
Gravité: HIGH
Score CVSS: 7.5
Service: SSH
Ports: 22
Description: Test description
"""

        print("🔧 Formatage du prompt...")
        prompt = format_vulnerability_prompt(
            os_info="Ubuntu 20.04",
            services="SSH",
            open_ports="22",
            vulnerabilities_data=test_data
        )

        print(f"✅ Prompt formaté: {len(prompt)} caractères")
        print(f"\nExtrait (300 premiers chars):")
        print("-" * 70)
        print(prompt[:300])
        print("-" * 70)

        return True

    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_5_analyzer_init():
    """Test 5: Initialisation de l'Analyzer"""
    print("\n" + "=" * 70)
    print("TEST 5: Initialisation de l'Analyzer")
    print("=" * 70)

    try:
        from src.core.analyzer import Analyzer

        print("🔧 Création de l'Analyzer...")
        analyzer = Analyzer()

        print(f"✅ Analyzer créé")
        print(f"   - Provider: {analyzer.current_provider}")
        print(f"   - Ready: {analyzer.is_ready}")
        print(f"   - Model: {analyzer._get_model_name()}")

        return True

    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_6_full_analysis():
    """Test 6: Analyse complète d'une vulnérabilité"""
    print("\n" + "=" * 70)
    print("TEST 6: Analyse complète")
    print("=" * 70)

    try:
        from src.core.analyzer import Analyzer

        # Données de test minimales
        test_vulns = [
            {
                "name": "OpenSSH Weak Encryption",
                "cve_id": "CVE-2023-12345",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "affected_service": "SSH",
                "ports": [22],
                "description": "Algorithmes de chiffrement faibles activés"
            }
        ]

        print("🔧 Création de l'Analyzer...")
        analyzer = Analyzer()

        print("📞 Lancement de l'analyse...")
        print("   (Cela peut prendre 10-30 secondes)")

        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=test_vulns,
            target_system="Ubuntu 20.04 Test System"
        )

        print(f"\n✅ Analyse terminée!")
        print(f"   - ID: {result.analysis_id}")
        print(f"   - Vulnérabilités analysées: {len(result.vulnerabilities)}")
        print(f"   - Temps de traitement: {result.processing_time:.2f}s")
        print(f"   - Score de confiance: {result.confidence_score:.2%}")

        if result.vulnerabilities:
            vuln = result.vulnerabilities[0]
            print(f"\n📋 Première vulnérabilité:")
            print(f"   - ID: {vuln.vulnerability_id}")
            print(f"   - Nom: {vuln.name}")
            print(f"   - Priorité: {vuln.priority_score}/10")
            print(f"   - Actions: {len(vuln.recommended_actions)} recommandations")

        return True

    except Exception as e:
        print(f"❌ Erreur: {e}")
        print(f"Type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Fonction principale"""
    print("\n🔍 TEST MINIMAL OPENAI - DIAGNOSTIC COMPLET\n")

    tests = [
        ("Import OpenAI", test_1_openai_import),
        ("Connexion OpenAI", test_2_openai_connection),
        ("Appel simple OpenAI", test_3_simple_openai_call),
        ("Formatage prompt", test_4_prompt_formatting),
        ("Initialisation Analyzer", test_5_analyzer_init),
        ("Analyse complète", test_6_full_analysis),
    ]

    results = []

    for test_name, test_func in tests:
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n💥 Exception non gérée dans {test_name}: {e}")
            results.append((test_name, False))

        # Petite pause entre les tests
        await asyncio.sleep(0.5)

    # Résumé final
    print("\n" + "=" * 70)
    print("RÉSUMÉ DES TESTS")
    print("=" * 70)

    for i, (test_name, result) in enumerate(results, 1):
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{i}. {test_name}: {status}")

    print("\n" + "=" * 70)

    passed = sum(1 for _, r in results if r)
    total = len(results)

    if passed == total:
        print(f"🎉 SUCCÈS COMPLET! {passed}/{total} tests réussis")
        print("\n✨ Votre système est prêt à analyser les vulnérabilités avec OpenAI!")
    else:
        print(f"⚠️  {passed}/{total} tests réussis")
        print("\n💡 Corrigez les erreurs ci-dessus avant de continuer.")
        print("   Le premier test qui échoue indique où se situe le problème.")

    print("=" * 70 + "\n")


if __name__ == "__main__":
    asyncio.run(main())