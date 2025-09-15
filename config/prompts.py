"""
Templates de prompts pour l'Agent IA de Cybersécurité

Ce module contient tous les prompts utilisés pour interagir avec les modèles IA
dans le cadre de l'analyse des vulnérabilités et la génération de correctifs.
"""

from typing import Dict, Any

# === PROMPT D'ANALYSE DES VULNÉRABILITÉS ===

VULNERABILITY_ANALYSIS_PROMPT = """
Tu es un expert en cybersécurité spécialisé dans l'analyse de vulnérabilités.

Voici les données de scan d'un système cible :

**INFORMATIONS SYSTÈME :**
- OS : {os_info}
- Services détectés : {services}
- Ports ouverts : {open_ports}

**VULNÉRABILITÉS DÉTECTÉES :**
{vulnerabilities_data}

**TÂCHE :**
Analyse ces vulnérabilités et fournis une réponse structurée en JSON avec :

1. **severity_assessment** : Pour chaque vulnérabilité, évalue la gravité (CRITICAL, HIGH, MEDIUM, LOW)
2. **impact_analysis** : Décris l'impact potentiel sur le système
3. **exploitability** : Évalue la facilité d'exploitation (EASY, MEDIUM, HARD)
4. **priority_score** : Score de priorité de 1 à 10 (10 = urgent)
5. **recommended_actions** : Actions recommandées pour corriger la vulnérabilité
6. **dependencies** : Liste des vulnérabilités qui doivent être corrigées en premier

**FORMAT DE RÉPONSE ATTENDU :**
```json
{
  "analysis_summary": {
    "total_vulnerabilities": 0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "overall_risk_score": 0
  },
  "vulnerabilities": [
    {
      "id": "CVE-XXXX-XXXX ou ID local",
      "name": "Nom de la vulnérabilité",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "cvss_score": 0.0,
      "impact_analysis": "Description détaillée de l'impact",
      "exploitability": "EASY|MEDIUM|HARD",
      "priority_score": 0,
      "affected_service": "Service concerné",
      "recommended_actions": [
        "Action 1",
        "Action 2"
      ],
      "dependencies": ["CVE-XXXX-XXXX"],
      "references": ["URL1", "URL2"]
    }
  ],
  "remediation_plan": {
    "immediate_actions": ["Actions urgentes"],
    "short_term": ["Actions à court terme"],
    "long_term": ["Actions à long terme"]
  }
}
```

**CRITÈRES D'ÉVALUATION :**
- Priorise les vulnérabilités selon CVSS, facilité d'exploitation et impact
- Considère les dépendances entre vulnérabilités
- Propose des actions concrètes et réalisables
- Reste factuel et technique dans l'analyse
"""

# === PROMPT DE GÉNÉRATION DE SCRIPTS ===

SCRIPT_GENERATION_PROMPT = """
Tu es un expert en administration système et cybersécurité.

**CONTEXTE :**
Système cible : {target_os}
Vulnérabilité à corriger : {vulnerability_name}
Gravité : {severity}
Service affecté : {affected_service}

**DÉTAILS DE LA VULNÉRABILITÉ :**
{vulnerability_details}

**TÂCHE :**
Génère un script bash sécurisé pour corriger cette vulnérabilité.

**CONTRAINTES IMPORTANTES :**
- Le script doit être SÛREMENT EXÉCUTABLE sans risquer de casser le système
- Inclure des vérifications préalables (pré-conditions)
- Inclure des points de sauvegarde avant modifications
- Ajouter des logs détaillés de chaque action
- Prévoir une procédure de rollback en cas d'échec
- Tester l'existence des fichiers/services avant modification
- Utiliser uniquement des commandes standards Linux

**FORMAT DE RÉPONSE :**
```json
{
  "script_info": {
    "vulnerability_id": "CVE ou ID",
    "description": "Description de ce que fait le script",
    "estimated_duration": "Temps estimé d'exécution",
    "requires_reboot": false,
    "risk_level": "LOW|MEDIUM|HIGH"
  },
  "pre_checks": [
    "Vérification 1",
    "Vérification 2"
  ],
  "backup_commands": [
    "cp /etc/config /etc/config.backup.$(date +%Y%m%d_%H%M%S)",
    "Autres sauvegardes nécessaires"
  ],
  "main_script": "#!/bin/bash\n\n# Script de correction généré automatiquement\n# Vulnérabilité: {vulnerability_name}\n# Date: $(date)\n\nset -euo pipefail\n\n# Vos commandes ici",
  "rollback_script": "#!/bin/bash\n\n# Script de rollback\n# Restaure l'état précédent\n\nset -euo pipefail\n\n# Commandes de restauration",
  "post_checks": [
    "Vérification que le correctif fonctionne",
    "Tests de régression"
  ],
  "warnings": [
    "Avertissements importants",
    "Points d'attention"
  ]
}
```

**BONNES PRATIQUES À RESPECTER :**
- Toujours commencer par `set -euo pipefail`
- Utiliser des variables pour les chemins importants
- Logger toutes les actions importantes
- Vérifier les codes de retour des commandes critiques
- Inclure des timeouts pour les opérations longues
- Ne jamais utiliser `rm -rf /` ou équivalent dangereux
"""

# === PROMPT D'ÉVALUATION DE PRIORITÉ ===

PRIORITY_ASSESSMENT_PROMPT = """
Tu es un CISO (Chief Information Security Officer) expérimenté.

**CONTEXTE :**
Voici une liste de vulnérabilités détectées sur un système en production :

{vulnerabilities_list}

**CONTRAINTES BUSINESS :**
- Budget limité : {budget_constraints}
- Fenêtre de maintenance : {maintenance_window}
- Services critiques : {critical_services}
- Niveau de tolérance au risque : {risk_tolerance}

**MISSION :**
Établis un plan de priorisation des correctifs en tenant compte :
1. Du risque technique (CVSS, exploitabilité)
2. De l'impact business
3. Des contraintes opérationnelles
4. Des dépendances entre correctifs

**FORMAT DE RÉPONSE :**
```json
{
  "executive_summary": {
    "total_vulnerabilities": 0,
    "immediate_action_required": 0,
    "estimated_total_effort": "X heures/jours",
    "business_risk_level": "LOW|MEDIUM|HIGH|CRITICAL"
  },
  "priority_matrix": [
    {
      "rank": 1,
      "vulnerability_id": "CVE-XXXX-XXXX",
      "justification": "Pourquoi cette priorité",
      "business_impact": "Impact sur l'activité",
      "technical_complexity": "SIMPLE|MEDIUM|COMPLEX",
      "estimated_effort": "X heures",
      "recommended_timing": "IMMEDIATE|THIS_WEEK|THIS_MONTH|NEXT_QUARTER"
    }
  ],
  "implementation_roadmap": {
    "phase_1_immediate": {
      "vulnerabilities": ["CVE-1", "CVE-2"],
      "duration": "24-48h",
      "resources_needed": ["Administrateur système", "Temps d'arrêt"]
    },
    "phase_2_short_term": {
      "vulnerabilities": ["CVE-3", "CVE-4"],
      "duration": "1-2 semaines",
      "resources_needed": ["Équipe dev", "Tests"]
    },
    "phase_3_long_term": {
      "vulnerabilities": ["CVE-5"],
      "duration": "1+ mois",
      "resources_needed": ["Refonte architecture"]
    }
  },
  "risk_acceptance": {
    "acceptable_risks": ["Vulnérabilités à risque acceptable"],
    "justification": "Pourquoi ces risques sont acceptables"
  },
  "recommendations": [
    "Recommandation stratégique 1",
    "Recommandation opérationnelle 2"
  ]
}
```

Sois pragmatique et oriente business dans tes recommandations.
"""

# === PROMPT DE VALIDATION DE SCRIPT ===

SCRIPT_VALIDATION_PROMPT = """
Tu es un expert en sécurité des systèmes et revue de code.

**TÂCHE :**
Analyse ce script bash et évalue sa sécurité avant exécution :

```bash
{script_content}
```

**CONTEXTE :**
- Système cible : {target_system}
- Utilisateur d'exécution : {execution_user}
- Vulnérabilité à corriger : {vulnerability_info}

**ANALYSE REQUISE :**
Évalue les risques potentiels et fournis une recommandation d'exécution.

**FORMAT DE RÉPONSE :**
```json
{
  "security_assessment": {
    "overall_risk": "LOW|MEDIUM|HIGH|CRITICAL",
    "execution_recommendation": "APPROVE|REVIEW_REQUIRED|REJECT",
    "confidence_level": "0-100%"
  },
  "identified_risks": [
    {
      "type": "COMMAND_INJECTION|FILE_MANIPULATION|PRIVILEGE_ESCALATION|DATA_LOSS",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "description": "Description du risque",
      "line_number": 42,
      "recommendation": "Comment mitiger ce risque"
    }
  ],
  "security_checks": {
    "dangerous_commands": ["rm -rf", "chmod 777"],
    "privilege_escalation": false,
    "external_downloads": false,
    "file_modifications": ["/etc/passwd", "/etc/shadow"],
    "network_connections": false
  },
  "improvements": [
    "Suggestion d'amélioration 1",
    "Suggestion d'amélioration 2"
  ],
  "alternative_approach": "Approche alternative plus sûre si applicable"
}
```

**CRITÈRES DE VALIDATION :**
- Pas de commandes destructrices non justifiées
- Gestion d'erreurs appropriée
- Permissions minimales requises
- Réversibilité des actions
- Logging approprié
"""

# === PROMPT DE RAPPORT EXÉCUTIF ===

EXECUTIVE_REPORT_PROMPT = """
Tu es un consultant en cybersécurité préparant un rapport pour la direction.

**DONNÉES D'AUDIT :**
{scan_results_summary}

**CONTEXTE ENTREPRISE :**
- Secteur d'activité : {business_sector}
- Taille de l'entreprise : {company_size}
- Niveau de maturité cyber : {cyber_maturity}
- Budget alloué : {allocated_budget}

**OBJECTIF :**
Rédige un rapport exécutif clair et actionnable pour des dirigeants non-techniques.

**STRUCTURE ATTENDUE :**
```json
{
  "executive_summary": {
    "key_findings": [
      "Point clé 1 en langage business",
      "Point clé 2 avec impact chiffré"
    ],
    "overall_security_posture": "POOR|FAIR|GOOD|EXCELLENT",
    "immediate_actions_required": 0,
    "estimated_budget_impact": "€X,XXX",
    "timeline_for_remediation": "X semaines/mois"
  },
  "business_impact": {
    "potential_financial_loss": "€X,XXX en cas d'incident",
    "regulatory_compliance": "COMPLIANT|AT_RISK|NON_COMPLIANT",
    "reputation_risk": "LOW|MEDIUM|HIGH",
    "operational_continuity": "SECURE|AT_RISK|VULNERABLE"
  },
  "prioritized_recommendations": [
    {
      "priority": "CRITICAL|HIGH|MEDIUM|LOW",
      "action": "Action concrète",
      "business_justification": "Pourquoi c'est important pour l'entreprise",
      "cost_estimate": "€X,XXX",
      "timeline": "X semaines",
      "roi_expected": "Retour sur investissement attendu"
    }
  ],
  "resource_requirements": {
    "internal_resources": ["Compétences nécessaires"],
    "external_expertise": ["Consultants spécialisés"],
    "technology_investments": ["Outils à acquérir"],
    "training_needs": ["Formations requises"]
  },
  "next_steps": [
    "Étape immédiate 1",
    "Étape suivante 2"
  ]
}
```

Utilise un langage accessible et oriente tes recommandations vers l'impact business.
"""


# === FONCTIONS UTILITAIRES POUR LES PROMPTS ===

def format_vulnerability_prompt(
        os_info: str,
        services: str,
        open_ports: str,
        vulnerabilities_data: str
) -> str:
    """
    Formate le prompt d'analyse de vulnérabilités avec les données du scan

    Args:
        os_info: Informations sur l'OS
        services: Services détectés
        open_ports: Ports ouverts
        vulnerabilities_data: Données des vulnérabilités

    Returns:
        str: Prompt formaté prêt à être envoyé à l'IA
    """
    return VULNERABILITY_ANALYSIS_PROMPT.format(
        os_info=os_info,
        services=services,
        open_ports=open_ports,
        vulnerabilities_data=vulnerabilities_data
    )


def format_script_generation_prompt(
        target_os: str,
        vulnerability_name: str,
        severity: str,
        affected_service: str,
        vulnerability_details: str
) -> str:
    """
    Formate le prompt de génération de scripts

    Args:
        target_os: Système d'exploitation cible
        vulnerability_name: Nom de la vulnérabilité
        severity: Niveau de gravité
        affected_service: Service affecté
        vulnerability_details: Détails de la vulnérabilité

    Returns:
        str: Prompt formaté pour la génération de script
    """
    return SCRIPT_GENERATION_PROMPT.format(
        target_os=target_os,
        vulnerability_name=vulnerability_name,
        severity=severity,
        affected_service=affected_service,
        vulnerability_details=vulnerability_details
    )


def format_priority_assessment_prompt(
        vulnerabilities_list: str,
        budget_constraints: str = "Limité",
        maintenance_window: str = "Week-end uniquement",
        critical_services: str = "Services web",
        risk_tolerance: str = "Faible"
) -> str:
    """
    Formate le prompt d'évaluation de priorité

    Args:
        vulnerabilities_list: Liste des vulnérabilités
        budget_constraints: Contraintes budgétaires
        maintenance_window: Fenêtres de maintenance
        critical_services: Services critiques
        risk_tolerance: Tolérance au risque

    Returns:
        str: Prompt formaté pour l'évaluation de priorité
    """
    return PRIORITY_ASSESSMENT_PROMPT.format(
        vulnerabilities_list=vulnerabilities_list,
        budget_constraints=budget_constraints,
        maintenance_window=maintenance_window,
        critical_services=critical_services,
        risk_tolerance=risk_tolerance
    )


def format_script_validation_prompt(
        script_content: str,
        target_system: str,
        execution_user: str,
        vulnerability_info: str
) -> str:
    """
    Formate le prompt de validation de script

    Args:
        script_content: Contenu du script à valider
        target_system: Système cible
        execution_user: Utilisateur d'exécution
        vulnerability_info: Informations sur la vulnérabilité

    Returns:
        str: Prompt formaté pour la validation de script
    """
    return SCRIPT_VALIDATION_PROMPT.format(
        script_content=script_content,
        target_system=target_system,
        execution_user=execution_user,
        vulnerability_info=vulnerability_info
    )


def format_executive_report_prompt(
        scan_results_summary: str,
        business_sector: str = "Entreprise générale",
        company_size: str = "PME",
        cyber_maturity: str = "Débutant",
        allocated_budget: str = "Budget limité"
) -> str:
    """
    Formate le prompt de rapport exécutif

    Args:
        scan_results_summary: Résumé des résultats de scan
        business_sector: Secteur d'activité
        company_size: Taille de l'entreprise
        cyber_maturity: Niveau de maturité cyber
        allocated_budget: Budget alloué

    Returns:
        str: Prompt formaté pour le rapport exécutif
    """
    return EXECUTIVE_REPORT_PROMPT.format(
        scan_results_summary=scan_results_summary,
        business_sector=business_sector,
        company_size=company_size,
        cyber_maturity=cyber_maturity,
        allocated_budget=allocated_budget
    )


# === DICTIONNAIRE DE TOUS LES PROMPTS ===

ALL_PROMPTS = {
    "vulnerability_analysis": VULNERABILITY_ANALYSIS_PROMPT,
    "script_generation": SCRIPT_GENERATION_PROMPT,
    "priority_assessment": PRIORITY_ASSESSMENT_PROMPT,
    "script_validation": SCRIPT_VALIDATION_PROMPT,
    "executive_report": EXECUTIVE_REPORT_PROMPT
}


def get_prompt(prompt_type: str) -> str:
    """
    Récupère un prompt par son type

    Args:
        prompt_type: Type de prompt souhaité

    Returns:
        str: Template de prompt

    Raises:
        ValueError: Si le type de prompt n'existe pas
    """
    if prompt_type not in ALL_PROMPTS:
        available = ", ".join(ALL_PROMPTS.keys())
        raise ValueError(f"Type de prompt '{prompt_type}' inconnu. Disponibles: {available}")

    return ALL_PROMPTS[prompt_type]