## Cas d’usage (proposés)

### À qui s’adresse cette page ?
- Décideurs (valeur)
- Dev/ops (comment rejouer)

### Cas 1 — Audit express d’une cible autorisée (CLI)
**Objectif** : obtenir rapidement ports/services + premières vulnérabilités.

```bash
python3 main.py --scan --target <cible_autorisée> --scan-type quick --output data/reports/scan.json --format json
```

**Valeur** : visibilité rapide, reproductible, exportable.

### Cas 2 — Priorisation et plan de remédiation (IA) à partir d’un fichier
**Objectif** : transformer une liste brute en plan d’action.

```bash
python3 main.py --analyze --analyze-file test_vulnerabilities.json --output data/reports/analysis.json --format json
```

**Valeur** : aide à la décision, priorités, actions recommandées.

### Cas 3 — Proposer des scripts de correction (avec rollback)
**Objectif** : accélérer l’exécution (après validation humaine).

```bash
python3 main.py --generate --analyze-file test_vulnerabilities.json --output data/scripts/scripts.json --format json
```

**Valeur** : accélération de la remédiation, standardisation des actions.
