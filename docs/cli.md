## CLI

### À qui s’adresse cette page ?
- Développeurs, pentesters/blue team (en environnement autorisé), DevSecOps

### Ce que vous allez apprendre
- Les commandes principales et les sorties

### Point d’entrée
- `main.py`

### Commandes principales
- **Scan** : `--scan --target <IP|domaine>`
- **Analyse IA** : `--analyze --analyze-file <json>` ou `--analyze --target <cible>`
- **Génération** : `--generate --analyze-file <json>`
- **Workflow complet** : `--full-workflow --target <cible>`
- **API** : `--api --host ... --port ...`

### Exemples
#### 1) Scan rapide (démo)
```bash
python3 main.py --scan --target 127.0.0.1 --scan-type ultra-quick --output data/scans/scan.json --format json
```

#### 2) Analyse IA d’un fichier
```bash
python3 main.py --analyze --analyze-file test_vulnerabilities.json --output data/reports/analysis.json --format json
```

#### 3) Workflow complet (scan + analyse + scripts)
```bash
python3 main.py --full-workflow --target 127.0.0.1 --scan-type quick --output data/reports/workflow.json --format json
```

### Formats de sortie
`--format` supporte : `json`, `txt`, `html`, `markdown`.

### Limites PoC (coûts)
Le PoC limite par défaut :
- l’analyse IA à **10 vulnérabilités** max
- la génération à **5 scripts** max

Ces limites sont configurables dans `.env`.
