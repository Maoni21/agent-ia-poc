## Vue d’ensemble

### À qui s’adresse cette page ?
- Lecteurs non techniques (compréhension produit)
- Développeurs / DevSecOps (compréhension du fonctionnement)

### Ce que vous allez apprendre
- Le problème adressé et la valeur du PoC
- Les composants (CLI / API / dashboard)
- Le flux global des données

### Pourquoi ce projet est important
Dans beaucoup d’organisations, l’identification de vulnérabilités est **fragmentée** (scan, tri, priorisation, remédiation, reporting). Ce PoC montre une approche « agent » pour :
- **centraliser** les résultats
- **prioriser** (risque + impact) plus vite
- **accélérer** la remédiation via des scripts proposés (avec rollback)

### Ce que fait le PoC
- **Scan** d’une cible via Nmap (ports, services, scripts NSE)
- **Enrichissement** des vulnérabilités (références officielles)
- **Analyse IA** : résumé, criticité, actions recommandées, score de priorité
- **Génération IA** : scripts de correction + script de rollback
- **Persistance** : base SQLite + fichiers `data/workflow_results/*.json`
- **Visualisation** : dashboard web (lecture seule)

### Ce que le PoC ne fait pas (limites)
- Pas un outil “prod-ready” (pas de durcissement complet, pas de SLA)
- Les scripts générés **doivent être relus** avant exécution
- Le scan Nmap dépend de l’environnement réseau et des permissions

### Composants
- **CLI** : `main.py`
  - scan / analyse / génération / workflow complet / serveur API
- **Core** : `src/core/`
  - `Collector` (scan) → `Analyzer` (analyse IA) → `Generator` (scripts)
  - orchestration par `Supervisor`
- **API REST** : `src/api/`
  - FastAPI, endpoints `/api/v1/*`
- **Base de données** : `src/database/` + fichier SQLite sous `data/database/`
- **Dashboard** : `src/web/`

### Flux (simplifié)
1. Entrée (cible ou fichier JSON)
2. Collecte (scan Nmap) → vulnérabilités
3. Analyse IA → priorisation + plan
4. Génération de scripts (optionnel)
5. Sauvegarde en `data/` (JSON + DB)
6. Lecture via dashboard
