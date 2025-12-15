## Sécurité (notes PoC)

### À qui s’adresse cette page ?
- Lecteurs non techniques (risques / limites)
- DevSecOps (bonnes pratiques)

### Ce que vous allez apprendre
- Les risques principaux
- Les règles à suivre pour une utilisation responsable

### Règles d’usage
- **Scan uniquement sur des cibles autorisées** (contrat / permission écrite).
- **Ne pas exécuter automatiquement** les scripts générés par IA sans revue humaine.

### Gestion des secrets
- Les clés API doivent être dans `.env` (non commité).
- Ne jamais publier de captures/logs contenant une clé.

### Données
- Les résultats peuvent contenir des informations sensibles (ports, services, versions).
- Avant publication de rapports : anonymiser cibles, adresses IP, bannières.

### Scripts de remédiation
- Les scripts sont générés à partir des vulnérabilités et du contexte.
- Toujours :
  - relire
  - tester en environnement de préprod
  - prévoir une fenêtre de maintenance
  - utiliser le rollback si nécessaire
