# Guide Utilisateur - Vulnerability Agent IA

## Connexion

1. Se rendre sur `http://localhost:3000`
2. Créer un compte via **Register** (organisation + admin)
3. Se connecter via **Login**

## Navigation principale

- **Dashboard** : vue d'ensemble (scans, vulns, stats)
- **Assets** : gestion des serveurs / machines
- **Scans** : lancer et suivre les scans
- **Vulnerabilities** : liste et détail des vulnérabilités
- **Scripts** : scripts générés par l'IA
- **Webhooks** : intégrations externes (optionnel)

## Flux typique

1. Créer un **Asset** (IP, type, environnement, tags)
2. Depuis **Scans**, lancer un **nouveau scan** sur cet asset
3. Attendre la fin du scan et consulter les **vulnérabilités**
4. Depuis **Vulnerabilities** :
   - Filtrer / rechercher
   - Ouvrir une vulnérabilité en détail
   - Lancer **Analyze with AI**
   - Générer un **script de remédiation**
5. Faire approuver / exécuter le script (workflow d'approbation simple)

