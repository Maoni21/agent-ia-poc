# Frontend Next.js - Vulnerability Agent

Application Next.js moderne pour l'Agent IA de Cybersécurité.

## 🚀 Installation

```bash
# Installer les dépendances
npm install

# Créer le fichier .env.local depuis .env.example
cp .env.example .env.local

# Éditer .env.local avec vos configurations
```

## 📝 Configuration

Éditez le fichier `.env.local` :

```env
REACT_APP_API_URL=http://localhost:8000
REACT_APP_WS_URL=ws://localhost:8000
```

## 🏃 Développement

```bash
# Lancer le serveur de développement
npm run dev
```

L'application sera accessible sur http://localhost:3000

## 🏗️ Build pour production

```bash
# Build
npm run build

# Démarrer en production
npm start
```

## 📦 Structure Next.js

```
frontend/
├── pages/           # Pages Next.js (routing automatique)
│   ├── _app.js     # Configuration globale
│   ├── _document.js # Document HTML personnalisé
│   ├── index.js     # Page d'accueil (/)
│   ├── scans.js    # Page scans (/scans)
│   └── vulnerabilities.js # Page vulnérabilités (/vulnerabilities)
├── components/      # Composants React réutilisables
├── lib/            # Utilitaires et services
│   └── services/   # Services API et WebSocket
├── styles/         # Styles CSS globaux
└── public/         # Fichiers statiques
```

## 🎨 Avantages de Next.js

- ✅ **Server-Side Rendering (SSR)** : Meilleur SEO et performance
- ✅ **Routing automatique** : Pas besoin de React Router
- ✅ **Optimisations automatiques** : Code splitting, image optimization
- ✅ **API Routes** : Possibilité de créer des endpoints API
- ✅ **Hot Reload** : Rechargement automatique en développement

## 🎨 Composants principaux

- **ScanForm** : Formulaire pour lancer un nouveau scan
- **ScanList** : Liste des scans avec statut en temps réel
- **VulnerabilityCard** : Carte d'affichage d'une vulnérabilité
- **Dashboard** : Tableau de bord avec statistiques
- **ProgressBar** : Barre de progression pour les scans
- **Layout** : Layout principal avec navigation

## 🔌 Services API

- **lib/services/api.js** : Configuration axios avec gestion d'erreurs
- **lib/services/scanService.js** : Appels API pour les scans
- **lib/services/vulnerabilityService.js** : Appels API pour les vulnérabilités
- **lib/services/wsService.js** : Service WebSocket pour la progression temps réel

## 🛠️ Technologies utilisées

- Next.js 14
- React 18
- Material-UI (MUI)
- Axios
- WebSocket API
