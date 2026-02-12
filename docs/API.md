# Documentation API - Vulnerability Agent IA

Ce document décrit les principaux endpoints de l'API FastAPI du backend.

## Authentification

- **POST `/auth/register`**  
  Crée une organisation + un utilisateur admin.

- **POST `/auth/login`**  
  Authentifie un utilisateur et retourne un JWT (header `Authorization: Bearer ...`).

- **GET `/auth/me`**  
  Retourne les informations de l'utilisateur courant.

## Assets

- **GET `/api/v1/assets`**  
  Liste des assets de l'organisation courante.

- **POST `/api/v1/assets`**  
  Crée un asset (validation IP + pas de doublons par organisation).

- **GET `/api/v1/assets/{id}`**  
  Détails d'un asset.

- **PUT `/api/v1/assets/{id}`**  
  Mise à jour d'un asset (y compris credentials SSH chiffrés).

- **DELETE `/api/v1/assets/{id}`**  
  Supprime un asset.

## Scans

- **POST `/api/v1/scans`**  
  Crée un scan pour un asset et lance une tâche Celery.

- **GET `/api/v1/scans`**  
  Liste des scans de l'organisation.

- **GET `/api/v1/scans/{id}`**  
  Détails d'un scan + vulnérabilités créées.

- **WebSocket `/ws/scans/{id}`**  
  Flux temps réel de progression (lecture périodique dans la BDD).

## Vulnérabilités & IA

- **GET `/api/v1/vulnerabilities`**  
  Liste filtrable (`severity`, `status`, `asset_id`, `scan_id`, `search`).

- **GET `/api/v1/vulnerabilities/{id}`**  
  Détail d'une vulnérabilité (infos CVE, IA, remédiation).

- **POST `/api/v1/vulnerabilities/{id}/analyze`**  
  Lance une analyse IA (via `Analyzer`) et stocke le résultat en BDD.

## Scripts de remédiation

- **POST `/api/v1/vulnerabilities/{id}/generate-script`**  
  Génère un script de correction (via `Generator`) et crée un `RemediationScript`.

- **GET `/api/v1/remediation-scripts/{id}`**  
  Retourne le script et ses métadonnées.

- **PUT `/api/v1/remediation-scripts/{id}/approve`**  
  Approuve un script (workflow simple).

- **POST `/api/v1/remediation-scripts/{id}/execute`**  
  Lance l'exécution SSH asynchrone (tâche Celery).

## Dashboard

- **GET `/api/v1/dashboard/stats`**  
  Statistiques globales : assets, scans, vulnérabilités, distribution par sévérité, trend 30 jours.

