FROM node:18-alpine

# Métadonnées
LABEL maintainer="CyberSec AI Team"
LABEL description="Frontend Next.js pour l'Agent IA de Cybersécurité"

# Définir le répertoire de travail
WORKDIR /app

# Installer les dépendances système
RUN apk add --no-cache libc6-compat

# Copier les fichiers de configuration
COPY package*.json ./

# Installer les dépendances
# Utiliser npm install au lieu de npm ci pour éviter les erreurs si package-lock.json est manquant
RUN npm install

# Copier le reste du code
COPY . .

# Exposer le port
EXPOSE 3000

# Variables d'environnement
ENV NODE_ENV=development
ENV NEXT_TELEMETRY_DISABLED=1

# Commande par défaut (développement)
CMD ["npm", "run", "dev"]
